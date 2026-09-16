package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	DefaultWorkers  = 3
	MaxAttempts     = 5
	leaseDuration   = 180 * time.Second
	pollInterval    = time.Second
	sweepInterval   = 10 * time.Second
	baseBackoff     = time.Second
	maxBackoff      = time.Hour
	constJobTimeout = 60 * time.Second
)

type Handler func(ctx context.Context, payload JobPayload) error

type JobPayload struct {
	TenantID uuid.UUID       `json:"tenant_id"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// Job is a claimed row from the jobs table.
type Job struct {
	ID      uuid.UUID
	Kind    string
	Payload json.RawMessage
}

type Worker struct {
	pool     *pgxpool.Pool
	handlers map[string]Handler
	mu       sync.RWMutex

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func New(pool *pgxpool.Pool) *Worker {
	return &Worker{
		pool:     pool,
		handlers: make(map[string]Handler),
	}
}

// Register binds a handler for kind. The registry is locked at claim time, so
// handlers must be registered before Run is called.
func (w *Worker) Register(kind string, fn Handler) {
	w.mu.Lock()
	w.handlers[kind] = fn
	w.mu.Unlock()
}

// Run derives an internal, cancellable context from ctx, starts n worker
// goroutines plus one sweeper goroutine, and blocks until that context is
// cancelled and every in-flight handler has drained (graceful shutdown: no
// new claims are taken once cancellation fires, running handlers run to
// completion or observe the cancellation).
func (w *Worker) Run(ctx context.Context, n int) {
	w.once.Do(func() {
		w.ctx, w.cancel = context.WithCancel(ctx)
	})
	for i := 0; i < n; i++ {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			w.worker(w.ctx)
		}()
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.sweeper(w.ctx)
	}()
	w.wg.Wait()
}

// Close cancels the internal context driving Run: workers stop claiming and
// in-flight handlers drain before Run returns. Safe to call before Run.
func (w *Worker) Close() {
	w.once.Do(func() {
		w.ctx, w.cancel = context.WithCancel(context.Background())
	})
	if w.cancel != nil {
		w.cancel()
	}
}

func (w *Worker) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		job, err := w.claim(ctx)
		if errors.Is(err, ErrNoJob) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollInterval):
			}
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return // shutdown race between poll sleep and claim
			}
			slog.Error("jobs: claim error", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollInterval):
			}
			continue
		}

		w.wg.Add(1)
		go func(j Job) {
			defer w.wg.Done()
			w.runJob(ctx, j)
		}(job)
	}
}

// ErrNoJob reports an empty queue (claim found nothing to run).
var ErrNoJob = errors.New("jobs: no job available")

// claim flips one queued job to running under a 180s lease in a short
// transaction. FOR UPDATE SKIP LOCKED keeps concurrent claimers disjoint, so
// a job is never claimed twice. attempts counts RUNS, not claims.
func (w *Worker) claim(ctx context.Context) (Job, error) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return Job{}, err
	}
	defer tx.Rollback(ctx)

	var job Job
	err = tx.QueryRow(ctx, `
		update jobs set
			state = 'running',
			attempts = attempts + 1,
			lease_until = now() + $1::interval,
			updated_at = now()
		where id = (
			select id from jobs
			where state = 'queued' and run_after <= now()
			order by run_after
			for update skip locked
			limit 1
		)
		returning id, kind, payload`,
		leaseDuration).Scan(&job.ID, &job.Kind, &job.Payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNoJob
	}
	if err != nil {
		return Job{}, err
	}
	return job, tx.Commit(ctx)
}

func (w *Worker) runJob(ctx context.Context, job Job) {
	var payload JobPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		w.fail(job, err)
		return
	}

	w.mu.RLock()
	handler, ok := w.handlers[job.Kind]
	w.mu.RUnlock()
	if !ok {
		// Unknown kind is a deployment bug, not a transient condition: fail
		// the job immediately rather than burning the retry budget.
		sctx, scancel := stateCtx()
		defer scancel()
		w.markFailed(sctx, job, errors.New("jobs: no handler registered for kind "+job.Kind))
		return
	}

	jobCtx, cancel := context.WithTimeout(ctx, constJobTimeout)
	defer cancel()

	if err := handler(jobCtx, payload); err != nil {
		w.fail(job, err)
	} else {
		sctx, scancel := stateCtx()
		defer scancel()
		w.done(sctx, job)
	}
}

func (w *Worker) done(ctx context.Context, job Job) {
	if _, err := w.pool.Exec(ctx,
		"update jobs set state = 'done', updated_at = now() where id = $1", job.ID); err != nil {
		slog.Error("jobs: mark done failed", "job", job.ID, "err", err)
	}
}

// stateCtx returns a short-lived context detached from the worker's shutdown
// cancellation: final state transitions must always land even mid-drain.
func stateCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// markFailed permanently fails a job, keeping last_err for ops.
func (w *Worker) markFailed(ctx context.Context, job Job, err error) {
	if _, execErr := w.pool.Exec(ctx,
		"update jobs set state = 'failed', last_err = $2, updated_at = now() where id = $1",
		job.ID, err.Error()); execErr != nil {
		slog.Error("jobs: mark failed failed", "job", job.ID, "err", execErr)
	}
}

// fail records the outcome of a failed run: attempts >= MaxAttempts moves the
// job to failed with last_err kept for ops; otherwise it requeues with
// run_after pushed out by an exponential backoff (base 1s x2, capped at 1h).
func (w *Worker) fail(job Job, err error) {
	sctx, scancel := stateCtx()
	defer scancel()

	var attempts int
	if scanErr := w.pool.QueryRow(sctx,
		"select attempts from jobs where id = $1", job.ID).Scan(&attempts); scanErr != nil {
		slog.Error("jobs: read attempts failed", "job", job.ID, "err", scanErr)
		return
	}

	if attempts >= MaxAttempts {
		w.markFailed(sctx, job, err)
		return
	}

	_, execErr := w.pool.Exec(sctx,
		`update jobs set state = 'queued', run_after = now() + $2::interval,
			lease_until = null, updated_at = now() where id = $1`,
		job.ID, computeBackoff(attempts))
	if execErr != nil {
		slog.Error("jobs: requeue failed", "job", job.ID, "err", execErr)
	}
}

// computeBackoff returns base * 2^(attempts-1), capped at maxBackoff.
// attempts=1 => 1s, 2 => 2s, 3 => 4s, 4 => 8s, capped at 1h.
func computeBackoff(attempts int) time.Duration {
	d := float64(baseBackoff) * math.Pow(2, float64(attempts-1))
	if d > float64(maxBackoff) {
		d = float64(maxBackoff)
	}
	return time.Duration(d)
}

// sweeper periodically requeues expired leases (crash recovery; attempts are
// untouched, so the retry budget stays a run budget) and runs the TTL
// cleanups. Tables are unscoped, so these run at store level.
func (w *Worker) sweeper(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

func (w *Worker) sweep(ctx context.Context) {
	if _, err := w.pool.Exec(ctx, `
		update jobs set state = 'queued', run_after = now(), lease_until = null, updated_at = now()
		where state = 'running' and lease_until < now()`); err != nil {
		slog.Error("jobs: lease sweep failed", "err", err)
	}

	// sessions: expiry + 7d grace.
	if _, err := w.pool.Exec(ctx,
		"delete from sessions where expires_at < now() - interval '7 days'"); err != nil {
		slog.Error("jobs: session cleanup failed", "err", err)
	}

	// oauth_flows: past expiry (table arrives with plan 003).
	if _, err := w.pool.Exec(ctx,
		"delete from oauth_flows where expires_at < now()"); err != nil {
		slog.Debug("jobs: oauth_flows cleanup skipped", "err", err) // table may not exist yet
	}
}
