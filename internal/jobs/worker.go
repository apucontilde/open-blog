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

// Register binds a handler for kind; handlers must be registered before Run.
func (w *Worker) Register(kind string, fn Handler) {
	w.mu.Lock()
	w.handlers[kind] = fn
	w.mu.Unlock()
}

// Run starts n workers plus a sweeper and blocks until cancellation and drain.
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

// Close cancels the context driving Run; safe to call before Run.
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

var ErrNoJob = errors.New("jobs: no job available")

// claim takes one due job with FOR UPDATE SKIP LOCKED; attempts counts runs, not claims.
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
		// Unknown kind is a deployment bug: fail immediately, don't retry.
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

// stateCtx detaches final state transitions from the shutdown cancellation.
func stateCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

func (w *Worker) markFailed(ctx context.Context, job Job, err error) {
	if _, execErr := w.pool.Exec(ctx,
		"update jobs set state = 'failed', last_err = $2, updated_at = now() where id = $1",
		job.ID, err.Error()); execErr != nil {
		slog.Error("jobs: mark failed failed", "job", job.ID, "err", execErr)
	}
}

// fail moves the job to failed at MaxAttempts, else requeues with 1s x2 backoff capped at 1h.
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

func computeBackoff(attempts int) time.Duration {
	d := float64(baseBackoff) * math.Pow(2, float64(attempts-1))
	if d > float64(maxBackoff) {
		d = float64(maxBackoff)
	}
	return time.Duration(d)
}

// sweeper requeues expired leases without burning attempts and runs the TTL cleanups.
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

	if _, err := w.pool.Exec(ctx,
		"delete from sessions where expires_at < now() - interval '7 days'"); err != nil {
		slog.Error("jobs: session cleanup failed", "err", err)
	}

	if _, err := w.pool.Exec(ctx,
		"delete from oauth_flows where expires_at < now()"); err != nil {
		slog.Debug("jobs: oauth_flows cleanup skipped", "err", err)
	}
}
