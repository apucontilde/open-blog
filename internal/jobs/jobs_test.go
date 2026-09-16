package jobs

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"math"
)

func testDBURL(t *testing.T) string {
	t.Helper()
	return os.Getenv("DATABASE_URL")
}

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	if testDBURL(t) == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed job tests")
	}
	pool, err := pgxpool.New(ctx, testDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testDBConnect(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := newTestPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "truncate table jobs"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func insertJob(t *testing.T, pool *pgxpool.Pool, kind, state string, attempts int, payload []byte) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(), `
		insert into jobs (id, kind, state, attempts, payload)
		values ($1, $2, $3, $4, $5)`, id, kind, state, attempts, payload)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func eventually(t *testing.T, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within", d)
}

func jobState(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, out *string) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		"select state from jobs where id = $1", id).Scan(out)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEnqueueCommitCarriesJob(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := Enqueue(ctx, tx, "commit-me", "", JobPayload{TenantID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		"select count(*) from jobs where id = $1 and kind = 'commit-me'", id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 job after commit, got %d", count)
	}
}

func TestEnqueueRollbackLosesJob(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Enqueue(ctx, tx, "rollback-me", "", JobPayload{}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		"select count(*) from jobs where kind = 'rollback-me'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected 0 jobs after rollback, got %d", count)
	}
}

func TestEnqueueDedupeConflict(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Enqueue(ctx, tx, "dedupe", "same-key", JobPayload{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Enqueue(ctx, tx2, "dedupe", "same-key", JobPayload{})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	if second != uuid.Nil {
		t.Fatalf("expected nil id on duplicate, got %v", second)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		"select count(*) from jobs where kind = 'dedupe'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 job, got %d", count)
	}
	if first == uuid.Nil {
		t.Fatal("expected a real id on first enqueue")
	}
}

func TestEnqueueEmptyDedupeIsNotDeduplicated(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Enqueue(ctx, tx, "no-dedupe", "", JobPayload{}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	var count int
	if err := pool.QueryRow(ctx,
		"select count(*) from jobs where kind = 'no-dedupe'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected 2 jobs, got %d", count)
	}
}

func TestEnqueueBatch(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, err := EnqueueBatch(ctx, tx, "batch", []any{
		JobPayload{TenantID: uuid.New()},
		JobPayload{TenantID: uuid.New()},
		JobPayload{TenantID: uuid.New()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if n != 3 {
		t.Fatalf("expected 3 rows inserted, got %d", n)
	}
	var count int
	if err := pool.QueryRow(ctx,
		"select count(*) from jobs where kind = 'batch'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("expected 3 batched jobs, got %d", count)
	}
}

func TestClaimRespectsRunAfter(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	w := New(pool)

	id := uuid.New()
	if _, err := pool.Exec(ctx, `
		insert into jobs (id, kind, run_after) values ($1, 'future', now() + interval '5 minutes')`,
		id); err != nil {
		t.Fatal(err)
	}

	if _, err := w.claim(ctx); !errors.Is(err, ErrNoJob) {
		t.Fatalf("expected ErrNoJob for future run_after, got %v", err)
	}

	if _, err := pool.Exec(ctx,
		"update jobs set run_after = now() - interval '1 second' where id = $1", id); err != nil {
		t.Fatal(err)
	}
	job, err := w.claim(ctx)
	if err != nil {
		t.Fatalf("claim should succeed once due, got %v", err)
	}
	if job.ID != id {
		t.Fatalf("claimed wrong job: got %v want %v", job.ID, id)
	}
}

func TestClaimSkipLockedNoDoubleClaim(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	w := New(pool)

	_ = insertJob(t, pool, "solo", "queued", 0, []byte("{}"))

	type result struct {
		id  uuid.UUID
		err error
	}
	ch := make(chan result, 6)
	for i := 0; i < 6; i++ {
		go func() {
			j, err := w.claim(ctx)
			ch <- result{j.ID, err}
		}()
	}

	var claimed uuid.UUID
	noJob := 0
	for i := 0; i < 6; i++ {
		r := <-ch
		switch {
		case r.err == nil:
			if claimed != uuid.Nil {
				t.Fatal("two concurrent claims both acquired a job")
			}
			claimed = r.id
		case errors.Is(r.err, ErrNoJob):
			noJob++
		default:
			t.Fatalf("unexpected claim error: %v", r.err)
		}
	}
	if claimed == uuid.Nil {
		t.Fatal("expected exactly one successful claim")
	}
	if noJob != 5 {
		t.Fatalf("expected 5 claimers to find no job, got %d", noJob)
	}
}

func TestClaimIncrementsAttempts(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	w := New(pool)

	id := insertJob(t, pool, "counted", "queued", 0, []byte("{}"))
	if _, err := w.claim(ctx); err != nil {
		t.Fatal(err)
	}

	var attempts int
	if err := pool.QueryRow(ctx,
		"select attempts from jobs where id = $1", id).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("expected attempts=1 after a claim (runs, not claims), got %d", attempts)
	}
}

func TestLeaseExpirySweepRequeuesWithoutBurningBudget(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	w := New(pool)

	id := insertJob(t, pool, "crashed", "running", 3, []byte("{}"))
	if _, err := pool.Exec(ctx,
		"update jobs set lease_until = now() - interval '1 second' where id = $1", id); err != nil {
		t.Fatal(err)
	}

	w.sweep(ctx)

	var state string
	var attempts int
	var lease *time.Time
	if err := pool.QueryRow(ctx,
		"select state, attempts, lease_until from jobs where id = $1", id).
		Scan(&state, &attempts, &lease); err != nil {
		t.Fatal(err)
	}
	if state != "queued" {
		t.Fatalf("expected requeue to queued, got %q", state)
	}
	if attempts != 3 {
		t.Fatalf("lease sweep must not touch attempts (budget = runs, not claims), got %d", attempts)
	}
	if lease != nil {
		t.Fatal("expected lease_until cleared on requeue")
	}
}

func TestUnresponsiveLeaseDoesNotRequeue(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	w := New(pool)

	id := insertJob(t, pool, "alive", "running", 1, []byte("{}"))
	if _, err := pool.Exec(ctx,
		"update jobs set lease_until = now() + interval '2 minutes' where id = $1", id); err != nil {
		t.Fatal(err)
	}

	w.sweep(ctx)

	var state string
	if err := pool.QueryRow(ctx,
		"select state from jobs where id = $1", id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "running" {
		t.Fatalf("expected still running under a live lease, got %q", state)
	}
}

func TestFailMarksFailedAtMaxAttempts(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	w := New(pool)

	w.Register("boom", func(ctx context.Context, p JobPayload) error {
		return errors.New("kaboom")
	})

	id := insertJob(t, pool, "boom", "running", MaxAttempts, []byte(`{"tenant_id":"00000000-0000-0000-0000-000000000000"}`))
	w.runJob(ctx, Job{ID: id, Kind: "boom", Payload: []byte(`{}`)})

	var state string
	var lastErr *string
	if err := pool.QueryRow(ctx,
		"select state, last_err from jobs where id = $1", id).Scan(&state, &lastErr); err != nil {
		t.Fatal(err)
	}
	if state != "failed" {
		t.Fatalf("expected failed at max attempts, got %q", state)
	}
	if lastErr == nil || *lastErr == "" {
		t.Fatal("expected last_err to be kept")
	}
}

func TestFailRequeuesWithBackoff(t *testing.T) {
	pool := testDBConnect(t)
	ctx := context.Background()
	w := New(pool)

	w.Register("flaky", func(ctx context.Context, p JobPayload) error {
		return errors.New("transient")
	})

	id := insertJob(t, pool, "flaky", "running", 1, []byte(`{}`))
	w.runJob(ctx, Job{ID: id, Kind: "flaky", Payload: []byte(`{}`)})

	var state string
	var runAfter time.Time
	var lease *time.Time
	if err := pool.QueryRow(ctx,
		"select state, run_after, lease_until from jobs where id = $1", id).
		Scan(&state, &runAfter, &lease); err != nil {
		t.Fatal(err)
	}
	if state != "queued" {
		t.Fatalf("expected requeue, got %q", state)
	}
	if lease != nil {
		t.Fatal("expected lease_until cleared on requeue")
	}
	if d := time.Until(runAfter); d < 0 || d > 5*time.Second {
		t.Fatalf("expected a near-future run_after, got %v away", d)
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	if b := computeBackoff(1); b != baseBackoff {
		t.Fatalf("attempt 1: want 1s, got %v", b)
	}
	if b := computeBackoff(2); b != 2*baseBackoff {
		t.Fatalf("attempt 2: want 2s, got %v", b)
	}
	if b := computeBackoff(3); b != 4*baseBackoff {
		t.Fatalf("attempt 3: want 4s, got %v", b)
	}
	if b := computeBackoff(12); b != time.Duration(math.Pow(2, 11))*baseBackoff {
		t.Fatalf("attempt 12: want 2048s, got %v", b)
	}
	if b := computeBackoff(13); b != maxBackoff {
		t.Fatalf("attempt 13: want 1h cap, got %v", b)
	}
	if b := computeBackoff(100); b != maxBackoff {
		t.Fatalf("attempt 100: want 1h cap, got %v", b)
	}
}

func TestHandlerRegistryDispatchAndDone(t *testing.T) {
	pool := testDBConnect(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := New(pool)

	tid := uuid.New()
	started := make(chan JobPayload, 1)
	release := make(chan struct{})
	w.Register("handle-me", func(ctx context.Context, p JobPayload) error {
		started <- p
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	id := insertJob(t, pool, "handle-me", "queued", 0,
		[]byte(`{"tenant_id":"`+tid.String()+`","data":{"n":7}}`))

	go w.Run(ctx, 1)

	var got JobPayload
	select {
	case got = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never invoked")
	}
	if got.TenantID != tid {
		t.Fatalf("handler received wrong tenant: %v", got.TenantID)
	}

	var state string
	jobState(t, pool, id, &state)
	if state != "running" {
		t.Fatalf("expected running while handled, got %q", state)
	}

	close(release)
	eventually(t, 5*time.Second, func() bool {
		var s string
		jobState(t, pool, id, &s)
		return s == "done"
	})

	cancel()
}

func TestUnknownKindFailsJob(t *testing.T) {
	pool := testDBConnect(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := New(pool)

	id := insertJob(t, pool, "no-such-kind", "queued", 0, []byte(`{}`))

	go w.Run(ctx, 1)

	eventually(t, 5*time.Second, func() bool {
		var state string
		var lastErr *string
		if err := pool.QueryRow(context.Background(),
			"select state, last_err from jobs where id = $1", id).Scan(&state, &lastErr); err != nil {
			t.Fatal(err)
		}
		return state == "failed" && lastErr != nil
	})

	cancel()
}

func TestGracefulShutdownWaitsForInFlight(t *testing.T) {
	pool := testDBConnect(t)
	ctx, cancel := context.WithCancel(context.Background())
	w := New(pool)

	started := make(chan struct{})
	release := make(chan struct{})
	w.Register("slow", func(ctx context.Context, p JobPayload) error {
		close(started)
		<-release // handler blocked purely on a channel: drain-proof to cancellation
		return nil
	})

	id := insertJob(t, pool, "slow", "queued", 0, []byte(`{}`))

	wgDone := make(chan struct{})
	go func() {
		w.Run(ctx, 1)
		close(wgDone)
	}()

	<-started
	cancel() // shutdown requested while handler is in flight

	// Handler does not observe the cancellation, so Run must keep waiting.
	select {
	case <-wgDone:
		t.Fatal("Run returned before the in-flight handler drained")
	case <-time.After(500 * time.Millisecond):
	}
	close(release)

	select {
	case <-wgDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after handler drained")
	}

	var state string
	jobState(t, pool, id, &state)
	if state != "done" {
		t.Fatalf("expected handler to finish cleanly during shutdown, got %q", state)
	}
}

func TestCloseCancelsRun(t *testing.T) {
	pool := testDBConnect(t)
	w := New(pool)

	wgDone := make(chan struct{})
	go func() {
		w.Run(context.Background(), 1)
		close(wgDone)
	}()

	time.Sleep(100 * time.Millisecond)
	w.Close()

	select {
	case <-wgDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not make Run return")
	}
}
