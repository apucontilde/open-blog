# 008 — Job queue + workers (PG inbox)

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 001. Used by 005 (purge), 006 (variant/sweep), 007 (import).

## Goal

Durable async work with zero new infra: Postgres is the queue (single instance now, replicas-safe later).
Claims are crash-safe, workers re-try with backoff, jobs are idempotent by `dedupe_key`.

## Schema (from 001) + claim lease

```sql
-- claim one (attempts counts RUNS, not claims — sweep: crash-safe budget)
UPDATE jobs SET state='running', attempts=attempts+1, lease_until=now() + interval '180 seconds', updated_at=now()
WHERE id = (
  SELECT id FROM jobs
  WHERE state='queued' AND run_after <= now()
  ORDER BY run_after
  FOR UPDATE SKIP LOCKED
  LIMIT 1
)
RETURNING id, kind, payload;
```

- `FOR UPDATE SKIP LOCKED` gives concurrency safety if a second worker ever appears → the "add replicas,
  no config" story keeps working.
- **Lease/expiry sweep (sweep, finding 9 — this was missing):** a periodic `EXPIRE` pass requeues crashed
  claims without burning their budget:
  `UPDATE jobs SET state='queued', run_after=now(), lease_until=NULL WHERE state='running' AND lease_until < now()`
  (attempts untouched — budget = runs, not claims). `lease_until` default 180 s ≥ any handler (import 30 s,
  variants 60 s).
- **Backoff:** `run_after = now() + base * 2^(attempts-2)` (base 1s, cap 1h); `attempts >= max (5)` →
  `failed`, `last_err` kept for ops. No DLQ table needed at this scale — `failed` rows are queryable.
- **Idempotency is enforce-able now (sweep, finding 9):** `dedupe_key` + `unique (kind, dedupe_key) where
  dedupe_key is not null`; every enqueue is `INSERT ... ON CONFLICT (kind, dedupe_key) DO NOTHING.**

## Enqueue-in-tx (sweep, finding 9 — the outbox is now concrete)

Every purge on publish/PATCH/archive (005), every variant enqueue on media confirm (006), and every import
enqueue (007) inserts the `jobs` row **inside the same `Scoped` transaction** as the domain write. A commit
always carries its job; a rollback takes the job with it. `jobs` is unscoped so the insert is unaffected by
RLS — but **payloads always carry `tenant_id`** and every handler runs its work inside a scope derived from
that `tenant_id` (validated at claim, never trusted from the payload alone; cross-tenant abuse impossible:
a handler's DB work only sees its scoped tenant even if a payload lies).

## Worker loop (`internal/jobs`)

```go
// N goroutines (JOBS_WORKERS default 3), poll interval 1s (env-tunable). Future: workers on replicas.
func (w *Worker) Run(ctx context.Context) {
	for i := 0; i < w.n; i++ {
		go func() { // each goroutine: claim -> run -> done/fail; SKIP LOCKED keeps claims disjoint
			for {
				select { case <-ctx.Done(): return; default: }
				job, err := w.claim(ctx)              // the UPDATE ... SKIP LOCKED above
				if err == ErrNoJob { sleep(poll); continue }
				handler := w.handlers[job.Kind]       // registered by module (005/006/007)
				if err := runWithTimeout(ctx, handler, job); err != nil {
					w.fail(ctx, job, err)           // backoff re-queue, or failed
				} else {
					w.done(ctx, job)
				}
			}
		}()
	}
	<-ctx.Done()
}
```

- Handlers are plain funcs: `kind → func(ctx, payload) error`. Modules register their own; the registry is
  a `map[string]func(context.Context, []byte) error` built at `main`.
- **Multiple claim goroutines** (sweep, finding 16): a stuck/hung 30 s import no longer blocks variant
  generation; `FOR UPDATE SKIP LOCKED` keeps them disjoint. Variants/imports additionally cap **native**
  process concurrency (libvips semaphore 006; pandoc/pdftotext bounded by the same), so memory stays flat.
- Periodically (every `EXPIRE_INTERVAL`), one goroutine runs the lease sweep plus the **expiry cleanups**
  (sweep, finding 29): delete `sessions.expires_at < now()-7d`, `oauth_flows.expires_at < now()`.
- **Poll, not LISTEN/NOTIFY** (sweep, 008 Q1): publish is human-rate, ≤1 s added latency is inside the
  "one purge cycle" tolerance, and the PgBouncer pooling line makes LISTEN unsupportable over pooled
  connections. Revisit only with a real throughput case.
- Timeouts & cancellation from `ctx`; per-job timeout via `context.WithTimeout` (import 30s, variants 60s).

## Batch insert perf

Enqueueing many jobs in one writepath (e.g. a future bulk-op) uses `pgx CopyFrom`; the current per-op
enqueue is a single `INSERT ... ON CONFLICT (kind, dedupe_key) DO NOTHING`.

## Sweep resolutions (see `review.md`)

1. **Poll vs LISTEN/NOTIFY:** poll; LISTEN rejected (PgBouncer/pooling + latency inside tolerance).
2. **Backoff constants:** base 1 s ×2, cap 1 h, `attempts>=5` failed; lease 180 s; verified against
   import/variant longest tails.
3. **Jobs unscoped + payload tenants:** fine by design; handlers re-derive scope from payload `tenant_id`
   and validate it at claim; no tenant secret ever rides a job payload.
4. **New in sweep:** `dedupe_key` unique index (idempotency now enforceable); lease/expiry sweep (crash
   safety + no budget burn); **enqueue-in-tx** replaces "outbox vagueness" everywhere; N worker goroutines;
   expiry cleanups for `sessions`/`oauth_flows`.