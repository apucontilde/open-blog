# 008 — Adversarial review adjudication

Sweep verdict: **REWRITE**. Author verdict: **APPROVED** (all findings applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 9 | High ×3 | correctness | **Adopt in full** — `jobs.dedupe_key` + `unique(kind, dedupe_key) where not null` (ON CONFLICT target now exists); **enqueue-in-tx** (outbox vagueness replaced: every domain tx inserts its job row; a commit always carries its job); **lease/expiry sweep** `state='running' AND lease_until<now() → queued`, attempts untouched — budget = runs, not claims | §Schema note + §Claim, §Enqueue-in-tx |
| 16 | High | perf | **Adopt** — N worker goroutines (`JOBS_WORKERS` default 3) so a stuck import doesn't block variants; `FOR UPDATE SKIP LOCKED` keeps claims disjoint; native processes (libvips/pandoc) bounded by semaphore | §Worker loop |
| 29 | Medium | cleanliness | **Adopt** — periodic expiry cleanups in the worker loop: `sessions` (7d), `oauth_flows` (now) | §Worker loop periodic |
| 1 | Critical-ish incentive | correctness | **Adopt (note)** — `lease_until` column + 180 s default (≥ import 30 s / variants 60 s) | §Claim, schema (001) |
| Q1 poll vs LISTEN/NOTIFY | — | decision | **Adopt poll, no NOTIFY** — PgBouncer/pooled connections make LISTEN unsupportable; ≤1 s added latency inside the "one purge cycle" tolerance | §Worker loop, §Sweep resolutions #1 |
| Q2 backoff constants | — | decision | **Keep base 1 s ×2, cap 1 h, attempts>=5 failed**; lease 180 s; verified against longest tails | §Sweep resolutions #2 |
| Q3 jobs unscoped + payload | — | decision | **Keep unscoped by design**; handlers derive + validate scope from payload `tenant_id` at claim; no tenant secret in payloads | §Sweep resolutions #3 |

Leaveover: `CopyFrom` batch enqueue; handlers registry shape; per-job timeouts — unchanged.