# 010 — Adversarial review adjudication

Sweep verdict: **REWRITE**. Author verdict: **APPROVED** (all findings applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 7 | Critical | consistency | **Adopt** — ST-15/ST-17 tenant routes wired: `GET/PATCH/DELETE /admin/tenants/{id}` (owner-or-superadmin, settings PATCH bumps `content_version` + same-tx purge); without them ST-15/ST-17 contract tests were unreachable | §Router, §Middleware |
| 21 | High | perf | **Adopt** — rate limiter on auth/mutation routes only, TTL-evicted bucket map (no unbounded IP growth); public read path under CDN/WAF; shared store deferred until replicas | §Middleware rateLimit |
| 26 | Medium | cleanliness | **Adopt** — single `scopeFromActor` construction site for `store.Scope{Platform:...}` (never from params/handlers); invariant test pinned in 001 (#7) | §Middleware auth |
| 11 | High (002) | correctness | **Adopt (note)** — SameSite=Lax cookie vs `Authorization: Bearer` token mode documented | §Middleware |
| 12b | High (003) | correctness | **Adopt (note)** — OAuth callback is GET (already correct in 010's mux) | §Router |
| Q1 in-memory rate limit | — | decision | **Adopt scoped + GC'd** (see #21) | §Sweep resolutions #1 |
| Q2 tenants listing | — | decision | **Adopt platform-only; slug resolver reused from 009** | §Sweep resolutions #2 |
| Q3 session verify latency | — | decision | **Adopt unchanged** — two PK reads ~µs, inside ST-22 budget | §Sweep resolutions #3 |

Leaveover: error envelope, strict `decodeJSON`, contract-test harness mapping ST-1…23 — unchanged.