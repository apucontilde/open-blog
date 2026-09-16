# 001 — Adversarial review adjudication

Sweep verdict: **REWRITE**. Author verdict: **APPROVED** (all findings applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 1 | Critical | correctness | **Adopt** — composite FK `(tenant_id, post_id)` on `post_images`/`imports`; `unique(tenant_id,id)` anchor on posts | §Schema, child tables |
| 5 | Critical | correctness | **Adopt** — `memberships` unscoped; DO-block comment/array contradiction fixed; membership queries always `user_id=$actor` | §Security contract, §RLS, rewrite of "Which tables" prose |
| 6 | Critical | consistency | **Adopt** — `tenants.content_version bigint` + `updated_at` | §Schema tenants |
| 7 | Critical | consistency | **Adopt** (routes live in 010; content_version bump there too) | §Schema (column) |
| 8 | Critical | correctness | **Adopt** — `Scoped` nil-cast for zero `TenantID` (never the `'0000…'` string); `TestFailClosed` reasserted vs nil-uuid tenant | §Go Scoped, §Contract tests #2 |
| 10 | High | perf | **Adopt** — index `(tenant_id, status, published_at desc, id desc)` | §Schema posts |
| 18 | High | correctness | **Adopt** — `lower(email)` unique index; normalization in Go on write | §Schema users |
| 19 | High | correctness | **Adopt** — DDL-only migrations + `TestRlsLint` rejects tenant-scoped DML in goose files | §Migrations, §Contract tests #6 |
| 24 | Medium | consistency | **Adopt** — `users.password_hash text` (argon2id encoded string, not bytea) | §Schema users |
| 25 | Medium | perf | **Adopt** — read-only scopes: `begin read only` + `set_config` in the same round trip | §Go Scoped, §Performance |
| 28 | Medium | perf | **Adopt** — GIN `(metadata jsonb_path_ops)` for `?tag=` | §Schema posts |
| 29 | Medium | cleanliness | **Adopt** — expiry sweeps owned by 008 (schema already carried `sessions(expires_at)` index) | §Schema (kept) |
| #1 id strategy (001 Q5) | — | decision | **Adopt A · uuid v7 app-minted everywhere** (presign/jobs/imports need pre-known ids; split-collision-free) | §ID strategy (decided) |
| 001 Q1 memberships | — | decision | **Adopt unscoped** (see #5) | §RLS rewrite |
| 001 Q2 roles | — | decision | **Adopt text + CHECK, Go iota enum** | §Schema headers + memberships/invitations |
| 001 Q3 migrations | — | decision | **Adopt DDL-only + lint** (see #19) | §Sweep resolutions |
| 001 Q4 invitations | — | decision | **Adopt unscoped**; consumption gated on verified mailbox + atomic consume | §RLS prose |

Note: `#14` (009 GROUP BY), `#17`/`#18` (consume/email, applied in 003), and `#26` (scope discipline,
invariant test is #7 here) are recorded in their owning plans.

## Open question verdicts (verdicts that affected THIS file only)
ID strategy, roles, memberships, invitations, migrations — all resolved above. No open questions remain.