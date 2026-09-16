# Implementation plans — Open Blog API (Go + PostgreSQL)

Modular-monolith plans. One file per small model, each written against the architecture in
[`.lavish/blog-api-plan.html`](../../.lavish/blog-api-plan.html) (contract tests ST-1…ST-23).
Every plan is adversarially reviewed before it is marked *approved*.

## Module map

| # | Module | Depends on | Status |
|---|--------|------------|--------|
| 001 | Schema, migrations & RLS foundation | — | **approved** (sweep applied) |
| 002 | Auth — password + opaque sessions | 001 | **approved** (sweep applied) |
| 003 | Auth — OAuth SSO (Google/GitHub) + identity linking | 001 | **approved** (sweep applied) |
| 004 | Tenant resolution & per-request RBAC middleware | 001 | **approved** (sweep applied) |
| 005 | Posts — CRUD, lifecycle, render-on-publish | 001, 004 | **approved** (sweep applied) |
| 006 | Media — presign/confirm, R2 layout, variants worker | 001, 004, 008 | **approved** (sweep applied) |
| 007 | Import — PDF/DOCX/Google Docs → markdown worker | 001, 003, 004, 008 | **approved** (sweep applied) |
| 008 | Job queue + workers (PG inbox, retries, idempotency) | 001 | **approved** (sweep applied) |
| 009 | Public read API + caching/CDN headers + cursor pagination | 001, 005, 006 | **approved** (sweep applied) |
| 010 | Admin HTTP layer — router, middleware, validation, errors | all | **approved** (sweep applied) |

## Sweep outcome (2026-09-15)

One adversarial pass over all ten plans → 30 findings + definitive verdicts on every open question.
**All findings adopted** (none rejected). Headline confirmations and changes:

- **IDs:** uuid v7 app-minted everywhere (001 Q5 → A). **Roles:** DB `text`+CHECK, Go iota enum.
- **RLS scope set is final:** only `posts, post_images, imports` (memberships/invitations/jobs/oauth/tenants
  unscoped). Fail-closed `Scoped` uses SQL NULL for the zero tenant (never `'0000…'`).
- **New in sweep:** `oauth_tokens` (007's Google import was otherwise unbuildable); composite
  `(tenant_id, post_id)` FKs; `tenants.content_version` (ETag anchor); `jobs.dedupe_key` + lease/expiry
  sweep + **enqueue-in-tx**; consistent 009 `srcset` contract on 006's canonical `variants` shape;
  ST-15/ST-17 tenant routes; SameSite=Lax cookie + token mode; conditional row-ownership; single
  `scopeFromActor` site.
- Every plan carries a `## Sweep resolutions` section and a `<nnn>/review.md` adjudication table.

Plans are implementation-ready; they become the build tasks the contract test suite (ST-1…ST-23) verifies.

## Stack constraints (whole repo)

- **Go 1.22+**, stdlib `net/http` ServeMux (method + `{param}` patterns). No web framework.
- **PostgreSQL**, single primary. One connection role `blog_app`, RLS enforced in-DB.
- **pgx/v5** (`pgxpool`) is the only DB dependency. No ORM; handwritten SQL.
- **goose** for migrations; SQL embedded with `embed.FS`.
- **golang.org/x/crypto/argon2** for passwords. OAuth via raw HTTP + `golang.org/x/oauth2`.
- IDs: `github.com/google/uuid`, generated app-side.
- Config: environment variables only, parsed once into one struct in `cmd/api`.
- Comments are for contracts and non-obvious invariants only — no header blocks, no narration.
- Performance defaults: prepared statements (pgx default), one round trip per op, batch for
  bulk writes, keyset cursors, render-on-publish. Favor plain code over abstraction.
- Single instance now; stateless replicas later. Nothing stateful leaves Postgres/R2.

## Review protocol

1. Plan author writes every `<nnn>-<slug>/plan.md` (self-contained, each marked *draft*, no cross-plan blockers left open).
2. When **all** plans exist, one adversarial reviewer agent runs a single sweep across the whole set (one read pass, cheaper to author and review), attacking correctness (RLS bypass, pooling, privilege), performance, simplicity, and comment discipline. It proposes replacements, not complaints. — **Done 2026-09-15: one sweep, 30 findings, all adopted.**
3. Author adjudicates every finding (adopt / adopt-modified / reject + reason) inside each `<nnn>-<slug>/review.md`; plans are edited to absorb adopted findings and re-marked *approved*. — **Done.**

Approved plans are implementation-ready; they then become the build tasks that the contract test
suite (ST-1…ST-23) verifies.