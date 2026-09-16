# 004 — Tenant resolution & per-request RBAC

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 001, 002. Unlocks 005+.

## Goal

Turn the raw session into an **Actor** every module can enforce against: `{UserID, TenantID, Role, Platform}`.
Layer split is explicit:

- **RLS (001)** = *which rows exist*. Tenant scope only.
- **RBAC (this plan)** = *which actions are allowed*. Capabilities per role.
- **Row ownership (Go)** = editor/author-specific rules RLS cannot express without per-user policies
  (e.g. "author edits only their own draft"). Implemented as an explicit Go check, never trusted client-side.

## Actor resolution

```
Verify(token) -> session.user_id / session.scope (active tenant)      <- 002
Load(user_id, scope.tenant) -> memberships.role                       <- one PK query
if users.super_admin -> Platform
```

**Super-admin is `users.super_admin boolean`** (sweep, 004 Q1): one global flag, no per-tenant row to
constrain a platform-wide capability; a "platform membership" was rejected because it would inherit the
same cross-tenant-switcher problem that memberships scoping had. Column already in 001.

**Role ordering is a Go enum** (sweep, 004 Q2): `type Role int` with `author < editor < admin < owner` and
`String()`; the DB stores `text` + CHECK (001). Ordering logic lives in one Go file; logs are readable.

Middleware shape (wired in 010):

```go
type Actor struct {
	UserID   uuid.UUID
	Tenant   *uuid.UUID // nil until a tenant is chosen
	Role     Role       // zero value until Tenant set
	Platform bool       // cross-tenant, set iff users.super_admin
}

// Require returns 403 unless the actor holds capability c in the active tenant.
func Require(a Actor, c capability) error {
	if a.Platform { return nil }
	if c == CapViewDrafts && a.Role >= RoleEditor { return nil } // etc
	return ErrForbidden
}
```

Capability ladder: `author < editor < admin < owner`; `platform` is a boolean, not a ladder rank.

**Scope construction is centralized** (sweep, finding 26): the *only* place a `store.Scope` is derived from
an Actor is the 010 auth middleware (`store.Scope{TenantID: actor.Tenant, Platform: actor.Platform}`).
`Platform:true` is never settable from session data, query params, or handler code; a store-invariant test
pins that (`TestPlatformScopeDiscipline`, 001).

## Active-tenant switching (ST-18, ST-20)

`PUT /auth/me/active-tenant {tenantId}` validates: `tenantId` ∈ actor's **full cross-tenant membership
list** (memberships are unscoped in 001 and always filtered by `user_id = $actor` server-side — this is
exactly what lets the switcher work, and ST-20 series b) → writes `sessions.scope`. Every subsequent
request loads that scope. Backs `Scope{Platform:true}` only when `Actor.Platform` — the 001 flag is *set
in Go after* this verification, in the same transaction wrapper.

## Row-ownership rules (Go)

- Author: draft ops limited to `posts.author_id == Actor.UserID` (ST-6). Enforced as an extra `WHERE` in
  the query + read-after-write check; RLS still provides the tenant wall. **Conditional on role** (sweep,
  finding 20): the filter applies *only* when `!actor.Platform && actor.Role == RoleAuthor` — a
  super-admin/platform actor editing any tenant must not be 403'd by this rule.
- Editor+: any post in the tenant (ST-9/ST-11).
- Owner/admin: members + settings (ST-12..15).

These are the *only* rules that live outside RLS. Everything else is capability-based.

## Cookie mode

Adopted from 002 sweep: `SameSite=Lax` (Strict broke the OAuth callback's state binding). Cookie only
when the editor origin is same-site; cross-origin SPA uses the HTTP token. (Open question 3 resolved.)

## Performance

- One extra PK lookup (`memberships(tenant_id, user_id)`) per authenticated request; joins the session PK
  hit from 002. Two indexed point reads, ~µs. No per-row authz work in list paths (RLS already filters).
- The `sessions.scope` write on switch is a single-row update; harmless.
- `/auth/me`'s membership listing is a `memberships WHERE user_id=$1` unscoped read — one index scan over
  the actor's own rows only.

## Sweep resolutions (see `review.md`)

1. **super_admin shape:** `users.super_admin boolean`.
2. **Role ordering:** Go iota enum; DB text+CHECK.
3. **Cookie mode:** SameSite=Lax (002); token mode for cross-origin.
4. **New in sweep:** memberships confirmed unscoped (switcher); conditional row-ownership; single
   Scope-construction site + invariant test.