# 010 — Admin HTTP layer

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 002, 003, 004, 005, 006, 007, 009 (assembly). Contract tests ST-1…ST-23.

## Goal

One `cmd/api` binary: router, middleware chain, validation, error envelope, and the httptest harness that
turns the stories into passing contract tests.

## Router (Go 1.22+ stdlib `http.ServeMux`)

```go
mux.Handle("GET /livez", liveness)
mux.Handle("GET /readyz", readiness)
// public (no auth) — 009; CDN-fronted, NO app-level rate limiting
mux.Handle("GET /public/{tenant}/site", pub.Site)
mux.Handle("GET /public/{tenant}/posts", pub.List)
mux.Handle("GET /public/{tenant}/posts/{slug}", pub.Get)
// auth entry — 002/003 (no session required)
mux.Handle("POST /auth/signup", auth.Signup)               // rate: IP + email
mux.Handle("POST /auth/login", auth.Login)                 // rate: IP + email
mux.Handle("POST /auth/oauth/start", oauth.Start)
mux.Handle("GET /auth/oauth/callback", oauth.Callback)     // GET, standardized (003 sweep)
// admin — session required, actor attached (004)
mux.Handle("POST /auth/logout", wrap(logout))          // session
mux.Handle("GET /auth/me", wrap(me))                    // actor view
mux.Handle("PUT /auth/me/active-tenant", wrap(setTenant))
mux.Handle("GET /admin/posts", wrap(posts.List))
mux.Handle("POST /admin/posts", wrap(posts.Create))
mux.Handle("GET /admin/posts/{id}", wrap(posts.Get))
mux.Handle("PATCH /admin/posts/{id}", wrap(posts.Update))
mux.Handle("DELETE /admin/posts/{id}", wrap(posts.Delete))
mux.Handle("POST /admin/posts/{id}/publish", wrap(posts.Publish))
mux.Handle("POST /admin/posts/{id}/unpublish", wrap(posts.Unpublish))
mux.Handle("POST /admin/media/presign", wrap(media.Presign))
mux.Handle("POST /admin/media/confirm", wrap(media.Confirm))
mux.Handle("DELETE /admin/media/{id}", wrap(media.Delete))
mux.Handle("POST /admin/imports", wrap(imports.Start))
mux.Handle("GET /admin/imports/{id}", wrap(imports.Status))
mux.Handle("POST /admin/imports/{id}/apply", wrap(imports.Apply))
mux.Handle("GET /admin/members", wrap(members.List))
mux.Handle("POST /admin/members", wrap(members.Invite))
mux.Handle("PATCH /admin/members/{userId}", wrap(members.SetRole))
mux.Handle("DELETE /admin/members/{userId}", wrap(members.Remove))
// tenants — settings + provisioning; sweep added the ST-15/ST-17 drill-down routes (finding 7)
mux.Handle("GET /admin/tenants", wrap(super.Tenants))          // platform-only listing
mux.Handle("POST /admin/tenants", wrap(super.CreateTenant))    // ST-16
mux.Handle("GET /admin/tenants/{id}", wrap(super.Tenant))      // ST-17 drill-down, platform-only
mux.Handle("PATCH /admin/tenants/{id}", wrap(super.UpdateTenant))    // owner-or-superadmin; bumps content_version + purge
mux.Handle("DELETE /admin/tenants/{id}", wrap(super.DeleteTenant))   // owner-or-superadmin; enqueues full-tenant CDN purge
```

(Session-protected routes are wrapped once by the middleware stack; the lists above adopt the naming so
004 can be consumed without a second router layer.)

## Middleware chain

```
recover → requestID → accessLog → rateLimit → [auth: verify session (002) → actor (004)]
```

- `recover/requestID/accessLog`: stdlib-only; access log = one line per request (method path status µs).
- `rateLimit` — **scoped to auth + mutation routes only** (sweep, 010 Q1): `golang.org/x/time/rate`
  buckets keyed by IP (+ email for auth routes), with a **TTL-eviction janitor** (idle bucket entries are
  dropped, so the map can't grow unbounded with distinct IPs). The public read path has **no app-level
  limiter** — 5k+ reads/s is a CDN/WAF job, not an API problem, and per-instance buckets would be
  inconsistent on the future multi-replica story. Shared Redis is deferred until replicas exist.
- `auth`: attaches `Actor` to `r.Context()`; 401 for protected paths, skips `/*`, `/auth/login`, etc.
  **`store.Scope` is derived from the Actor in exactly one place — `scopeFromActor` here (sweep, finding
  26); `Platform:true` can never be set from session data, params, or handler code.** `require(cap)`
  helper → 403 (004). Actor id + tenant set **inside** the request; `store.Scoped` in each handler
  receives exactly that scope.
- Cookie/token mode: `SameSite=Lax` session cookie when the editor origin is same-site; cross-origin SPA
  uses `Authorization: Bearer <token>` (002 sweep). CORS: allow-list from env for the editor SPA origin;
  `OPTIONS` preflight handled by middleware.
- Tenant endpoints (ST-15/ST-17): `GET /admin/tenants/:id` platform-only; `PATCH`/`DELETE` owner-or-
  superadmin; `PATCH` bumps `tenants.content_version` + enqueues the same-tx purge (005/008) — a settings
  change is public-visible content.

## Validation & errors

```go
// JSON request decode with a strict reader: unknown fields rejected (no silent typos).
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error

// unified envelope:
{"error":{"code":"not_found","message":"..."}}
```

Error → code mapping: `not_found` 404, `forbidden` 403 (ST-6/ST-9/ST-13), `unauthorized` 401,
`conflict` 409 (ST-16 slug, ST-23 double-apply), `validation` 422. No stack traces across the API.

## Contract test harness (the real deliverable of the repo → 001 seeding)

- `internal/httptest`: spins the binary's router against a throwaway Postgres (migrations run from embed),
  a test session/token helper, and seeds tenants/users.
- Each ST-x file exercises endpoints as Given/When/Then assertions: ST-2 (draft 404), ST-3 (beta listing
  never shows alpha), ST-5/6 (author creates own draft, 403 elsewhere), ST-16 (tenant provision + slug
  409), ST-20 (active-tenant switch), ST-22 (perf smoke: the read path under `-bench`), ST-23 (import
  apply → draft).
- The suite runs in CI with `DATABASE_URL` from CI setup; `go test ./...` is the whole gate.
- Adds ST-15/ST-17 coverage: owner edits tenant settings → `content_version` bumped + purge enqueued;
  non-owner PATCH/DELETE → 403; platform drill-down shape.

## Sweep resolutions (see `review.md`)

1. **Rate limiting:** in-memory on auth/mutation routes only, TTL-evicted; public read path belongs to the
   CDN/WAF (deferred shared store until replicas).
2. **`GET /admin/tenants` shape:** platform-only; slug resolver reused from 009 (`internal/tenancy`).
3. **Session verify per request:** two PK reads (~µs) — inside the ST-22 budget; no change.
4. **New in sweep:** ST-15/ST-17 tenant routes added (`GET`/`PATCH`/`DELETE /admin/tenants/{id}`);
   GET-standard OAuth callback; single `scopeFromActor` construction site + invariant test (001);
   cookie vs token mode documented.