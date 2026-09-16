# 002 — Auth: password + opaque sessions

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 001. 'Unlocks' 003, 004, 010.

## Goal

Password sign-up/login/logout and the session primitive every authenticated route trusts. OAuth (003)
reuses the same session issuance; 004/010 consume the verify primitive.

## Contracts

| Endpoint | Behavior |
|---|---|
| `POST /auth/signup` `{email, password}` | 201 user (no membership yet; tenancy arrives via 003/004). Disabled when `SSO_ONLY=on`. **409 `code:"invited"` if a pending invitation exists for the normalized email** (sweep: an unverified password signup must not be able to pre-empt an invited/verified email and hijack its membership). |
| `POST /auth/login` `{email, password}` | 200 `{token}` + `Set-Cookie`; **both branches constant-time** (unknown email runs argon2 against a fixed dummy hash — same 401, no email enumeration by timing); wrong password → same 401. |
| `POST /auth/logout` | 204; `DELETE` the session row for the presented token. |
| `(primitive) Verify(ctx, raw) -> Session` | sha256(raw) → PK lookup on `sessions`; reject if `expires_at <= now()`. No writes, no touch. |

## Design

- **Password hashing:** Argon2id (`golang.org/x/crypto/argon2`, `time=3, mem=64MiB, threads=2`), salt 16B
  random, encoded `$argon2id$…`; constants from env. In-handler, **no worker pool** (sweep): login is rare
  and rate-limited; a pooled run queue would add latency variance for no throughput. Bound peak memory
  with a small weighted semaphore (≤4 concurrent argon2 hashes = ≤256 MiB worst case).
- **Token:** 32 random bytes → base64url to the client; only its **sha256** is stored (`sessions.token_hash`,
  the PK). The DB never holds a usable token. `rand.Read` errors are checked.
- **Cookie:** `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=30d` (sweep: **Lax**, not Strict — the OAuth
  callback is a cross-site top-level GET and Strict would withhold the session, killing state binding).
  The JSON `token` is for non-browser clients and for cross-origin editor deployments (`Authorization:
  Bearer` instead of cookie); cookie mode applies when the editor origin is same-site.
- **Expiry/rotation:** absolute 30 days from issue (sweep, no sliding). Login issues a new session row (old
  ones stay valid; logout deletes only the presented one). `SESSIONS_SINGLE=1` later can delete other rows
  for that user. Expired rows are swept by a periodic 008 job (delete `expires_at < now()-7d`).
- **Rate limiting:** login/signup throttled per IP + email (in-memory token bucket, `golang.org/x/time/rate`)
  **on auth routes only**, with a TTL-eviction janitor — the public read path belongs to the CDN (010).
  Single instance → in-memory is correct; a Redis swap is future-only.

## Implementation sketch (`internal/auth`)

```go
package auth

type Auth struct {
	store *store.DB
	cfg   Config
	ar    sem chan struct{} // weighted semaphore, cap 4
}

// Login is issued on the verified USER ID, not an email re-lookup (sweep fix: the old sketch
// inserted a session with a zero user id, which the sessions FK rejects).
func (a *Auth) Login(ctx context.Context, email, password string) (Session, error) {
	// one round trip: SELECT id, password_hash FROM users WHERE lower(email) = lower($1)
	var userID uuid.UUID
	// argon2id compare (constant time on derived key). Unknown email => compare against a
	// fixed dummy hash so timing does not reveal whether the account exists. Then:
	return a.Issue(ctx, userID, a.cfg.TokenTTL, nil)
}

// Issue is the primitive 003 reuses; it is the only session-insert path.
func (a *Auth) Issue(ctx context.Context, userID uuid.UUID, ttl time.Duration, scope *uuid.UUID) (Session, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Session{}, err
	}
	hash := sha256.Sum256(raw)
	err := a.store.Scoped(ctx, store.Scope{}, func(q *store.Queries) error { // unscoped platform insert
		return q.InsertSession(ctx, store.Session{
			TokenHash: hash[:], UserID: userID, Scope: scope,
			ExpiresAt: time.Now().Add(ttl),
		})
	})
	return Session{TokenHash: hash[:], UserID: userID, ...}, err
}
```

Single pattern to carry the session hash → claims: `Verify` returns the full `Session` row and the app
binds it as the **actor** in 004.

## Performance

- Session lookup is a PK hit on `sessions.token_hash` (one index, hash equality) — no scan, ~µs.
- Argon2id dominates login (≈50–100 ms by design); signup/login run on the API goroutine but are rare and
  rate-limited — acceptable on one instance. Do **not** cache password checks anywhere.

## Sweep resolutions (see `review.md`)

1. **Multi-session vs single-session:** multi (unchanged); optional logout-others later.
2. **Argon2 in-handler?** Yes — no worker pool; weighted semaphore (≤4) bounds the 64 MiB/hash peak.
3. **SameSite=Strict vs Lax:** **Lax** (Strict breaks the OAuth callback's state binding); cookie mode is
   same-site-only, cross-origin editor uses the HTTP token.
4. **Sliding vs fixed expiry:** fixed absolute 30d; expired rows swept by the 008 expiry job.
5. **Signup vs a pending invitation:** 409 `code:"invited"` (see contracts) — invitation consumption stays
   SSO-only and gated on verified email (ST-12/ST-19).