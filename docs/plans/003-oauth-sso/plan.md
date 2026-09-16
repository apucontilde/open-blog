# 003 — Auth: OAuth SSO (Google / GitHub) + identity linking

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 001, 002. Unlocks 004 (actor has identity → membership), 007 (Google export scope).

## Goal

Authorization-Code + PKCE against Google and GitHub; first sign-in links user + `identities` row and
consumes a pending invitation (ST-19); every later sign-in is idempotent. Same backend as posts (no IdP
service), only the handshake leaves the process.

## Contracts

| Endpoint | Behavior |
|---|---|
| `GET /auth/oauth/start?provider=github&redirect=…` | Persist `oauth_flows` row (state, PKCE verifier, redirect, **hashed bound-session token**: the flow is tied to the initiating session) → 302 to IdP with `code_challenge`. |
| `GET /auth/oauth/callback?code&state` | **GET** (IdP callbacks are always GET; the arch sequence-diagram `POST` was wrong). 302 back to `redirect` with a session cookie; consume the flow row (single-use state, expired → 401 before any IdP call), **verify the bound session still matches**, exchange code, upsert user+identity, consume invitation atomically, issue session (`auth.IssueReasoned`). |
| `(primitive) ConsumeInvitation(userID, email, token)` | Atomic `UPDATE invitations SET consumed_at = now() WHERE id=$1 AND consumed_at IS NULL [AND lower(email) = lower($2)] RETURNING tenant_id, role` → 0 rows = already consumed (idempotent, ST-19) → `INSERT memberships ON CONFLICT (tenant_id, user_id) DO NOTHING`. 002 signup reads pending invitations directly (unscoped, 001) to 409-invited accounts. |

## Data — migration `0003_oauth.sql` (append-only, unscoped platform tables)

```sql
create table oauth_flows (
    id            uuid primary key,
    provider      text not null,            -- 'google' | 'github'
    state         bytea not null,           -- random nonce, single use
    code_verifier bytea not null,
    redirect      text not null,            -- exact allow-list match at callback
    session_token_hash bytea,               -- sweep: sha256 of the initiating session, checked at callback
    expires_at    timestamptz not null,
    created_at    timestamptz not null default now()
);

-- sweep (finding 2/3): without this table 007's "refresh server-side from stored token" was unbuildable.
-- Encrypt refresh/access tokens at rest (AEAD, key from env); never log them.
create table oauth_tokens (
    user_id       uuid not null references users(id) on delete cascade,
    provider      text not null,            -- 'google' | 'github'
    refresh_token bytea,                    -- AEAD ciphertext; NULL when provider never issued one
    access_token  bytea,                    -- AEAD ciphertext (short-lived)
    token_scopes  text not null default '', -- comma-joined granted scopes
    token_expiry  timestamptz,
    primary key (user_id, provider)
);
```

## Design

- **State = CSRF/link-injection guard:** random 32B nonce in `oauth_flows.state`, bound to the initiating
  session's token hash; callback verifies both in one transaction — replay of the same `state` fails, and a
  session mismatch (Strict→Lax being insufficient on its own) aborts before the exchange.
- **PKCE (S256):** verifier stored server-side only, never in a cookie; `code_challenge` sent at start.
- **Identity claims:** Google OIDC `sub`+`email` (+`email_verified`); GitHub user id from `/user` + email
  from `/user/emails` (verified flag honored). `identities(provider, subject)` is the PK — duplicate sign-in
  upserts, never duplicates (ST-19). **Email normalized lowercase on every write** (sweep). **One `users`
  row per normalized verified email; multiple identities.** Identity linking to an *existing password-only
  user* is allowed only when the IdP email is verified — mailbox control is proven, so tenancies transfer
  legitimately.
- **Google scopes — lazy (sweep):** login requests `openid email profile` only. `drive.readonly` is granted
  ad hoc at the **first Google import** (007) via a fresh `start` with an augmented scope + re-consent,
  then stored in `oauth_tokens.token_scopes`. Always-on consent widens the blast radius of the stored
  token for zero benefit on most logins.
- **Invitation consumption (ST-19):** on first verified link, match the *verified* normalized identity email
  against a pending `invitations(lower(email), consumed_at IS NULL)`; consume atomically (contract above)
  and insert the `memberships` row with the invited role. Role-baked links (`invitations.token_hash`)
  consume by token instead of email, still atomically. Unverified identity emails can join an existing
  account but never consume an invitation.
- **Callback security:** `redirect` must match an allow-list (scheme+host+path, base URL from env) — no open
  redirect; token exchange happens server-side only (client never sees IdP tokens). Replay of a consumed
  `state`, mismatched bound session, or expired flow → 401 with **no IdP calls**.
- **011 flows sweeping:** expired `oauth_flows` are deleted by the periodic 008 cleanup job (like `sessions`).

## Implementation sketch (`internal/oauth`)

```go
package oauth

// scopes for a normal login — drive is added lazily for the first Google import (sweep).
const scopes = "openid email profile"

func (o *OAuth) Start(w http.ResponseWriter, r *http.Request) { // provider from query
	state := randBytes(32)
	verifier := randBytes(32)
	// bind to the presented session (if any); the callback re-checks it
	o.store.Scoped(r.Context(), store.Scope{}, func(q *store.Queries) error {
		return q.InsertOAuthFlow(r.Context(), store.OAuthFlow{
			State: state, CodeVerifier: verifier,
			SessionTokenHash: boundSessionHash(r),
			Redirect:         o.redirectFor(r), ExpiresAt: time.Now().Add(15 * time.Minute),
		})
	})
	u := o.provider.AuthCodeURL(string(state), oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge(verifier)))
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (o *OAuth) Callback(w http.ResponseWriter, r *http.Request) {
	// 1. consume oauth_flows by state + bound-session match (single tx) — missing/expired/mismatch
	//    => 401, no IdP calls
	// 2. oauth2.Exchange with verifier; google tokeninfo / gh user+emails
	// 3. lowercase email; upsert user + identities; if verified => ConsumeInvitation (atomic)
	// 4. store/refresh oauth_tokens (AEAD) when the provider returned a refresh token (google; drive scope later)
	// 5. session := auth.Issue(userID); redirect(redirect, cookie)
}
```

## Performance

- 1 extra PK write (`oauth_flows`) per flow start + 1 consume + 1 identity upsert + 1 session insert.
- The two IdP HTTPS calls dominate; nothing here runs on the read path.

## Sweep resolutions (see `review.md`)

1. **`drive.readonly` always-on vs lazy:** lazy — `openid email profile` at login; augmented consent at
   first Google import (007). Consent at scale vs stored-token blast radius.
2. **Same email password+SSO:** one `users` row per normalized verified email, multiple `identities`; merge
   on verified match only.
3. **Callback redirect allow-list:** scheme+host+path from env; callback method standardized on **GET**.
4. **New in sweep:** `oauth_tokens` table (without it, 007's Google import was unbuildable); flow↔session
   binding; atomic invitation consume; lowercase email normalization.