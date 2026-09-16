// Package auth implements password authentication and opaque session tokens.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"openblog/internal/store"
)

// Session and token constants — the single source of truth for 010's wiring.
const (
	// TokenLen is the size in bytes of the raw session token before base64url.
	TokenLen = 32
	// TokenTTL is the fixed absolute session lifetime; Verify never extends it.
	TokenTTL = 30 * 24 * time.Hour
)

// argon2id parameters. Fixed — performance and memory are load-bearing, not config.
const (
	argon2Time    uint32 = 3
	argon2Memory  uint32 = 64 * 1024 // KiB → 64 MiB per hash
	argon2Threads uint8  = 2
	argon2KeyLen  uint32 = 32
	argon2SaltLen        = 16
)

// argon2Concurrency caps concurrent in-handler hashes to 4 (≤256 MiB peak).
const argon2Concurrency = 4

var (
	// ErrInvalidCredentials covers an unknown email, a wrong password, and a
	// passwordless account — indistinguishably, by design (constant time).
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrInvited rejects a password signup that would pre-empt an invite.
	ErrInvited = errors.New("auth: a pending invitation exists for this email")

	// ErrInvalidUserID guards the session FK: Issue must never insert a row
	// for a zero/unknown user.
	ErrInvalidUserID = errors.New("auth: refusing to issue a session for a zero user id")

	// ErrNoSession and ErrSessionExpired both map to 401 in 010.
	ErrNoSession      = errors.New("auth: no session for this token")
	ErrSessionExpired = errors.New("auth: session expired")
)

// Auth is the password + session service. Safe for concurrent use.
type Auth struct {
	store *store.DB
	lim   *limiter
}

// New builds an Auth over the store connection pool.
func New(s *store.DB) *Auth {
	return &Auth{store: s, lim: newLimiter(argon2Concurrency)}
}

// Issue mints a new session for the verified user and returns the raw token
// string. It is the only session-insert path. ttl is the absolute lifetime;
// callers pass TokenTTL. scope may be nil (no tenant selected yet).
func (a *Auth) Issue(ctx context.Context, userID uuid.UUID, ttl time.Duration, scope *uuid.UUID) (string, error) {
	if userID == uuid.Nil {
		return "", ErrInvalidUserID
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	hash := tokenHash(token)
	err = a.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.InsertSession(ctx, store.Session{
			TokenHash: hash[:],
			UserID:    userID,
			Scope:     scope,
			ExpiresAt: time.Now().Add(ttl),
		})
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// Verify looks up the session by token hash and checks expiry. Returns the
// bound user and tenant scope. Two PK-level reads at most, microseconds.
func (a *Auth) Verify(ctx context.Context, token string) (uuid.UUID, uuid.UUID, error) {
	hash := tokenHash(token)
	var userID, scope uuid.UUID
	err := a.store.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		s, err := q.GetSessionByTokenHash(ctx, hash[:])
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoSession
			}
			return err
		}
		if !s.ExpiresAt.After(time.Now()) {
			return ErrSessionExpired
		}
		userID = s.UserID
		if s.Scope != nil {
			scope = *s.Scope
		}
		return nil
	})
	return userID, scope, err
}

// Logout deletes the session row for the presented token.
func (a *Auth) Logout(ctx context.Context, token string) error {
	hash := tokenHash(token)
	return a.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.DeleteSessionByTokenHash(ctx, hash[:])
	})
}

// Login authenticates email/password and mints a fresh session token.
// Both branches run the same argon2 cost (unknown email verifies against a
// fixed dummy hash that is never accepted) so timing reveals nothing.
func (a *Auth) Login(ctx context.Context, email, password string) (string, error) {
	email = normalizeEmail(email)
	var userID uuid.UUID
	err := a.store.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		u, err := q.GetUserByEmail(ctx, email)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return a.verifyBestEffort(ctx, nil, password)
			}
			return err
		}
		userID = u.ID
		return a.verifyBestEffort(ctx, u.PasswordHash, password)
	})
	if err != nil {
		return "", err
	}
	return a.Issue(ctx, userID, TokenTTL, nil)
}

// Signup creates a password-identity user. Normalizes email to lowercase.
// Returns ErrInvited if a live invitation exists for that email.
func (a *Auth) Signup(ctx context.Context, email, password string) (uuid.UUID, error) {
	email = normalizeEmail(email)
	if email == "" || password == "" {
		return uuid.Nil, errors.New("auth: email and password are required")
	}
	invited, err := a.HasPendingInvitation(ctx, email)
	if err != nil {
		return uuid.Nil, err
	}
	if invited {
		return uuid.Nil, ErrInvited
	}
	encoded, err := hashPassword(ctx, a.lim, password)
	if err != nil {
		return uuid.Nil, err
	}
	userID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	displayName := email
	if i := strings.IndexByte(email, '@'); i > 0 {
		displayName = email[:i]
	}
	err = a.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.CreateUser(ctx, userID, email, displayName, &encoded)
	})
	if err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

// HasPendingInvitation reports whether a live (unconsumed, non-expired)
// invitation exists for the normalized email. Thin helper for signup/010.
func (a *Auth) HasPendingInvitation(ctx context.Context, email string) (bool, error) {
	email = normalizeEmail(email)
	var invited bool
	err := a.store.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		var err error
		invited, err = q.HasPendingInvitation(ctx, email)
		return err
	})
	return invited, err
}

// verifyBestEffort compares password against stored, or — for a NULL stored
// hash (unknown email or SSO-only account) — against the fixed dummy hash but
// always fails, so both branches cost the same argon2 run and leak nothing.
func (a *Auth) verifyBestEffort(ctx context.Context, stored *string, password string) error {
	if stored == nil {
		_ = verifyPassword(ctx, a.lim, dummyHash(), password)
		return ErrInvalidCredentials
	}
	if err := verifyPassword(ctx, a.lim, *stored, password); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

// tokenHash is the sha256 of the token string exactly as the client presents
// it — the only form ever stored or looked up.
func tokenHash(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

// newToken returns a fresh opaque token: TokenLen random bytes, base64url.
func newToken() (string, error) {
	raw := make([]byte, TokenLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
