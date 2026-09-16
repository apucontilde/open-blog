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

const TokenLen = 32

// TokenTTL is the fixed absolute session lifetime; Verify never extends it.
const TokenTTL = 30 * 24 * time.Hour

// Fixed argon2id parameters — not config.
const (
	argon2Time    uint32 = 3
	argon2Memory  uint32 = 64 * 1024 // KiB (64 MiB/hash)
	argon2Threads uint8  = 2
	argon2KeyLen  uint32 = 32
	argon2SaltLen        = 16
)

// argon2Concurrency caps concurrent in-handler hashes (peak 4×64 MiB).
const argon2Concurrency = 4

var (
	// Covers unknown email, wrong password, and passwordless accounts indistinguishably.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrInvited rejects a signup for an email with a pending invitation.
	ErrInvited = errors.New("auth: a pending invitation exists for this email")

	// Guards the sessions FK: never issue for a zero user id.
	ErrInvalidUserID = errors.New("auth: refusing to issue a session for a zero user id")

	// ErrNoSession and ErrSessionExpired both map to 401.
	ErrNoSession      = errors.New("auth: no session for this token")
	ErrSessionExpired = errors.New("auth: session expired")
)

// Auth is safe for concurrent use.
type Auth struct {
	store *store.DB
	lim   *limiter
}

func New(s *store.DB) *Auth {
	return &Auth{store: s, lim: newLimiter(argon2Concurrency)}
}

// Issue is the only session-insert path; ttl is the absolute lifetime.
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

func (a *Auth) Logout(ctx context.Context, token string) error {
	hash := tokenHash(token)
	return a.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.DeleteSessionByTokenHash(ctx, hash[:])
	})
}

// Unknown email and SSO-only accounts verify the fixed dummy hash but always
// fail, so both branches cost the same argon2 run and leak nothing.
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

// A nil stored hash runs the dummy hash but always fails, keeping both branches equal.
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

// tokenHash is the only form ever stored or looked up — never the raw token.
func tokenHash(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

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
