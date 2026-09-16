package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"openblog/internal/store"
)

// GoogleExporter is 007's handle into 003's stored Google token: a refresh
// engine that returns a usable access token or a 401-class error.
type GoogleExporter func(ctx context.Context, userID uuid.UUID, wantDriveReadonly bool) (string, error)

// GoogleExporter returns the handle 007 stores and calls at import time.
func (o *OAuth) GoogleExporter() GoogleExporter { return o.GetGoogleToken }

// GetGoogleToken returns a live Google access token for userID. The stored
// token_scopes gate the attempt: wantDriveReadonly requires the lazily granted
// drive.readonly scope, never assumed. A still-valid access token is returned
// as-is; an expired one is silently refreshed from the AEAD-stored refresh
// token and the rotated pair re-encrypted and stored. Errors: ErrNoToken when
// no token exists, ErrScopeMissing when the required scope was never granted,
// ErrRefreshFailed when the token is expired and cannot be refreshed.
func (o *OAuth) GetGoogleToken(ctx context.Context, userID uuid.UUID, wantDriveReadonly bool) (string, error) {
	p, ok := o.providers[ProviderGoogle]
	if !ok {
		return "", ErrUnknownProvider
	}
	var stored store.OAuthToken
	err := o.store.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		var err error
		stored, err = q.GetOAuthTokenByUser(ctx, userID, ProviderGoogle)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoToken
	}
	if err != nil {
		return "", err
	}
	scopes := scopeSet(stored.TokenScopes)
	if wantDriveReadonly && !scopes[GoogleDriveReadonly] {
		return "", ErrScopeMissing
	}
	access, err := open(o.key, stored.AccessToken)
	if err != nil {
		return "", errDecrypt
	}
	if stored.TokenExpiry != nil && time.Until(*stored.TokenExpiry) > refreshMargin {
		return string(access), nil
	}
	if len(stored.RefreshToken) == 0 {
		return "", ErrRefreshFailed
	}
	refresh, err := open(o.key, stored.RefreshToken)
	if err != nil {
		return "", errDecrypt
	}
	// Force a refresh: a zero or future expiry would make reuseTokenSource
	// return the stored access token unchanged.
	old := &oauth2.Token{
		AccessToken:  string(access),
		TokenType:    "Bearer",
		RefreshToken: string(refresh),
		Expiry:       time.Now().Add(-time.Minute),
	}
	nt, err := o.newSource(ctx, p.conf, old).Token()
	if err != nil {
		return "", ErrRefreshFailed
	}
	if nt.AccessToken == "" {
		return "", ErrRefreshFailed
	}
	// Upsert's coalesce keeps the stored refresh token untouched when Google
	// does not rotate one, preserving offline access for the next import.
	if err := o.storeOAuthToken(ctx, userID, ProviderGoogle, nt); err != nil {
		return "", err
	}
	return nt.AccessToken, nil
}
