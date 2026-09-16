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

// GoogleExporter returns a live Google access token for the import job.
type GoogleExporter func(ctx context.Context, userID uuid.UUID, wantDriveReadonly bool) (string, error)

func (o *OAuth) GoogleExporter() GoogleExporter { return o.GetGoogleToken }

// GetGoogleToken returns a live token, refreshing and re-storing the rotated pair when expired; wantDriveReadonly requires the recorded grant.
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
	// Force a refresh: a future expiry would leave the stored token unchanged.
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
	// Keep the stored refresh token when the IdP does not rotate one.
	if err := o.storeOAuthToken(ctx, userID, ProviderGoogle, nt); err != nil {
		return "", err
	}
	return nt.AccessToken, nil
}
