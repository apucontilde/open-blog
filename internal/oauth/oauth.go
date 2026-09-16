package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"openblog/internal/auth"
	"openblog/internal/store"
)

const (
	ProviderGoogle = "google"
	ProviderGitHub = "github"

	// GoogleDriveReadonly is granted lazily at the first Google import and gated by token_scopes on reuse.
	GoogleDriveReadonly = "https://www.googleapis.com/auth/drive.readonly"

	flowTTL = 15 * time.Minute

	// refreshMargin absorbs clock skew when deciding a stored token is expired.
	refreshMargin = 30 * time.Second
)

var (
	ErrUnknownProvider    = errors.New("oauth: unknown provider")
	ErrDisallowedRedirect = errors.New("oauth: redirect is not on the allow-list")
	ErrInvalidFlow        = errors.New("oauth: unknown, expired, or replayed flow state")
	ErrProviderDenied     = errors.New("oauth: identity provider denied the request")
	ErrExchangeFailed     = errors.New("oauth: token exchange failed")
	ErrIdentityClaims     = errors.New("oauth: could not fetch identity claims")
	ErrUnverifiedEmail    = errors.New("oauth: identity email is not verified")
	ErrIdentityTaken      = errors.New("oauth: identity already linked to another user")
	ErrNoInvitation       = errors.New("oauth: no live invitation for this email")
	ErrNoToken            = errors.New("oauth: no stored token for this user")
	ErrScopeMissing       = errors.New("oauth: required scope not granted")
	ErrRefreshFailed      = errors.New("oauth: token refresh failed")
	ErrInvalidUserID      = errors.New("oauth: refusing to act for a zero user id")

	errDecrypt = errors.New("oauth: failed to decrypt stored token")
)

// ProviderConfig holds one IdP's credentials; empty endpoints use the public URLs.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	RedirectURL  string
	UserInfoURL  string
	Scopes       []string
}

type Config struct {
	Store    *store.DB
	Sessions *auth.Auth
	Key      []byte // AES-256-GCM key for token at rest; exactly 32 bytes

	Google ProviderConfig
	GitHub ProviderConfig

	// RedirectAllow is the scheme+host+path allow-list for the post-login redirect.
	RedirectAllow []*url.URL

	SessionTTL time.Duration // defaults to auth.TokenTTL
	HTTPClient *http.Client
}

// OAuth is safe for concurrent use.
type OAuth struct {
	store     *store.DB
	sessions  *auth.Auth
	key       []byte
	providers map[string]provider
	allow     []*url.URL
	ttl       time.Duration
	newSource func(ctx context.Context, c *oauth2.Config, t *oauth2.Token) oauth2.TokenSource
}

// New validates Config and wires both providers; Key must be exactly 32 bytes.
func New(cfg Config) (*OAuth, error) {
	if len(cfg.Key) != 32 {
		return nil, errors.New("oauth: key must be exactly 32 bytes (AES-256-GCM)")
	}
	if cfg.Store == nil {
		return nil, errors.New("oauth: store is required")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("oauth: sessions (auth.Auth) is required")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = auth.TokenTTL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	o := &OAuth{
		store:     cfg.Store,
		sessions:  cfg.Sessions,
		key:       cfg.Key,
		allow:     cfg.RedirectAllow,
		ttl:       cfg.SessionTTL,
		providers: map[string]provider{},
		newSource: func(ctx context.Context, c *oauth2.Config, t *oauth2.Token) oauth2.TokenSource {
			return c.TokenSource(ctx, t)
		},
	}
	if len(cfg.Google.Scopes) == 0 {
		cfg.Google.Scopes = strings.Fields(googleLoginScopes)
	}
	o.providers[ProviderGoogle] = provider{
		name: ProviderGoogle,
		conf: &oauth2.Config{
			ClientID:     cfg.Google.ClientID,
			ClientSecret: cfg.Google.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   orDefault(cfg.Google.AuthURL, googleAuthURL),
				TokenURL:  orDefault(cfg.Google.TokenURL, googleTokenURL),
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: cfg.Google.RedirectURL,
			Scopes:      cfg.Google.Scopes,
		},
		claims: oidcUserinfo(orDefault(cfg.Google.UserInfoURL, googleUserinfoURL), client),
	}
	if len(cfg.GitHub.Scopes) == 0 {
		cfg.GitHub.Scopes = strings.Fields(githubLoginScopes)
	}
	o.providers[ProviderGitHub] = provider{
		name: ProviderGitHub,
		conf: &oauth2.Config{
			ClientID:     cfg.GitHub.ClientID,
			ClientSecret: cfg.GitHub.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   orDefault(cfg.GitHub.AuthURL, githubAuthURL),
				TokenURL:  orDefault(cfg.GitHub.TokenURL, githubTokenURL),
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: cfg.GitHub.RedirectURL,
			Scopes:      cfg.GitHub.Scopes,
		},
		claims: githubUserAndEmails(orDefault(cfg.GitHub.UserInfoURL, githubUserURL), githubEmailsURL, client),
	}
	return o, nil
}

// Start persists an oauth_flows row bound to sessionToken's hash and returns the consent URL.
func (o *OAuth) Start(ctx context.Context, providerName, redirect, sessionToken string, extraScopes ...string) (string, error) {
	p, ok := o.providers[providerName]
	if !ok {
		return "", ErrUnknownProvider
	}
	if !o.isAllowedRedirect(redirect) {
		return "", ErrDisallowedRedirect
	}
	state, err := randBytes(32)
	if err != nil {
		return "", err
	}
	verifier, err := randBytes(32)
	if err != nil {
		return "", err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	flow := store.OAuthFlow{
		ID:               id,
		Provider:         providerName,
		State:            sha256Sum(state),
		CodeVerifier:     verifier,
		Redirect:         redirect,
		SessionTokenHash: sessionHash(sessionToken),
		ExpiresAt:        time.Now().Add(flowTTL),
	}
	if err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.InsertOAuthFlow(ctx, flow)
	}); err != nil {
		return "", err
	}
	c := *p.conf
	c.Scopes = mergeScopes(p.conf.Scopes, extraScopes)
	return c.AuthCodeURL(string(state),
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256")), nil
}

type CallbackResult struct {
	SessionToken string
	UserID       uuid.UUID
	Redirect     string
	Provider     string
}

// Callback verifies and consumes the single-use flow against the bound session before any IdP call.
func (o *OAuth) Callback(ctx context.Context, state, code, sessionToken string) (CallbackResult, error) {
	var res CallbackResult
	var flow store.OAuthFlow
	err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		var err error
		flow, err = q.ConsumeOAuthFlow(ctx, sha256Sum([]byte(state)), sessionHash(sessionToken))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return res, ErrInvalidFlow
	}
	if err != nil {
		return res, err
	}
	p, ok := o.providers[flow.Provider]
	if !ok {
		return res, ErrUnknownProvider
	}
	res.Provider, res.Redirect = flow.Provider, flow.Redirect
	if code == "" {
		return res, ErrProviderDenied
	}
	tok, err := p.conf.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", string(flow.CodeVerifier)))
	if err != nil {
		return res, ErrExchangeFailed
	}
	claims, err := p.claims(ctx, tok.AccessToken)
	if err != nil {
		return res, ErrIdentityClaims
	}
	userID, err := o.resolveIdentity(ctx, flow.Provider, claims)
	if err != nil {
		return res, err
	}
	if err := o.storeOAuthToken(ctx, userID, flow.Provider, tok); err != nil {
		return res, err
	}
	session, err := o.sessions.Issue(ctx, userID, o.ttl, nil)
	if err != nil {
		return res, err
	}
	res.UserID, res.SessionToken = userID, session
	return res, nil
}

// resolveIdentity links or returns the user, requiring a verified email for a new identity.
func (o *OAuth) resolveIdentity(ctx context.Context, providerName string, c Claims) (uuid.UUID, error) {
	email := normalizeEmail(c.Email)
	var userID uuid.UUID
	err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		existing, err := q.GetIdentity(ctx, providerName, c.Subject)
		if err == nil {
			userID = existing.UserID
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if !c.EmailVerified || email == "" {
			return ErrUnverifiedEmail
		}
		u, err := q.GetUserByEmail(ctx, email)
		switch {
		case err == nil:
			userID = u.ID
		case errors.Is(err, pgx.ErrNoRows):
			uid, err2 := uuid.NewV7()
			if err2 != nil {
				return err2
			}
			if err2 := q.CreateUser(ctx, uid, email, displayName(c, email), nil); err2 != nil {
				return err2
			}
			userID = uid
		default:
			return err
		}
		if err := linkIdentityTx(ctx, q, userID, providerName, c.Subject); err != nil {
			return err
		}
		inv, err := q.ConsumePendingInvitation(ctx, email, nil)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return q.AddMembershipIfAbsent(ctx, inv.TenantID, userID, inv.Role)
	})
	if err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

// storeOAuthToken AEAD-encrypts and upserts the pair, preserving an unrotated refresh token.
func (o *OAuth) storeOAuthToken(ctx context.Context, userID uuid.UUID, providerName string, tok *oauth2.Token) error {
	encAccess, err := seal(o.key, []byte(tok.AccessToken))
	if err != nil {
		return err
	}
	var encRefresh []byte
	if tok.RefreshToken != "" {
		encRefresh, err = seal(o.key, []byte(tok.RefreshToken))
		if err != nil {
			return err
		}
	}
	var expiry *time.Time
	if !tok.Expiry.IsZero() {
		e := tok.Expiry
		expiry = &e
	}
	row := store.OAuthToken{
		UserID:       userID,
		Provider:     providerName,
		RefreshToken: encRefresh,
		AccessToken:  encAccess,
		TokenScopes:  grantedScopes(providerName, tok, o.providers[providerName].conf),
		TokenExpiry:  expiry,
	}
	return o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.UpsertOAuthToken(ctx, row)
	})
}

// isAllowedRedirect enforces the scheme+host+path allow-list (open-redirect guard).
func (o *OAuth) isAllowedRedirect(callbackURL string) bool {
	u, err := url.Parse(callbackURL)
	if err != nil || !u.IsAbs() || u.User != nil || u.Host == "" {
		return false
	}
	for _, base := range o.allow {
		if !strings.EqualFold(u.Scheme, base.Scheme) {
			continue
		}
		if !strings.EqualFold(u.Host, base.Host) {
			continue
		}
		prefix := strings.TrimRight(base.Path, "/")
		if u.Path == base.Path || (prefix != "" && strings.HasPrefix(u.Path, prefix+"/")) ||
			prefix == "" && strings.HasPrefix(u.Path, "/") {
			return true
		}
	}
	return false
}

func orDefault(given, fallback string) string {
	if given == "" {
		return fallback
	}
	return given
}

// normalizeEmail lowercases and trims verified emails before any write.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func displayName(c Claims, email string) string {
	if c.DisplayName != "" {
		return c.DisplayName
	}
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

func mergeScopes(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, s := range append(append([]string{}, base...), extra...) {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func scopeSet(joined string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(joined, ",") {
		if s != "" {
			m[s] = true
		}
	}
	return m
}

// grantedScopes is Google's echoed scope set, or the configured scopes for GitHub.
func grantedScopes(providerName string, tok *oauth2.Token, conf *oauth2.Config) string {
	if providerName == ProviderGoogle {
		if s, ok := tok.Extra("scope").(string); ok && s != "" {
			return strings.Join(strings.Fields(s), ",")
		}
	}
	return strings.Join(conf.Scopes, ",")
}
