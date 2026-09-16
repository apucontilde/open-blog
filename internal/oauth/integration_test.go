package oauth

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"openblog/internal/auth"
	"openblog/internal/store"
)

// testOAuth builds a service over DATABASE_URL (already migrated by
// cmd/migrate); skipped when unset — the pure-logic tests still run.
func testOAuth(t *testing.T) *OAuth {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed oauth tests")
	}
	ctx := context.Background()
	db, err := store.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(db.Close)
	o, err := New(Config{
		Store:         db,
		Sessions:      auth.New(db),
		Key:           testKey(),
		Google:        ProviderConfig{RedirectURL: "https://app.example/auth/oauth/callback?provider=google"},
		GitHub:        ProviderConfig{RedirectURL: "https://app.example/auth/oauth/callback?provider=github"},
		RedirectAllow: []*url.URL{{Scheme: "https", Host: "ok.example", Path: "/app"}},
	})
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	return o
}

func createUser(t *testing.T, o *OAuth, email string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.CreateUser(ctx, id, email, email, nil)
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return id
}

func createTenant(t *testing.T, o *OAuth) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.CreateTenant(ctx, id, "tx-"+uuid.NewString(), "tenant")
	}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	return id
}

func insertInvitation(t *testing.T, o *OAuth, tenantID uuid.UUID, email, role string) {
	t.Helper()
	ctx := context.Background()
	if err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.InsertInvitation(ctx, uuid.New(), tenantID, &email, role, nil, time.Now().Add(24*time.Hour))
	}); err != nil {
		t.Fatalf("InsertInvitation: %v", err)
	}
}

func TestStartPersistsHashedStateAndSessionBinding(t *testing.T) {
	o := testOAuth(t)
	ctx := context.Background()
	sess := "pre-login-session-token"

	// Start returns a consent URL; the raw state must never be stored as-is.
	loginURL, err := o.Start(ctx, ProviderGoogle, "https://ok.example/app/dashboard", sess)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("parsing consent URL: %v", err)
	}
	if u.Query().Get("code_challenge") == "" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("consent URL missing PKCE params: %s", loginURL)
	}
	rawState := u.Query().Get("state")

	// Consuming by the RAW state finds nothing (only the sha256 is stored)...
	err = o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		_, err := q.ConsumeOAuthFlow(ctx, []byte(rawState), sessionHash(sess))
		return err
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("raw state matched a stored flow: %v", err)
	}
	// ...but the hashed state + bound session consumes the row.
	if err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		_, err := q.ConsumeOAuthFlow(ctx, sha256Sum([]byte(rawState)), sessionHash(sess))
		return err
	}); err != nil {
		t.Fatalf("hashed state consume: %v", err)
	}

	// Fresh flow: a mismatched bound session is rejected before any IdP call.
	loginURL2, err := o.Start(ctx, ProviderGoogle, "https://ok.example/app/dashboard", sess)
	if err != nil {
		t.Fatalf("second Start: %v", err)
	}
	rawState2, err := url.Parse(loginURL2)
	if err != nil {
		t.Fatalf("parsing second consent URL: %v", err)
	}
	if _, err := o.Callback(ctx, rawState2.Query().Get("state"), "", "attacker-session"); !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("session mismatch = %v, want ErrInvalidFlow", err)
	}
	// Correct bound session consumes the flow; empty code (IdP denied) is
	// handled without any IdP traffic.
	if _, err := o.Callback(ctx, rawState2.Query().Get("state"), "", sess); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("denied callback = %v, want ErrProviderDenied", err)
	}
	// The consumed state is single-use: replay fails.
	if _, err := o.Callback(ctx, rawState2.Query().Get("state"), "code", sess); !errors.Is(err, ErrInvalidFlow) {
		t.Fatalf("replay = %v, want ErrInvalidFlow", err)
	}
}

func TestConsumeInvitationAtomicIdempotentAndScoped(t *testing.T) {
	o := testOAuth(t)
	ctx := context.Background()
	email := "invitee-" + uuid.NewString() + "@example.com"

	tenantA := createTenant(t, o)
	tenantB := createTenant(t, o)
	insertInvitation(t, o, tenantA, email, "editor")
	insertInvitation(t, o, tenantB, email, "author")

	inv, err := o.ConsumeInvitation(ctx, email, &tenantA)
	if err != nil {
		t.Fatalf("ConsumeInvitation A: %v", err)
	}
	if inv.TenantID != tenantA || inv.Role != "editor" {
		t.Fatalf("first consume = %+v, want {tenantA editor}", inv)
	}
	// Double-consume of the same tenant is an idempotent no-op.
	if _, err := o.ConsumeInvitation(ctx, email, &tenantA); !errors.Is(err, ErrNoInvitation) {
		t.Fatalf("double consume A = %v, want ErrNoInvitation", err)
	}
	// The unscoped consume picks up the remaining live invitation.
	inv, err = o.ConsumeInvitation(ctx, email, nil)
	if err != nil {
		t.Fatalf("ConsumeInvitation unscoped: %v", err)
	}
	if inv.TenantID != tenantB || inv.Role != "author" {
		t.Fatalf("second consume = %+v, want {tenantB author}", inv)
	}
	if _, err := o.ConsumeInvitation(ctx, email, nil); !errors.Is(err, ErrNoInvitation) {
		t.Fatalf("consume after all consumed = %v, want ErrNoInvitation", err)
	}

	// The callback path grants the invited membership exactly once: a fresh
	// live invite consumed and membershipped in one transaction, then a
	// repeat membership insert is absorbed by ON CONFLICT DO NOTHING.
	user := createUser(t, o, email)
	insertInvitation(t, o, tenantA, email, "editor")
	if err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		inv, err := q.ConsumePendingInvitation(ctx, email, nil)
		if err != nil {
			return err
		}
		return q.AddMembershipIfAbsent(ctx, inv.TenantID, user, inv.Role)
	}); err != nil {
		t.Fatalf("callback consume+membership: %v", err)
	}
	if role, err := o.store.MembershipRole(ctx, user, tenantA); err != nil || role != "editor" {
		t.Fatalf("MembershipRole after consume = %q, %v; want editor", role, err)
	}
	if err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.AddMembershipIfAbsent(ctx, tenantA, user, "owner") // upgraded role must NOT overwrite
	}); err != nil {
		t.Fatalf("idempotent membership insert: %v", err)
	}
	if role, err := o.store.MembershipRole(ctx, user, tenantA); err != nil || role != "editor" {
		t.Fatalf("MembershipRole after repeat insert = %q, %v; want editor unchanged", role, err)
	}
}

type fakeSource struct {
	tok  *oauth2.Token
	err  error
	used *bool
}

func (f fakeSource) Token() (*oauth2.Token, error) {
	*f.used = true
	return f.tok, f.err
}

func tokenRow(t *testing.T, o *OAuth, userID uuid.UUID, scopes string, access, refresh string, expiry *time.Time) {
	t.Helper()
	ctx := context.Background()
	var encR []byte
	var err error
	if refresh != "" {
		if encR, err = seal(o.key, []byte(refresh)); err != nil {
			t.Fatalf("seal refresh: %v", err)
		}
	}
	encA, err := seal(o.key, []byte(access))
	if err != nil {
		t.Fatalf("seal access: %v", err)
	}
	if err := o.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.UpsertOAuthToken(ctx, store.OAuthToken{
			UserID:       userID,
			Provider:     ProviderGoogle,
			RefreshToken: encR,
			AccessToken:  encA,
			TokenScopes:  scopes,
			TokenExpiry:  expiry,
		})
	}); err != nil {
		t.Fatalf("UpsertOAuthToken: %v", err)
	}
}

func readToken(t *testing.T, o *OAuth, userID uuid.UUID) store.OAuthToken {
	t.Helper()
	ctx := context.Background()
	var tok store.OAuthToken
	if err := o.store.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		var err error
		tok, err = q.GetOAuthTokenByUser(ctx, userID, ProviderGoogle)
		return err
	}); err != nil {
		t.Fatalf("GetOAuthTokenByUser: %v", err)
	}
	return tok
}

func TestGetGoogleTokenScopeGateAndRefresh(t *testing.T) {
	o := testOAuth(t)
	ctx := context.Background()
	user := createUser(t, o, "gtk-"+uuid.NewString()+"@example.com")

	var used bool
	o.newSource = func(context.Context, *oauth2.Config, *oauth2.Token) oauth2.TokenSource {
		return fakeSource{tok: &oauth2.Token{
			AccessToken:  "access-fresh",
			RefreshToken: "refresh-new",
			Expiry:       time.Now().Add(time.Hour),
		}, used: &used}
	}

	// No stored token.
	if _, err := o.GetGoogleToken(ctx, user, false); !errors.Is(err, ErrNoToken) {
		t.Fatalf("no token = %v, want ErrNoToken", err)
	}

	exp := time.Now().Add(time.Hour)
	tokenRow(t, o, user, "openid,email,profile", "access-old", "refresh-old", &exp)

	// Drive scope absent: gated off without ever consulting the token source.
	used = false
	if _, err := o.GetGoogleToken(ctx, user, true); !errors.Is(err, ErrScopeMissing) {
		t.Fatalf("missing drive scope = %v, want ErrScopeMissing", err)
	}
	if used {
		t.Fatal("token source must not fire when the scope gate rejects")
	}

	// Unexpired access with no drive need: returned as-is, no refresh.
	used = false
	got, err := o.GetGoogleToken(ctx, user, false)
	if err != nil {
		t.Fatalf("unexpired token: %v", err)
	}
	if got != "access-old" {
		t.Fatalf("unexpired GetGoogleToken = %q, want access-old", got)
	}
	if used {
		t.Fatal("unexpired access token must not trigger a refresh")
	}
	tok := readToken(t, o, user)
	if refresh, err := open(o.key, tok.RefreshToken); err != nil || string(refresh) != "refresh-old" {
		t.Fatalf("stored refresh after no-op = %q, %v; want refresh-old", refresh, err)
	}

	// Expired token forces a refresh; the rotated pair is re-encrypted back.
	exp = time.Now().Add(-time.Minute)
	tokenRow(t, o, user, "openid,email,profile,"+GoogleDriveReadonly, "access-old", "refresh-old", &exp)
	var forced *oauth2.Token
	o.newSource = func(_ context.Context, _ *oauth2.Config, t *oauth2.Token) oauth2.TokenSource {
		forced, used = t, true
		return fakeSource{tok: &oauth2.Token{
			AccessToken:  "access-fresh",
			RefreshToken: "refresh-new",
			Expiry:       time.Now().Add(time.Hour),
		}, used: &used}
	}
	used = false
	got, err = o.GetGoogleToken(ctx, user, true) // drive scope now present
	if err != nil {
		t.Fatalf("refresh path: %v", err)
	}
	if got != "access-fresh" {
		t.Fatalf("refreshed GetGoogleToken = %q, want access-fresh", got)
	}
	if !used {
		t.Fatal("expired token must trigger a refresh")
	}
	if forced == nil || !forced.Expiry.Before(time.Now()) {
		t.Fatal("the token handed to the source must be forced-expired")
	}
	tok = readToken(t, o, user)
	access, err := open(o.key, tok.AccessToken)
	if err != nil || string(access) != "access-fresh" {
		t.Fatalf("stored access after refresh = %q, %v; want access-fresh", access, err)
	}
	refresh, err := open(o.key, tok.RefreshToken)
	if err != nil || string(refresh) != "refresh-new" {
		t.Fatalf("stored refresh after rotation = %q, %v; want refresh-new", refresh, err)
	}
	if scopes := scopeSet(tok.TokenScopes); !scopes[GoogleDriveReadonly] || !scopes["openid"] {
		t.Fatalf("scopes after refresh = %q, drive grant must survive", tok.TokenScopes)
	}

	// Refresh failure surfaces as ErrRefreshFailed.
	exp = time.Now().Add(-time.Minute)
	tokenRow(t, o, user, "openid,email,profile,"+GoogleDriveReadonly, "access-old", "refresh-old", &exp)
	used = false
	o.newSource = func(context.Context, *oauth2.Config, *oauth2.Token) oauth2.TokenSource {
		used = true
		return fakeSource{err: errors.New("google says no"), used: &used}
	}
	if _, err := o.GetGoogleToken(ctx, user, true); !errors.Is(err, ErrRefreshFailed) {
		t.Fatalf("refresh failure = %v, want ErrRefreshFailed", err)
	}

	// Expired token with NO stored refresh token cannot refresh.
	exp = time.Now().Add(-time.Minute)
	tokenRow(t, o, user, "openid,email,profile", "access-old", "", &exp)
	used = false
	if _, err := o.GetGoogleToken(ctx, user, false); !errors.Is(err, ErrRefreshFailed) {
		t.Fatalf("no-refresh expired = %v, want ErrRefreshFailed", err)
	}
}

func TestResolveIdentityVerifiedLinkConsumesInvitation(t *testing.T) {
	o := testOAuth(t)
	ctx := context.Background()
	email := "sso-" + uuid.NewString() + "@Example.COM" // mixed case on purpose
	subjG := "g-" + uuid.NewString()
	subjGH := "gh-" + uuid.NewString()
	tenant := createTenant(t, o)
	insertInvitation(t, o, tenant, email, "editor")

	// An unverified NEW identity must not create an account or consume invites.
	if _, err := o.resolveIdentity(ctx, ProviderGoogle, Claims{Subject: subjG, Email: email, EmailVerified: false}); !errors.Is(err, ErrUnverifiedEmail) {
		t.Fatalf("unverified new identity = %v, want ErrUnverifiedEmail", err)
	}

	// A verified NEW identity creates the user (email normalized lowercase),
	// links the identity, and consumes the pending invitation with membership.
	userID, err := o.resolveIdentity(ctx, ProviderGoogle, Claims{Subject: subjG, Email: email, EmailVerified: true, DisplayName: "Sso User"})
	if err != nil {
		t.Fatalf("verified link: %v", err)
	}
	if userID == uuid.Nil {
		t.Fatal("verified link returned the zero user id")
	}
	var found store.User
	if err := o.store.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		var err error
		found, err = q.GetUserByEmail(ctx, normalizeEmail(email))
		return err
	}); err != nil || found.ID != userID {
		t.Fatalf("user not found by lowercase email: %v, %v", found.ID, err)
	}
	// The invitation is gone: nothing left to consume.
	if _, err := o.ConsumeInvitation(ctx, email, nil); !errors.Is(err, ErrNoInvitation) {
		t.Fatalf("invitation after first verified link = %v, want ErrNoInvitation", err)
	}
	if role, err := o.store.MembershipRole(ctx, userID, tenant); err != nil || role != "editor" {
		t.Fatalf("MembershipRole after verified link = %q, %v; want editor", role, err)
	}

	// A second provider with the same verified email joins the SAME user.
	userID2, err := o.resolveIdentity(ctx, ProviderGitHub, Claims{Subject: subjGH, Email: email, EmailVerified: true})
	if err != nil {
		t.Fatalf("second provider link: %v", err)
	}
	if userID2 != userID {
		t.Fatalf("second provider resolved to %v, want same user %v", userID2, userID)
	}

	// Re-login via the already-linked identity is idempotent — it succeeds
	// even if the current email claim is unverified — and never re-consumes.
	if got, err := o.resolveIdentity(ctx, ProviderGoogle, Claims{Subject: subjG, Email: email, EmailVerified: false}); err != nil || got != userID {
		t.Fatalf("already-linked re-login = %v, %v; want %v, nil", got, err, userID)
	}
	if role, err := o.store.MembershipRole(ctx, userID, tenant); err != nil || role != "editor" {
		t.Fatalf("MembershipRole after re-login = %q, %v; want editor", role, err)
	}
}

func TestLinkIdentityIdempotentAndTaken(t *testing.T) {
	o := testOAuth(t)
	ctx := context.Background()
	u1 := createUser(t, o, "link-"+uuid.NewString()+"@example.com")
	u2 := createUser(t, o, "link-"+uuid.NewString()+"@example.com")

	subj := "subject-" + uuid.NewString()
	if err := o.LinkIdentity(ctx, u1, ProviderGoogle, subj); err != nil {
		t.Fatalf("first link: %v", err)
	}
	if err := o.LinkIdentity(ctx, u1, ProviderGoogle, subj); err != nil {
		t.Fatalf("repeat link to same user = %v, want nil (idempotent)", err)
	}
	if err := o.LinkIdentity(ctx, u2, ProviderGoogle, subj); !errors.Is(err, ErrIdentityTaken) {
		t.Fatalf("link to another user = %v, want ErrIdentityTaken", err)
	}
	if err := o.LinkIdentity(ctx, uuid.Nil, ProviderGoogle, "s"); !errors.Is(err, ErrInvalidUserID) {
		t.Fatalf("zero user = %v, want ErrInvalidUserID", err)
	}
	// A second provider may bind the same user independently.
	if err := o.LinkIdentity(ctx, u1, ProviderGitHub, subj); err != nil {
		t.Fatalf("second provider link: %v", err)
	}
}
