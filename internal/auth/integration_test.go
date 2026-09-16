package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openblog/internal/store"
)

// testAuth builds an Auth over DATABASE_URL; skips the test if unset.
func testAuth(t *testing.T) *Auth {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed auth tests")
	}
	ctx := context.Background()
	db, err := store.New(ctx, url)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(db.Close)
	return New(db)
}

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%s@example.com", prefix, uuid.NewString())
}

func createUser(t *testing.T, a *Auth, email string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if err := a.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.CreateUser(ctx, id, email, email, nil)
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return id
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	a := testAuth(t)
	ctx := context.Background()
	userID := createUser(t, a, uniqueEmail("issue"))

	token, err := a.Issue(ctx, userID, TokenTTL, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	gotUID, gotScope, err := a.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotUID != userID {
		t.Fatalf("Verify userID = %v, want %v", gotUID, userID)
	}
	if gotScope != uuid.Nil {
		t.Fatalf("Verify scope = %v, want nil", gotScope)
	}

	// Logout deletes only the presented session; verify then fails.
	if err := a.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, _, err := a.Verify(ctx, token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Verify after logout = %v, want ErrNoSession", err)
	}
}

func TestIssueRejectsZeroUser(t *testing.T) {
	a := testAuth(t)
	if _, err := a.Issue(context.Background(), uuid.Nil, TokenTTL, nil); !errors.Is(err, ErrInvalidUserID) {
		t.Fatalf("Issue with zero user = %v, want ErrInvalidUserID", err)
	}
}

func TestIssueRejectsUnknownUser(t *testing.T) {
	a := testAuth(t)
	// A random id that has no users row: the sessions FK must reject the insert.
	if _, err := a.Issue(context.Background(), uuid.New(), TokenTTL, nil); err == nil {
		t.Fatal("Issue for an unknown user must fail (sessions FK)")
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	a := testAuth(t)
	ctx := context.Background()
	userID := createUser(t, a, uniqueEmail("expired"))

	token, err := a.Issue(ctx, userID, -time.Hour, nil)
	if err != nil {
		t.Fatalf("Issue with past TTL: %v", err)
	}
	if _, _, err := a.Verify(ctx, token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Verify expired = %v, want ErrSessionExpired", err)
	}
}

func TestVerifyUnknownToken(t *testing.T) {
	a := testAuth(t)
	if _, _, err := a.Verify(context.Background(), "no-such-token"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Verify unknown token = %v, want ErrNoSession", err)
	}
}

func TestSignupLoginLogoutRoundTrip(t *testing.T) {
	a := testAuth(t)
	ctx := context.Background()
	email := uniqueEmail("signup")

	userID, err := a.Signup(ctx, email, "hunter2")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if userID == uuid.Nil {
		t.Fatal("Signup returned the zero user id")
	}

	token, err := a.Login(ctx, email, "hunter2")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	gotUID, _, err := a.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotUID != userID {
		t.Fatalf("Verify userID = %v, want signup id %v", gotUID, userID)
	}

	if _, err := a.Login(ctx, email, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login wrong password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := a.Login(ctx, uniqueEmail("nope"), "hunter2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login unknown email = %v, want ErrInvalidCredentials", err)
	}

	// email is normalized on write: a mixed-case login finds the same user.
	_, err = a.Login(ctx, strings.ToUpper(email), "hunter2")
	if err != nil {
		t.Fatalf("Login mixed-case email: %v", err)
	}

	if err := a.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, _, err := a.Verify(ctx, token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Verify after logout = %v, want ErrNoSession", err)
	}
}

func TestSignupBlockedByPendingInvitation(t *testing.T) {
	a := testAuth(t)
	ctx := context.Background()
	email := uniqueEmail("invited")

	// Seed a live pure-email invitation; a real tenant row satisfies both FKs.
	tenantID := uuid.New()
	if err := a.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		if err := q.CreateTenant(ctx, tenantID, "inv-"+uuid.NewString(), "invite tenant"); err != nil {
			return err
		}
		return q.InsertInvitation(ctx, uuid.New(), tenantID, &email, "editor", nil, time.Now().Add(24*time.Hour))
	}); err != nil {
		t.Fatalf("seeding invitation: %v", err)
	}

	if invited, err := a.HasPendingInvitation(ctx, email); err != nil || !invited {
		t.Fatalf("HasPendingInvitation = %v, %v; want true, nil", invited, err)
	}
	if _, err := a.Signup(ctx, email, "hunter2"); !errors.Is(err, ErrInvited) {
		t.Fatalf("Signup with pending invitation = %v, want ErrInvited", err)
	}

	if err := a.store.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.ConsumeInvitationByEmail(ctx, email)
	}); err != nil {
		t.Fatalf("consuming invitation: %v", err)
	}
	if invited, err := a.HasPendingInvitation(ctx, email); err != nil || invited {
		t.Fatalf("HasPendingInvitation after consume = %v, %v; want false, nil", invited, err)
	}
	if _, err := a.Signup(ctx, email, "hunter2"); err != nil {
		t.Fatalf("Signup after invitation consumed: %v", err)
	}
}
