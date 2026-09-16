// Package httptest is the ST-1…ST-23 contract harness for the 010 HTTP layer.
// It spins the REAL router (internal/api) against a throwaway Postgres so the
// tests exercise the same middleware chain, handlers, and SQL the binary runs.
// Follows the repo convention: skip when DATABASE_URL is unset.
package httptest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"openblog/internal/api"
	"openblog/internal/auth"
	docimport "openblog/internal/import"
	"openblog/internal/media"
	"openblog/internal/oauth"
	"openblog/internal/posts"
	"openblog/internal/publicapi"
	"openblog/internal/store"
	"openblog/migrations"
)

const (
	appRole     = "blog_app"
	appPassword = "blog_secret"
	testOrigin  = "https://app.example"
)

var dbSeq uint64

var (
	sharedPool *pgxpool.Pool
	sharedDB   *store.DB
	adminPool  *pgxpool.Pool
	dropDB     string
)

func TestMain(m *testing.M) {
	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		os.Exit(0)
	}
	ctx := context.Background()

	var err error
	adminPool, err = pgxpool.New(ctx, adminURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "httptest: admin pool: %v\n", err)
		os.Exit(1)
	}
	if err := adminPool.Ping(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "httptest: DATABASE_URL unreachable: %v\n", err)
		os.Exit(1)
	}
	_, _ = adminPool.Exec(ctx, fmt.Sprintf(`do $$ begin
		if not exists (select from pg_roles where rolname = '%s') then
			create role %s login password '%s';
		end if;
	end $$`, appRole, appRole, appPassword))

	u, _ := url.Parse(adminURL)
	dropDB = fmt.Sprintf("openblog_httptest_%d_%d", os.Getpid(), atomic.AddUint64(&dbSeq, 1))
	if _, err := adminPool.Exec(ctx, "create database "+dropDB+" owner "+appRole); err != nil {
		fmt.Fprintf(os.Stderr, "httptest: create scratch db: %v\n", err)
		os.Exit(1)
	}

	scratch := *u
	scratch.User = url.UserPassword(appRole, appPassword)
	scratch.Path = "/" + dropDB

	sharedPool, err = pgxpool.New(ctx, scratch.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "httptest: scratch pool: %v\n", err)
		os.Exit(1)
	}
	var rolsuper bool
	_ = sharedPool.QueryRow(ctx, "select rolsuper from pg_roles where rolname = current_user").Scan(&rolsuper)
	if rolsuper {
		fmt.Fprintln(os.Stderr, "httptest: must connect as non-superuser; superusers bypass RLS")
		os.Exit(1)
	}

	goose.SetBaseFS(migrations.FS)
	_ = goose.SetDialect("postgres")
	gdb := stdlib.OpenDBFromPool(sharedPool)
	if err := goose.Up(gdb, "."); err != nil {
		fmt.Fprintf(os.Stderr, "httptest: goose up: %v\n", err)
		os.Exit(1)
	}
	_ = gdb.Close()

	sharedDB = store.NewFromPool(sharedPool)

	code := m.Run()

	sharedDB.Close()
	_, _ = adminPool.Exec(context.Background(), "drop database "+dropDB+" with (force)")
	adminPool.Close()
	os.Exit(code)
}

// harness wires the real router against the shared scratch database.
type harness struct {
	t       *testing.T
	db      *store.DB
	pool    *pgxpool.Pool
	posts   *posts.Service
	media   *media.Media
	imports *docimport.Service
	session *auth.Auth
	pub     *publicapi.API
}

// newHarness resets state and returns a ready harness. Each ST gets a clean DB
// (truncate) so tests cannot leak tenants/users into one another.
func newHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set; skipping httptest harness")
	}
	h := &harness{
		t:       t,
		db:      sharedDB,
		pool:    sharedPool,
		posts:   posts.New(sharedDB, posts.Config{}),
		media:   media.New(media.Config{Endpoint: "https://r2.example", Bucket: "test", PresignExpiry: 15 * time.Minute, CDNBase: "https://media.example"}, sharedDB, nil),
		session: auth.New(sharedDB),
		pub:     publicapi.New(sharedDB, publicapi.Config{MediaCDN: "https://media.example"}),
	}
	h.imports = docimport.New(docimport.Config{DB: sharedPool, R2: &noopR2{}, Posts: h.posts})
	h.reset()
	return h
}

func (h *harness) reset() {
	if _, err := h.pool.Exec(context.Background(),
		"truncate tenants, users, jobs, oauth_flows, oauth_tokens restart identity cascade"); err != nil {
		h.t.Fatalf("reset db: %v", err)
	}
}

// httpServer returns an httptest.Server running the real router.
func (h *harness) httpServer() *httptest.Server {
	srv := api.New(api.Deps{
		DB:            h.db,
		Posts:         h.posts,
		Media:         h.media,
		Imports:       h.imports,
		Session:       h.session,
		OAuth:         (*oauth.OAuth)(nil),
		Pub:           h.pub,
		SessionName:   "test_session",
		SessionSecure: false,
		Origins:       []string{testOrigin},
	})
	return httptest.NewServer(srv.Routes())
}

func (h *harness) createUser(email, password string) uuid.UUID {
	h.t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		h.t.Fatal(err)
	}
	display := email
	if i := strings.IndexByte(email, '@'); i > 0 {
		display = email[:i]
	}
	if err := h.db.ScopedRW(context.Background(), store.Scope{}, func(q *store.Queries) error {
		return q.CreateUser(context.Background(), id, email, display, &password)
	}); err != nil {
		h.t.Fatalf("create user: %v", err)
	}
	return id
}

// issueToken mints a session for userID. tenantID may be nil (no tenant chosen).
func (h *harness) issueToken(userID uuid.UUID, tenantID *uuid.UUID) string {
	h.t.Helper()
	token, err := h.session.Issue(context.Background(), userID, auth.TokenTTL, tenantID)
	if err != nil {
		h.t.Fatalf("issue token: %v", err)
	}
	return token
}

func (h *harness) createTenant(slug, name string) uuid.UUID {
	h.t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.db.ScopedRW(context.Background(), store.Scope{}, func(q *store.Queries) error {
		return q.CreateTenant(context.Background(), id, slug, name)
	}); err != nil {
		h.t.Fatalf("create tenant: %v", err)
	}
	return id
}

func (h *harness) addMembership(tenantID, userID uuid.UUID, role string) {
	h.t.Helper()
	if err := h.db.ScopedRW(context.Background(), store.Scope{}, func(q *store.Queries) error {
		return q.AddMembership(context.Background(), tenantID, userID, role)
	}); err != nil {
		h.t.Fatalf("add membership: %v", err)
	}
}

func (h *harness) setSuperAdmin(userID uuid.UUID, super bool) {
	h.t.Helper()
	if err := h.db.ScopedRW(context.Background(), store.Scope{}, func(q *store.Queries) error {
		return q.SetSuperAdmin(context.Background(), userID, super)
	}); err != nil {
		h.t.Fatalf("set super admin: %v", err)
	}
}

// authHeader builds the Authorization header for a session token.
func authHeader(token string) string { return "Bearer " + token }

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// req builds a JSON request.
func req(t *testing.T, method, url string, body any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequest(method, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

// do performs r against srv, attaching the bearer token when non-empty.
func do(t *testing.T, srv *httptest.Server, r *http.Request, token string) *http.Response {
	t.Helper()
	if token != "" {
		r.Header.Set("Authorization", authHeader(token))
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("request %s %s: %v", r.Method, r.URL.Path, err)
	}
	return resp
}

// decode reads and decodes a JSON response body, closing it.
func decode(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s %s body: %v", resp.Request.Method, resp.Request.URL.Path, err)
	}
}

// noopR2 is a no-op object store for harnesses that never touch real bytes.
type noopR2 struct{}

func (n *noopR2) Put(_ context.Context, _ string, _ []byte) error { return nil }
func (n *noopR2) Get(_ context.Context, _ string) ([]byte, error) { return nil, nil }
