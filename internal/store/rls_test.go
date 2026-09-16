package store_test

import (
	"context"
	"embed"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"openblog/internal/store"
	"openblog/migrations"
)

// RLS only bites a non-superuser, so the harness runs as the plain app role it provisions as owner.
const (
	appRole     = "blog_app"
	appPassword = "blog_secret"
)

var dbSeq uint64

type testDB struct {
	s    *store.DB
	pool *pgxpool.Pool
}

func newScratchDB(t *testing.T) *testDB {
	t.Helper()
	ctx := context.Background()

	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Skipf("DATABASE_URL unreachable: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		t.Skipf("DATABASE_URL unreachable: %v", err)
	}

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatalf("DATABASE_URL: %v", err)
	}
	if _, err := admin.Exec(ctx, `do $$ begin
		if not exists (select from pg_roles where rolname = '`+appRole+`') then
			create role `+appRole+` login password '`+appPassword+`';
		end if;
	end $$`); err != nil {
		t.Skipf("cannot provision role %s (needs a privileged DATABASE_URL): %v", appRole, err)
	}

	name := fmt.Sprintf("openblog_rls_%d_%d", os.Getpid(), atomic.AddUint64(&dbSeq, 1))
	if _, err := admin.Exec(ctx, "create database "+name+" owner "+appRole); err != nil {
		t.Skipf("cannot create scratch database: %v", err)
	}

	scratch := *u
	scratch.User = url.UserPassword(appRole, appPassword)
	scratch.Path = "/" + name

	pool, err := pgxpool.New(ctx, scratch.String())
	if err != nil {
		t.Fatalf("scratch pool: %v", err)
	}
	var rolsuper bool
	if err := pool.QueryRow(ctx, "select rolsuper from pg_roles where rolname = current_user").Scan(&rolsuper); err != nil {
		t.Fatalf("probe current_user: %v", err)
	}
	if rolsuper {
		t.Fatal("RLS tests require a non-superuser connection; superusers bypass row-level security")
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	gdb := stdlib.OpenDBFromPool(pool)
	if err := goose.Up(gdb, "."); err != nil {
		t.Fatalf("goose up on scratch db: %v", err)
	}
	if err := gdb.Close(); err != nil {
		t.Fatalf("close goose db: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "drop database "+name+" with (force)")
		admin.Close()
	})

	return &testDB{s: store.NewFromPool(pool), pool: pool}
}

type fixture struct {
	td      *testDB
	a, b, c uuid.UUID // tenants
	u, v, w uuid.UUID // users
	pa, pb  uuid.UUID // posts in a and b
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{td: newScratchDB(t)}
	f.a, f.b, f.c = uuid.New(), uuid.New(), uuid.New()
	f.u, f.v, f.w = uuid.New(), uuid.New(), uuid.New()
	f.pa, f.pb = uuid.New(), uuid.New()

	assertErr(t, f.td.s.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		for _, v := range []struct {
			id   uuid.UUID
			slug string
			name string
		}{
			{f.a, "tenant-a", "Tenant A"},
			{f.b, "tenant-b", "Tenant B"},
			{f.c, "tenant-c", "Tenant C"},
		} {
			if err := q.CreateTenant(ctx, v.id, v.slug, v.name); err != nil {
				return err
			}
		}
		for _, v := range []struct {
			id    uuid.UUID
			email string
			name  string
		}{
			{f.u, "u@x.io", "U"},
			{f.v, "v@x.io", "V"},
			{f.w, "w@x.io", "W"},
		} {
			if err := q.CreateUser(ctx, v.id, v.email, v.name, nil); err != nil {
				return err
			}
		}
		for _, v := range []struct {
			tenant, user uuid.UUID
			role         string
		}{
			{f.a, f.u, "owner"},
			{f.b, f.u, "editor"},
			{f.c, f.v, "author"},
		} {
			if err := q.AddMembership(ctx, v.tenant, v.user, v.role); err != nil {
				return err
			}
		}
		return nil
	}))

	assertErr(t, f.td.s.ScopedRW(ctx, store.Scope{TenantID: f.a}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{ID: f.pa, TenantID: f.a, AuthorID: f.u, Slug: "pa", Title: "Post A"})
		return err
	}))
	assertErr(t, f.td.s.ScopedRW(ctx, store.Scope{TenantID: f.b}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{ID: f.pb, TenantID: f.b, AuthorID: f.u, Slug: "pb", Title: "Post B"})
		return err
	}))
	return f
}

func assertErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func postIDs(ps []store.Post) map[uuid.UUID]bool {
	m := make(map[uuid.UUID]bool, len(ps))
	for _, p := range ps {
		m[p.ID] = true
	}
	return m
}

func equal(m map[uuid.UUID]bool, ids ...uuid.UUID) bool {
	if len(m) != len(ids) {
		return false
	}
	for _, id := range ids {
		if !m[id] {
			return false
		}
	}
	return true
}

func stripSQLComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// TestTenantIsolation: Scope{A} lists only its rows and cannot attach a child to B's post (composite FK).
func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	posts := []store.Post{}
	assertErr(t, f.td.s.Scoped(ctx, store.Scope{TenantID: f.a}, func(q *store.Queries) error {
		var err error
		posts, err = q.ListPosts(ctx)
		return err
	}))
	if ids := postIDs(posts); !equal(ids, f.pa) {
		t.Fatalf("Scope{A} listed %v, want only post A", ids)
	}

	// composite FK has no (A, PB) anchor in posts
	err := f.td.s.ScopedRW(ctx, store.Scope{TenantID: f.a}, func(q *store.Queries) error {
		return q.CreatePostImage(ctx, uuid.New(), f.a, f.pb, "r2-key", "https://img", 1, 1, 1, "image/png")
	})
	if err == nil {
		t.Fatal("attaching an image to another tenant's post succeeded; expected FK rejection")
	}
	err = f.td.s.ScopedRW(ctx, store.Scope{TenantID: f.a}, func(q *store.Queries) error {
		return q.CreateImport(ctx, uuid.New(), f.a, f.u, &f.pb, "pdf", "src-key")
	})
	if err == nil {
		t.Fatal("attaching an import to another tenant's post succeeded; expected FK rejection")
	}

	posts = []store.Post{}
	assertErr(t, f.td.s.Scoped(ctx, store.Scope{TenantID: f.a}, func(q *store.Queries) error {
		var err error
		posts, err = q.ListPosts(ctx)
		return err
	}))
	if !equal(postIDs(posts), f.pa) {
		t.Fatalf("tenant A reached tenant B rows: %v", postIDs(posts))
	}
}

// TestFailClosed: a zero scope reads 0 rows, writes hit RLS with-check, and a nil-uuid tenant stays unreachable.
func TestFailClosed(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	posts := []store.Post{}
	assertErr(t, f.td.s.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		var err error
		posts, err = q.ListPosts(ctx)
		return err
	}))
	if len(posts) != 0 {
		t.Fatalf("unscoped read saw %v posts; wants 0", postIDs(posts))
	}

	// with check (app_scope() or tenant_id = NULL) is NULL -> row rejected
	err := f.td.s.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{ID: uuid.New(), TenantID: f.a, AuthorID: f.u, Slug: "x", Title: "X"})
		return err
	})
	if err == nil {
		t.Fatal("write under a zero scope succeeded; RLS with check must reject")
	}

	// a tenant whose id is the nil uuid must stay unreachable: nil cast -> SQL NULL -> no rows
	nilTen := uuid.Nil
	nilPost := uuid.New()
	assertErr(t, f.td.s.ScopedRW(ctx, store.Scope{Platform: true}, func(q *store.Queries) error {
		if err := q.CreateTenant(ctx, nilTen, "nil-tenant", "Nil"); err != nil {
			return err
		}
		_, err := q.CreatePost(ctx, store.Post{ID: nilPost, TenantID: nilTen, AuthorID: f.u, Slug: "pn", Title: "PN"})
		return err
	}))

	n := -1
	assertErr(t, f.td.s.Scoped(ctx, store.Scope{TenantID: uuid.Nil}, func(q *store.Queries) error {
		ps, err := q.ListPosts(ctx)
		n = len(ps)
		return err
	}))
	if n != 0 {
		t.Fatalf("nil-uuid scope saw %d rows; the nil-cast must stay SQL NULL, never the '0000…' string", n)
	}
	err = f.td.s.ScopedRW(ctx, store.Scope{TenantID: uuid.Nil}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{ID: uuid.New(), TenantID: nilTen, AuthorID: f.u, Slug: "qx", Title: "QX"})
		return err
	})
	if err == nil {
		t.Fatal("write against the nil-uuid tenant under a nil scope succeeded; must fail closed")
	}
}

// TestPlatformSeesAll: an app_scope() set sees every tenant's rows but still cannot break Postgres FK rules.
func TestPlatformSeesAll(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	posts := []store.Post{}
	assertErr(t, f.td.s.Scoped(ctx, store.Scope{Platform: true}, func(q *store.Queries) error {
		var err error
		posts, err = q.ListPosts(ctx)
		return err
	}))
	if ids := postIDs(posts); !equal(ids, f.pa, f.pb) {
		t.Fatalf("platform scope saw %v, want both A and B posts", ids)
	}

	// platform widens RLS only; the FK to tenants(id) still holds
	err := f.td.s.ScopedRW(ctx, store.Scope{Platform: true}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{ID: uuid.New(), TenantID: uuid.New(), AuthorID: f.u, Slug: "rogue", Title: "Rogue"})
		return err
	})
	if err == nil {
		t.Fatal("platform scope inserted a post for a nonexistent tenant; FK must reject")
	}
	// platform still cannot attach across tenants via the composite anchor
	err = f.td.s.ScopedRW(ctx, store.Scope{Platform: true}, func(q *store.Queries) error {
		return q.CreatePostImage(ctx, uuid.New(), f.a, f.pb, "r2-key", "https://img", 1, 1, 1, "image/png")
	})
	if err == nil {
		t.Fatal("platform scope attached an image across tenants; composite FK must reject")
	}
}

// TestNoScopeLeakBetweenConnections: a scoped tx leaves no setting on the pooled connection; READ ONLY rejects writes.
func TestNoScopeLeakBetweenConnections(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	assertErr(t, f.td.s.Scoped(ctx, store.Scope{TenantID: f.a}, func(q *store.Queries) error {
		_, err := q.ListPosts(ctx)
		return err
	}))

	post := []store.Post{}
	assertErr(t, f.td.s.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		var err error
		post, err = q.ListPosts(ctx)
		return err
	}))
	if len(post) != 0 {
		t.Fatalf("tenant scope leaked into the next unscoped op: %v", postIDs(post))
	}

	// SET LOCAL is transaction-scoped: a bare pooled connection carries no tenant
	leaked := "set"
	if err := f.td.pool.QueryRow(ctx, "select coalesce(current_setting('app.tenant_id', true), '')").Scan(&leaked); err != nil {
		t.Fatalf("probe leaked setting: %v", err)
	}
	if leaked != "" {
		t.Fatalf("app.tenant_id leaked onto a pooled connection: %q", leaked)
	}

	// BEGIN READ ONLY is the write guard
	err := f.td.s.Scoped(ctx, store.Scope{TenantID: f.a}, func(q *store.Queries) error {
		return q.CreatePostImage(ctx, uuid.New(), f.a, f.pa, "r2-key", "https://img", 1, 1, 1, "image/png")
	})
	if err == nil {
		t.Fatal("write inside a read-only scope succeeded; BEGIN READ ONLY must guard")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("expected a read-only-transaction error, got: %v", err)
	}
}

// TestMembershipScoping: memberships is unscoped; each query binds the actor's own user_id server-side.
func TestMembershipScoping(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	ms, err := f.td.s.Memberships(ctx, f.u)
	assertErr(t, err)
	got := make(map[uuid.UUID]string, len(ms))
	for _, m := range ms {
		got[m.TenantID] = m.Role
	}
	if len(got) != 2 || got[f.a] != "owner" || got[f.b] != "editor" {
		t.Fatalf("actor U memberships = %v; want {a:owner, b:editor}", got)
	}
	if _, ok := got[f.c]; ok {
		t.Fatal("actor U must never see V's tenant C membership")
	}

	// a foreign probe returns that user's rows only; no memberships probes to 0
	msV, err := f.td.s.Memberships(ctx, f.v)
	assertErr(t, err)
	if len(msV) != 1 || msV[0].TenantID != f.c {
		t.Fatalf("actor V memberships = %v; want only {c}", msV)
	}
	msW, err := f.td.s.Memberships(ctx, f.w)
	assertErr(t, err)
	if len(msW) != 0 {
		t.Fatalf("actor W has no memberships but returned %v", msW)
	}

	role, err := f.td.s.MembershipRole(ctx, f.u, f.a)
	assertErr(t, err)
	if role != "owner" {
		t.Fatalf("Role(U, a) = %q, want owner", role)
	}
	if _, err := f.td.s.MembershipRole(ctx, f.u, f.c); err != store.ErrNotMember {
		t.Fatalf("Role(U, c) err = %v, want ErrNotMember", err)
	}

	assertErr(t, f.td.s.Scoped(ctx, store.Scope{TenantID: f.a}, func(q *store.Queries) error {
		within, err := f.td.s.Memberships(ctx, f.u)
		if err != nil {
			return err
		}
		if len(within) != 2 {
			return fmt.Errorf("tenant scope filtered the switcher list: %v", within)
		}
		return nil
	}))
}

// TestRlsLint: the fixed set {posts, post_images, imports} has FORCE + one tenant_scope policy, no other RLS, migrations DDL-only.
func TestRlsLint(t *testing.T) {
	ctx := context.Background()
	td := newScratchDB(t)

	scoped := map[string]bool{"posts": true, "post_images": true, "imports": true}
	for _, tbl := range []string{"posts", "post_images", "imports"} {
		var relrowsecurity, relforce bool
		err := td.pool.QueryRow(ctx, `
			select c.relrowsecurity, c.relforcerowsecurity
			from pg_class c
			join pg_namespace n on n.oid = c.relnamespace
			where n.nspname = 'public' and c.relname = $1`, tbl).Scan(&relrowsecurity, &relforce)
		assertErr(t, err)
		if !relrowsecurity || !relforce {
			t.Fatalf("%s: relrowsecurity=%v relforcerowsecurity=%v; want ENABLE + FORCE", tbl, relrowsecurity, relforce)
		}
		var pol int
		assertErr(t, td.pool.QueryRow(ctx, `
			select count(*) from pg_policies
			where schemaname = 'public' and tablename = $1 and policyname = 'tenant_scope'`, tbl).Scan(&pol))
		if pol != 1 {
			t.Fatalf("%s: tenant_scope policies = %d, want exactly 1", tbl, pol)
		}
	}

	rows, err := td.pool.Query(ctx, `
		select c.relname from pg_class c
		join pg_namespace n on n.oid = c.relnamespace
		where n.nspname = 'public' and c.relkind = 'r'
		  and (c.relrowsecurity or c.relforcerowsecurity
		   or exists (select 1 from pg_policy p where p.polrelid = c.oid))`)
	assertErr(t, err)
	got := []string{}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("%v", err)
		}
		got = append(got, r)
	}
	rows.Close()
	for _, r := range got {
		if !scoped[r] {
			t.Fatalf("table %q has RLS/policies but is outside the tenant-scoped set", r)
		}
	}

	// embedded migrations must be DDL-only w.r.t. the scoped set
	migDML := regexp.MustCompile(`(?is)\b(insert\s+into|update|delete\s+from|truncate\s+table|copy)\s+(posts|post_images|imports)\b`)
	entries, err := migrations.FS.ReadDir(".")
	assertErr(t, err)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := migrations.FS.ReadFile(e.Name())
		assertErr(t, err)
		code := stripSQLComments(string(b))
		if hit := migDML.FindString(code); hit != "" {
			t.Fatalf("%s contains tenant-scoped DML: %q", e.Name(), hit)
		}
		if strings.Contains(strings.ToLower(code), "disable row level security") {
			t.Fatalf("%s disables row level security", e.Name())
		}
	}
}

//go:embed *.go
var storeSources embed.FS

// TestPlatformScopeDiscipline: no store code mints Platform; callers verify the actor and pass it in.
func TestPlatformScopeDiscipline(t *testing.T) {
	entries, err := storeSources.ReadDir(".")
	assertErr(t, err)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := storeSources.ReadFile(e.Name())
		assertErr(t, err)
		for n, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "Platform: true") || strings.Contains(line, ".Platform = true") {
				t.Fatalf("%s:%d mints Platform ad hoc: %s", e.Name(), n+1, strings.TrimSpace(line))
			}
		}
	}

	src, err := storeSources.ReadFile("store.go")
	assertErr(t, err)
	for _, fn := range []string{"func (d *DB) Scoped(", "func (d *DB) ScopedRW("} {
		if !strings.Contains(string(src), fn) {
			t.Fatalf("store.go missing %s", fn)
		}
	}
}
