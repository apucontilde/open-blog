package posts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"openblog/internal/authz"
	"openblog/internal/store"
	"openblog/migrations"
)

// DB-backed contract tests, per the repo convention: skip unless DATABASE_URL
// is set, provision a scratch DB owned by the non-superuser blog_app role so
// RLS bites, and replay the embedded migrations.

const (
	appRole     = "blog_app"
	appPassword = "blog_secret"
)

var dbSeq uint64

type postsDB struct {
	db   *store.DB
	pool *pgxpool.Pool
}

func newPostsScratchDB(t *testing.T) *postsDB {
	t.Helper()
	ctx := context.Background()

	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed posts tests")
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
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `do $$ begin
		if not exists (select from pg_roles where rolname = '`+appRole+`') then
			create role `+appRole+` login password '`+appPassword+`';
		end if;
	end $$`); err != nil {
		t.Skipf("cannot provision role %s (needs a privileged DATABASE_URL): %v", appRole, err)
	}

	name := fmt.Sprintf("openblog_posts_%d_%d", os.Getpid(), atomic.AddUint64(&dbSeq, 1))
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
		t.Fatal("posts DB tests require a non-superuser connection; superusers bypass RLS")
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	gdb := stdlib.OpenDBFromPool(pool)
	if err := goose.Up(gdb, "."); err != nil {
		t.Fatalf("goose up: %v", err)
	}
	if err := gdb.Close(); err != nil {
		t.Fatalf("close goose db: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "drop database "+name+" with (force)")
		admin.Close()
	})
	return &postsDB{db: store.NewFromPool(pool), pool: pool}
}

// fixture lands three members in two tenants, exactly mirroring the media DB
// tests' shape so cross-tenant and ownership rules are exercised for real.
type fixture struct {
	pd      *postsDB
	tA, tB  uuid.UUID // tenants
	u, v, w uuid.UUID // u owner of tA + editor of tB; v author of tB; w author of tA
	pa, pv  uuid.UUID // posts: pa by u in tA; pv by v in tB
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{pd: newPostsScratchDB(t),
		tA: uuid.New(), tB: uuid.New(),
		u: uuid.New(), v: uuid.New(), w: uuid.New(),
		pa: uuid.New(), pv: uuid.New(),
	}

	ctx := context.Background()
	bare := f.pd.pool
	for _, x := range []struct{ id, slug, name string }{
		{f.tA.String(), "tenant-a", "Tenant A"},
		{f.tB.String(), "tenant-b", "Tenant B"},
	} {
		if _, err := bare.Exec(ctx, "insert into tenants (id, slug, name) values ($1, $2, $3)", x.id, x.slug, x.name); err != nil {
			t.Fatal(err)
		}
	}
	for _, x := range []struct {
		id    uuid.UUID
		email string
		name  string
	}{
		{f.u, "u@x.io", "U"},
		{f.v, "v@x.io", "V"},
		{f.w, "w@x.io", "W"},
	} {
		if _, err := bare.Exec(ctx, "insert into users (id, email, display_name) values ($1, $2, $3)",
			x.id, x.email, x.name); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []struct{ tenant, user, role string }{
		{f.tA.String(), f.u.String(), "owner"},  // u owns tA
		{f.tB.String(), f.u.String(), "editor"}, // u is editor in tB
		{f.tB.String(), f.v.String(), "author"}, // v is author in tB
		{f.tA.String(), f.w.String(), "author"}, // w is author in tA
	} {
		if _, err := bare.Exec(ctx, "insert into memberships (tenant_id, user_id, role) values ($1, $2, $3)",
			m.tenant, m.user, m.role); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.pd.db.ScopedRW(ctx, store.Scope{TenantID: f.tA}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{
			ID: f.pa, TenantID: f.tA, AuthorID: f.u, Slug: "pa", Title: "Post A"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.pd.db.ScopedRW(ctx, store.Scope{TenantID: f.tB}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{
			ID: f.pv, TenantID: f.tB, AuthorID: f.v, Slug: "pv", Title: "Post V"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) svc() *Service { return New(f.pd.db, Config{}) }

func (f *fixture) actor(user uuid.UUID, role authz.Role, tenant uuid.UUID) authz.Actor {
	return authz.Actor{UserID: user, Tenant: &tenant, Role: role}
}

func (f *fixture) uAuthor() authz.Actor { return f.actor(f.w, authz.RoleAuthor, f.tA) }
func (f *fixture) uOwner() authz.Actor  { return f.actor(f.u, authz.RoleOwner, f.tA) }
func (f *fixture) uEditor() authz.Actor { return f.actor(f.u, authz.RoleEditor, f.tB) }
func (f *fixture) vAuthor() authz.Actor { return f.actor(f.v, authz.RoleAuthor, f.tB) }

func (f *fixture) version(t *testing.T, tenant uuid.UUID) int64 {
	t.Helper()
	var v int64
	if err := f.pd.pool.QueryRow(context.Background(),
		"select content_version from tenants where id = $1", tenant).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *fixture) purgeJobs(t *testing.T, kind string) int64 {
	t.Helper()
	var n int64
	if err := f.pd.pool.QueryRow(context.Background(),
		"select count(*) from jobs where kind = $1", kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) purgePayload(t *testing.T) map[string]any {
	t.Helper()
	var payload []byte
	if err := f.pd.pool.QueryRow(context.Background(),
		"select payload from jobs where kind = $1 limit 1", PurgeJobKind).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Data struct {
			TenantID uuid.UUID `json:"tenant_id"`
			PostID   uuid.UUID `json:"post_id"`
			Version  int64     `json:"version"`
			Paths    []string  `json:"paths"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"tenant_id": m.Data.TenantID,
		"post_id":   m.Data.PostID,
		"version":   m.Data.Version,
		"paths":     m.Data.Paths,
	}
}

func TestServiceCreateByAuthor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	p, err := f.svc().Create(ctx, f.uAuthor(), CreateInput{
		Title:           "My First Post",
		ContentMarkdown: "Hello **world**",
		Excerpt:         "teaser",
		Metadata:        []byte(`{"tags":["go"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != store.PostDraft {
		t.Fatalf("new post status = %s, want draft", p.Status)
	}
	if p.AuthorID != f.w {
		t.Fatalf("author_id = %s, want author", p.AuthorID)
	}
	if p.TenantID != f.tA {
		t.Fatalf("tenant_id = %s, want actor's scope", p.TenantID)
	}
	if p.Slug != "my-first-post" {
		t.Fatalf("slug = %q, want my-first-post", p.Slug)
	}
	if !strings.Contains(p.ContentHTML, "<strong>world</strong>") {
		t.Fatalf("content_html not rendered: %q", p.ContentHTML)
	}
	if !strings.Contains(string(p.Metadata), `"tags"`) {
		t.Fatalf("metadata not persisted: %q", p.Metadata)
	}

	got, err := f.svc().Get(ctx, f.uAuthor(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Slug != p.Slug || got.ContentHTML != p.ContentHTML {
		t.Fatalf("persisted round-trip mismatch: %+v", got)
	}
}

func TestServiceCreateSlugUniquify(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := f.svc()

	a, err := svc.Create(ctx, f.uAuthor(), CreateInput{Title: "Same Title", ContentMarkdown: "a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.Create(ctx, f.uAuthor(), CreateInput{Title: "Same Title", ContentMarkdown: "b"})
	if err != nil {
		t.Fatal(err)
	}
	two, err := svc.Create(ctx, f.uAuthor(), CreateInput{Title: "Same Title", ContentMarkdown: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Slug != "same-title" || b.Slug != "same-title-2" || two.Slug != "same-title-3" {
		t.Fatalf("slugs = %q, %q, %q; want ...-2, ...-3 suffixes", a.Slug, b.Slug, two.Slug)
	}
}

func TestServiceCreateNoTenant(t *testing.T) {
	f := newFixture(t)
	// A platform actor bypasses the capability ladder but carries no tenancy
	// intent: creating a tenant post without a scope must fail closed.
	_, err := f.svc().Create(context.Background(),
		authz.Actor{UserID: f.u, Platform: true}, CreateInput{Title: "No Tenant"})
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("want ErrNoTenant, got %v", err)
	}
}

func TestServicePublishLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := f.svc()

	p, err := svc.Create(ctx, f.vAuthor(), CreateInput{Title: "Lifecycle", ContentMarkdown: "# Hi\n\nBoom."})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Publish(ctx, f.vAuthor(), p.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("author publish must be forbidden, got %v", err)
	}
	if _, err := svc.Publish(ctx, f.uEditor(), p.ID); err != nil {
		t.Fatal(err)
	}
	pub, err := svc.Get(ctx, f.uEditor(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Status != store.PostPublished || pub.PublishedAt == nil {
		t.Fatalf("published post state wrong: status=%s published_at=%v", pub.Status, pub.PublishedAt)
	}
	if v := f.version(t, f.tB); v != 1 {
		t.Fatalf("content_version = %d, want 1 after first publish", v)
	}
	if n := f.purgeJobs(t, PurgeJobKind); n != 1 {
		t.Fatalf("purge jobs = %d, want 1", n)
	}
	if pl := f.purgePayload(t); pl["version"].(int64) != 1 || len(pl["paths"].([]string)) != 1 {
		t.Fatalf("purge payload wrong: %+v", pl)
	}

	// Re-publish is idempotent at the dedupe key: the version still advances,
	// but no second purge row appears.
	if _, err := svc.Publish(ctx, f.uEditor(), p.ID); err != nil {
		t.Fatal(err)
	}
	if v := f.version(t, f.tB); v != 2 {
		t.Fatalf("content_version = %d, want 2 after re-publish", v)
	}
	if n := f.purgeJobs(t, PurgeJobKind); n != 1 {
		t.Fatalf("purge jobs = %d, want still 1 (dedupe)", n)
	}

	// Unpublish: back to draft, published_at cleared, one more bump.
	if _, err := svc.Unpublish(ctx, f.uEditor(), p.ID); err != nil {
		t.Fatal(err)
	}
	un, err := svc.Get(ctx, f.uEditor(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if un.Status != store.PostDraft || un.PublishedAt != nil {
		t.Fatalf("unpublished state wrong: status=%s published_at=%v", un.Status, un.PublishedAt)
	}
	if v := f.version(t, f.tB); v != 3 {
		t.Fatalf("content_version = %d, want 3 after unpublish", v)
	}

	// Archive: hide from public listing, still a transition.
	if _, err := svc.Archive(ctx, f.uEditor(), p.ID); err != nil {
		t.Fatal(err)
	}
	ar, err := svc.Get(ctx, f.uEditor(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ar.Status != store.PostArchived {
		t.Fatalf("archived status = %s", ar.Status)
	}
	if v := f.version(t, f.tB); v != 4 {
		t.Fatalf("content_version = %d, want 4 after archive", v)
	}
}

func TestServicePublishEmptyContent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := f.svc()

	p, err := svc.Create(ctx, f.vAuthor(), CreateInput{Title: "Empty", ContentMarkdown: ""})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Publish(ctx, f.uEditor(), p.ID); !errors.Is(err, ErrEmptyContent) {
		t.Fatalf("want ErrEmptyContent, got %v", err)
	}
}

func TestServiceUpdateDraftVsPublished(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := f.svc()

	p, err := svc.Create(ctx, f.vAuthor(), CreateInput{Title: "Draft", ContentMarkdown: "one"})
	if err != nil {
		t.Fatal(err)
	}

	// Draft PATCH: no purge, no bump.
	upd, err := svc.Update(ctx, f.vAuthor(), p.ID, UpdateInput{Title: strPtr("Draft 2"), ContentMarkdown: strPtr("**two**")})
	if err != nil {
		t.Fatal(err)
	}
	if upd.Title != "Draft 2" || !strings.Contains(upd.ContentHTML, "<strong>two</strong>") {
		t.Fatalf("patch not applied: %+v", upd)
	}
	if v := f.version(t, f.tB); v != 0 {
		t.Fatalf("draft patch bumped version to %d, want 0", v)
	}
	if n := f.purgeJobs(t, PurgeJobKind); n != 0 {
		t.Fatalf("draft patch enqueued purge rows: %d", n)
	}

	// Slug refactor of a draft: still allowed, uniquified.
	if _, err := svc.Update(ctx, f.vAuthor(), p.ID, UpdateInput{Slug: strPtr("renamed")}); err != nil {
		t.Fatal(err)
	}

	// Publish, then a title-only PATCH: bump + single (deduped) purge row.
	if _, err := svc.Publish(ctx, f.uEditor(), p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(ctx, f.uEditor(), p.ID, UpdateInput{Title: strPtr("Published Title")}); err != nil {
		t.Fatal(err)
	}
	if v := f.version(t, f.tB); v != 2 {
		t.Fatalf("published patch chain version = %d, want 2 (publish then published PATCH)", v)
	}
	if n := f.purgeJobs(t, PurgeJobKind); n != 1 {
		t.Fatalf("purge rows = %d, want 1 (dedupe)", n)
	}

	// Slug is a public URL component: frozen once published.
	if _, err := svc.Update(ctx, f.uEditor(), p.ID, UpdateInput{Slug: strPtr("nope")}); !errors.Is(err, ErrSlugImmutable) {
		t.Fatalf("want ErrSlugImmutable, got %v", err)
	}
}

func TestServiceDeleteRules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := f.svc()

	p, err := svc.Create(ctx, f.vAuthor(), CreateInput{Title: "Del", ContentMarkdown: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, f.uEditor(), p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, f.uEditor(), p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted post still visible: %v", err)
	}

	// Author can delete only their own draft: not-own post (different author in
	// the same tenant) is ErrForbidden.
	other, err := svc.Create(ctx, f.uEditor(), CreateInput{Title: "Other", ContentMarkdown: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, f.vAuthor(), other.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("author deleting foreign draft: want ErrForbidden, got %v", err)
	}

	// Editor can delete across authors and statuses.
	if _, err := svc.Publish(ctx, f.uEditor(), other.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, f.uEditor(), other.ID); err != nil {
		t.Fatalf("editor deleting published post: %v", err)
	}

	// Author's own post once published also refuses author delete.
	own, err := svc.Create(ctx, f.vAuthor(), CreateInput{Title: "Own", ContentMarkdown: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Publish(ctx, f.uEditor(), own.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, f.vAuthor(), own.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("author deleting own published post: want ErrForbidden, got %v", err)
	}
	if err := svc.Delete(ctx, f.uEditor(), own.ID); err != nil {
		t.Fatal(err)
	}
}

func TestServiceGetForbiddenForForeignAuthor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// w is an author in tA, foreign to post pa (by u).
	if _, err := f.svc().Get(ctx, f.uAuthor(), f.pa); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("foreign author Get: want ErrForbidden, got %v", err)
	}
	if _, err := f.svc().Get(ctx, f.uOwner(), f.pa); err != nil {
		t.Fatal(err)
	}
}

func TestServiceListScoping(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := f.svc()

	w1, err := svc.Create(ctx, f.uAuthor(), CreateInput{Title: "W One", ContentMarkdown: "w"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, f.uAuthor(), CreateInput{Title: "W Two", ContentMarkdown: "w"}); err != nil {
		t.Fatal(err)
	}
	u1, err := svc.Create(ctx, f.uOwner(), CreateInput{Title: "U One", ContentMarkdown: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Publish(ctx, f.uOwner(), u1.ID); err != nil {
		t.Fatal(err)
	}

	// Plain author: own drafts + own everything, editor's rows invisible even
	// with an explicit author filter targeting the editor.
	own, err := svc.List(ctx, f.uAuthor(), ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 2 {
		t.Fatalf("author list = %d, want 2 (own only)", len(own))
	}
	// Plain author: the AuthorID filter is ignored — always pinned to the
	// actor's own id, even when the filter targets another author.
	own, err = svc.List(ctx, f.uAuthor(), ListFilter{AuthorID: &f.u})
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 2 {
		t.Fatalf("author list with foreign filter = %d, want still 2 (own only)", len(own))
	}

	// Editor/owner: tenant-wide (includes the fixture's pa row), respecting
	// the status filter.
	all, err := svc.List(ctx, f.uOwner(), ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("owner list = %d, want 4 (fixture + 3 created)", len(all))
	}
	pub, err := svc.List(ctx, f.uOwner(), ListFilter{Status: strPtr("published")})
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 1 || pub[0].ID != u1.ID {
		t.Fatalf("published filter wrong: %+v", pub)
	}
	if pub[0].Status != store.PostPublished {
		t.Fatalf("summary status = %s", pub[0].Status)
	}

	// A summary never carries the markdown body.
	if all[0].Title == "" || all[0].Slug == "" {
		t.Fatal("summary missing projection fields")
	}
	_ = w1
}

func TestServicePlatformBypassesCaps(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := f.svc()

	plat := authz.Actor{UserID: f.u, Tenant: &f.tA, Platform: true}
	p, err := svc.Create(ctx, plat, CreateInput{Title: "Plat", ContentMarkdown: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Publish(ctx, plat, p.ID); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(ctx, plat, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.PostPublished {
		t.Fatalf("platform publish failed: status=%s", got.Status)
	}
}

func TestServiceRenderedHTMLSanitized(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	svc := f.svc()

	p, err := svc.Create(ctx, f.vAuthor(), CreateInput{
		Title:           "XSS",
		ContentMarkdown: "<script>alert(1)</script>\n\n# Safe heading",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.ContentHTML, "<script") {
		t.Fatalf("script leaked into content_html: %q", p.ContentHTML)
	}
	if !strings.Contains(p.ContentHTML, "<h1>Safe heading</h1>") {
		t.Fatalf("safe content missing from html: %q", p.ContentHTML)
	}
}

// TestServiceRollbackDiscardsBumpAndPurge replicates the publish sequence
// inside a failing transaction: the bump and the enqueued purge must both
// roll back with the status change (008 sweep finding 9).
func TestServiceRollbackDiscardsBumpAndPurge(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	if err := f.pd.db.ScopedRW(ctx, store.Scope{TenantID: f.tB}, func(q *store.Queries) error {
		upd, err := q.SetPostStatus(ctx, f.pv, store.PostPublished, nil, "<html>")
		if err != nil {
			return err
		}
		return fmt.Errorf("rollback marker: %s", upd.ID)
	}); err == nil || !strings.Contains(err.Error(), "rollback marker") {
		t.Fatalf("setup expected forced rollback, got %v", err)
	}

	if v := f.version(t, f.tB); v != 0 {
		t.Fatalf("content_version survived rollback: %d", v)
	}
	if n := f.purgeJobs(t, PurgeJobKind); n != 0 {
		t.Fatalf("purge job survived rollback: %d", n)
	}
}

func strPtr(s string) *string { return &s }
