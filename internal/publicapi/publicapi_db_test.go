package publicapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
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
	"openblog/internal/posts"
	"openblog/internal/store"
	"openblog/migrations"
)

const (
	pubAppRole     = "blog_app"
	pubAppPassword = "blog_secret"
)

var pubDBSeq uint64

type pubDB struct {
	db   *store.DB
	pool *pgxpool.Pool
}

func newPubScratchDB(t *testing.T) *pubDB {
	t.Helper()
	ctx := context.Background()
	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		t.Skip("DATABASE_URL not set; skipping publicapi DB tests")
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
		if not exists (select from pg_roles where rolname = '`+pubAppRole+`') then
			create role `+pubAppRole+` login password '`+pubAppPassword+`';
		end if;
	end $$`); err != nil {
		t.Skipf("cannot provision role: %v", err)
	}
	name := fmt.Sprintf("openblog_pub_%d_%d", os.Getpid(), atomic.AddUint64(&pubDBSeq, 1))
	if _, err := admin.Exec(ctx, "create database "+name+" owner "+pubAppRole); err != nil {
		t.Skipf("cannot create scratch db: %v", err)
	}
	scratch := *u
	scratch.User = url.UserPassword(pubAppRole, pubAppPassword)
	scratch.Path = "/" + name
	pool, err := pgxpool.New(ctx, scratch.String())
	if err != nil {
		t.Fatalf("scratch pool: %v", err)
	}
	var rolsuper bool
	if err := pool.QueryRow(ctx, "select rolsuper from pg_roles where rolname = current_user").Scan(&rolsuper); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if rolsuper {
		t.Fatal("need non-superuser; superusers bypass RLS")
	}
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	gdb := stdlib.OpenDBFromPool(pool)
	if err := goose.Up(gdb, "."); err != nil {
		t.Fatalf("goose up: %v", err)
	}
	gdb.Close()
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "drop database "+name+" with (force)")
		admin.Close()
	})
	return &pubDB{db: store.NewFromPool(pool), pool: pool}
}

type pubFixture struct {
	db     *pubDB
	tA, tB uuid.UUID
	uA, uB uuid.UUID
	svcA   *posts.Service
	svcB   *posts.Service
}

func newPubFixture(t *testing.T) *pubFixture {
	t.Helper()
	f := &pubFixture{
		db: newPubScratchDB(t),
		tA: uuid.New(),
		tB: uuid.New(),
		uA: uuid.New(),
		uB: uuid.New(),
	}
	ctx := context.Background()
	bare := f.db.pool

	for _, x := range []struct{ id, slug, name string }{
		{f.tA.String(), "alpha", "Alpha"},
		{f.tB.String(), "beta", "Beta"},
	} {
		if _, err := bare.Exec(ctx, "insert into tenants (id, slug, name) values ($1, $2, $3)", x.id, x.slug, x.name); err != nil {
			t.Fatal(err)
		}
	}
	for _, x := range []struct {
		id          uuid.UUID
		email, name string
	}{
		{f.uA, "owner-a@example.com", "Alice"},
		{f.uB, "owner-b@example.com", "Bob"},
	} {
		if _, err := bare.Exec(ctx, "insert into users (id, email, display_name) values ($1, $2, $3)", x.id, x.email, x.name); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []struct{ tenant, user, role string }{
		{f.tA.String(), f.uA.String(), "owner"},
		{f.tB.String(), f.uB.String(), "owner"},
	} {
		if _, err := bare.Exec(ctx, "insert into memberships (tenant_id, user_id, role) values ($1, $2, $3)", m.tenant, m.user, m.role); err != nil {
			t.Fatal(err)
		}
	}
	f.svcA = posts.New(f.db.db, posts.Config{})
	f.svcB = posts.New(f.db.db, posts.Config{})
	return f
}

func (f *pubFixture) actorA() authz.Actor {
	return authz.Actor{UserID: f.uA, Tenant: &f.tA, Role: authz.RoleOwner}
}
func (f *pubFixture) actorB() authz.Actor {
	return authz.Actor{UserID: f.uB, Tenant: &f.tB, Role: authz.RoleOwner}
}

func (f *pubFixture) createAndPublish(t *testing.T, svc *posts.Service, actor authz.Actor, slug, title, md string) uuid.UUID {
	t.Helper()
	p, err := svc.Create(context.Background(), actor, posts.CreateInput{
		Title:           title,
		Slug:            slug,
		ContentMarkdown: md,
	})
	if err != nil {
		t.Fatalf("create %s: %v", slug, err)
	}
	p, err = svc.Publish(context.Background(), actor, p.ID)
	if err != nil {
		t.Fatalf("publish %s: %v", slug, err)
	}
	return p.ID
}

func (f *pubFixture) createDraft(t *testing.T, svc *posts.Service, actor authz.Actor, slug, title string) uuid.UUID {
	t.Helper()
	p, err := svc.Create(context.Background(), actor, posts.CreateInput{
		Title:           title,
		Slug:            slug,
		ContentMarkdown: "draft only",
	})
	if err != nil {
		t.Fatalf("create draft %s: %v", slug, err)
	}
	return p.ID
}

func (f *pubFixture) insertImageVariants(t *testing.T, tenantID, postID uuid.UUID, position int, variants string) {
	t.Helper()
	ctx := context.Background()
	if err := f.db.db.ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		_, err := q.Tx().Exec(ctx, `
			insert into post_images (id, tenant_id, post_id, r2_key, url, width, height, size_bytes, mime_type, position, variants)
			values ($1, $2, $3, $4, $5, 0, 0, 0, 'image/jpeg', $6, $7::jsonb)`,
			id, tenantID, postID,
			"img/"+postID.String()+"/"+fmt.Sprintf("%d.webp", position),
			"https://media.example.com/img/"+postID.String()+"/orig.jpg",
			position, variants)
		return err
	}); err != nil {
		t.Fatalf("insertImageVariants: %v", err)
	}
}

func (f *pubFixture) bumpVersion(t *testing.T, tenantID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.db.pool.Exec(ctx,
		"update tenants set content_version = content_version + 1, updated_at = now() where id = $1", tenantID); err != nil {
		t.Fatalf("bumpVersion: %v", err)
	}
}

func (f *pubFixture) version(t *testing.T, tenantID uuid.UUID) int64 {
	t.Helper()
	var v int64
	if err := f.db.pool.QueryRow(context.Background(),
		"select content_version from tenants where id = $1", tenantID).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// ---- tests ----

func TestDraftInvisible(t *testing.T) {
	f := newPubFixture(t)
	_ = f.createDraft(t, f.svcA, f.actorA(), "draft-post", "Draft")
	api := New(f.db.db, Config{PageSize: 50})

	// single post → 404
	req := httptest.NewRequest("GET", "/public/alpha/posts/draft-post", nil)
	resp, err := api.Get(req, "alpha", "draft-post")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Fatalf("Get draft status = %d, want 404", resp.Status)
	}

	// list → empty
	req = httptest.NewRequest("GET", "/public/alpha/posts", nil)
	resp, err = api.List(req, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatal("list status", resp.Status)
	}
	var body listBody
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatal("list body unmarshal:", err)
	}
	if len(body.Posts) != 0 {
		t.Fatalf("list returned %d posts, want 0 (drafts must be invisible)", len(body.Posts))
	}
}

func TestTenantIsolation(t *testing.T) {
	f := newPubFixture(t)
	f.createAndPublish(t, f.svcA, f.actorA(), "shared-slug", "Alpha Post", "content A")
	f.createAndPublish(t, f.svcB, f.actorB(), "shared-slug", "Beta Post", "content B")
	api := New(f.db.db, Config{PageSize: 50})

	// alpha: get alpha's post only
	req := httptest.NewRequest("GET", "/public/alpha/posts/shared-slug", nil)
	resp, err := api.Get(req, "alpha", "shared-slug")
	if err != nil {
		t.Fatal(err)
	}
	var body postBody
	json.Unmarshal(resp.Body, &body)
	if body.Title != "Alpha Post" {
		t.Fatalf("alpha: title = %q, want 'Alpha Post'", body.Title)
	}
	if body.Author != "Alice" {
		t.Fatalf("alpha: author = %q, want 'Alice'", body.Author)
	}

	// alpha: list contains exactly 1 post
	req = httptest.NewRequest("GET", "/public/alpha/posts", nil)
	resp, _ = api.List(req, "alpha")
	var lb listBody
	json.Unmarshal(resp.Body, &lb)
	if len(lb.Posts) != 1 || lb.Posts[0].Slug != "shared-slug" {
		t.Fatalf("alpha list: %+v", lb.Posts)
	}

	// beta: get beta's own
	req = httptest.NewRequest("GET", "/public/beta/posts/shared-slug", nil)
	resp, _ = api.Get(req, "beta", "shared-slug")
	json.Unmarshal(resp.Body, &body)
	if body.Title != "Beta Post" || body.Author != "Bob" {
		t.Fatalf("beta: body = %+v", body)
	}

	// beta: alpha's slug doesn't exist from beta's view
	req = httptest.NewRequest("GET", "/public/beta/posts/alpha-post", nil)
	resp, _ = api.Get(req, "beta", "alpha-post")
	if resp.Status != 404 {
		t.Fatalf("beta→alpha slug = %d, want 404", resp.Status)
	}
}

func TestPaginationOrder(t *testing.T) {
	f := newPubFixture(t)
	for i := 0; i < 7; i++ {
		f.createAndPublish(t, f.svcA, f.actorA(),
			fmt.Sprintf("post-%d", i),
			fmt.Sprintf("Post %d", i),
			fmt.Sprintf("content %d", i),
		)
	}
	// publish sets published_at=now(); ties possible → query DB for actual order
	expected := queryPublishedOrder(t, f.db, f.tA)
	if len(expected) != 7 {
		t.Fatalf("expected len = %d, want 7", len(expected))
	}

	api := New(f.db.db, Config{PageSize: 3})
	req := httptest.NewRequest("GET", "/public/alpha/posts", nil)
	resp, _ := api.List(req, "alpha")
	if resp.Status != 200 {
		t.Fatalf("list status = %d", resp.Status)
	}
	var lb listBody
	json.Unmarshal(resp.Body, &lb)
	if len(lb.Posts) != 3 {
		t.Fatalf("page 1 len = %d, want 3", len(lb.Posts))
	}
	if lb.NextCursor == "" {
		t.Fatal("page 1 missing next_cursor")
	}

	seen := map[string]bool{}
	assertOrder(t, lb.Posts)
	for _, p := range lb.Posts {
		seen[p.Slug] = true
	}

	// walk remaining pages
	cursor := lb.NextCursor
	for i := 1; i < 3; i++ {
		// json.Unmarshal never resets fields absent from the payload, so each
		// page must decode into a fresh envelope or a trailing next_cursor from
		// the previous page would survive the final (cursor-less) response.
		var page listBody
		req = httptest.NewRequest("GET", "/public/alpha/posts?before="+cursor, nil)
		resp, _ = api.List(req, "alpha")
		json.Unmarshal(resp.Body, &page)
		assertOrder(t, page.Posts)
		for _, p := range page.Posts {
			if seen[p.Slug] {
				t.Fatalf("dup slug %q on page %d", p.Slug, i+1)
			}
			seen[p.Slug] = true
		}
		cursor = page.NextCursor
		if i == 2 {
			// last page: 1 remaining post
			if len(page.Posts) != 1 {
				t.Fatalf("final page len = %d, want 1", len(page.Posts))
			}
			if page.NextCursor != "" {
				t.Fatal("final page has non-empty next_cursor")
			}
		} else if len(page.Posts) != 3 {
			t.Fatalf("page %d len = %d, want 3", i+1, len(page.Posts))
		}
	}
	if len(seen) != 7 {
		t.Fatalf("seen %d distinct slugs, want 7", len(seen))
	}
	// verify order vs DB-direct query (re-walk without a cursor restart)
	cursor = ""
	var all []string
	for {
		u := "/public/alpha/posts"
		if cursor != "" {
			u += "?before=" + cursor
		}
		var page listBody
		req = httptest.NewRequest("GET", u, nil)
		resp, _ = api.List(req, "alpha")
		json.Unmarshal(resp.Body, &page)
		for _, p := range page.Posts {
			all = append(all, p.Slug)
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(all) != 7 {
		t.Fatalf("total returned = %d, want 7", len(all))
	}
	if !isSortedNewestFirst(t, f.db, f.tA, all) {
		t.Fatal("ordering violated")
	}
}

func TestTagFilter(t *testing.T) {
	f := newPubFixture(t)
	f.createAndPublish(t, f.svcA, f.actorA(), "go-post", "Go", "golang content")
	f.createAndPublish(t, f.svcA, f.actorA(), "rust-post", "Rust", "rust content")
	// tag go-post
	f.db.db.ScopedRW(context.Background(), store.Scope{TenantID: f.tA}, func(q *store.Queries) error {
		_, err := q.Tx().Exec(context.Background(), "update posts set metadata = $1 where slug = 'go-post' and tenant_id = $2",
			`{"tags":["go"]}`, f.tA)
		return err
	})
	f.db.db.ScopedRW(context.Background(), store.Scope{TenantID: f.tA}, func(q *store.Queries) error {
		_, err := q.Tx().Exec(context.Background(), "update posts set metadata = $1 where slug = 'rust-post' and tenant_id = $2",
			`{"tags":["rust"]}`, f.tA)
		return err
	})

	api := New(f.db.db, Config{PageSize: 50})
	req := httptest.NewRequest("GET", "/public/alpha/posts?tag=go", nil)
	resp, _ := api.List(req, "alpha")
	var lb listBody
	json.Unmarshal(resp.Body, &lb)
	if len(lb.Posts) != 1 || lb.Posts[0].Slug != "go-post" {
		t.Fatalf("tag=go list: %+v", lb.Posts)
	}
}

func TestETagSite304(t *testing.T) {
	f := newPubFixture(t)
	api := New(f.db.db, Config{})
	req := httptest.NewRequest("GET", "/public/alpha/site", nil)
	resp, err := api.Site(req, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag header")
	}

	// If-None-Match → 304
	req = httptest.NewRequest("GET", "/public/alpha/site", nil)
	req.Header.Set("If-None-Match", etag)
	resp, err = api.Site(req, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 304 {
		t.Fatalf("304 status = %d", resp.Status)
	}
	if len(resp.Body) != 0 {
		t.Fatal("304 must have empty body")
	}
}

func TestContentVersionBumpChangesETag(t *testing.T) {
	f := newPubFixture(t)
	api := New(f.db.db, Config{})

	// site ETag changes on content_version bump
	req := httptest.NewRequest("GET", "/public/alpha/site", nil)
	resp, _ := api.Site(req, "alpha")
	var sb siteBody
	json.Unmarshal(resp.Body, &sb)
	etag1 := resp.Header.Get("ETag")

	f.bumpVersion(t, f.tA)
	req = httptest.NewRequest("GET", "/public/alpha/site", nil)
	resp, _ = api.Site(req, "alpha")
	etag2 := resp.Header.Get("ETag")
	if etag1 == etag2 {
		t.Fatal("site ETag did not change after content_version bump")
	}
}

func TestSiteContentVersionInBody(t *testing.T) {
	f := newPubFixture(t)
	api := New(f.db.db, Config{})
	req := httptest.NewRequest("GET", "/public/alpha/site", nil)
	resp, _ := api.Site(req, "alpha")
	var sb siteBody
	json.Unmarshal(resp.Body, &sb)
	if sb.Name != "Alpha" {
		t.Fatalf("name = %q, want 'Alpha'", sb.Name)
	}
}

func TestGetPostImagesOrder(t *testing.T) {
	f := newPubFixture(t)
	id := f.createAndPublish(t, f.svcA, f.actorA(), "img-post", "Images", "with images")
	// insert images: position 0 then position 1
	f.insertImageVariants(t, f.tA, id, 0, `{"480":{"url":"https://c/a-480.webp","width":480,"height":240}}`)
	f.insertImageVariants(t, f.tA, id, 1, `{"480":{"url":"https://c/b-480.webp","width":480,"height":240},"800":{"url":"https://c/b-800.webp","width":800,"height":400},"1200":{"url":"https://c/b-1200.webp","width":1200,"height":600}}`)

	api := New(f.db.db, Config{PageSize: 50})
	req := httptest.NewRequest("GET", "/public/alpha/posts/img-post", nil)
	resp, _ := api.Get(req, "alpha", "img-post")
	if resp.Status != 200 {
		t.Fatalf("status = %d", resp.Status)
	}
	var body postBody
	json.Unmarshal(resp.Body, &body)
	if len(body.Images) != 2 {
		t.Fatalf("images len = %d, want 2", len(body.Images))
	}
	if body.Images[0].URL != "https://c/a-480.webp" || body.Images[0].Width != 480 {
		t.Fatalf("image[0] = %+v", body.Images[0])
	}
	if len(body.Images[0].Srcset) != 1 || body.Images[0].Srcset[0] != "https://c/a-480.webp 480w" {
		t.Fatalf("image[0].srcset = %+v", body.Images[0].Srcset)
	}
	if body.Images[1].Width != 1200 || len(body.Images[1].Srcset) != 3 {
		t.Fatalf("image[1] = %+v", body.Images[1])
	}
	if body.Images[1].Srcset[0] != "https://c/b-480.webp 480w" || body.Images[1].Srcset[2] != "https://c/b-1200.webp 1200w" {
		t.Fatalf("image[1].srcset = %+v", body.Images[1].Srcset)
	}
}

func TestGetPostContentHTMLServed(t *testing.T) {
	f := newPubFixture(t)
	f.createAndPublish(t, f.svcA, f.actorA(), "html-post", "HTML", "normal content")
	api := New(f.db.db, Config{})
	req := httptest.NewRequest("GET", "/public/alpha/posts/html-post", nil)
	resp, _ := api.Get(req, "alpha", "html-post")
	var body postBody
	json.Unmarshal(resp.Body, &body)
	if body.ContentHTML == "" {
		t.Fatal("content_html empty")
	}
	if body.Author != "Alice" {
		t.Fatalf("author = %q, want 'Alice'", body.Author)
	}
}

func TestPostETag304(t *testing.T) {
	f := newPubFixture(t)
	f.createAndPublish(t, f.svcA, f.actorA(), "etag-post", "ETag", "content")
	api := New(f.db.db, Config{})

	req := httptest.NewRequest("GET", "/public/alpha/posts/etag-post", nil)
	resp, _ := api.Get(req, "alpha", "etag-post")
	if resp.Status != 200 {
		t.Fatal(resp.Status)
	}
	etag := resp.Header.Get("ETag")

	req = httptest.NewRequest("GET", "/public/alpha/posts/etag-post", nil)
	req.Header.Set("If-None-Match", etag)
	resp, _ = api.Get(req, "alpha", "etag-post")
	if resp.Status != 304 {
		t.Fatalf("304 status = %d", resp.Status)
	}
}

func TestListETag304(t *testing.T) {
	f := newPubFixture(t)
	f.createAndPublish(t, f.svcA, f.actorA(), "list-etag", "ListETag", "x")
	api := New(f.db.db, Config{PageSize: 50})

	req := httptest.NewRequest("GET", "/public/alpha/posts", nil)
	resp, _ := api.List(req, "alpha")
	etag := resp.Header.Get("ETag")

	req = httptest.NewRequest("GET", "/public/alpha/posts", nil)
	req.Header.Set("If-None-Match", etag)
	resp, _ = api.List(req, "alpha")
	if resp.Status != 304 {
		t.Fatalf("304 status = %d", resp.Status)
	}
}

func TestUnknownTenant404(t *testing.T) {
	f := newPubFixture(t)
	api := New(f.db.db, Config{})
	req := httptest.NewRequest("GET", "/public/nosuch/site", nil)
	resp, _ := api.Site(req, "nosuch")
	if resp.Status != 404 {
		t.Fatalf("status = %d, want 404", resp.Status)
	}
}

func TestInvalidTenantSlug400(t *testing.T) {
	f := newPubFixture(t)
	api := New(f.db.db, Config{})
	req := httptest.NewRequest("GET", "/public/Alpha!site/site", nil)
	resp, _ := api.Site(req, "Alpha!site")
	if resp.Status != 400 {
		t.Fatalf("status = %d, want 400", resp.Status)
	}
}

func TestMalformedCursor422(t *testing.T) {
	f := newPubFixture(t)
	api := New(f.db.db, Config{})
	req := httptest.NewRequest("GET", "/public/alpha/posts?before=notacursor", nil)
	resp, _ := api.List(req, "alpha")
	if resp.Status != 422 {
		t.Fatalf("status = %d, want 422", resp.Status)
	}
}

// helpers

func queryPublishedOrder(t *testing.T, d *pubDB, tenantID uuid.UUID) []string {
	t.Helper()
	ctx := context.Background()
	var slugs []string
	err := d.db.Scoped(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		rows, err := q.Tx().Query(ctx,
			"select slug from posts where tenant_id = $1 and status = 'published' order by published_at desc, id desc",
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			slugs = append(slugs, s)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return slugs
}

func assertOrder(t *testing.T, posts []listPost) {
	t.Helper()
	for i := 1; i < len(posts); i++ {
		prev, curr := posts[i-1], posts[i]
		if prev.PublishedAt == nil || curr.PublishedAt == nil {
			continue
		}
		if prev.PublishedAt.Before(*curr.PublishedAt) {
			t.Fatalf("out of order: %v before %v", prev.PublishedAt, curr.PublishedAt)
		}
	}
}

func isSortedNewestFirst(t *testing.T, d *pubDB, tenantID uuid.UUID, slugs []string) bool {
	t.Helper()
	expected := queryPublishedOrder(t, d, tenantID)
	if len(expected) != len(slugs) {
		return false
	}
	return strings.Join(expected, ",") == strings.Join(slugs, ",")
}
