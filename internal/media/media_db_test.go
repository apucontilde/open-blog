package media

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"openblog/internal/store"
	"openblog/migrations"
)

// DB tests skip without DATABASE_URL; a scratch DB owned by non-superuser
// blog_app makes RLS bite.

const (
	mediaAppRole     = "blog_app"
	mediaAppPassword = "blog_secret"
)

var mediaDBSeq uint64

type mediaDB struct {
	db   *store.DB
	pool *pgxpool.Pool
}

func newMediaScratchDB(t *testing.T) *mediaDB {
	t.Helper()
	ctx := context.Background()

	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed media tests")
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
		if not exists (select from pg_roles where rolname = '`+mediaAppRole+`') then
			create role `+mediaAppRole+` login password '`+mediaAppPassword+`';
		end if;
	end $$`); err != nil {
		t.Skipf("cannot provision role %s (needs a privileged DATABASE_URL): %v", mediaAppRole, err)
	}

	name := fmt.Sprintf("openblog_media_%d_%d", os.Getpid(), atomic.AddUint64(&mediaDBSeq, 1))
	if _, err := admin.Exec(ctx, "create database "+name+" owner "+mediaAppRole); err != nil {
		t.Skipf("cannot create scratch database: %v", err)
	}

	scratch := *u
	scratch.User = url.UserPassword(mediaAppRole, mediaAppPassword)
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
		t.Fatal("media DB tests require a non-superuser connection; superusers bypass RLS")
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
	return &mediaDB{db: store.NewFromPool(pool), pool: pool}
}

type mediaFixture struct {
	md     *mediaDB
	tA, tB uuid.UUID
	u, v   uuid.UUID
	pa, pb uuid.UUID // posts in tA (u) and tB (u)
}

func newMediaFixture(t *testing.T) *mediaFixture {
	t.Helper()
	f := &mediaFixture{md: newMediaScratchDB(t), tA: uuid.New(), tB: uuid.New(),
		u: uuid.New(), v: uuid.New(), pa: uuid.New(), pb: uuid.New()}

	ctx := context.Background()
	bare := f.md.pool
	// tenants + users + memberships are unscoped: direct pool writes.
	for _, x := range []struct {
		id, slug, name string
	}{{f.tA.String(), "tenant-a", "Tenant A"}, {f.tB.String(), "tenant-b", "Tenant B"}} {
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
	} {
		if _, err := bare.Exec(ctx, "insert into users (id, email, display_name) values ($1, $2, $3)",
			x.id, x.email, x.name); err != nil {
			t.Fatal(err)
		}
	}
	// u owns tenant-a (owner) and is an editor in tenant-b; v is an author in b.
	for _, m := range []struct{ tenant, user, role string }{
		{f.tA.String(), f.u.String(), "owner"},
		{f.tB.String(), f.u.String(), "editor"},
		{f.tB.String(), f.v.String(), "author"},
	} {
		if _, err := bare.Exec(ctx, "insert into memberships (tenant_id, user_id, role) values ($1, $2, $3)",
			m.tenant, m.user, m.role); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.md.db.ScopedRW(ctx, store.Scope{TenantID: f.tA}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{ID: f.pa, TenantID: f.tA, AuthorID: f.u, Slug: "pa", Title: "Post A"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.md.db.ScopedRW(ctx, store.Scope{TenantID: f.tB}, func(q *store.Queries) error {
		_, err := q.CreatePost(ctx, store.Post{ID: f.pb, TenantID: f.tB, AuthorID: f.u, Slug: "pb", Title: "Post B"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *mediaFixture) media(t *testing.T) *Media {
	t.Helper()
	return New(Config{Endpoint: "https://acct.r2.cloudflarestorage.com", Bucket: "openblog",
		AccessKeyID: "AKID", SecretAccessKey: "SECRET", CDNBase: "https://media.example.com"}, f.md.db, nil)
}

// countScoped runs a SELECT count through a scoped read-only tx so RLS sees
// post_images.
func (f *mediaFixture) countScoped(t *testing.T, tenant uuid.UUID, query string, args ...any) int64 {
	t.Helper()
	ctx := context.Background()
	var n int64
	if err := f.md.db.Scoped(ctx, store.Scope{TenantID: tenant}, func(q *store.Queries) error {
		return q.Tx().QueryRow(ctx, query, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// confirm runs Confirm inside a scoped RW tx for tenant.
func (f *mediaFixture) confirm(t *testing.T, m *Media, tenant, post uuid.UUID, key string, size int64, mime string) (bool, error) {
	t.Helper()
	ctx := context.Background()
	var ins bool
	err := f.md.db.ScopedRW(ctx, store.Scope{TenantID: tenant}, func(q *store.Queries) error {
		var e error
		ins, e = m.Confirm(ctx, q, tenant, post, key, size, mime)
		return e
	})
	return ins, err
}

// TestConfirmEnqueuesVariantsJobInTx: confirm inserts the row and the variants
// job in the SAME tx (a rollback drops both).
func TestConfirmEnqueuesVariantsJobInTx(t *testing.T) {
	f := newMediaFixture(t)
	m := f.media(t)
	ctx := context.Background()
	key := "tenant-a/posts/" + f.pa.String() + "/img.jpg"

	inserted, err := f.confirm(t, m, f.tA, f.pa, key, 4096, "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first confirm inserted=false")
	}
	if n := f.countScoped(t, f.tA, "select count(*) from post_images where r2_key = $1", key); n != 1 {
		t.Fatalf("post_images rows = %d, want 1", n)
	}

	// jobs is unscoped: read directly.
	var jobID uuid.UUID
	var payload []byte
	if err := f.md.pool.QueryRow(ctx, "select id, payload from jobs where kind = 'variants' and dedupe_key = $1", key).
		Scan(&jobID, &payload); err != nil {
		t.Fatalf("variants job not enqueued in the confirm tx: %v", err)
	}
	if jobID == uuid.Nil {
		t.Fatal("job id is nil")
	}
	var jp struct {
		TenantID uuid.UUID `json:"tenant_id"`
		Data     struct {
			ImageID uuid.UUID `json:"image_id"`
			R2Key   string    `json:"r2_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &jp); err != nil {
		t.Fatal(err)
	}
	if jp.TenantID != f.tA || jp.Data.ImageID == uuid.Nil || jp.Data.R2Key != key {
		t.Fatalf("variants payload mismatch: %+v", jp)
	}

	// A rollback in the same tx drops both the image row and its job.
	rbKey := "tenant-a/posts/" + f.pa.String() + "/rb.jpg"
	err = f.md.db.ScopedRW(ctx, store.Scope{TenantID: f.tA}, func(q *store.Queries) error {
		if _, e := m.Confirm(ctx, q, f.tA, f.pa, rbKey, 10, "image/png"); e != nil {
			return e
		}
		return errors.New("rollback marker")
	})
	if err == nil {
		t.Fatal("expected the forced rollback error")
	}
	if n := f.countScoped(t, f.tA, "select count(*) from post_images where r2_key = $1", rbKey); n != 0 {
		t.Fatalf("rollback leaked rows: %d", n)
	}
	var rbJobs int64
	if err := f.md.pool.QueryRow(ctx, "select count(*) from jobs where dedupe_key = $1", rbKey).Scan(&rbJobs); err != nil {
		t.Fatal(err)
	}
	if rbJobs != 0 {
		t.Fatalf("rollback leaked job: %d; enqueue-in-tx must roll back together", rbJobs)
	}
}

// TestConfirmDoubleConfirmIdempotent: unique(tenant_id, r2_key) makes a second
// confirm a 0-row ON CONFLICT: no new row, no second job.
func TestConfirmDoubleConfirmIdempotent(t *testing.T) {
	f := newMediaFixture(t)
	m := f.media(t)
	key := "tenant-a/posts/" + f.pa.String() + "/img.jpg"

	first, err := f.confirm(t, m, f.tA, f.pa, key, 4096, "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.confirm(t, m, f.tA, f.pa, key, 4096, "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	if first != true || second != false {
		t.Fatalf("first=%v second=%v, want first=true second=false (the 204 case)", first, second)
	}
	if n := f.countScoped(t, f.tA, "select count(*) from post_images where r2_key = $1", key); n != 1 {
		t.Fatalf("rows after double-confirm = %d, want 1", n)
	}
	var jobs int64
	ctx := context.Background()
	if err := f.md.pool.QueryRow(ctx, "select count(*) from jobs where kind = 'variants' and dedupe_key = $1", key).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("jobs after double-confirm = %d, want 1", jobs)
	}
}

// TestConfirmCrossTenantFKRejected: attaching to another tenant's post is
// rejected by the composite FK (tenant_id, post_id) → posts(tenant_id, id).
func TestConfirmCrossTenantFKRejected(t *testing.T) {
	f := newMediaFixture(t)
	m := f.media(t)
	// key shaped like tenant-b's layout, but confirmed inside tenant a's scope
	// against tenant b's post row: the composite FK must reject it.
	key := "tenant-b/posts/" + f.pb.String() + "/img.jpg"

	_, err := f.confirm(t, m, f.tA, f.pb, key, 4096, "image/jpeg")
	if err == nil {
		t.Fatal("cross-tenant confirm succeeded; composite FK must reject")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("expected a foreign_key_violation (23503), got %v", err)
	}
	if n := f.countScoped(t, f.tA, "select count(*) from post_images where r2_key = $1", key); n != 0 {
		t.Fatalf("cross-tenant image row leaked: %d", n)
	}
}

// TestWorkerWritesCanonicalVariants: the worker persists the canonical
// {"480":{url,width,height},...} shape and backfills decoded width/height.
func TestWorkerWritesCanonicalVariants(t *testing.T) {
	f := newMediaFixture(t)
	m := f.media(t)
	ctx := context.Background()
	key := "tenant-a/posts/" + f.pa.String() + "/img.png"

	if _, err := f.confirm(t, m, f.tA, f.pa, key, 64, "image/png"); err != nil {
		t.Fatal(err)
	}

	var img store.PostImage
	if err := f.md.db.ScopedRW(ctx, store.Scope{TenantID: f.tA}, func(q *store.Queries) error {
		im, e := q.GetPostImageByR2Key(ctx, key)
		img = im
		return e
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	rgba := image.NewRGBA(image.Rect(0, 0, 8, 4))
	rgba.Set(0, 0, color.RGBA{R: 255, A: 255})
	if err := png.Encode(&buf, rgba); err != nil {
		t.Fatal(err)
	}
	pngBytes := buf.Bytes()

	processed, err := NewNoopProcessor().Process(ctx, ".png", pngBytes, key)
	if err != nil {
		t.Fatal(err)
	}
	if processed.OriginalWidth != 8 || processed.OriginalHeight != 4 {
		t.Fatalf("processor dims = %dx%d, want 8x4", processed.OriginalWidth, processed.OriginalHeight)
	}

	if err := m.writeVariants(ctx, f.tA, img.ID, processed, key); err != nil {
		t.Fatal(err)
	}

	// Backfilled dims + canonical shape, read back under the same RLS scope.
	var width, height int
	var variantsRaw []byte
	if err := f.md.db.Scoped(ctx, store.Scope{TenantID: f.tA}, func(q *store.Queries) error {
		return q.Tx().QueryRow(ctx,
			"select width, height, variants from post_images where id = $1", img.ID).
			Scan(&width, &height, &variantsRaw)
	}); err != nil {
		t.Fatal(err)
	}
	if width == 0 || height == 0 {
		t.Fatalf("worker did not backfill width/height: %dx%d", width, height)
	}

	variants := map[string]struct {
		URL        string `json:"url"`
		Width      int    `json:"width"`
		Height     int    `json:"height"`
		Processing string `json:"processing"`
	}{}
	if err := json.Unmarshal(variantsRaw, &variants); err != nil {
		t.Fatal(err)
	}
	if len(variants) != 3 {
		t.Fatalf("variants entries = %d, want 3", len(variants))
	}
	for _, w := range []string{"480", "800", "1200"} {
		e, ok := variants[w]
		if !ok {
			t.Fatalf("missing canonical variant %q", w)
		}
		if e.URL == "" {
			t.Fatalf("variant %q has no url", w)
		}
		if !strings.Contains(e.URL, key) {
			t.Fatalf("variant %q url = %q, want it to point at the original key", w, e.URL)
		}
		if e.Processing != "pending" {
			t.Fatalf("variant %q processing = %q, want pending (no-vips branch)", w, e.Processing)
		}
	}
}
