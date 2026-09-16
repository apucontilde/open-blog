package tenancy

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"openblog/internal/store"
	"openblog/migrations"
)

const (
	appRole     = "blog_app"
	appPassword = "blog_secret"
)

var tenDBSeq uint64

type scratchDB struct {
	db   *store.DB
	pool *pgxpool.Pool
}

func newScratchDB(t *testing.T) *scratchDB {
	t.Helper()
	ctx := context.Background()

	adminURL := os.Getenv("DATABASE_URL")
	if adminURL == "" {
		t.Skip("DATABASE_URL not set; skipping tenancy DB-backed tests")
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

	name := fmt.Sprintf("openblog_ten_%d_%d", os.Getpid(), atomic.AddUint64(&tenDBSeq, 1))
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
		t.Fatal("tenancy DB tests require a non-superuser connection; superusers bypass RLS")
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
	return &scratchDB{db: store.NewFromPool(pool), pool: pool}
}

func TestResolveSlugValid(t *testing.T) {
	sd := newScratchDB(t)
	ctx := context.Background()

	alphaID := uuid.New()
	if _, err := sd.pool.Exec(ctx,
		"insert into tenants (id, slug, name) values ($1, $2, $3)", alphaID, "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}

	resolver := New(sd.db, 0) // 0 → DefaultTTL
	got, ver, err := resolver.ResolveSlug(ctx, "alpha")
	if err != nil {
		t.Fatalf("ResolveSlug: %v", err)
	}
	if got != alphaID {
		t.Fatalf("id = %s, want %s", got, alphaID)
	}
	if ver != 0 {
		t.Fatalf("version = %d, want 0", ver)
	}
}

func TestResolveSlugCachesHit(t *testing.T) {
	sd := newScratchDB(t)
	ctx := context.Background()

	alphaID := uuid.New()
	if _, err := sd.pool.Exec(ctx,
		"insert into tenants (id, slug, name) values ($1, $2, $3)", alphaID, "alpha", "Alpha"); err != nil {
		t.Fatal(err)
	}

	resolver := New(sd.db, 0)
	// first hit: cache miss → DB
	got, _, err := resolver.ResolveSlug(ctx, "alpha")
	if err != nil || got != alphaID {
		t.Fatalf("first resolve: id=%s err=%v", got, err)
	}
	// second hit: cache hit, no DB error
	got2, _, err := resolver.ResolveSlug(ctx, "alpha")
	if err != nil || got2 != alphaID {
		t.Fatalf("second resolve: id=%s err=%v", got2, err)
	}
}

func TestResolveSlugUnknown(t *testing.T) {
	sd := newScratchDB(t)
	resolver := New(sd.db, 0)
	_, _, err := resolver.ResolveSlug(context.Background(), "nosuch")
	if err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestResolveSlugInvalid(t *testing.T) {
	sd := newScratchDB(t)
	resolver := New(sd.db, 0)
	_, _, err := resolver.ResolveSlug(context.Background(), "BadSlug!")
	if err != ErrInvalidSlug {
		t.Fatalf("want ErrInvalidSlug, got %v", err)
	}
}

func TestContentVersionInResolverResult(t *testing.T) {
	sd := newScratchDB(t)
	ctx := context.Background()

	id := uuid.New()
	if _, err := sd.pool.Exec(ctx,
		"insert into tenants (id, slug, name, content_version) values ($1, $2, $3, $4)",
		id, "alpha", "Alpha", int64(42)); err != nil {
		t.Fatal(err)
	}
	resolver := New(sd.db, 0)
	_, ver, err := resolver.ResolveSlug(ctx, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if ver != 42 {
		t.Fatalf("content_version = %d, want 42", ver)
	}
}
