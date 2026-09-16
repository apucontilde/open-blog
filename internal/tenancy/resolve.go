// Package tenancy owns slug→tenant resolution for the public read path: the
// single, TTL-cached authority that turns a {tenant} URL segment into a
// tenant id plus the current content_version. Public reads carry no auth and
// no session — the tenants table is the only identity on this path (009 Q1).
package tenancy

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"openblog/internal/store"
)

const (
	// DefaultTTL bounds how long a tenant rename/purge may lag a replica:
	// new-tenant visibility lags ≤ one TTL, which the CDN
	// stale-while-revalidate window absorbs (009 sweep Q1).
	DefaultTTL = 30 * time.Second
)

var (
	// ErrInvalidSlug reports a slug that fails the tenants.slug CHECK shape;
	// the public handler maps it to 400.
	ErrInvalidSlug = errors.New("tenancy: invalid tenant slug")
	// ErrNotFound reports a well-formed slug with no tenants row; 404.
	ErrNotFound = errors.New("tenancy: tenant not found")
)

// slugShape mirrors the tenants.slug CHECK constraint exactly; a malformed
// {tenant} segment is rejected here and never reaches the DB.
var slugShape = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// cacheEntry is one resolved slug; entries expire after the resolver TTL.
type cacheEntry struct {
	tenantID       uuid.UUID
	contentVersion int64
	expiresAt      time.Time
}

// Resolver resolves tenant slugs with an in-process TTL cache. The cache is
// per-replica (no shared state), so every replica converges to a rename/purge
// within one DefaultTTL.
type Resolver struct {
	db        *store.DB
	ttl       time.Duration
	mu        sync.Mutex
	cache     map[string]cacheEntry
	lastSweep time.Time
}

// New builds a Resolver over db; a non-positive ttl selects DefaultTTL.
func New(db *store.DB, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Resolver{db: db, ttl: ttl, cache: make(map[string]cacheEntry)}
}

// ValidSlug reports whether slug matches the tenants.slug shape.
func ValidSlug(slug string) bool { return slugShape.MatchString(slug) }

// ResolveSlug returns the tenant id and current content_version for slug.
// The id is the scope anchor for every public read; content_version is the
// ETag base of the tenant's public surface (009 sweep finding 6). Positive
// resolutions are cached for the resolver TTL; failures never are.
func (r *Resolver) ResolveSlug(ctx context.Context, slug string) (uuid.UUID, int64, error) {
	if !ValidSlug(slug) {
		return uuid.Nil, 0, ErrInvalidSlug
	}
	r.mu.Lock()
	e, ok := r.cache[slug]
	now := time.Now()
	// Light sweep on access: expired entries are dropped at most once per TTL,
	// bounding cache growth for a churning set of slugs.
	if r.lastSweep.Add(r.ttl).Before(now) {
		for k, v := range r.cache {
			if v.expiresAt.Before(now) {
				delete(r.cache, k)
			}
		}
		r.lastSweep = now
	}
	r.mu.Unlock()
	if ok && now.Before(e.expiresAt) {
		return e.tenantID, e.contentVersion, nil
	}

	// tenants is unscoped (RLS covers posts, post_images, imports only); the
	// read-only scope still guards any accidental tenant-table access.
	var id uuid.UUID
	var version int64
	err := r.db.Scoped(ctx, store.Scope{}, func(q *store.Queries) error {
		return q.Tx().QueryRow(ctx,
			"select id, content_version from tenants where slug = $1", slug).
			Scan(&id, &version)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, 0, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, 0, err
	}

	r.mu.Lock()
	r.cache[slug] = cacheEntry{tenantID: id, contentVersion: version, expiresAt: time.Now().Add(r.ttl)}
	r.mu.Unlock()
	return id, version, nil
}
