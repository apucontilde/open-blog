// Package tenancy resolves tenant slugs for the public read path via one shared TTL cache.
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
	// DefaultTTL bounds how long a tenant rename/purge may lag a replica.
	DefaultTTL = 30 * time.Second
)

var (
	// ErrInvalidSlug: slug fails the tenants.slug CHECK shape (→ 400).
	ErrInvalidSlug = errors.New("tenancy: invalid tenant slug")
	// ErrNotFound: no tenants row for a well-formed slug (→ 404).
	ErrNotFound = errors.New("tenancy: tenant not found")
)

// slugShape mirrors the tenants.slug CHECK; malformed segments never reach the DB.
var slugShape = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type cacheEntry struct {
	tenantID       uuid.UUID
	contentVersion int64
	expiresAt      time.Time
}

type Resolver struct {
	db        *store.DB
	ttl       time.Duration
	mu        sync.Mutex
	cache     map[string]cacheEntry
	lastSweep time.Time
}

func New(db *store.DB, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Resolver{db: db, ttl: ttl, cache: make(map[string]cacheEntry)}
}

func ValidSlug(slug string) bool { return slugShape.MatchString(slug) }

// ResolveSlug returns tenant id and current content_version; only positive resolutions are cached.
func (r *Resolver) ResolveSlug(ctx context.Context, slug string) (uuid.UUID, int64, error) {
	if !ValidSlug(slug) {
		return uuid.Nil, 0, ErrInvalidSlug
	}
	r.mu.Lock()
	e, ok := r.cache[slug]
	now := time.Now()
	// Light sweep on access bounds cache growth for a churning slug set.
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

	// tenants is unscoped (RLS covers posts, post_images, imports only).
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
