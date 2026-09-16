// Package store owns the pool, migrations, and the scoped-transaction wrapper.
package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotMember reports that the actor has no membership in the tenant.
var ErrNotMember = errors.New("store: actor is not a member of this tenant")

// Scope carries exactly one tenancy intent per transaction: a tenant UUID, or
// platform-wide. A zero TenantID is unscoped and fails closed on tenant tables.
type Scope struct {
	TenantID uuid.UUID // zero => unscoped (fails closed for tenant tables)
	Platform bool      // cross-tenant read; only Go-set after role verification
}

// DB owns the pgx connection pool shared by every query.
type DB struct {
	pool *pgxpool.Pool
}

// New builds a DB over a fresh pool for databaseURL.
func New(ctx context.Context, databaseURL string) (*DB, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	return NewFromPool(pool), nil
}

// NewFromPool wraps an existing pool; the caller retains pool ownership.
func NewFromPool(pool *pgxpool.Pool) *DB {
	return &DB{pool: pool}
}

// Pool returns the underlying connection pool. Used by co-owned modules
// (docimport) that need a *pgxpool.Pool for their own store construction.
func (d *DB) Pool() *pgxpool.Pool {
	return d.pool
}

// Close releases the pool.
func (d *DB) Close() {
	d.pool.Close()
}

// Scoped runs fn in a short READ-ONLY transaction that carries exactly this
// scope. Every tenant-aware read must go through here. Writes under a
// read-only scope are rejected by the transaction itself (SQLSTATE 25006).
func (d *DB) Scoped(ctx context.Context, s Scope, fn func(q *Queries) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// zero TenantID => SQL NULL (fail closed), NEVER the empty string: '0000…'
	// would match a tenant row whose id is the nil uuid and degenerate
	// fail-closed into a real scope.
	var tenantID any // nil
	if s.TenantID != uuid.Nil {
		tenantID = s.TenantID
	}
	// Single multi-statement round trip: open read-only + set the scope var.
	if _, err := tx.Exec(ctx, "begin read only; select set_config('app.tenant_id', $1, true)",
		pgx.QueryExecModeSimpleProtocol, tenantID); err != nil {
		return err
	}
	if s.Platform {
		if _, err := tx.Exec(ctx, "select set_config('app.platform', 'on', true)"); err != nil {
			return err
		}
	}
	if err := fn(&Queries{tx: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ScopedRW is the mutating counterpart to Scoped: the same scope semantics on
// a read-write transaction, so tenant-scoped DML reaches RLS and FK
// enforcement instead of the transaction read-only guard.
func (d *DB) ScopedRW(ctx context.Context, s Scope, fn func(q *Queries) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var tenantID any // nil
	if s.TenantID != uuid.Nil {
		tenantID = s.TenantID
	}
	if _, err := tx.Exec(ctx, "select set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return err
	}
	if s.Platform {
		if _, err := tx.Exec(ctx, "select set_config('app.platform', 'on', true)"); err != nil {
			return err
		}
	}
	if err := fn(&Queries{tx: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Membership joins an actor to a tenant. Roles are text (CHECK-constrained in
// the schema); ordering/authz semantics live in a Go-side enum (plan 004).
type Membership struct {
	TenantID uuid.UUID
	Role     string
}

// Memberships lists every membership of actorID across all tenants, unscoped
// by design: the tenant switcher (ST-20) needs the full set before any tenant
// scope exists. Privacy relies on this query always binding the actor's own
// user_id server-side; no membership query accepts a foreign user id.
func (d *DB) Memberships(ctx context.Context, actorID uuid.UUID) ([]Membership, error) {
	rows, err := d.pool.Query(ctx,
		"select tenant_id, role from memberships where user_id = $1", actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ms := []Membership{}
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.TenantID, &m.Role); err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	return ms, rows.Err()
}

// IsSuperAdmin reports whether userID holds the platform-wide super_admin flag.
func (d *DB) IsSuperAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	var ok bool
	err := d.pool.QueryRow(ctx,
		"select super_admin from users where id = $1", userID).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotMember
	}
	return ok, err
}

// MembershipRole resolves the actor's role inside tenantID, or ErrNotMember.
func (d *DB) MembershipRole(ctx context.Context, actorID, tenantID uuid.UUID) (string, error) {
	var role string
	err := d.pool.QueryRow(ctx,
		"select role from memberships where user_id = $1 and tenant_id = $2",
		actorID, tenantID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotMember
	}
	return role, err
}
