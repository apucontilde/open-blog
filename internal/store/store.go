package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotMember = errors.New("store: actor is not a member of this tenant")

// Scope carries one tenancy intent; a zero TenantID is unscoped and fails closed on tenant tables.
type Scope struct {
	TenantID uuid.UUID
	Platform bool // cross-tenant read; only Go-set after upstream role verification
}

type DB struct {
	pool *pgxpool.Pool
}

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

// Pool is exposed for co-owned modules that construct their own store.
func (d *DB) Pool() *pgxpool.Pool {
	return d.pool
}

func (d *DB) Close() {
	d.pool.Close()
}

// Scoped runs fn in a READ-ONLY tx carrying this scope; tenant writes fail with SQLSTATE 25006.
func (d *DB) Scoped(ctx context.Context, s Scope, fn func(q *Queries) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// zero TenantID => SQL NULL (fail closed); the empty string would match a nil-uuid tenant row.
	var tenantID any // nil
	if s.TenantID != uuid.Nil {
		tenantID = s.TenantID
	}
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

// ScopedRW is Scoped on a read-write tx so tenant DML reaches RLS/FK, not the read-only guard.
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

type Membership struct {
	TenantID uuid.UUID
	Role     string
}

// Memberships is unscoped by design: the switcher needs the actor's full set;
// the query always binds actorID server-side and accepts no foreign user id.
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

func (d *DB) IsSuperAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	var ok bool
	err := d.pool.QueryRow(ctx,
		"select super_admin from users where id = $1", userID).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotMember
	}
	return ok, err
}

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
