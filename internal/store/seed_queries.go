package store

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// SeedUser upserts a bootstrap user by case-insensitive email; on conflict the
// id and created_at are kept and the password/super flag are refreshed.
func (q *Queries) SeedUser(ctx context.Context, id uuid.UUID, email, hash string, super bool) error {
	display := email
	if i := strings.IndexByte(email, '@'); i > 0 {
		display = email[:i]
	}
	_, err := q.tx.Exec(ctx, `
		insert into users (id, email, password_hash, display_name, super_admin)
		values ($1, $2, $3, $4, $5)
		on conflict (lower(email)) do update
		  set password_hash = excluded.password_hash,
		      super_admin   = excluded.super_admin,
		      display_name  = excluded.display_name`,
		id, email, hash, display, super)
	return err
}

// SeedTenant creates the bootstrap tenant if the slug is new; existing rows are
// left untouched.
func (q *Queries) SeedTenant(ctx context.Context, id uuid.UUID, slug, name string) error {
	_, err := q.tx.Exec(ctx, `
		insert into tenants (id, slug, name) values ($1, $2, $3)
		on conflict (slug) do nothing`, id, slug, name)
	return err
}

// SeedMembership grants the named role, resolving user and tenant by their
// natural keys so re-runs survive a user id already being taken.
func (q *Queries) SeedMembership(ctx context.Context, slug, email, role string) error {
	_, err := q.tx.Exec(ctx, `
		insert into memberships (tenant_id, user_id, role)
		select t.id, u.id, $3
		from tenants t, users u
		where t.slug = $1 and lower(u.email) = lower($2)
		on conflict (tenant_id, user_id) do update set role = excluded.role`,
		slug, email, role)
	return err
}
