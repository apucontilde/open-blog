package authz

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"openblog/internal/store"
)

// Actor is the authenticated principal for one request: the user plus exactly
// one tenancy intent. Tenant is nil until a tenant is chosen (session scope);
// Role is its zero value until Tenant is set; Platform is set iff the user is
// a global super_admin and bypasses the ladder but not RLS row visibility.
type Actor struct {
	UserID   uuid.UUID
	Tenant   *uuid.UUID
	Role     Role
	Platform bool
}

// ResolveActor loads the actor's role inside tenantID (one PK read) plus the
// users.super_admin flag. A super_admin resolves platform-wide with no tenant
// and zero role; anyone with neither a membership nor the flag is ErrNotMember.
// The membership read filters user_id = actor server-side — memberships is not
// RLS-scoped, and that WHERE clause is the privacy boundary.
func ResolveActor(ctx context.Context, db *store.DB, userID, tenantID uuid.UUID) (Actor, error) {
	roleText, err := db.MembershipRole(ctx, userID, tenantID)
	notMember := errors.Is(err, store.ErrNotMember)
	if err != nil && !notMember {
		return Actor{}, err
	}
	super, err := db.IsSuperAdmin(ctx, userID)
	if errors.Is(err, store.ErrNotMember) {
		return Actor{}, store.ErrNotMember
	}
	if err != nil {
		return Actor{}, err
	}
	if super {
		return Actor{UserID: userID, Platform: true}, nil
	}
	if notMember {
		return Actor{}, store.ErrNotMember
	}
	role, err := ParseRole(roleText)
	if err != nil {
		return Actor{}, err
	}
	return Actor{UserID: userID, Tenant: &tenantID, Role: role}, nil
}
