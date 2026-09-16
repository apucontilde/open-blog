package authz

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"openblog/internal/store"
)

// Actor is one request's principal: Tenant is nil until a tenant is chosen;
// Platform is set iff the user is a global super_admin (no platform membership).
type Actor struct {
	UserID   uuid.UUID
	Tenant   *uuid.UUID
	Role     Role
	Platform bool
}

// ResolveActor loads the tenant role plus users.super_admin; a super_admin
// resolves platform-wide with no tenant, anyone with neither is ErrNotMember.
// The membership read MUST filter user_id = actor: memberships is not
// RLS-scoped, so that WHERE clause is the privacy boundary.
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
