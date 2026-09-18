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

// ResolveActor loads the tenant role plus users.super_admin. With no active
// tenant a super_admin resolves platform-wide; with an active tenant the tenant
// scope wins, so a super_admin acts as owner there (ST-18) even without a
// membership row. Anyone with neither is ErrNotMember. The membership read MUST
// filter user_id = actor: memberships is not RLS-scoped, so that WHERE clause is
// the privacy boundary.
func ResolveActor(ctx context.Context, db *store.DB, userID, tenantID uuid.UUID) (Actor, error) {
	super, err := db.IsSuperAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotMember) {
			return Actor{}, store.ErrNotMember
		}
		return Actor{}, err
	}

	if tenantID == uuid.Nil {
		if super {
			return Actor{UserID: userID, Platform: true}, nil
		}
		return Actor{}, store.ErrNotMember
	}

	roleText, err := db.MembershipRole(ctx, userID, tenantID)
	switch {
	case err == nil:
		role, perr := ParseRole(roleText)
		if perr != nil {
			return Actor{}, perr
		}
		return Actor{UserID: userID, Tenant: &tenantID, Role: role, Platform: super}, nil
	case errors.Is(err, store.ErrNotMember) && super:
		return Actor{UserID: userID, Tenant: &tenantID, Role: RoleOwner, Platform: true}, nil
	case errors.Is(err, store.ErrNotMember):
		return Actor{}, store.ErrNotMember
	default:
		return Actor{}, err
	}
}
