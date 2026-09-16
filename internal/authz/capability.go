package authz

import "errors"

// Capability is one granular action a role may hold in a tenant. Platform is a
// boolean on Actor, never a ladder rank; every capability is still gated by it.
type Capability int

const (
	CapCreateDraft Capability = iota
	CapEditOwnDraft
	CapUploadMedia
	CapRunImport
	CapEditAnyPost
	CapPublishArchive
	CapViewMembers
	CapInviteMembers
	CapRemoveMembers
	CapChangeRoles
	CapTenantSettings
)

// RoleFor returns the minimum Role able to hold cap. It defines the ladder and
// is the single source of truth for capability tests.
func RoleFor(cap Capability) Role {
	switch cap {
	case CapEditAnyPost, CapPublishArchive, CapViewMembers:
		return RoleEditor
	case CapInviteMembers, CapRemoveMembers, CapChangeRoles:
		return RoleAdmin
	case CapTenantSettings:
		return RoleOwner
	default:
		return RoleAuthor
	}
}

// ErrForbidden reports that the actor lacks a required capability.
var ErrForbidden = errors.New("authz: forbidden")

// Can reports whether actor holds cap in its active tenant. Platform bypasses
// the whole ladder; a zero Actor (no tenant) or invalid role holds nothing.
func (a Actor) Can(cap Capability) bool {
	if a.Platform {
		return true
	}
	if a.Tenant == nil || a.Role > RoleOwner {
		return false
	}
	return a.Role >= RoleFor(cap)
}

// Require returns nil if actor holds cap in its active tenant, else the sentinel
// ErrForbidden that callers map to a 403.
func Require(a Actor, cap Capability) error {
	if a.Can(cap) {
		return nil
	}
	return ErrForbidden
}
