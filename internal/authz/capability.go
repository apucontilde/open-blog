package authz

import "errors"

// Capability is one granular tenant action. Platform is a bool on Actor, never
// a ladder rank; every capability is still gated by it.
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

// RoleFor defines the ladder; the single source of truth for capability thresholds.
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

var ErrForbidden = errors.New("authz: forbidden")

// Can lets Platform bypass the whole ladder; a zero Actor (no tenant) holds nothing.
func (a Actor) Can(cap Capability) bool {
	if a.Platform {
		return true
	}
	if a.Tenant == nil || a.Role > RoleOwner {
		return false
	}
	return a.Role >= RoleFor(cap)
}

func Require(a Actor, cap Capability) error {
	if a.Can(cap) {
		return nil
	}
	return ErrForbidden
}
