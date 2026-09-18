package authz

import (
	"openblog/internal/store"
)

// ScopeFromActor is the only scope-construction site. An active tenant always
// scopes to that tenant, even for a super_admin (RLS stays on); only a
// platform-only actor, one with no tenant, gets the cross-tenant bypass.
func ScopeFromActor(a Actor) store.Scope {
	if a.Tenant != nil {
		return store.Scope{TenantID: *a.Tenant}
	}
	if a.Platform {
		return store.Scope{Platform: true}
	}
	return store.Scope{}
}
