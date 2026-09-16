package authz

import (
	"github.com/google/uuid"

	"openblog/internal/store"
)

// ScopeFromActor is the only scope-construction site. Platform is never
// settable from session data or params — only a Platform Actor yields it.
func ScopeFromActor(a Actor) store.Scope {
	var tenantID uuid.UUID
	if a.Tenant != nil {
		tenantID = *a.Tenant
	}
	return store.Scope{TenantID: tenantID, Platform: a.Platform}
}
