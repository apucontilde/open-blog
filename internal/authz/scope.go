package authz

import (
	"github.com/google/uuid"

	"openblog/internal/store"
)

// ScopeFromActor is the single construction site for deriving a store.Scope
// from an Actor: exactly TenantID / Platform, nothing else. 010's auth
// middleware is the only caller. Platform:true is never settable from session
// data, params, or handler code — only a platform super_admin Actor yields it.
func ScopeFromActor(a Actor) store.Scope {
	s := store.Scope{TenantID: uuidFromPtr(a.Tenant), Platform: a.Platform}
	return s
}

func uuidFromPtr(p *uuid.UUID) uuid.UUID {
	if p == nil {
		return uuid.Nil
	}
	return *p
}
