package authz

import (
	"testing"

	"github.com/google/uuid"
)

func TestScopeFromActor(t *testing.T) {
	tid := uuid.New()
	cases := []struct {
		name     string
		actor    Actor
		wantID   uuid.UUID
		wantPlat bool
	}{
		{"platform super admin", Actor{UserID: tid, Platform: true}, uuid.Nil, true},
		{"author in tenant", Actor{UserID: tid, Tenant: &tid, Role: RoleAuthor}, tid, false},
		{"editor in tenant", Actor{UserID: tid, Tenant: &tid, Role: RoleEditor}, tid, false},
		{"admin in tenant", Actor{UserID: tid, Tenant: &tid, Role: RoleAdmin}, tid, false},
		{"owner in tenant", Actor{UserID: tid, Tenant: &tid, Role: RoleOwner}, tid, false},
	}
	for _, c := range cases {
		got := ScopeFromActor(c.actor)
		if got.TenantID != c.wantID {
			t.Errorf("%s: TenantID = %v, want %v", c.name, got.TenantID, c.wantID)
		}
		if got.Platform != c.wantPlat {
			t.Errorf("%s: Platform = %v, want %v", c.name, got.Platform, c.wantPlat)
		}
	}
}

func TestScopeFromActorPlatformOnlyForSuperAdmin(t *testing.T) {
	// Platform:true must never be derivable from a non-super role — only the
	// Platform bool on the Actor carries it into the scope.
	tid := uuid.New()
	for _, role := range []Role{RoleAuthor, RoleEditor, RoleAdmin, RoleOwner} {
		a := Actor{UserID: uuid.New(), Tenant: &tid, Role: role}
		if got := ScopeFromActor(a); got.Platform {
			t.Errorf("role %d leaked Platform:true into scope", role)
		}
	}
}
