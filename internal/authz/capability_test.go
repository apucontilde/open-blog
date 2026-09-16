package authz

import (
	"testing"

	"github.com/google/uuid"
)

var allCaps = []Capability{
	CapCreateDraft, CapEditOwnDraft, CapUploadMedia, CapRunImport,
	CapEditAnyPost, CapPublishArchive, CapViewMembers,
	CapInviteMembers, CapRemoveMembers, CapChangeRoles, CapTenantSettings,
}

func mkActor(role Role) Actor {
	return Actor{UserID: uuid.Nil, Tenant: &uuid.Nil, Role: role}
}

// firstCapFor gives the count of capabilities role holds.
func firstCapFor(role Role) int {
	for i, cap := range allCaps {
		if RoleFor(cap) > role {
			return i
		}
	}
	return len(allCaps)
}

func TestCanLadderMatrix(t *testing.T) {
	for _, role := range []Role{RoleAuthor, RoleEditor, RoleAdmin, RoleOwner} {
		hold := firstCapFor(role)
		for i, cap := range allCaps {
			want := i < hold
			a := mkActor(role)
			if got := a.Can(cap); got != want {
				t.Errorf("role %s cap %d: Can = %v, want %v", role, i, got, want)
			}
		}
	}
}

func TestCanZeroActorHoldsNothing(t *testing.T) {
	var zero Actor // no tenant, no platform
	for _, cap := range allCaps {
		if zero.Can(cap) {
			t.Errorf("zero actor unexpectedly holds %d", cap)
		}
	}
	if err := Require(zero, CapCreateDraft); err != ErrForbidden {
		t.Errorf("Require on zero actor = %v, want %v", err, ErrForbidden)
	}
}

func TestPlatformHoldsEverything(t *testing.T) {
	plat := Actor{Platform: true}
	for _, cap := range allCaps {
		if !plat.Can(cap) {
			t.Errorf("platform actor should hold %d", cap)
		}
	}
	if err := Require(plat, CapTenantSettings); err != nil {
		t.Errorf("Require(platform, owner cap) = %v, want nil", err)
	}
}

func TestRequireForbidden(t *testing.T) {
	author := mkActor(RoleAuthor)
	if err := Require(author, CapInviteMembers); err != ErrForbidden {
		t.Errorf("Require(author, invite) = %v, want ErrForbidden", err)
	}
}

func TestAuthorHoldsAuthorCaps(t *testing.T) {
	author := mkActor(RoleAuthor)
	for _, cap := range allCaps[:firstCapFor(RoleAuthor)] {
		if !author.Can(cap) {
			t.Errorf("author should hold %d", cap)
		}
	}
}
