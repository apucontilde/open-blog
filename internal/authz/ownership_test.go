package authz

import (
	"testing"

	"github.com/google/uuid"
)

func TestOwnsPostTruthTable(t *testing.T) {
	me := uuid.New()
	other := uuid.New()
	cases := []struct {
		name  string
		actor Actor
		owner uuid.UUID
		want  bool
	}{
		{"super admin foreign post", Actor{Platform: true, UserID: me}, other, true},
		{"super admin own post", Actor{Platform: true, UserID: me}, me, true},
		{"author own post", Actor{UserID: me, Tenant: &me, Role: RoleAuthor}, me, true},
		{"author other's post", Actor{UserID: me, Tenant: &me, Role: RoleAuthor}, other, false},
		{"editor other's post", Actor{UserID: me, Tenant: &me, Role: RoleEditor}, other, true},
		{"admin other's post", Actor{UserID: me, Tenant: &me, Role: RoleAdmin}, other, true},
		{"owner other's post", Actor{UserID: me, Tenant: &me, Role: RoleOwner}, other, true},
	}
	for _, c := range cases {
		if got := c.actor.OwnsPost(c.owner); got != c.want {
			t.Errorf("%s: OwnsPost = %v, want %v", c.name, got, c.want)
		}
	}
}
