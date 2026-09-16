package authz

import "testing"

func TestRoleOrdering(t *testing.T) {
	if !(RoleAuthor < RoleEditor) || !(RoleEditor < RoleAdmin) || !(RoleAdmin < RoleOwner) {
		t.Fatalf("role ordering broken: author<%[1]v, editor<%[2]v, admin<%[3]v, owner<%[4]v",
			RoleAuthor, RoleEditor, RoleAdmin, RoleOwner)
	}
}

func TestRoleString(t *testing.T) {
	cases := []struct {
		r   Role
		got string
	}{
		{RoleAuthor, "author"},
		{RoleEditor, "editor"},
		{RoleAdmin, "admin"},
		{RoleOwner, "owner"},
	}
	for _, c := range cases {
		if s := c.r.String(); s != c.got {
			t.Errorf("Role(%d).String() = %q, want %q", c.r, s, c.got)
		}
	}
}

func TestParseRoleRoundTrip(t *testing.T) {
	for _, r := range []Role{RoleAuthor, RoleEditor, RoleAdmin, RoleOwner} {
		back, err := ParseRole(r.String())
		if err != nil {
			t.Fatalf("ParseRole(%q): %v", r.String(), err)
		}
		if back != r {
			t.Errorf("round trip %q -> %d, want %d", r.String(), back, r)
		}
	}
	if _, err := ParseRole("publisher"); err == nil {
		t.Error("ParseRole accepted an unknown text role")
	}
}
