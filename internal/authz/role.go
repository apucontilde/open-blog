package authz

import "fmt"

// Role is a tenant membership's privilege level, ordered author < editor <
// admin < owner. The DB stores it as text with a CHECK constraint; ordering
// and derivation live exclusively here.
type Role int

const (
	RoleAuthor Role = iota
	RoleEditor
	RoleAdmin
	RoleOwner
)

func (r Role) String() string {
	switch r {
	case RoleEditor:
		return "editor"
	case RoleAdmin:
		return "admin"
	case RoleOwner:
		return "owner"
	default:
		return "author"
	}
}

// ParseRole maps the DB CHECK-constrained text back to a Role.
func ParseRole(s string) (Role, error) {
	switch s {
	case "author":
		return RoleAuthor, nil
	case "editor":
		return RoleEditor, nil
	case "admin":
		return RoleAdmin, nil
	case "owner":
		return RoleOwner, nil
	default:
		return 0, fmt.Errorf("authz: unknown role %q", s)
	}
}
