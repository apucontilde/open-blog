package authz

import "fmt"

// Role is ordered author < editor < admin < owner; the DB stores it as
// CHECK-constrained text and both ordering and derivation live here only.
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
