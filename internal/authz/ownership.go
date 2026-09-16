package authz

import (
	"github.com/google/uuid"
)

// OwnsPost reports whether actor may touch a post row by row ownership: every
// non-platform actor with a role may work tenant-wide, but a plain author is
// confined to posts whose author_id is their own user. The condition matches
// the plan's sweep finding 20 — applied only when !actor.Platform and the role
// is exactly author; editors and above are not subject to it.
func (a Actor) OwnsPost(authorID uuid.UUID) bool {
	if a.Platform || a.Role != RoleAuthor {
		return true
	}
	return authorID == a.UserID
}
