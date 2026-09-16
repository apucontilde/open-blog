package authz

import (
	"github.com/google/uuid"
)

// OwnsPost confines a plain author to their own posts; platform and editors+
// are unrestricted. The condition is !Platform && Role == RoleAuthor.
func (a Actor) OwnsPost(authorID uuid.UUID) bool {
	if a.Platform || a.Role != RoleAuthor {
		return true
	}
	return authorID == a.UserID
}
