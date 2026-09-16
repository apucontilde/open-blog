// Package posts is the domain service for the post lifecycle: authoring,
// publishing, archiving and deleting, with markdown rendered to sanitized HTML
// once at write time and never on the read path (ST-22).
package posts

import "errors"

var (
	// ErrNotFound reports a post id that is absent or outside the actor's
	// tenant (RLS yields no row): maps to 404.
	ErrNotFound = errors.New("posts: post not found")

	// ErrSlugTaken reports a unique (tenant_id, slug) violation on create —
	// the uniquify probe lost a concurrent race: maps to 409.
	ErrSlugTaken = errors.New("posts: slug already in use")

	// ErrSlugImmutable reports a slug change on a post that is already
	// published: the slug is a public URL component and never changes
	// (005 sweep resolution Q3): maps to 409.
	ErrSlugImmutable = errors.New("posts: slug is immutable once published")

	// ErrEmptyContent reports a publish of a post with no markdown body, the
	// publish validation sentinel: maps to 422.
	ErrEmptyContent = errors.New("posts: content is empty")

	// ErrNoTenant reports a create with no tenant in scope. The client
	// supplied tenant is ignored (ST-5): the tenant always comes from the
	// actor's scope, and a platform actor without a tenant has no target.
	ErrNoTenant = errors.New("posts: no tenant in scope")
)
