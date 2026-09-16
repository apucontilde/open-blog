// Package posts is the post lifecycle service; markdown is rendered on write,
// never on read.
package posts

import "errors"

var (
	// ErrNotFound: absent or outside the actor's tenant (RLS); maps to 404.
	ErrNotFound = errors.New("posts: post not found")

	// ErrSlugTaken: unique (tenant_id, slug) lost a concurrent race; maps to 409.
	ErrSlugTaken = errors.New("posts: slug already in use")

	// ErrSlugImmutable: slug is a public URL component, frozen once published; maps to 409.
	ErrSlugImmutable = errors.New("posts: slug is immutable once published")

	// ErrEmptyContent: publish of an empty markdown body; maps to 422.
	ErrEmptyContent = errors.New("posts: content is empty")

	// ErrNoTenant: create with no tenant in the actor's scope (the client
	// tenant is ignored).
	ErrNoTenant = errors.New("posts: no tenant in scope")
)
