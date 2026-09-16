package posts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"openblog/internal/authz"
	"openblog/internal/jobs"
	"openblog/internal/store"
)

// PurgeJobKind is the jobs.kind for a CDN purge, written in the same tx as the
// public change; (kind, dedupe_key = tenant id) dedupes per tenant. Its Data is
// a purgePayload.
const PurgeJobKind = "purge"

// purgePayload is a PurgeJobKind job's Data: the changed tenant/post, the new
// tenants.content_version (ETag anchor) and the paths to invalidate.
type purgePayload struct {
	TenantID uuid.UUID `json:"tenant_id"`
	PostID   uuid.UUID `json:"post_id"`
	Version  int64     `json:"version"`
	Paths    []string  `json:"paths"`
}

// Config carries the renderer's media policy, supplied from env.
type Config struct {
	MediaOrigin string // <img> host allow-list
}

// Service is authorized through authz; row visibility comes from store RLS
// scoped to the actor.
type Service struct {
	db  *store.DB
	cfg Config
}

func New(db *store.DB, cfg Config) *Service {
	if cfg.MediaOrigin == "" {
		cfg.MediaOrigin = defaultMediaOrigin
	}
	return &Service{db: db, cfg: cfg}
}

// CreateInput is the POST /admin/posts body; an empty Slug is derived from
// Title and uniquified.
type CreateInput struct {
	Title           string
	ContentMarkdown string
	Slug            string
	Excerpt         string
	Metadata        []byte // jsonb
}

// Create drafts a post under the actor's tenant; author and tenant come from
// the actor, never from the input.
func (s *Service) Create(ctx context.Context, actor authz.Actor, in CreateInput) (store.Post, error) {
	if err := authz.Require(actor, authz.CapCreateDraft); err != nil {
		return store.Post{}, err
	}
	scope := authz.ScopeFromActor(actor)
	if scope.TenantID == uuid.Nil {
		return store.Post{}, ErrNoTenant
	}
	html, err := s.render([]byte(in.ContentMarkdown), in.Metadata)
	if err != nil {
		return store.Post{}, err
	}
	post := store.Post{
		ID:              uuid.New(),
		TenantID:        scope.TenantID,
		AuthorID:        actor.UserID,
		Title:           in.Title,
		Excerpt:         in.Excerpt,
		ContentMarkdown: in.ContentMarkdown,
		ContentHTML:     string(html),
		Metadata:        in.Metadata,
		Status:          store.PostDraft,
	}
	err = s.db.ScopedRW(ctx, scope, func(q *store.Queries) error {
		base := in.Slug
		if base == "" {
			base = in.Title
		}
		slug, err := uniqueSlug(ctx, q, scope.TenantID, base)
		if err != nil {
			return err
		}
		post.Slug = slug
		created, err := q.CreatePost(ctx, post)
		if isUniqueViolation(err) {
			return ErrSlugTaken
		}
		if err != nil {
			return err
		}
		post = created
		return nil
	})
	if err != nil {
		return store.Post{}, err
	}
	return post, nil
}

// Get is role-aware: a plain author may read only their own rows, editors+ and
// platform tenant-wide. RLS confines the read to the actor's tenant.
func (s *Service) Get(ctx context.Context, actor authz.Actor, id uuid.UUID) (store.Post, error) {
	scope := authz.ScopeFromActor(actor)
	var p store.Post
	err := s.db.Scoped(ctx, scope, func(q *store.Queries) error {
		var err error
		p, err = q.GetPostByID(ctx, id)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Post{}, ErrNotFound
	}
	if err != nil {
		return store.Post{}, err
	}
	if !actor.OwnsPost(p.AuthorID) {
		return store.Post{}, authz.ErrForbidden
	}
	return p, nil
}

// ListFilter filters the post list; a nil field is open.
type ListFilter struct {
	Status   *string    // "draft"|"published"|"archived"
	AuthorID *uuid.UUID // editors+ filter; authors are pinned to themselves
}

// List returns the summary projection (no markdown body). Authors see their own
// posts only; editors+ see the tenant-wide set.
func (s *Service) List(ctx context.Context, actor authz.Actor, f ListFilter) ([]store.PostSummary, error) {
	if err := authz.Require(actor, authz.CapCreateDraft); err != nil {
		return nil, err
	}
	authorID := f.AuthorID
	if !actor.Platform && actor.Role == authz.RoleAuthor {
		u := actor.UserID
		authorID = &u // author: own only, whatever the filter says
	}
	var out []store.PostSummary
	err := s.db.Scoped(ctx, authz.ScopeFromActor(actor), func(q *store.Queries) error {
		var err error
		out, err = q.ListPostSummaries(ctx, f.Status, authorID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateInput is the PATCH body: nil fields are unchanged. Every PATCH
// re-renders content_html; on a published post it also bumps
// tenants.content_version and enqueues the purge in the same tx.
type UpdateInput struct {
	Title           *string
	ContentMarkdown *string
	Slug            *string
	Excerpt         *string
	Metadata        *[]byte
}

func (s *Service) Update(ctx context.Context, actor authz.Actor, id uuid.UUID, in UpdateInput) (store.Post, error) {
	if err := authz.Require(actor, authz.CapEditOwnDraft); err != nil {
		return store.Post{}, err
	}
	scope := authz.ScopeFromActor(actor)
	var out store.Post
	err := s.db.ScopedRW(ctx, scope, func(q *store.Queries) error {
		p, err := q.GetPostByID(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !actor.OwnsPost(p.AuthorID) {
			return authz.ErrForbidden
		}
		if !actor.Platform && actor.Role == authz.RoleAuthor && p.Status != store.PostDraft {
			return authz.ErrForbidden // plain author: own draft only
		}

		title := p.Title
		if in.Title != nil {
			title = *in.Title
		}
		excerpt := p.Excerpt
		if in.Excerpt != nil {
			excerpt = *in.Excerpt
		}
		md := p.ContentMarkdown
		if in.ContentMarkdown != nil {
			md = *in.ContentMarkdown
		}
		meta := p.Metadata
		if in.Metadata != nil {
			meta = *in.Metadata
		}
		slug := p.Slug
		if in.Slug != nil {
			if p.Status == store.PostPublished {
				return ErrSlugImmutable
			}
			slug, err = uniqueSlug(ctx, q, scope.TenantID, *in.Slug)
			if err != nil {
				return err
			}
		}
		html, err := s.render([]byte(md), meta)
		if err != nil {
			return err
		}
		out, err = q.UpdatePost(ctx, store.Post{
			ID: id, Title: title, Slug: slug, Excerpt: excerpt,
			ContentMarkdown: md, ContentHTML: string(html),
		})
		if err != nil {
			return err
		}
		if out.Status == store.PostPublished {
			return s.purge(ctx, q, scope.TenantID, out)
		}
		return nil
	})
	if err != nil {
		return store.Post{}, err
	}
	return out, nil
}

// Publish makes the post public (editor+): non-empty content, published_at =
// now, re-render, content_version bump and purge in one tx.
func (s *Service) Publish(ctx context.Context, actor authz.Actor, id uuid.UUID) (store.Post, error) {
	return s.transition(ctx, actor, id, store.PostPublished, true)
}

// Unpublish returns a public post to draft (editor+), same atomic bump + purge.
func (s *Service) Unpublish(ctx context.Context, actor authz.Actor, id uuid.UUID) (store.Post, error) {
	return s.transition(ctx, actor, id, store.PostDraft, false)
}

// Archive hides a post from the public listing (editor+), same atomic bump + purge.
func (s *Service) Archive(ctx context.Context, actor authz.Actor, id uuid.UUID) (store.Post, error) {
	return s.transition(ctx, actor, id, store.PostArchived, false)
}

// transition always re-renders content_html and, atomically, bumps
// content_version and enqueues the purge.
func (s *Service) transition(ctx context.Context, actor authz.Actor, id uuid.UUID, status store.PostStatus, publishing bool) (store.Post, error) {
	if err := authz.Require(actor, authz.CapPublishArchive); err != nil {
		return store.Post{}, err
	}
	scope := authz.ScopeFromActor(actor)
	var out store.Post
	err := s.db.ScopedRW(ctx, scope, func(q *store.Queries) error {
		p, err := q.GetPostByID(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if publishing && strings.TrimSpace(p.ContentMarkdown) == "" {
			return ErrEmptyContent
		}
		html, err := s.render([]byte(p.ContentMarkdown), p.Metadata)
		if err != nil {
			return err
		}
		var publishedAt *time.Time
		if publishing {
			t := time.Now()
			publishedAt = &t
		}
		out, err = q.SetPostStatus(ctx, id, status, publishedAt, string(html))
		if err != nil {
			return err
		}
		return s.purge(ctx, q, scope.TenantID, out)
	})
	if err != nil {
		return store.Post{}, err
	}
	return out, nil
}

// Delete: a plain author may delete only their own draft, editors+ any post.
// post_images cascade; imports are set NULL so re-import stays possible.
func (s *Service) Delete(ctx context.Context, actor authz.Actor, id uuid.UUID) error {
	if err := authz.Require(actor, authz.CapEditOwnDraft); err != nil {
		return err
	}
	scope := authz.ScopeFromActor(actor)
	return s.db.ScopedRW(ctx, scope, func(q *store.Queries) error {
		p, err := q.GetPostByID(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !actor.OwnsPost(p.AuthorID) {
			return authz.ErrForbidden
		}
		if !actor.Platform && actor.Role == authz.RoleAuthor && p.Status != store.PostDraft {
			return authz.ErrForbidden // plain author: own draft only
		}
		return q.DeletePost(ctx, id)
	})
}

// purge records a public-visible change atomically: content_version bump plus
// CDN purge in the same tx. A duplicate (kind, dedupe_key) re-publish is a no-op.
func (s *Service) purge(ctx context.Context, q *store.Queries, tenantID uuid.UUID, p store.Post) error {
	version, err := q.BumpContentVersion(ctx, tenantID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(purgePayload{
		TenantID: tenantID,
		PostID:   p.ID,
		Version:  version,
		Paths:    []string{"/"},
	})
	if err != nil {
		return err
	}
	_, err = jobs.Enqueue(ctx, q.Tx(), PurgeJobKind, tenantID.String(), jobs.JobPayload{
		TenantID: tenantID,
		Data:     data,
	})
	if errors.Is(err, jobs.ErrDuplicate) {
		return nil
	}
	return err
}

// render applies the image-host policy; metadata {"allow_external_images":true}
// opens all http(s) hosts.
func (s *Service) render(md, metadata []byte) ([]byte, error) {
	hosts := []string{s.cfg.MediaOrigin}
	if metadataAllowsExternalImages(metadata) {
		hosts = nil
	}
	return renderGFMHosts(md, hosts)
}

func metadataAllowsExternalImages(meta []byte) bool {
	if len(meta) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(meta, &m) != nil {
		return false
	}
	on, _ := m["allow_external_images"].(bool)
	return on
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// uniqueSlug makes desired unique within the tenant: derive from title if
// empty, suffix -2, -3 on collision.
func uniqueSlug(ctx context.Context, q *store.Queries, tenantID uuid.UUID, desired string) (string, error) {
	base := deriveSlug(desired)
	slug := base
	for attempt := 2; ; attempt++ {
		exists, err := q.SlugExists(ctx, tenantID, slug)
		if err != nil {
			return "", err
		}
		if !exists {
			return slug, nil
		}
		if attempt > 10000 {
			return "", ErrSlugTaken
		}
		slug = fmt.Sprintf("%s-%d", base, attempt)
	}
}

// deriveSlug lowercases/hyphenates a title, falling back to "post"; capped at
// 63 chars (DB CHECK).
func deriveSlug(title string) string {
	s := strings.ToLower(title)
	s = nonSlug.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "post"
	}
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	if s == "" {
		return "post"
	}
	return s
}

func isUniqueViolation(err error) bool {
	var pgerr *pgconn.PgError
	return errors.As(err, &pgerr) && pgerr.Code == "23505"
}
