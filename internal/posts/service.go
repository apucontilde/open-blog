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

// PurgeJobKind is the jobs.kind marking a CDN purge, written INSIDE the same
// transaction as the public change (008 sweep finding 9). A worker (006/010 or
// a hardcoded handler) consumes jobs.JobPayload: TenantID plus Data holding a
// purgePayload jsonb. (kind, dedupe_key) dedupes per tenant — the key is the
// tenant id — so re-publication never double-inserts.
const PurgeJobKind = "purge"

// purgePayload is the Data payload of a PurgeJobKind job: the tenant whose
// public surface changed, the post that changed, the new tenants.content_version
// (ETag anchor, sweep finding 6), and the paths to invalidate. Paths covers the
// whole tenant surface because content_version is tenant-global; 009's read path
// tolerates a purge lag of one cycle.
type purgePayload struct {
	TenantID uuid.UUID `json:"tenant_id"`
	PostID   uuid.UUID `json:"post_id"`
	Version  int64     `json:"version"`
	Paths    []string  `json:"paths"`
}

// Config carries the renderer's media policy. Supplied by 010 from env, never
// parsed here.
type Config struct {
	MediaOrigin string // <img> host allow-list, e.g. "media.example.com"
}

// Service exposes the post lifecycle to 010's handlers. Authorization is
// routed through authz (capabilities + OwnsPost); row visibility is enforced
// by store RLS scoped to the actor.
type Service struct {
	db  *store.DB
	cfg Config
}

// New builds a Service over db; an empty MediaOrigin defaults to
// media.example.com.
func New(db *store.DB, cfg Config) *Service {
	if cfg.MediaOrigin == "" {
		cfg.MediaOrigin = defaultMediaOrigin
	}
	return &Service{db: db, cfg: cfg}
}

// CreateInput is the request body of POST /admin/posts. Slug is optional;
// an empty title-derived slug is auto-derived and uniquified (ST-5).
type CreateInput struct {
	Title           string
	ContentMarkdown string
	Slug            string
	Excerpt         string
	Metadata        []byte // jsonb
}

// Create drafts a post: author_id from the actor, tenant_id from the actor's
// scope (client-supplied tenant ignored), slug derived and uniquified, markdown
// rendered to sanitized HTML once.
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

// Get reads one post by id, role-aware: a plain author may read only their own
// rows; editors+ and platform read tenant-wide. RLS already confines the read
// to the actor's tenant.
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

// List returns the list projection (metadata + slug only, no markdown body).
// Authors see their own posts only; editors+ see the tenant-wide set (ST-6,
// ST-11).
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

// UpdateInput is the PATCH body: nil fields are unchanged. Setting
// ContentMarkdown re-renders content_html; every PATCH re-renders regardless
// (draft-preview parity), and a PATCH on a published post additionally bumps
// tenants.content_version and enqueues the CDN purge in the same tx.
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
			return authz.ErrForbidden // plain author: own draft only (ST-6)
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
				return ErrSlugImmutable // slug is a public URL component (Q3)
			}
			slug, err = uniqueSlug(ctx, q, scope.TenantID, *in.Slug)
			if err != nil {
				return err
			}
		}
		// Every PATCH re-renders: the stored content_html is never stale for
		// the editor preview, and a published PATCH ships current HTML.
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

// Publish makes the post public: editor+ only (ST-9), non-empty content,
// published_at = now(), re-render, tenants.content_version bump and the CDN
// purge enqueued atomically.
func (s *Service) Publish(ctx context.Context, actor authz.Actor, id uuid.UUID) (store.Post, error) {
	return s.transition(ctx, actor, id, store.PostPublished, publish)
}

// Unpublish returns a public post to draft (editor+, ST-10) with the same
// atomic bump + purge; content_version anchors the hide.
func (s *Service) Unpublish(ctx context.Context, actor authz.Actor, id uuid.UUID) (store.Post, error) {
	return s.transition(ctx, actor, id, store.PostDraft, unpublish)
}

// Archive hides a post from the public listing (editor+, ST-10) with the same
// atomic bump + purge.
func (s *Service) Archive(ctx context.Context, actor authz.Actor, id uuid.UUID) (store.Post, error) {
	return s.transition(ctx, actor, id, store.PostArchived, archive)
}

type transitionKind int

const (
	publish transitionKind = iota
	unpublish
	archive
)

func (s *Service) transition(ctx context.Context, actor authz.Actor, id uuid.UUID, status store.PostStatus, kind transitionKind) (store.Post, error) {
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
		if kind == publish && strings.TrimSpace(p.ContentMarkdown) == "" {
			return ErrEmptyContent // never publish an empty body
		}
		html, err := s.render([]byte(p.ContentMarkdown), p.Metadata)
		if err != nil {
			return err
		}
		var publishedAt *time.Time
		if kind == publish {
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

// Delete removes a post: a plain author may delete only their own draft,
// editors+ any post (005 DELETE rule). Child post_images cascade; imports are
// set NULL so re-import stays possible; orphan purge is the 006 sweeper's job.
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

// purge records a public-visible change atomically: bump the tenant's
// content_version and enqueue the CDN purge in the same transaction (008
// sweep finding 9). The job payload follows the workers.JobPayload contract —
// {tenant_id, data:{...}} — so any kind handler can consume it regardless of
// which domain produced it. A duplicate (kind, dedupe_key) is the normal
// re-publish case and is a no-op.
func (s *Service) purge(ctx context.Context, q *store.Queries, tenantID uuid.UUID, p store.Post) error {
	version, err := q.BumpContentVersion(ctx, tenantID)
	if err != nil {
		return err
	}
	_, err = jobs.Enqueue(ctx, q.Tx(), PurgeJobKind, tenantID.String(), jobs.JobPayload{
		TenantID: tenantID,
		Data: mustJSON(purgePayload{
			TenantID: tenantID,
			PostID:   p.ID,
			Version:  version,
			Paths:    []string{"/"},
		}),
	})
	if errors.Is(err, jobs.ErrDuplicate) {
		return nil
	}
	return err
}

// mustJSON marshals a purge payload into the JobPayload.Data slot; a marshal
// failure of our own fixed-shape struct cannot happen (all fields JSON-safe).
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// render is the service's single rendezvous with the renderer: it applies the
// metadata opt-in — {"allow_external_images": true} relaxes the image origin
// whitelist to any http(s) host.
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

var (
	nonSlug = regexp.MustCompile(`[^a-z0-9]+`)
)

// uniqueSlug returns desired (or a derived form of it) made unique inside the
// tenant: an explicit slug is the base, otherwise one is derived from the
// title; collisions get a numeric suffix (create + draft PATCH).
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

// deriveSlug derives a slug from a title (empty or all-punctuation titles
// fall back to "post"). The DB CHECK regex caps it at 63 chars.
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
