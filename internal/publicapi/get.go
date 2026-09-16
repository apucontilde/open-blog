package publicapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"openblog/internal/store"
)

// postBody serves content_html verbatim; the read path never renders markdown.
type postBody struct {
	Slug        string      `json:"slug"`
	Title       string      `json:"title"`
	Excerpt     string      `json:"excerpt"`
	ContentHTML string      `json:"content_html"`
	Author      string      `json:"author"`
	PublishedAt *time.Time  `json:"published_at"`
	Images      []imageItem `json:"images"`
}

// Get serves the published post; drafts and archives 404 like unknown slugs.
// Query contract: GROUP BY p.id, u.id with the composite-tenant LEFT JOIN and jsonb_agg ORDER BY pi.position.
func (a *API) Get(r *http.Request, tenantSlug, postSlug string) (*Response, error) {
	ctx := r.Context()
	id, _, err := a.resolver.ResolveSlug(ctx, tenantSlug)
	if resp, handled := resolveTenant(err); handled {
		return resp, nil
	}
	if err != nil {
		return nil, err
	}
	if postSlug == "" {
		return errorResponse(http.StatusNotFound, "post not found"), nil
	}

	var (
		title       string
		excerpt     string
		contentHTML string
		publishedAt *time.Time
		author      string
		updatedAt   time.Time
		imagesRaw   []byte
	)
	err = a.db.Scoped(ctx, store.Scope{TenantID: id}, func(q *store.Queries) error {
		return q.Tx().QueryRow(ctx, `
			select p.title, p.excerpt, p.content_html, p.published_at,
			       u.display_name, p.updated_at,
			       coalesce(jsonb_agg(pi.variants order by pi.position)
			                filter (where pi.id is not null), '[]'::jsonb)
			from posts p
			join users u on u.id = p.author_id
			left join post_images pi on pi.post_id = p.id and pi.tenant_id = p.tenant_id
			where p.tenant_id = $1 and p.slug = $2 and p.status = 'published'
			group by p.id, u.id`, id, postSlug).
			Scan(&title, &excerpt, &contentHTML, &publishedAt, &author, &updatedAt, &imagesRaw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errorResponse(http.StatusNotFound, "post not found"), nil
	}
	if err != nil {
		return nil, err
	}

	body := postBody{
		Slug:        postSlug,
		Title:       title,
		Excerpt:     excerpt,
		ContentHTML: contentHTML,
		Author:      author,
		PublishedAt: publishedAt,
		Images:      a.decodeImages(imagesRaw),
	}
	v := etag(len(contentHTML), updatedAt.UnixNano())
	if etagMatches(r.Header.Get("If-None-Match"), v) {
		return notModified(v), nil
	}
	return jsonResponse(http.StatusOK, body, v)
}

func (a *API) decodeImages(raw []byte) []imageItem {
	var raws []json.RawMessage
	if err := json.Unmarshal(raw, &raws); err != nil {
		return []imageItem{}
	}
	out := make([]imageItem, 0, len(raws))
	for _, r := range raws {
		if img, ok := imageFromVariants(r, a.mediaOrigin); ok {
			out = append(out, img)
		}
	}
	return out
}
