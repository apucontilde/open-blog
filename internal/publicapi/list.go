package publicapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openblog/internal/store"
)

// listRow is the metadata-only projection (never the body or content_html).
type listRow struct {
	id          uuid.UUID
	slug        string
	title       string
	excerpt     string
	publishedAt *time.Time
	metadata    []byte
}

// listBody omits next_cursor on the final page.
type listBody struct {
	Posts      []listPost `json:"posts"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

// listPost's Images carries at most the lowest-position attachment.
type listPost struct {
	Slug        string          `json:"slug"`
	Title       string          `json:"title"`
	Excerpt     string          `json:"excerpt"`
	PublishedAt *time.Time      `json:"published_at"`
	Metadata    json.RawMessage `json:"metadata"`
	Images      []imageItem     `json:"images"`
}

// List serves published posts newest-first with keyset pagination (?before=) and optional ?tag=.
// The ETag includes the tenant's content_version, so any bump invalidates every page.
func (a *API) List(r *http.Request, tenantSlug string) (*Response, error) {
	ctx := r.Context()
	id, _, err := a.resolver.ResolveSlug(ctx, tenantSlug)
	if resp, handled := resolveTenant(err); handled {
		return resp, nil
	}
	if err != nil {
		return nil, err
	}

	q := r.URL.Query()
	tag := q.Get("tag")
	before := q.Get("before")
	var cur *Cursor
	if before != "" {
		c, err := decodeCursor(before)
		if err != nil {
			return errorResponse(http.StatusUnprocessableEntity, "malformed cursor"), nil
		}
		cur = &c
	}

	var version int64
	rows, err := a.fetchPage(ctx, id, tag, cur, &version)
	if err != nil {
		return nil, err
	}

	hasMore := len(rows) > a.pageSize
	page := rows
	if hasMore {
		page = rows[:a.pageSize]
	}

	var next string
	if hasMore {
		// published rows always carry published_at; advertise a next page only when the anchor exists.
		last := page[len(page)-1]
		if last.publishedAt != nil {
			next = encodeCursor(Cursor{PublishedAt: *last.publishedAt, ID: last.id})
		}
	}

	imgs, err := a.fetchFirstImages(ctx, id, page)
	if err != nil {
		return nil, err
	}

	body := listBody{Posts: make([]listPost, 0, len(page))}
	for _, row := range page {
		meta := row.metadata
		if len(meta) == 0 {
			meta = []byte("{}")
		}
		body.Posts = append(body.Posts, listPost{
			Slug:        row.slug,
			Title:       row.title,
			Excerpt:     row.excerpt,
			PublishedAt: row.publishedAt,
			Metadata:    json.RawMessage(meta),
			Images:      firstImageSlice(imgs[row.id]),
		})
	}
	body.NextCursor = next

	v := etag(version, before, tag, a.pageSize)
	if etagMatches(r.Header.Get("If-None-Match"), v) {
		return notModified(v), nil
	}
	return jsonResponse(http.StatusOK, body, v)
}

// fetchPage runs the list scan and the tenant's content_version in one read scope.
func (a *API) fetchPage(ctx context.Context, tenantID uuid.UUID, tag string, cur *Cursor, version *int64) ([]listRow, error) {
	stmt, args := listStatement(tenantID, a.pageSize, tag, cur)
	var rows []listRow
	err := a.db.Scoped(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		if err := q.Tx().QueryRow(ctx,
			"select content_version from tenants where id = $1", tenantID).Scan(version); err != nil {
			return err
		}
		r, err := q.Tx().Query(ctx, stmt, args...)
		if err != nil {
			return err
		}
		defer r.Close()
		rows = []listRow{}
		for r.Next() {
			var lr listRow
			if err := r.Scan(&lr.id, &lr.slug, &lr.title, &lr.excerpt, &lr.publishedAt, &lr.metadata); err != nil {
				return err
			}
			rows = append(rows, lr)
		}
		return r.Err()
	})
	return rows, err
}

// fetchFirstImages reads the lowest-position image per page post in one set read.
func (a *API) fetchFirstImages(ctx context.Context, tenantID uuid.UUID, rows []listRow) (map[uuid.UUID][]imageItem, error) {
	out := make(map[uuid.UUID][]imageItem, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.id)
	}
	err := a.db.Scoped(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		r, err := q.Tx().Query(ctx,
			"select post_id, variants from post_images where tenant_id = $1 and post_id = any($2) order by post_id, position",
			tenantID, ids)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var pid uuid.UUID
			var variants []byte
			if err := r.Scan(&pid, &variants); err != nil {
				return err
			}
			if _, seen := out[pid]; seen {
				continue // keep the lowest position
			}
			if img, ok := imageFromVariants(variants, a.mediaOrigin); ok {
				out[pid] = []imageItem{img}
			}
		}
		return r.Err()
	})
	return out, err
}

// firstImageSlice ensures an empty images field marshals as [] not null.
func firstImageSlice(imgs []imageItem) []imageItem {
	if imgs == nil {
		return []imageItem{}
	}
	return imgs
}
