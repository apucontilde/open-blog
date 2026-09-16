package publicapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"openblog/internal/store"
)

// siteBody is the reader-site bootstrap payload: branding nav + settings.
// content_version rides along so reader UIs can key their own caches off the
// same ETag anchor the CDN purge uses (009 sweep finding 6).
type siteBody struct {
	Name           string          `json:"name"`
	Settings       json.RawMessage `json:"settings"`
	ContentVersion int64           `json:"content_version"`
}

// Site serves GET /public/{tenant}/site: tenant name + settings with an ETag
// of hash(content_version, updated_at) — the tenant-global generation tag.
func (a *API) Site(r *http.Request, tenantSlug string) (*Response, error) {
	ctx := r.Context()
	id, _, err := a.resolver.ResolveSlug(ctx, tenantSlug)
	if resp, handled := resolveTenant(err); handled {
		return resp, nil
	}
	if err != nil {
		return nil, err
	}

	out := siteBody{Settings: json.RawMessage("{}")}
	var updatedAt time.Time
	err = a.db.Scoped(ctx, store.Scope{TenantID: id}, func(q *store.Queries) error {
		var settings []byte
		if err := q.Tx().QueryRow(ctx,
			"select name, settings, content_version, updated_at from tenants where id = $1", id).
			Scan(&out.Name, &settings, &out.ContentVersion, &updatedAt); err != nil {
			return err
		}
		out.Settings = json.RawMessage(settings)
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// tenant deleted between the resolver's cache and this read.
		return errorResponse(http.StatusNotFound, "tenant not found"), nil
	}
	if err != nil {
		return nil, err
	}

	v := etag(out.ContentVersion, updatedAt.UnixNano())
	if etagMatches(r.Header.Get("If-None-Match"), v) {
		return notModified(v), nil
	}
	return jsonResponse(http.StatusOK, out, v)
}
