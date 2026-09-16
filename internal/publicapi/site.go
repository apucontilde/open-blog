package publicapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"openblog/internal/store"
)

// siteBody carries content_version as the ETag anchor.
type siteBody struct {
	Name           string          `json:"name"`
	Settings       json.RawMessage `json:"settings"`
	ContentVersion int64           `json:"content_version"`
}

// Site serves tenant name + settings; ETag = hash(content_version, updated_at).
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
		// tenant deleted between the resolver cache and this read.
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
