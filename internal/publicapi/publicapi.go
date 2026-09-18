// Package publicapi is the public read surface: published-only, no auth, no app-level rate limiting.
package publicapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"openblog/internal/store"
	"openblog/internal/tenancy"
)

const (
	// CacheControl: s-maxage bounds edge freshness; stale-while-revalidate covers purge lag.
	CacheControl = "public, s-maxage=60, stale-while-revalidate=300"

	defaultPageSize = 25
	maxPageSize     = 100
)

// tenantResolver is the minimal slug→tenant surface the handlers depend on.
type tenantResolver interface {
	ResolveSlug(ctx context.Context, slug string) (uuid.UUID, int64, error)
}

// Config carries the constructor knobs.
type Config struct {
	PageSize   int           // 0 => defaultPageSize
	ResolveTTL time.Duration // 0 => tenancy.DefaultTTL
	MediaCDN   string        // e.g. https://media.example.com
}

type API struct {
	db          *store.DB
	resolver    tenantResolver
	pageSize    int
	mediaOrigin string
}

func New(db *store.DB, cfg Config) *API {
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
	if cfg.PageSize > maxPageSize {
		cfg.PageSize = maxPageSize
	}
	return &API{
		db:          db,
		resolver:    tenancy.New(db, cfg.ResolveTTL),
		pageSize:    cfg.PageSize,
		mediaOrigin: strings.TrimRight(cfg.MediaCDN, "/"),
	}
}

// Response is a fully-formed HTTP response the mux writes verbatim; client errors are encoded in Status/Body.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func jsonResponse(status int, v any, etag string) (*Response, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	h := make(http.Header)
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", CacheControl)
	if etag != "" {
		h.Set("ETag", `"`+etag+`"`)
	}
	return &Response{Status: status, Header: h, Body: b}, nil
}

func errorResponse(status int, msg string) *Response {
	b, _ := json.Marshal(map[string]string{"error": msg})
	h := make(http.Header)
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", CacheControl)
	return &Response{Status: status, Header: h, Body: b}
}

// htmlResponse serves a rendered post body as HTML so it can be opened directly
// in a browser; the body is the server-sanitized content_html artifact.
func htmlResponse(body []byte, etag string) *Response {
	h := make(http.Header)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", CacheControl)
	if etag != "" {
		h.Set("ETag", `"`+etag+`"`)
	}
	return &Response{Status: http.StatusOK, Header: h, Body: body}
}

func notModified(etag string) *Response {
	h := make(http.Header)
	h.Set("Cache-Control", CacheControl)
	h.Set("ETag", `"`+etag+`"`)
	return &Response{Status: http.StatusNotModified, Header: h}
}

// etag derives a deterministic, replica-stable validator: sha256 over NUL-separated parts.
func etag(parts ...any) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%v\x00", p)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// etagMatches implements RFC 7232 weak If-None-Match comparison (quotes/W-prefix/wildcard ignored).
func etagMatches(ifNoneMatch, current string) bool {
	if ifNoneMatch == "" {
		return false
	}
	for _, p := range strings.Split(ifNoneMatch, ",") {
		p = strings.TrimSpace(p)
		if p == "*" {
			return true
		}
		p = strings.TrimPrefix(p, "W/")
		p = strings.Trim(p, `"`)
		if p == current {
			return true
		}
	}
	return false
}

// resolveTenant maps resolver failures to client responses; unexpected errors propagate (handled=false).
func resolveTenant(err error) (*Response, bool) {
	switch {
	case errors.Is(err, tenancy.ErrInvalidSlug):
		return errorResponse(http.StatusBadRequest, "invalid tenant slug"), true
	case errors.Is(err, tenancy.ErrNotFound):
		return errorResponse(http.StatusNotFound, "tenant not found"), true
	}
	return nil, false
}
