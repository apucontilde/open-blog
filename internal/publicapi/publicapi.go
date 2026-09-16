// Package publicapi is the cache-friendly public read surface for reader
// sites: GET /public/{tenant}/site, /public/{tenant}/posts and /posts/{slug}.
// No auth, no sessions, no rate limiting — flood control is a CDN/WAF job
// (plan 009). Only status='published' rows are served; drafts and archives
// are indistinguishable from missing (ST-2, ST-3). content_html is the
// render-on-publish artifact and is served verbatim: the read path never
// renders markdown (ST-22).
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
	// CacheControl is shared by every public response. s-maxage bounds edge
	// freshness; stale-while-revalidate=300 covers purge lag of ≤ one
	// reconcile cycle (009 sweep Q2).
	CacheControl = "public, s-maxage=60, stale-while-revalidate=300"

	// defaultPageSize is the page the list index scan walks when the
	// constructor omits one; maxPageSize caps the configurable limit.
	defaultPageSize = 25
	maxPageSize     = 100
)

// tenantResolver is the minimal slug→tenant surface the handlers depend on.
type tenantResolver interface {
	ResolveSlug(ctx context.Context, slug string) (uuid.UUID, int64, error)
}

// Config carries the constructor knobs: page size, resolver TTL and the media
// CDN origin used as the fallback base for relative variant urls.
type Config struct {
	PageSize   int           // 0 => defaultPageSize
	ResolveTTL time.Duration // 0 => tenancy.DefaultTTL
	MediaCDN   string        // e.g. https://media.example.com
}

// API is the public read surface. Handlers are pure request→response funcs
// returning a fully-formed Response; the admin mux (010) wires the routes and
// writes them verbatim.
type API struct {
	db          *store.DB
	resolver    tenantResolver
	pageSize    int
	mediaOrigin string
}

// New builds an API over db; Config zero values select the defaults.
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

// Response is a fully-formed HTTP response the mux writes verbatim without
// further transformation; handlers never touch the network. Client errors are
// encoded in Status/Body; only unexpected failures surface as Go errors.
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

// errorResponse is the JSON-only error shape shared by every client error.
func errorResponse(status int, msg string) *Response {
	b, _ := json.Marshal(map[string]string{"error": msg})
	h := make(http.Header)
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", CacheControl)
	return &Response{Status: status, Header: h, Body: b}
}

// notModified honors a matching If-None-Match: 304 with the validator and
// cache directives, no body.
func notModified(etag string) *Response {
	h := make(http.Header)
	h.Set("Cache-Control", CacheControl)
	h.Set("ETag", `"`+etag+`"`)
	return &Response{Status: http.StatusNotModified, Header: h}
}

// etag derives a deterministic, replica-stable validator from its parts:
// hex-encoded sha256 over each part separated by NUL. The value is stable
// across replicas because it never includes process-local state.
func etag(parts ...any) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%v\x00", p)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// etagMatches implements the RFC 7232 weak comparison for If-None-Match:
// the whole comma-separated list against one current tag, ignoring quotes,
// a leading W/ and wildcard semantics.
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

// resolveTenant maps the shared resolver's failures to client responses;
// unexpected errors propagate so the mux can 500 without caching the failure.
func resolveTenant(err error) (*Response, bool) {
	switch {
	case errors.Is(err, tenancy.ErrInvalidSlug):
		return errorResponse(http.StatusBadRequest, "invalid tenant slug"), true
	case errors.Is(err, tenancy.ErrNotFound):
		return errorResponse(http.StatusNotFound, "tenant not found"), true
	}
	return nil, false
}
