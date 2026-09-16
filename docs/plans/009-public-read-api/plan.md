# 009 — Public read API + caching + cursor pagination

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 001, **005 (render-on-publish), 006 (variants → srcset)**. ST-1..4, ST-22.

## Goal

A read-only, massively cacheable API for the reader sites. Public reads cost near-nothing: CDN first,
pre-rendered HTML second, an indexed point-read last. No markdown, no rendering, no auth on this path.

## Contracts (ST-1..ST-4)

| Endpoint | Behavior |
|---|---|
| `GET /public/{tenantSlug}/site` | Tenant settings (nav/branding/SEO). ETag = hash(`tenants.content_version`, `updated_at`). |
| `GET /public/{tenantSlug}/posts?before={cursor}&tag=` | Keyset-paginated list, newest-first; metadata only (no body) — ST-3/ST-4. ETag includes `content_version`. |
| `GET /public/{tenantSlug}/posts/{slug}` | Full post: `title, excerpt, content_html, author, published_at, images[]` — ST-1. 404 for drafts/archives, indistinguishable from missing (ST-2). |

## Caching strategy

- **CDN directives:** `Cache-Control: public, s-maxage=60, stale-while-revalidate=300`; single-post + list +
  site all edge-cacheable. Reader sites revalidate via ISR.
- **Currently no tenant:** resolve `tenantSlug → tenant_id` via a small shared resolver
  `internal/tenancy.ResolveSlug(ctx, slug)` (sweep, 009 Q1): exposed once, used by the public handlers
  (and by platform drill-down if ever needed); unscoped `tenants` lookup by slug, cached per-replica with a
  short TTL — new-tenant visibility lags ≤TTL. 004 never resolves slugs (its scope is already an id from
  `sessions.scope`), so there is nothing duplicated.
- **Generation tag for purge (sweep, finding 6 — 001 now has the column):** `tenants.content_version`,
  bumped in the same tx as every publish/PATCH-of-published/archive/unpublish (005) and tenant-settings
  change (010); purge job (008) tells the CDN to drop exactly that tenant's keys. ETags are derived from it.
- **Published-only filter is explicit:** RLS gives tenant isolation but not status; the public query adds
  `status='published'` unconditionally (ST-2/ST-3).
- **App-level rate limiting does not run on this path** (sweep, finding 21): flood control is a CDN/WAF
  job; the in-memory buckets live on auth/mutation routes only (010).

## Implementation sketch (`internal/publicapi`)

```go
// list — one query, keyset cursor, no OFFSET. Matches 001's index EXACTLY (id desc appended, finding 10):
SELECT id, slug, title, excerpt, published_at, author_id
FROM posts
WHERE tenant_id = $1 AND status = 'published'
  AND (published_at, id) < ($2, $3)             -- cursor: (published_at, id)
ORDER BY published_at DESC, id DESC
LIMIT $4
```

Cursor encodes `(published_at, id)`; stable under concurrent writes (keyset, not OFFSET). The 001 index
`posts (tenant_id, status, published_at desc, id desc)` satisfies the whole query as a pure range scan —
published-at ties (batch imports) stay O(rows-in-page), never a heap sort.

```go
// single post — fixed GROUP BY, deterministic image order (sweep, finding 14):
SELECT p.title, p.excerpt, p.content_html, p.published_at, u.display_name,
       coalesce(jsonb_agg(pi.variants ORDER BY pi.position)
                filter (where pi.id is not null), '[]')
FROM posts p
JOIN users u ON u.id = p.author_id
LEFT JOIN post_images pi ON pi.post_id = p.id AND pi.tenant_id = p.tenant_id
WHERE p.tenant_id = $1 AND p.slug = $2 AND p.status = 'published'
GROUP BY p.id, u.id
```

`images[]` is built **in Go from the canonical `variants` shape (006)** — width/url pairs → `srcset`;
no `->'srcset'` assumption (sweep, finding 13), no per-image queries.

## ETag / conditional GET

- List/site: ETag = hash(`tenants.content_version`, cursor, filters). Single post: ETag = hash of
  `content_html` length + `updated_at` (cheap, stable across replicas). 304 honors `If-None-Match`.

## Performance (ST-22)

- Read path: 1 point-read / 1 indexed range-scan. `content_html` is already rendered (005) → the API does
  **no** markdown, **no** highlight, **no** per-request joins beyond the single post's author+images.
- CDN absorbs repeat traffic; a repeat reader rarely touches a DB connection (plan §10).
- `?tag=` filter (JSONB `@>` on `posts.metadata`) is backed by the 001 GIN index; the app-level limiter is
  off this path by design.

## Sweep resolutions (see `review.md`)

1. **Slug→tenant resolver:** `internal/tenancy.ResolveSlug`, shared, TTL-cached; lives here (no cycle).
2. **stale-while-revalidate=300:** kept — purge deadline ≤1 purge cycle; ISR revalidates within the window.
3. **`jsonb_agg` shape:** adopted with fixes (GROUP BY `p.id, u.id`, `ORDER BY pi.position`,
   composite-tenant join); variants handled in Go from 006's canonical shape.
4. **New in sweep:** depends on 006; ETag base = `content_version` (+`updated_at`); index + `id desc`;
   app rate limit kept off the public path.