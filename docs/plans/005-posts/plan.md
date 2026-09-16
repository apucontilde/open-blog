# 005 — Posts: CRUD, lifecycle, render-on-publish

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 001, 004 (Actor), 008 (purge job). Unlocks 006, 007, 009.

## Goal

The authorization object. Draft/published/archived lifecycle with **render-on-publish**: markdown is
converted to sanitized HTML once (at save/publish), never on the read path (ST-22). **Every PATCH and
every lifecycle transition re-renders** (sweep, 005 Q1): draft-preview parity (the editor autosave) and
the published representation both depend on `content_html` being current.

## Contracts (ST-5, ST-6, ST-8, ST-9, ST-10, ST-11)

| Endpoint | Rules |
|---|---|
| `POST /admin/posts` `{title, content_markdown, slug?, excerpt, metadata}` | 201 draft; `author_id` from Actor, `tenant_id` from scope (client-supplied tenant ignored — ST-5). Slug auto-derived and uniquified. |
| `GET /admin/posts?status=&author=` | Author sees own only; editor+ sees tenant-wide (ST-6/ST-11 listing half). Metadata + slug only, no markdown body. |
| `GET /admin/posts/{id}` | Draft or published; role-aware. Returns markdown + html (for editor preview refresh). |
| `PATCH /admin/posts/{id}` | Author: own draft only (ST-6). Editor+: any (ST-11). Re-renders `content_html`. **If the target is published: bumps `tenants.content_version`, enqueues the CDN purge in the same tx** (sweep, finding 15 — otherwise readers serve stale HTML until the s-maxage expires). Draft PATCHes do not purge. Slug immutable once published. |
| `POST /admin/posts/{id}/publish` | Editor+ (ST-9); requires non-empty content; sets `published_at = now()`; **bumps `tenants.content_version`**; enqueues purge job (008, same tx). |
| `POST /admin/posts/{id}/unpublish` / `archive` | Editor+ (ST-10); purge enqueued + `content_version` bumped; archived hides from public listing. |
| `DELETE /admin/posts/{id}` | Author (own draft) / editor+ (any); cascades images/imports refs by FK (imports `post_id` → NULL, so re-import is allowed); orphan purge via 006 sweeper. |

## Renderer (parity contract with the editor + import)

- GFM via `github.com/yuin/goldmark`, extension: fenced code + tables + strikethrough (GFM set), autolink.
- Syntax highlight via goldmark-highlighting (chroma) → **fenced code blocks only**, built-in theme,
  no external CLI. Server-side, deterministic output (ST-22: rendering never happens per-read).
- Sanitization: goldmark HTML parser emits a fixed element allow-list (ha1 `html5` safe by default but
  verified by a golden test for `data:`/`javascript:`), images restricted to the tenant's media CDN origin
  (`media.example.com`) unless `metadata` opts in otherwise.
- Output stored pun intended → `content_html` column already in 001; `updated_at` bumped on every write.

```go
func renderGFM(md []byte) ([]byte, error) // one call site, used by PATCH, publish, 007 apply
```

Golden tests (ST-1 body shape + preview parity): a known markdown fixture → expected sanitized HTML
snapshot; CI fails on any renderer/library bump that changes output. Same harness used by the editor's
preview-path test (draft preview must equal server `content_html`).

## Publish/PATCH sequence (atomic where possible)

1. tx: `UPDATE posts SET status='published', published_at=now(), updated_at=now() WHERE id=$1 AND tenant=$scope`
2. same tx: `UPDATE tenants SET content_version = content_version + 1, updated_at = now() WHERE id=$scope`
3. same tx: `INSERT INTO jobs (kind, dedupe_key, payload) VALUES ('purge', $dedupe, $payload)` — the job
   row is written **inside the transaction** (008, sweep, finding 9), not after commit: a crash between
   commit and enqueue would otherwise lose the purge forever.
4. On worker failure the job queue retries (008); the read path tolerates ≤1 purge cycle (001/009).

## Performance

- Read path is `SELECT ... WHERE tenant=$1 AND status='published' AND slug=$2` over the 001 index —
  `content_html` is a text column already rendered; zero CPU per read.
- List path projects only `(id, slug, title, excerpt, published_at, author)`; no markdown (001 note).
- `content_html` renders at write frequency only (edits are rare).

## Sweep resolutions (see `review.md`)

1. **Re-render every PATCH vs only publish:** every PATCH and publish (draft-preview parity + current
   published HTML in one tx); published PATCHes also purge.
2. **metadata shape:** JSONB stays (schema freedom is a stated product value); a `GIN (jsonb_path_ops)`
   index on `posts.metadata` backs `?tag=` filters (001) — defer it if tag filters stay rare.
3. **Slug immutability:** immutable once published; PATCH rejects slug changes on a published post.
4. **New in sweep:** same-tx job insert for every purge (publish/PATCH/archive/unpublish) + `content_version`
   bump; conditional author row-ownership lives in 004.