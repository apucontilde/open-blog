# 006 — Media: presign/confirm, R2 layout, variants worker

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 001, 004, 008 (variant + sweeper jobs). Unlocks 007; **consumed by 009** (variants → `srcset`).

## Goal

Images never pass through the API: bytes go client → R2, DB keeps metadata only (ST-7). Variants
(480/800/1200 + WebP) are built by a worker at confirm time; the blocker deploys R2 + Cloudflare CDN.

## Contracts (ST-7)

| Endpoint | Rules |
|---|---|
| `POST /admin/media/presign` `{post_id, filename}` | 201 `{upload_url, key}`: S3 presigned PUT (15 min) for `{tenant}/posts/{post_id}/{uuid}.{ext}`. Key pinned to the *active tenant* + an existing post the actor can edit — the composite FK below is the DB backstop. |
| `POST /admin/media/confirm` `{key, post_id, size_bytes, mime_type}` | Validate mime allow-list + size cap + key shape → insert `post_images` row (scope write) → enqueue `variant` job (008). **Idempotent** (sweep, finding 23): `unique (tenant_id, r2_key)` + `ON CONFLICT DO NOTHING`; 0 rows inserted = already confirmed → 204. **Composite FK `(tenant_id, post_id) → posts(tenant_id, id)` (001) blocks attaching to another tenant's post even with a compromised presign.** Confirm also verifies the post is editable in scope (author-own-draft rule, 005). |
| `DELETE /admin/media/{id}` | Post-edit permission (author own draft / editor+, aligned with 005); removes row; the R2 object dies via sweeper. |
| `(worker:variant)` | Resize original → `-480.webp`, `-800.webp`, `-1200.webp` (original stays); writes object + canonical `post_images.variants`; retried on failure. |
| `(worker:sweep)` | List tenant R2 prefix, diff against `post_images` rows, delete orphans; lifecycle rule on delete-marker as backstop. |

## Canonical `variants` JSON shape (sweep, finding 13 — 009 depends on this)

```json
{"480":{"url":"/posts/{postId}/{uuid}-480.webp","width":480,"height":320},
 "800":{"url":"...","width":800,"height":533},
 "1200":{"url":"...","width":1200,"height":800}}
```

`url` is a path (CDN-origin prefixed at render); **009 builds `srcset` in Go** from the parsed width/url
pairs — it never reads `->'srcset'` (deliberate: no shape drift between 006 and 009).

## R2 object layout (must match the CDN plan)

```
media.example.com/{tenantSlug}/posts/{postId}/{uuid}.jpg         (original)
media.example.com/{tenantSlug}/posts/{postId}/{uuid}-480.webp
media.example.com/{tenantSlug}/posts/{postId}/{uuid}-800.webp
media.example.com/{tenantSlug}/posts/{postId}/{uuid}-1200.webp
```

Keys embed tenant+post+random — a compromised presign URL cannot address another tenant's object.

## Media module (`internal/media`)

- **Presigner:** `aws-sdk-go-v2` S3 client pointed at R2 endpoint with `region=auto`, signature v4,
  `PresignClient.PresignPutObject` 15 min expiry; bucket + account prefix from env (no creds in code).
- **Image resize — govips/libvips kept** (sweep, 006 Q1): the one cgo dep in the repo is justified — WebP
  *encoding* has no mature pure-Go path, `cwebp` exec spawns a process per variant, and govips gives the
  fastest multi-size decode/resize on the worker. Constraints accepted by this choice: worker-only (never
  request goroutines), **concurrent variant jobs capped with a semaphore (2–4) so libvips memory stays
  bounded**, container-pinned libvips version, animated-GIF → first frame, AVIF decode supported.

```go
func (m *Media) ResizeVariants(ctx context.Context, original []byte, sizes []int) (map[string][]byte, error)
```

- **Security:** mimetype sniffed at confirm (not trusted from client), allow-list
  `image/jpeg|png|webp|gif|avif`, size cap 15 MiB (env). `width/height` recorded server-side after decode.

## Job wiring (008)

- `variant` job: `{key, post_id}` → read object → resize → multipart PUT variants → update
  `post_images.variants` (canonical shape). Idempotent (key-based; re-run safe).
- `sweep` job: `{tenant}` → per-tenant R2 list vs rows → delete orphans older than 24h (quarantine).

## Performance

- Zero bytes through the app on upload/download; the worker streams via S3 multipart (memory-bounded).
- Variants are the only CPU-heavy work — on the job queue (008), never a request goroutine, concurrency
  capped (2–4 libvips instances).
- CDN serves everything read-side; no API round trip per image (match plan section 9).

## Sweep resolutions (see `review.md`)

1. **libvips/cgo vs pure-Go:** kept (see Design). Container-pinned; semaphore-capped; worker-only.
2. **Deletion permission:** author-own-draft / editor+ — aligned with 005 (no divergence).
3. **Variants jsonb vs child table:** jsonb, **with the canonical shape above**; 009 renders `srcset` in Go.
4. **New in sweep:** composite `(tenant_id, post_id)` FK; `unique(tenant_id, r2_key)` + idempotent confirm;
   006 added to 009's dependency list.