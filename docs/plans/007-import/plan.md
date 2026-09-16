# 007 — Import: PDF/DOCX/Google Docs/open formats → markdown

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: 001, 003 (`oauth_tokens`), 004, 005 (draft creation + renderer), 008 (job). Fidelity contract
per ST-23.

## Goal

Author uploads a document, lands in a **markdown draft**. Async conversion, preview before apply, never a
partial post (fidelity matrix mirrors plan section 9).

## Contracts (ST-23)

| Endpoint | Behavior |
|---|---|
| `POST /admin/imports` (multipart `{file}` or `{source:"google_docs", docId})` | 202 `{id, status:"converting"}`; original file stored in R2 (media presign reuse); `imports` row (scope write) + `import` job enqueued in the same tx. |
| `GET /admin/imports/{id}` | `{status, markdown_out?, fidelity, error?}` — idempotent poll + preview. |
| `POST /admin/imports/{id}/apply` | 201 draft via 005 rules (ST-5) with `content_markdown` = converted body; records `imports.post_id`. **Idempotency gate** (sweep, 007 Q2): `post_id IS NOT NULL` → 409 (re-apply is refused); when the produced draft is deleted, `imports.post_id` is NULLed by the FK and re-apply **is** allowed to create a fresh draft (the recoverable path). Never re-convert an applied import. |

## Conversion matrix (per-format job)

| Source | Converter | Fidelity |
|---|---|---|
| DOCX / ODT / RTF / HTML / MD | `pandoc` (system binary, `--wrap=none`) → markdown | high |
| Google Docs | export via linked Google identity → docx → pandoc path | high |
| PDF (text layer) | `pdftotext -layout` + heading heuristics | medium — flagged in `fidelity` warning |
| PDF (scanned, no text) | detect → `error` + remediation hint; no partial post | n/a |

- **pandoc + pdftotext kept as container-pinned system binaries, worker-only** (sweep, 007 Q1): DOCX/ODT/RTF/PDF
  fidelity is not a problem the repo should own in pure Go, and both are stable, pinned, offline. Explicit
  timeouts (10 s) and output size caps (2 MiB). Not found → `error` with a setup hint.
- **Google Docs path reads the author's token from `oauth_tokens` (003), keyed `(user_id, provider)`**
  (sweep, finding 2 — this table is what makes 007 buildable): `drive.readonly` was granted **lazily at
  the first Google import** (003), the refresh token is decrypted (AEAD), access token refreshed
  server-side; failure → 401 with a re-consent redirect (ST-23's "re-consent" clause). `gdocExport` never
  assumes a token exists; `oauth_tokens.token_scopes` gates the attempt.
- Sanitization is **not optional**: converted markdown passes through the exact 005 renderer on apply, so a
  hostile DOCX can never inject raw HTML into a reader page. Fixture tests include a malicious document.
- `imports.fidelity` and `error` persist **after apply** (sweep, 007 Q2 half): re-import warnings and the
  fidelity matrix stay queryable; nothing is discarded at apply time.

```go
type converter func(ctx context.Context, src []byte) (md []byte, fidelity string, err error)
var converters = map[string]converter{ "docx": pandoc, "odt": pandoc, "pdf": pdftotext+post, "gdoc": gdocExport }
```

## Performance

- Conversion is off-path (008 worker); one `pandoc` process ~100 ms–1 s, unbounded only by the per-format
  timeout. Scaled-safe: queue parallelism already caps via 008; imports and variants share the worker pool
  but native subprocesses (pandoc/pdftotext) are bounded by 008's semaphore.

## Sweep resolutions (see `review.md`)

1. **pandoc vs pure-Go:** pandoc + pdftotext, container-pinned, worker-only (fidelity argument wins).
2. **Fidelity metadata lost on apply?** No — `imports.fidelity`/`error` survive; `post_id` governs
   re-apply (409 when set, allowed again after the draft is deleted).
3. **Google re-consent dance:** silent refresh-then-hint; `drive.readonly` granted lazily at first import
   (003); refresh token in `oauth_tokens`; 401 + re-consent on expiry.
4. **New in sweep:** token store dependency on 003; same-tx job enqueue; composite FK keeps imports
   tenant-bound.