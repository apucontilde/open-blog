# 005 — Adversarial review adjudication

Sweep verdict: **APPROVE-WITH-EDITS**. Author verdict: **APPROVED** (edits applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 15 | High | correctness | **Adopt** — PATCH on a published post re-renders AND enqueues the CDN purge + bumps `tenants.content_version` in the same tx (draft PATCHes don't purge) | §Contracts PATCH, §Publish/PATCH sequence |
| 6 | Critical (consistency) | consistency | **Adopt** — the purge's generation key is now `tenants.content_version` (column added in 001) | §Publish/PATCH sequence, §Contracts |
| 9 | High (008) | correctness | **Adopt** — every purge job row is inserted **inside** the domain tx (jobs inserts carry `dedupe_key`) | §Publish/PATCH sequence |
| 20 | High (004) | correctness | **Adopt (note)** — author-own-draft row filter is role-conditional (004 owns it); 005 consumes it | §Contracts (rules text) |
| Q1 re-render | — | decision | **Adopt every PATCH + publish** (draft-preview parity + editor autosave depend on current `content_html`) | §Goal, §Contracts |
| Q2 metadata shape | — | decision | **Adopt JSONB + GIN index** (001) for `?tag=`; schema freedom retained | §Sweep resolutions #2 |
| Q3 slug immutability | — | decision | **Adopt immutable once published**; PATCH rejects slug on published posts | §Contracts, §Sweep resolutions #3 |

Leaveover: renderer/parity golden tests (both preview path and ST-1 body shape) unchanged — extended to
assert draft-preview == server `content_html`.