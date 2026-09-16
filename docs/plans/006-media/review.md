# 006 — Adversarial review adjudication

Sweep verdict: **APPROVE-WITH-EDITS**. Author verdict: **APPROVED** (edits applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 1 | Critical (001) | correctness | **Adopt (note)** — composite FK `(tenant_id, post_id) → posts(tenant_id, id)` (001) is the DB backstop behind presign key pinning | §Contracts confirm |
| 13 | High | consistency | **Adopt** — canonical `variants` JSON shape defined here (`{"480":{url,width,height},...}`); **009 builds `srcset` in Go**, no `->'srcset'` assumption; 006 is now a 009 dependency | §Canonical shape, §Contracts worker |
| 23 | Medium | correctness | **Adopt** — `unique (tenant_id, r2_key)` + confirm `ON CONFLICT DO NOTHING` (double-confirm = 0 rows = idempotent); delete permission aligned with 005: author-own-draft / editor+ | §Contracts confirm/delete |
| 16 | High (008) | perf | **Adopt (note)** — variant jobs capped by a libvips semaphore (2–4); multiple worker goroutines in 008 | §Design resize |
| Q1 libvips/cgo | — | decision | **Adopt keep govips** — WebP encoding has no mature pure-Go path; container-pinned, worker-only, semaphore-capped, animated-GIF → first frame, AVIF decode supported | §Design, §Sweep resolutions #1 |
| Q2 deletion permission | — | decision | **Adopt author-own-draft / editor+** (aligned with 005) | §Sweep resolutions #2 |
| Q3 variants storage | — | decision | **Adopt jsonb with the canonical shape** (no child table; no join on read) | §Sweep resolutions #3 |

Leaveover: R2 layout, presigner, sweeper quarantines (24h) unchanged.