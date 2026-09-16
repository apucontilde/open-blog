# 009 — Adversarial review adjudication

Sweep verdict: **REWRITE**. Author verdict: **APPROVED** (all findings applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 13 | High | consistency | **Adopt (note)** — `images[]` built in Go from 006's canonical `variants` shape → `srcset`; no `->'srcset'`; deps now `001, 005, 006` | §Goal, §Implementation sketch |
| 14 | High | correctness | **Adopt** — single-post query fixed: `GROUP BY p.id, u.id` (functional dependence), `jsonb_agg(pi.variants ORDER BY pi.position)`, LEFT JOIN pinned with `pi.tenant_id = p.tenant_id` | §Implementation sketch |
| 10 | High (001) | perf | **Adopt (note)** — list runs as a pure index range scan on `(tenant_id, status, published_at desc, id desc)`; ties stay O(rows-in-page) | §Implementation sketch, §Sweep resolutions |
| 6 | Critical (001) | consistency | **Adopt** — ETags derive from `tenants.content_version` (+`updated_at`); site ETag = hash(content_version, updated_at) | §Contracts, §Caching |
| 21 | High (010) | perf | **Adopt (note)** — no app-level rate limiter on this path (CDN/WAF owns flood control) | §Caching, §Sweep resolutions #2 |
| 28 | Medium (001) | perf | **Adopt (note)** — `?tag=` backed by the 001 GIN index | §Sweep resolutions #2 |
| Q1 slug resolver | — | decision | **Adopt shared `internal/tenancy.ResolveSlug`**, TTL-cached, lives here (004 never resolves slugs; no cycle, nothing duplicated) | §Caching, §Sweep resolutions #1 |
| Q2 stale-while-revalidate | — | decision | **Keep 300s** — purge deadline ≤1 reconcile cycle; ISR revalidates within the window | §Sweep resolutions #2 |
| Q3 jsonb_agg shape | — | decision | **Keep jsonb_agg** with the #14 fixes | §Sweep resolutions #3 |

Leaveover: conditional GET/304; published-only filter explicit; cursor keyset — unchanged.