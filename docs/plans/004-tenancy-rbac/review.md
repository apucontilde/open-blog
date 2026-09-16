# 004 — Adversarial review adjudication

Sweep verdict: **APPROVE-WITH-EDITS**. Author verdict: **APPROVED** (edits applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 5 | Critical | correctness | **Adopt** — memberships resolved unscoped across all of the actor's tenants (switcher + `/auth/me` depend on it); every membership query filters `user_id=$actor` | §Actor resolution, §Active-tenant switching |
| 20 | High | correctness | **Adopt** — author row-ownership filter is **conditional**: applied only when `!actor.Platform && actor.Role == RoleAuthor` — a platform actor editing any tenant isn't 403'd by it | §Row-ownership rules |
| 26 | Medium | cleanliness | **Adopt** — the only `store.Scope` construction site from an Actor is the 010 middleware `scopeFromActor`; `Platform:true` never settable from handlers; invariant test pinned in 001 (#7 contract test) | §Scope construction |
| 11 | High (002) | correctness | **Adopt** — cookie mode SameSite=Lax; the 004 question (#3) resolved the same way | §Cookie mode |
| Q1 super_admin shape | — | decision | **Adopt `users.super_admin boolean`** (one global flag; platform-membership rejected) | §Actor resolution |
| Q2 role ordering | — | decision | **Adopt Go iota enum** for ordering; DB `text`+CHECK stores it | §Actor resolution |
| Q3 cookie mode | — | decision | **Adopt SameSite=Lax + token mode** (see #11) | §Cookie mode |

Leaveover: capability ladder + `require(cap)` unchanged; platform is a boolean, not a ladder rank.