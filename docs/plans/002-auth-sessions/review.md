# 002 — Adversarial review adjudication

Sweep verdict: **REWRITE**. Author verdict: **APPROVED** (all findings applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 3 | Critical | correctness | **Adopt** — `Login` selects `id,password_hash` and issues on the verified `userID` via exported `Issue(ctx, userID, ttl, scope)` (fixes the zero-`userID` insert AND the 003↔002 name mismatch); `rand.Read` errors checked | §Implementation sketch |
| 3b | Critical | correctness | **Adopt** — constant-time login: unknown email runs argon2 against a fixed dummy hash | §Contracts, §Login |
| 4 | Critical | correctness | **Adopt** — signup 409 `code:"invited"` when a pending invitation exists for the normalized email; invitation consumption stays SSO-only, verified-email-gated | §Contracts, §Sweep resolutions #5 |
| 11 | High | correctness | **Adopt** — cookie `SameSite=Lax` (Strict breaks the OAuth callback); token mode for cross-origin editor | §Design cookie |
| 24 | Medium | consistency | **Adopt** — password_hash is **text** (`$argon2id$…` string; schema fix in 001) | §Design hashing |
| 29 | Medium | cleanliness | **Adopt** — fixed absolute 30d expiry; expired rows swept by the 008 cleanup job | §Design expiry |
| Q1 multi-session | — | decision | **Keep multi** (optional logout-others later) | §Sweep resolutions #1 |
| Q2 argon2 worker pool | — | decision | **Adopt in-handler, no pool**; weighted semaphore ≤4 bounds the 64 MiB/hash peak | §Design, sketch |
| Q3 SameSite | — | decision | **Adopt Lax** (see #11) | §Sweep resolutions #3 |
| Q4 sliding vs fixed | — | decision | **Adopt fixed absolute 30d** | §Sweep resolutions #4 |

Leaveover: `Verify` touches nothing (no sliding extension) — unchanged.