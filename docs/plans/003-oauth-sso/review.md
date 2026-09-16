# 003 — Adversarial review adjudication

Sweep verdict: **REWRITE**. Author verdict: **APPROVED** (all findings applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 2 | Critical | consistency | **Adopt** — new `oauth_tokens` table (refresh/access AEAD-encrypted + `token_scopes`) — without it 007's Google import was unbuildable | §Data, migration `0003_oauth.sql` |
| 12 | High | correctness | **Adopt** — `oauth_flows.session_token_hash` binds the flow to the initiating session; verify at callback before any IdP call | §Data, §Design + sketch |
| 12b | High | correctness | **Adopt** — callback standardized on **GET** (arch sequence-diagram `POST` was wrong); expired flows cleared by the 008 cleanup job | §Contracts, §Design |
| 17 | High | correctness | **Adopt** — atomic invitation consume: `UPDATE invitations SET consumed_at=now() WHERE id=$1 AND consumed_at IS NULL [AND lower(email)=lower($2)] RETURNING role,tenant_id`; 0 rows → idempotent (ST-19); membership insert `ON CONFLICT ... DO NOTHING` | §Contracts `ConsumeInvitation`, §Design |
| 18 | High | correctness | **Adopt** — email normalized lowercase on every write; matching on `lower(email)` | §Design, contracts |
| Q1 drive.readonly scope | — | decision | **Adopt lazy** — login = `openid email profile`; `drive.readonly` granted ad hoc at first Google import (007), stored in `oauth_tokens.token_scopes` | §Design scopes, contracts |
| Q2 merge accounts | — | decision | **Adopt one `users` per normalized verified email, multiple `identities`**; link allowed on verified mailbox proof | §Design |
| Q3 redirect allow-list | — | decision | **Adopt scheme+host+path from env** | §Design callback security |

Leaveover: replay of a consumed `state` or expired flow → 401 with zero IdP calls (unchanged).