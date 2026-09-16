# 007 — Adversarial review adjudication

Sweep verdict: **APPROVE-WITH-EDITS**. Author verdict: **APPROVED** (edits applied to `plan.md`).

| # | Severity | Category | Verdict | Applied in plan |
|---|----------|----------|---------|-----------------|
| 2 | Critical (003) | consistency | **Adopt (note)** — the Google path reads `oauth_tokens` (003), keyed `(user_id, provider)`, decrypted AEAD; `gdocExport` never assumes a token exists; `token_scopes` gates the attempt | §Conversion matrix, §Sweep resolutions #4 |
| 27 | Medium | consistency | **Adopt** — apply-idempotency gate: `post_id IS NOT NULL` → 409; after the draft is deleted (`post_id` NULLed by FK) re-apply creates a fresh draft; never re-convert an applied import | §Contracts apply |
| 9 | High (008) | correctness | **Adopt (note)** — import job enqueued in the same tx as the `imports` row | §Contracts imports |
| Q1 pandoc vs pure-Go | — | decision | **Adopt pandoc + pdftotext**, container-pinned, worker-only, 10 s timeout + 2 MiB caps | §Conversion matrix, §Sweep resolutions #1 |
| Q2 fidelity metadata | — | decision | **Adopt keep `imports.fidelity`/`error` after apply** (re-import warnings stay queryable); `post_id` owns re-apply semantics | §Sweep resolutions #2 |
| Q3 re-consent dance | — | decision | **Adopt silent refresh-then-hint**; lazy `drive.readonly` grant + refresh token in `oauth_tokens`; 401 + re-consent on expiry | §Sweep resolutions #3 |

Leaveover: conversion matrix, malicious-document fixture, sanitization via the 005 renderer — unchanged.