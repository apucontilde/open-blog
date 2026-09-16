# 001 — Schema, migrations & RLS foundation

Status: **approved** (sweep adjudicated — see `review.md`).
Depends on: none · Unlocks: 002–010.
Verify against: `docs/plans/00-index.md` (stack constraints), stories ST-2, ST-3, ST-6, ST-16, ST-17, ST-20.

## Goal

The relational schema + row-level security layer everything else runs on. Grants one Oracle-of-Truth: a
connection is either scoped to one tenant, or platform-wide, and **the DB itself** enforces it.

Not included (later plans): HTTP, services, auth flows, caching.

## Security & tenancy contract

- Single DB role `blog_app` owns the schema. Not superuser; never dropped into `SET ROLE`.
- Scope is carried on the connection with `SET LOCAL` **inside a short transaction per request**:
  - `SELECT set_config('app.tenant_id', $1, true)` — the tenant UUID (`$1 = NULL` → "no tenant").
  - `SELECT set_config('app.platform', 'on', true)` — only set when Go already verified the actor is
    `super_admin`/tenant-owner. The flag is a DB-side capability, the *authorization* stays in Go.
- `FORCE ROW LEVEL SECURITY` on every tenant-scoped table: the owner role is
  subject to policies — no owner-bypass backdoor. (With one connection role, plain `ENABLE` would let the
  owner read everything; `FORCE` closes that.)
- **`memberships` is NOT RLS-scoped** (sweep, 001 Q1): the tenant switcher (ST-20) and `/auth/me` must
  resolve a user's memberships across *all* their tenants, which single-tenant scoping forbids. Platform
  tables: `users, identities, sessions, memberships, invitations, oauth_flows, oauth_tokens, jobs, tenants`.
  Tenant-scoped tables (RLS `FORCE` + `tenant_scope` policy): **`posts, post_images, imports`**. All
  membership queries filter `user_id = $actor` (server-bound).
- Every tenant-scoped table gets one policy, identical shape:

  ```sql
  create policy tenant_scope on <table>
    using      (app_scope() or tenant_id = current_tenant())
    with check (app_scope() or tenant_id = current_tenant());
  ```

  `current_tenant()` is `NULL` when unset → policy evaluates to `NULL` → no rows. **Fail closed.**
  `app_scope()` is `true` only when `app.platform` was set — the sole cross-tenant path, and it only
  *widens the row filter*; base permissions still run through Go RBAC (plan 004).
- `SET` without `LOCAL` is banned by convention + linted (single spot: the scope wrapper). Pooled
  connections never leak a tenant.

## ID strategy — decided (sweep, finding 1/001 Q5)

**A · UUID v7 everywhere, app-minted.** `github.com/google/uuid`. Runtime inserts always supply a v7 id
(pre-known for media, jobs, imports, idempotent create-retries); the DDL default stays `gen_random_uuid()`
(v4) purely as a safety fallback for tooling inserts. Ids are opaque to clients and **never ordered by**;
ordering is by `created_at`/`published_at`/`content_version`. Rationale: presign keys need key material
before a row exists, jobs/imports need ids for retry dedupe, and future schema split is collision-free.
The `(tenant_id, bigserial)` alternative loses all three for marginal index width.

## Schema (`migrations/0001_tables.sql`)

**Role storage (sweep, 001 Q2):** DB `text` + CHECK constraint; Go-side iota enum with `String()`
owns ordering/authz logic. `CREATE TYPE … role` was rejected: adding a role would force an
`ALTER TYPE … ADD VALUE` migration for a string. Identical constraint safety, cheaper evolution.

```sql
create type post_status   as enum ('draft','published','archived');
create type import_status as enum ('converting','done','error');
create type job_state     as enum ('queued','running','done','failed');

create table tenants (
    id              uuid primary key default gen_random_uuid(),
    slug            text not null unique check (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    name            text not null,
    settings        jsonb not null default '{}'::jsonb,
    content_version bigint not null default 0,   -- bumped on any public-visible change (sweep, 005/009 ETags)
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

create table users (
    id            uuid primary key default gen_random_uuid(),
    email         text not null,
    password_hash text,                     -- argon2id encoded string ($argon2id$v=19$…), text not bytea (sweep)
    display_name  text not null,
    avatar_url    text,
    super_admin   boolean not null default false,   -- single global flag (sweep, 004 Q1)
    created_at    timestamptz not null default now()
);
-- email uniqueness is case-insensitive: normalized in Go + enforced here (sweep, ST-19)
create unique index on users (lower(email));

create table memberships (
    tenant_id uuid not null references tenants(id) on delete cascade,
    user_id   uuid not null references users(id)   on delete cascade,
    role      text not null check (role in ('owner','admin','editor','author')),
    primary key (tenant_id, user_id)
);

create table identities (
    provider text not null,             -- 'google' | 'github'
    subject  text not null,             -- provider user id
    user_id  uuid not null references users(id) on delete cascade,
    primary key (provider, subject)
);
create index on identities (user_id);

create table sessions (
    token_hash bytea not null primary key,  -- sha256 of the opaque token
    user_id    uuid not null references users(id) on delete cascade,
    scope      uuid,                       -- active tenant, nullable = none yet
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);
create index on sessions (user_id);
create index on sessions (expires_at);

create table posts (
    id               uuid primary key default gen_random_uuid(),
    tenant_id        uuid not null references tenants(id) on delete cascade,
    author_id        uuid not null references users(id),
    slug             text not null,
    title            text not null,
    excerpt          text not null default '',
    content_markdown text not null default '',
    content_html     text not null default '',   -- render-on-publish artifact
    status           post_status not null default 'draft',
    published_at     timestamptz,
    metadata         jsonb not null default '{}'::jsonb,
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now(),
    unique (tenant_id, slug),
    unique (tenant_id, id)         -- FK anchor for child tables (sweep: prevents cross-tenant attach)
);
create index on posts (tenant_id, status, published_at desc, id desc);
create index on posts using gin (metadata jsonb_path_ops);   -- ?tag= filters (sweep)

create table post_images (
    id         uuid primary key default gen_random_uuid(),
    tenant_id  uuid not null references tenants(id) on delete cascade,
    post_id    uuid not null references posts(id) on delete cascade,
    r2_key     text not null,
    url        text not null,
    width      integer not null,
    height     integer not null,
    size_bytes bigint not null,
    mime_type  text not null,
    position   integer not null default 0,
    variants   jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, post_id) references posts (tenant_id, id) on delete cascade,  -- sweep: no cross-tenant attach
    unique (tenant_id, r2_key)                                                            -- sweep: confirm idempotency
);
create index on post_images (post_id);

create table invitations (
    id         uuid primary key default gen_random_uuid(),
    tenant_id  uuid not null references tenants(id) on delete cascade,
    email      text,
    role       text not null check (role in ('owner','admin','editor','author')),
    token_hash bytea,                 -- role-baked link, nullable for pure-email invites
    expires_at timestamptz not null,
    consumed_at timestamptz
);
create index on invitations (lower(email)) where email is not null;

create table imports (
    id            uuid primary key default gen_random_uuid(),
    tenant_id     uuid not null references tenants(id) on delete cascade,
    user_id       uuid not null references users(id),
    post_id       uuid references posts(id) on delete set null,
    source_format text not null,
    source_key    text not null,
    status        import_status not null default 'converting',
    markdown_out  text,
    error         text,
    created_at    timestamptz not null default now(),
    updated_at    timestamptz not null default now(),
    foreign key (tenant_id, post_id) references posts (tenant_id, id) on delete set null  -- sweep: no cross-tenant attach
);
create index on imports (status, updated_at);

create table jobs (
    id         uuid primary key default gen_random_uuid(),
    kind       text    not null,
    dedupe_key text,                 -- sweep: makes the ON CONFLICT idempotency enforceable
    payload    jsonb   not null default '{}'::jsonb,
    state      job_state not null default 'queued',
    attempts   integer not null default 0,   -- counts RUNS (incremented on claim), not failures
    run_after  timestamptz not null default now(),
    lease_until timestamptz,                  -- sweep: claim lease; EXPIRE sweep requeues while running
    last_err   text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index on jobs (state, run_after) where state <> 'done';
create unique index on jobs (kind, dedupe_key) where dedupe_key is not null;
```

Rub: `post_images`, `imports`, `jobs` carry `tenant_id` — only the first two are tenant-scoped by RLS
(`jobs` is platform-owned; see "Non-scoped tables" below).

## RLS (`migrations/0002_rls.sql`)

```sql
create function app_scope() returns boolean
language sql stable strict as $$
    select current_setting('app.platform', true) = 'on'
$$;
-- NULL-safe: strict + current_setting with missing_ok drops to NULL -> not 'on' -> false

create function current_tenant() returns uuid
language sql stable strict as $$
    select nullif(current_setting('app.tenant_id', true), '')::uuid
$$;

-- one call per tenant-scoped table; the set is FIXED: posts, post_images, imports only (sweep)
do $$
declare t text;
begin
    foreach t in array array['posts','post_images','imports'] loop
        execute format('alter table %I enable row level security', t);
        execute format('alter table %I force row level security', t);
        execute format($p$
            create policy tenant_scope on %I
            using      (app_scope() or tenant_id = current_tenant())
            with check (app_scope() or tenant_id = current_tenant())$p$, t);
    end loop;
end $$;
```

**Which tables are tenant-scoped?** Only `posts`, `post_images`, `imports` (the DO-block set). `memberships`
is **deliberately unscoped** (sweep, 001 Q1): the tenant switcher (ST-20) and `/auth/me` must resolve a
user's memberships across all their tenants *before* a tenant scope exists — a single-tenant scope on
memberships would make it impossible to list "which tenants can I switch to". Cross-tenant privacy comes
from every membership query filtering on `user_id = $actor` (server-bound, never client-supplied), not from
RLS. `sessions`, `users`, `identities`, `invitations`, `oauth_flows`, `oauth_tokens`, `jobs`, `tenants`
stay unscoped (platform/identity data; invitation consumption guards itself by `token_hash` + verified
email + atomic consume in 003). `invitations` unscoped (sweep, 001 Q4): it is tenant-cosmetic and must be
readable before a session scope exists; risking a pending-invite row leak is acceptable because the
consuming identity must also prove verified mailbox control.

## Go — `internal/store`

```go
// Package store owns the pool, migrations, and the scoped-transaction wrapper.
package store

type Scope struct {
	TenantID uuid.UUID // zero => unscoped (fails closed for tenant tables)
	Platform bool      // cross-tenant read; only Go-set after role verification
}

// Scoped runs fn in a short transaction that carries exactly this scope.
// Every tenant-aware query must go through here.
func (d *DB) Scoped(ctx context.Context, s Scope, fn func(q *Queries) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// zero TenantID => SQL NULL (fail closed), NEVER the empty string (sweep): '0000…' would match
	// a tenant row whose id is the nil uuid and degenerate fail-closed into a real scope.
	var tenantID any // nil
	if !s.TenantID.IsNil() {
		tenantID = s.TenantID
	}
	// Single multi-statement round trip: open + set scoping vars (sweep, read path thrift).
	if _, err := tx.Exec(ctx, "begin read only; select set_config('app.tenant_id', $1, true)",
		tenantID); err != nil {
		return err
	}
	if s.Platform {
		if _, err := tx.Exec(ctx, "select set_config('app.platform', 'on', true)"); err != nil {
			return err
		}
	}
	if err := fn(&Queries{tx: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

`Queries` is a thin, explicit struct — handwritten `SELECT`s returning domain types; no ORM, no
autogenerated model layer. Example (tenant-scoped write stays invisible to other tenants via RLS):

```go
func (q *Queries) CreatePost(ctx context.Context, p Post) (Post, error) {
	row := q.tx.QueryRow(ctx, `
		insert into posts (id, tenant_id, author_id, slug, title, excerpt, content_markdown)
		values ($1, $2, $3, $4, $5, $6, $7)
		returning id, tenant_id, author_id, slug, title, excerpt, content_markdown,
		          status, published_at, metadata, created_at, updated_at`,
		p.ID, p.TenantID, p.AuthorID, p.Slug, p.Title, p.Excerpt, p.ContentMarkdown)
	return scanPost(row)
}
```

Rationale: SQL is the plan of record (RLS must see *exactly* what DB tuples a query touches), pgx
executes it at near-plain-C speed, and there is no mapping layer to drift from the schema.

## Migrations pipeline

- `goose` embedded via `embed.FS`; `cmd/migrate` runs `goose up`, `goose down` for test reset.
- One schema (`public`). Migrations are append-only; tests re-run them from scratch on a disposable DB.
- Idempotency: migration files are immutable; no `if not exists` inside them.

## Contract tests (this is the module's real deliverable)

`internal/store/rls_test.go` — runs migrations into a scratch database, then asserts RLS behavior from
the same `Scope` API the app uses:

1. `TestTenantIsolation` — tenants A+B, one post each; `Scope{A}` lists 1 row; A cannot attach a
   `post_images`/`imports` row to B's post (composite FK rejects: cross-tenant `posts(tenant_id,id)`
   has no match), cannot update B's memberships, cannot reach B's rows.
2. `TestFailClosed` — a bare `Scoped{scope zero}` (no tenant) reads 0 rows from `posts`; write attempts
   are rejected by `with check`. **Reasserted against a tenant row whose id is the nil uuid** (sweep:
   the nil-cast must still yield SQL NULL → policy NULL → no rows). Drafts in another tenant are not
   visible (ST-2/ST-3).
3. `TestPlatformSeesAll` — `Scope{Platform:true}` sees A and B (ST-17); and still cannot bypass Postgres
   FK/type rules.
4. `TestNoScopeLeakBetweenConnections` — run A, reuse the same pooled connection for an unscoped op;
   the second op sees nothing. Asserts `SET LOCAL` provenance + pgx pool safety. Also assert writes are
   `BEGIN READ ONLY`-guarded where the scope is non-mutating.
5. `TestMembershipScoping` (sweep re-target) — reads of memberships **always** filter on the actor's own
   `user_id` (server-bound); a cross-tenant or foreign `user_id` probe returns 0 rows; the switcher
   (ST-20) can list all of the actor's memberships unscoped; role resolvable per tenant.
6. `TestRlsLint` — introspect `pg_policies`/`relrowsecurity`; fail if any table in the tenant-scoped set
   (`posts, post_images, imports`) lacks `FORCE` + the `tenant_scope` policy, or if any other table got
   one. Also **rejects tenant-scoped DML in goose migrations** (sweep): backfills must run under a
   privileged `blog_migrate` role or an explicit `SET LOCAL app.platform` — otherwise `FORCE` silently
   no-ops DML into 0 rows and migrations "succeed". CI runs it on every push.
7. `TestPlatformScopeDiscipline` (sweep, 004-invariant) — `Platform` in a scope is only ever derived from
   an actor whose flag/role was verified in middleware; the test pins the one construction site (010
   `scopeFromActor`) and fails if any store call flips it ad hoc.

## Performance notes

- `FORCE` + add `SET LOCAL` costs microseconds; the real cost is one tx per request — negligible next to
  auth/markdown work, and it buys atomicity for every multi-write (e.g. publish+cleanup).
- Indexes above match the ST-22 hot path: `posts (tenant_id, status, published_at desc, id desc)` fully
  satisfies the 009 keyset cursor (`ORDER BY published_at DESC, id DESC`) as an index range scan — without
  the trailing `id`, published-at ties (batch imports) would degrade to a heap sort (sweep).
- `gen_random_uuid()` in DDL is a v4 fallback default; runtime inserts always supply an app-minted v7 id
  (pre-known for media/jobs/imports).
- Batch: import/job workers use `tx.CopyFrom` for multi-row inserts (plan 008). Read-only scopes open
  `BEGIN READ ONLY` and set scoping vars in the same round trip as `BEGIN` (see `Scoped`).

## Sweep resolutions (see `review.md`)

1. **memberships under RLS?** No — unscoped by design (switcher + `/auth/me` need cross-tenant reads);
   the 0002 DO-block comment/array contradiction is fixed; membership privacy = `user_id = $actor`.
2. **Role enum vs text+Go enum?** Text + CHECK; Go iota enum owns semantics. No `ALTER TYPE` tax.
3. **`FORCE` + migrations-as-owner?** All migrations are DDL-only; `TestRlsLint` rejects tenant-scoped
   DML in goose files; backfills use a privileged `blog_migrate` role or explicit platform scope.
4. **Invitations RLS?** Unscoped; consumption gated on verified mailbox + atomic consume (003).
5. **ID strategy?** A · uuid v7 app-minted everywhere (see §ID strategy). Decided.