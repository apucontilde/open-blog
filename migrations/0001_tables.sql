-- +goose Up
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
