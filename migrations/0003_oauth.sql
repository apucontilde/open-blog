-- +goose Up
-- +goose StatementBegin
create table oauth_flows (
    id            uuid primary key default gen_random_uuid(),
    provider      text not null check (provider in ('google','github')),
    state         bytea not null,            -- sha256 of the single-use state nonce
    code_verifier bytea not null,            -- PKCE S256 verifier, server-side only
    redirect      text not null,
    session_token_hash bytea,                -- sha256 of the initiating session; NULL for guest start
    expires_at    timestamptz not null,
    created_at    timestamptz not null default now()
);
create index on oauth_flows (expires_at);

create table oauth_tokens (
    user_id       uuid not null references users(id) on delete cascade,
    provider      text not null check (provider in ('google','github')),
    refresh_token bytea,                     -- AEAD-GCM ciphertext; NULL when never issued
    access_token  bytea,                     -- AEAD-GCM ciphertext
    token_scopes  text not null default '',  -- comma-joined granted scopes; gates refresh
    token_expiry  timestamptz,
    primary key (user_id, provider)
);
-- +goose StatementEnd