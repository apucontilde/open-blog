-- +goose Up
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
-- +goose StatementBegin
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
-- +goose StatementEnd
