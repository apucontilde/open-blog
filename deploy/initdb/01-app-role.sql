-- Runs once on first cluster init as the superuser.
-- The API must connect as a NON-superuser, otherwise Postgres bypasses RLS
-- regardless of ENABLE/FORCE and tenant isolation silently breaks.
create role blog_app login password 'blog_secret';
create database openblog owner blog_app;
