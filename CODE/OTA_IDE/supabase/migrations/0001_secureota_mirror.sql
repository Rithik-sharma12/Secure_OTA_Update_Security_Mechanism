-- SecureOTA dashboard: tables the server mirrors user profiles and
-- firmware-upload jobs into (see lib/supabase-sync.ts).
--
-- Run once in Supabase → SQL Editor → New query → paste → Run.
-- Safe to re-run.
--
-- Only the dashboard server writes these, with SUPABASE_SERVICE_ROLE_KEY
-- (which bypasses RLS). RLS is on with no policies, so the public anon key
-- cannot read or change them from a browser.

create table if not exists public.ota_profiles (
  local_id        text primary key,
  clerk_id        text unique,
  username        text not null,
  email           text,
  display_name    text,
  image_url       text,
  auth_providers  text[] not null default '{}',
  role            text not null check (role in ('admin', 'operator', 'viewer')),
  is_active       boolean not null default true,
  last_login_at   timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create index if not exists ota_profiles_email_idx on public.ota_profiles (lower(email));

create table if not exists public.ota_uploads (
  job_id          text primary key,
  user_local_id   text,
  file_name       text,
  file_hash       text,
  board_type      text,
  fqbn            text,
  com_port        text,
  status          text check (status in ('queued', 'compiling', 'uploading', 'success', 'failed')),
  progress        integer,
  error_message   text,
  started_at      timestamptz,
  ended_at        timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create index if not exists ota_uploads_user_idx on public.ota_uploads (user_local_id, started_at desc);

alter table public.ota_profiles enable row level security;
alter table public.ota_uploads  enable row level security;
