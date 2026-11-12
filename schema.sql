-- Run this once in the Supabase SQL editor (Project -> SQL Editor -> New query)
create table if not exists events (
    id            text primary key,
    ts            timestamptz not null default now(),
    ip            inet,
    xff           text,
    peer          text,
    method        text,
    path          text,
    query         text,
    ua            text,
    host          text,
    referer       text,
    content_type  text,
    header_names  jsonb,
    body          text,
    creds         jsonb,
    is_mine       boolean default false,
    country       text,       -- filled in later by analyze.py, left null at insert time
    category      text,
    mitre_id      text,
    mitre_name    text
);

create index if not exists events_ip_idx on events (ip);
create index if not exists events_ts_idx on events (ts);
create index if not exists events_path_idx on events (path);

-- Row Level Security: keep the table locked down from the public anon key.
-- The app connects with the direct DB connection string (service/postgres role),
-- which bypasses RLS entirely, so this just protects against the anon/public API key
-- ever being used against this table.
alter table events enable row level security;
