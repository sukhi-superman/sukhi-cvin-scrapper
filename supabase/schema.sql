-- =============================================================================
-- Sukhi CVIN Scrapper — Supabase schema
-- Run once in: Supabase Dashboard → SQL Editor → New query → paste → Run.
-- Safe to re-run (idempotent).
-- =============================================================================

create extension if not exists pg_trgm with schema extensions;

-- -----------------------------------------------------------------------------
-- 1. Vulnerability notes (one row per CIVN advisory)
-- -----------------------------------------------------------------------------
create table if not exists public.vulnerability_notes (
  civn_id            text primary key
                     check (civn_id ~ '^CIVN-[0-9]{4}-[0-9]+$'),
  year               smallint not null,
  title              text not null,
  published_date     date,
  severity           text,                       -- CRITICAL / HIGH / MEDIUM / LOW
  software_affected  text,
  overview           text,                       -- includes Target Audience / Risk text on newer notes
  impact             text,                       -- older notes have a separate "Impact" section
  description        text,
  workaround         text,
  solution           text,
  vendor_information text,
  reference_urls     text[] not null default '{}',
  cve_ids            text[] not null default '{}',
  cwe_ids            text[] not null default '{}',
  other_sections     jsonb  not null default '{}'::jsonb,  -- any heading we didn't map
  source_url         text not null,
  first_seen_at      timestamptz not null default now(),  -- never overwritten by upserts
  last_scraped_at    timestamptz not null default now(),

  -- Full-text search vector, maintained by Postgres automatically.
  fts tsvector generated always as (
    setweight(to_tsvector('english', coalesce(civn_id, '') || ' ' || coalesce(title, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(software_affected, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(overview, '') || ' ' || coalesce(description, '')), 'C')
  ) stored
);

create index if not exists vn_published_idx  on public.vulnerability_notes (published_date desc, civn_id desc);
create index if not exists vn_year_idx       on public.vulnerability_notes (year);
create index if not exists vn_severity_idx   on public.vulnerability_notes (severity);
create index if not exists vn_civn_like_idx  on public.vulnerability_notes (civn_id text_pattern_ops);
create index if not exists vn_cve_gin_idx    on public.vulnerability_notes using gin (cve_ids);
create index if not exists vn_fts_gin_idx    on public.vulnerability_notes using gin (fts);
create index if not exists vn_title_trgm_idx on public.vulnerability_notes using gin (title extensions.gin_trgm_ops);

-- -----------------------------------------------------------------------------
-- 2. Sync runs (powers the "Last Data Pulled" timestamp)
-- -----------------------------------------------------------------------------
create table if not exists public.sync_runs (
  id             bigint generated always as identity primary key,
  mode           text not null,                 -- incremental / backfill / note
  status         text not null default 'running'
                 check (status in ('running', 'success', 'partial', 'failed')),
  started_at     timestamptz not null default now(),
  finished_at    timestamptz,
  years          int[],
  notes_listed   int not null default 0,
  notes_new      int not null default 0,
  notes_upserted int not null default 0,
  notes_failed   int not null default 0,
  message        text
);

create index if not exists sync_runs_finished_idx on public.sync_runs (finished_at desc);

create or replace view public.latest_sync
with (security_invoker = true) as
  select id, mode, status, started_at, finished_at,
         notes_listed, notes_new, notes_upserted, notes_failed
  from public.sync_runs
  where status in ('success', 'partial')
  order by finished_at desc nulls last
  limit 1;

-- -----------------------------------------------------------------------------
-- 3. Smart search RPC — one box handles CIVN ID, CVE ID or keyword.
--    Frontend:  supabase.rpc('search_notes', { q: 'CVE-2026-1022', max_results: 50 })
-- -----------------------------------------------------------------------------
create or replace function public.search_notes(q text, max_results int default 50)
returns setof public.vulnerability_notes
language sql
stable
security invoker
set search_path = public, extensions
as $$
  with i as (
    select trim(coalesce(q, ''))        as raw,
           upper(trim(coalesce(q, ''))) as u
  )
  select n.*
  from public.vulnerability_notes n, i
  where case
          when i.raw = ''        then true
          when i.u ~ '^CIVN-'    then n.civn_id like i.u || '%'
          when i.u ~ '^CVE-'     then exists (select 1 from unnest(n.cve_ids) c where c like i.u || '%')
          else n.fts @@ websearch_to_tsquery('english', i.raw)
               or n.title ilike '%' || i.raw || '%'
        end
  order by n.published_date desc nulls last, n.civn_id desc
  limit least(greatest(coalesce(max_results, 50), 1), 200);
$$;

-- -----------------------------------------------------------------------------
-- 4. Security: public read-only. Writes only via the service-role key
--    (used by GitHub Actions), which bypasses RLS.
-- -----------------------------------------------------------------------------
alter table public.vulnerability_notes enable row level security;
alter table public.sync_runs           enable row level security;

drop policy if exists "public read notes" on public.vulnerability_notes;
create policy "public read notes" on public.vulnerability_notes
  for select to anon, authenticated using (true);

drop policy if exists "public read sync runs" on public.sync_runs;
create policy "public read sync runs" on public.sync_runs
  for select to anon, authenticated using (true);

-- Defence in depth: the browser roles can never write, even if RLS is disabled by mistake.
revoke insert, update, delete, truncate on public.vulnerability_notes from anon, authenticated;
revoke insert, update, delete, truncate on public.sync_runs           from anon, authenticated;
grant  select on public.vulnerability_notes, public.sync_runs, public.latest_sync to anon, authenticated;
grant  execute on function public.search_notes(text, int) to anon, authenticated;
