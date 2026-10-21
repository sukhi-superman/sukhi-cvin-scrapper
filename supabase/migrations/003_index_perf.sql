-- =============================================================================
-- Sukhi CVIN Intelligence — migration 003 (additive; safe to re-run)
-- Store the derived fields (vendor_raw, products, categories) when a note is
-- written instead of recomputing regex rules on every dashboard request.
-- Source columns are untouched; derived values live in their own columns and are
-- recomputed by the trigger whenever the source text changes.
-- =============================================================================

alter table public.vulnerability_notes
  add column if not exists d_vendor_raw text,
  add column if not exists d_products   text[] not null default '{}',
  add column if not exists d_categories text[] not null default '{}';

create or replace function public.cvin_derive() returns trigger
language plpgsql as $$
begin
  new.d_vendor_raw := public.cvin_vendor_raw(new.vendor_information);
  new.d_products   := public.cvin_products(new.software_affected);
  new.d_categories := public.cvin_categories(new.title, new.overview, new.description);
  return new;
end $$;

drop trigger if exists trg_cvin_derive on public.vulnerability_notes;
create trigger trg_cvin_derive
  before insert or update on public.vulnerability_notes
  for each row execute function public.cvin_derive();

-- A few more spellings seen in the live data.
insert into public.vendor_aliases (alias_key, vendor) values
  ('googlechromeos','Google'), ('chromeos','Google'), ('arubanetwork','Aruba Networks'),
  ('microsoftcorporation','Microsoft'), ('microsoftedge','Microsoft')
on conflict (alias_key) do update set vendor = excluded.vendor;

-- Backfill existing rows (the change-tracking trigger sees no content change, so
-- content_changed_at is preserved).
update public.vulnerability_notes
   set d_vendor_raw = public.cvin_vendor_raw(vendor_information)
 where d_vendor_raw is distinct from public.cvin_vendor_raw(vendor_information)
    or d_categories = '{}';

create index if not exists vn_dvendor_idx on public.vulnerability_notes (d_vendor_raw);

-- View now reads the stored columns (no per-request regex work).
create or replace view public.advisory_index
with (security_invoker = true) as
with k as (
  select n.civn_id, n.year, n.title, n.published_date, n.severity,
         cardinality(n.cve_ids) as cve_count,
         n.first_seen_at, n.last_scraped_at, n.content_changed_at,
         n.d_vendor_raw as vendor_raw, n.d_products as products, n.d_categories as categories,
         a.vendor as alias_vendor,
         public.cvin_vendor_key(coalesce(a.vendor, n.d_vendor_raw)) as vendor_key
  from public.vulnerability_notes n
  left join public.vendor_aliases a on a.alias_key = public.cvin_vendor_key(n.d_vendor_raw)
), names as (
  select vendor_key, coalesce(max(alias_vendor), mode() within group (order by vendor_raw)) as vendor
  from k where vendor_key is not null group by vendor_key
)
select k.civn_id, k.year, k.title, k.published_date, k.severity, k.cve_count,
       k.vendor_key, nm.vendor, k.products, k.categories,
       k.first_seen_at, k.last_scraped_at, k.content_changed_at
from k left join names nm using (vendor_key);

grant select on public.advisory_index to anon, authenticated;
