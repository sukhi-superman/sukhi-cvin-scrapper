-- =============================================================================
-- Sukhi CVIN Intelligence — migration 002 (additive; safe to re-run)
--   * content_changed_at + trigger  → honest "updated" signal (only real text changes)
--   * vendor / product / category derivations (transparent, deterministic)
--   * advisory_index view            → compact canonical dataset for the dashboard
--   * search_advisory_ids()          → uncapped search returning IDs (paged by PostgREST)
--   * index_stats()                  → advisory vs unique-CVE counts
-- Nothing existing is altered or removed. Source columns are never overwritten.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Change tracking
--    CERT-In publishes no per-note "last updated" date. When a re-scrape actually
--    changes a note's content, this trigger stamps content_changed_at. NULL means
--    "no change observed since we started tracking" — never "never changed".
-- -----------------------------------------------------------------------------
alter table public.vulnerability_notes add column if not exists content_changed_at timestamptz;

create or replace function public.cvin_track_content_change() returns trigger
language plpgsql as $$
begin
  if (new.title, new.published_date, new.severity, new.software_affected, new.overview,
      new.impact, new.description, new.workaround, new.solution, new.vendor_information,
      new.cve_ids, new.reference_urls)
     is distinct from
     (old.title, old.published_date, old.severity, old.software_affected, old.overview,
      old.impact, old.description, old.workaround, old.solution, old.vendor_information,
      old.cve_ids, old.reference_urls) then
    new.content_changed_at := now();
  else
    new.content_changed_at := old.content_changed_at;
  end if;
  return new;
end $$;

drop trigger if exists trg_cvin_content_change on public.vulnerability_notes;
create trigger trg_cvin_content_change
  before update on public.vulnerability_notes
  for each row execute function public.cvin_track_content_change();

create index if not exists vn_changed_idx on public.vulnerability_notes (content_changed_at desc nulls last);

-- -----------------------------------------------------------------------------
-- 2. Vendor normalisation (derived from CERT-In's "Vendor Information" section)
-- -----------------------------------------------------------------------------
-- First meaningful line of the vendor section (skips blank lines and bare URLs).
create or replace function public.cvin_vendor_raw(vi text) returns text
language sql immutable parallel safe as $$
  select left(trim(both ' :-' from trim(l)), 60)
  from unnest(string_to_array(coalesce(vi, ''), E'\n')) with ordinality as u(l, i)
  where trim(l) <> '' and trim(l) !~* '^(https?://|www\.)'
  order by i limit 1
$$;

-- Comparison key: lower-case, legal suffixes removed, non-alphanumerics dropped.
-- "CISCO" = "Cisco", "Sonic Wall" = "SonicWall", "Gitlab" = "GitLab".
create or replace function public.cvin_vendor_key(t text) returns text
language sql immutable parallel safe as $$
  select nullif(regexp_replace(
           regexp_replace(lower(coalesce(t, '')),
             '\m(inc|incorporated|ltd|limited|corp|corporation|llc|gmbh|plc)\M\.?', '', 'g'),
           '[^a-z0-9]', '', 'g'), '')
$$;

-- Editable spelling map: alias key → canonical vendor name. Transparent and auditable.
create table if not exists public.vendor_aliases (
  alias_key text primary key,
  vendor    text not null
);
insert into public.vendor_aliases (alias_key, vendor) values
  ('cisco','Cisco'), ('ciscosystems','Cisco'),
  ('google','Google'), ('googlechrome','Google'), ('chrome','Google'), ('android','Google'),
  ('microsoft','Microsoft'), ('apple','Apple'), ('adobe','Adobe'),
  ('mozilla','Mozilla'), ('mozillafirefox','Mozilla'), ('firefox','Mozilla'), ('mozillathunderbird','Mozilla'),
  ('fortinet','Fortinet'), ('fortiguard','Fortinet'), ('fortiguardlabs','Fortinet'),
  ('paloalto','Palo Alto Networks'), ('paloaltonetworks','Palo Alto Networks'),
  ('redhat','Red Hat'), ('gitlab','GitLab'), ('github','GitHub'),
  ('vmware','VMware'), ('ibm','IBM'), ('f5','F5'), ('f5networks','F5'), ('qnap','QNAP'),
  ('tplink','TP-Link'), ('dlink','D-Link'), ('nodejs','Node.js'), ('openssl','OpenSSL'),
  ('sonicwall','SonicWall'), ('wordpress','WordPress'), ('drupal','Drupal'),
  ('apache','Apache'), ('apachetomcat','Apache'), ('apachesoftwarefoundation','Apache'),
  ('juniper','Juniper Networks'), ('junipernetworks','Juniper Networks'),
  ('siemens','Siemens'), ('citrix','Citrix'), ('zoom','Zoom'), ('ivanti','Ivanti'),
  ('splunk','Splunk'), ('solarwinds','SolarWinds'), ('wireshark','Wireshark'),
  ('schneiderelectric','Schneider Electric'), ('zimbra','Zimbra'), ('oracle','Oracle'),
  ('sap','SAP'), ('hp','HP'), ('hpe','HPE'), ('hewlettpackardenterprise','HPE'),
  ('samsung','Samsung'), ('qualcomm','Qualcomm'), ('intel','Intel'), ('nvidia','NVIDIA'),
  ('atlassian','Atlassian'), ('jenkins','Jenkins'), ('veeam','Veeam'), ('dell','Dell'),
  ('lenovo','Lenovo'), ('zyxel','Zyxel'), ('netgear','NETGEAR'), ('mediatek','MediaTek'),
  ('arubanetworks','Aruba Networks'), ('aruba','Aruba Networks'), ('checkpoint','Check Point'),
  ('trendmicro','Trend Micro'), ('isc','ISC'), ('php','PHP'), ('linux','Linux'), ('linuxkernel','Linux')
on conflict (alias_key) do update set vendor = excluded.vendor;

-- -----------------------------------------------------------------------------
-- 3. Product names (derived from "Software Affected" bullets, version text removed)
--    "Google Chrome prior to 154.0.8037.57"  → "Google Chrome"
--    "SMA 1000 (6210, 7210 …)"               → "SMA 1000"
-- -----------------------------------------------------------------------------
create or replace function public.cvin_products(sw text) returns text[]
language sql immutable parallel safe as $$
  select coalesce(array_agg(distinct p order by p), '{}')
  from (
    select nullif(trim(both ' .,:;-' from regexp_replace(
             regexp_replace(
               regexp_replace(trim(l), '^[•*·\s-]+', ''),
               '\s*(\(|<|≤|\m(prior to|before|versions?|version|ver\.|up to|through|and earlier|earlier than|all versions|all builds|for|x32|x64|x86|arm64|32-bit|64-bit|v?\d+(\.\d+)+)\M).*$',
               '', 'i'),
             '\s+', ' ', 'g')), '') as p
    from unnest(string_to_array(coalesce(sw, ''), E'\n')) as l
  ) t
  where p is not null and length(p) between 2 and 60
$$;

-- -----------------------------------------------------------------------------
-- 4. Vulnerability categories — keyword rules over title + overview + description.
--    Multi-label (one advisory can be RCE and DoS). "Other" = text present but no
--    rule matched; "Unclassified" = no descriptive text to classify.
-- -----------------------------------------------------------------------------
create or replace function public.cvin_categories(title text, overview text, description text) returns text[]
language sql immutable parallel safe as $$
  with t as (
    select lower(coalesce(title, '') || ' ' || coalesce(overview, '') || ' ' || coalesce(description, '')) as s,
           (overview is null and description is null) as empty
  )
  select case when empty then array['Unclassified'] else coalesce(nullif(array_remove(array[
    case when s ~ '(remote code execution|execut\w* (of )?arbitrary (\w+ ){0,3}(code|commands?)|arbitrary code execution|\mrce\M|command injection)' then 'Remote Code Execution' end,
    case when s ~ '(privilege escalation|elevation of privilege|elevat\w* privileges?|escalat\w* (of )?privileges?|gain (elevated|root|administrative|system|admin) (level )?(privileges|access))' then 'Privilege Escalation' end,
    case when s ~ '(authentication bypass|bypass\w* (the )?authentication|bypass\w* (multi-factor|mfa|2fa|login)|unauthenticated access|improper authentication|missing authentication)' then 'Authentication Bypass' end,
    case when s ~ '(information disclosure|sensitive information|disclos\w* (of )?(sensitive )?(information|data)|data (leak|exposure)|obtain (sensitive )?information)' then 'Information Disclosure' end,
    case when s ~ '(denial[- ]of[- ]service|\mdos\M|\mddos\M)' then 'Denial of Service' end,
    case when s ~ '(cross[- ]site scripting|\mxss\M)' then 'Cross-Site Scripting' end,
    case when s ~ '(sql injection|\msqli\M)' then 'SQL Injection' end,
    case when s ~ '(misconfigur\w*|insecure default|default credentials|hard-?coded (credentials|passwords?|keys?)|incorrect default permissions)' then 'Security Misconfiguration' end
  ], null), '{}'), array['Other']) end
  from t
$$;

-- -----------------------------------------------------------------------------
-- 5. advisory_index — one compact row per advisory (the dashboard's canonical dataset)
-- -----------------------------------------------------------------------------
create or replace view public.advisory_index
with (security_invoker = true) as
with b as (
  select n.civn_id, n.year, n.title, n.published_date, n.severity,
         cardinality(n.cve_ids) as cve_count,
         n.first_seen_at, n.last_scraped_at, n.content_changed_at,
         public.cvin_vendor_raw(n.vendor_information)          as vendor_raw,
         public.cvin_products(n.software_affected)             as products,
         public.cvin_categories(n.title, n.overview, n.description) as categories
  from public.vulnerability_notes n
), k as (
  select b.*, a.vendor as alias_vendor,
         public.cvin_vendor_key(coalesce(a.vendor, b.vendor_raw)) as vendor_key
  from b left join public.vendor_aliases a on a.alias_key = public.cvin_vendor_key(b.vendor_raw)
), names as (
  select vendor_key, coalesce(max(alias_vendor), mode() within group (order by vendor_raw)) as vendor
  from k where vendor_key is not null group by vendor_key
)
select k.civn_id, k.year, k.title, k.published_date, k.severity, k.cve_count,
       k.vendor_key, nm.vendor, k.products, k.categories,
       k.first_seen_at, k.last_scraped_at, k.content_changed_at
from k left join names nm using (vendor_key);

-- -----------------------------------------------------------------------------
-- 6. Uncapped ID search (CIVN prefix / CVE prefix / keyword incl. vendor & product text)
--    Returns IDs only; the client pages through with offset/limit and intersects
--    with its own filters, so search + filters always combine correctly.
-- -----------------------------------------------------------------------------
create or replace function public.search_advisory_ids(q text)
returns table (civn_id text)
language sql stable security invoker
set search_path = public, extensions
as $$
  with i as (select trim(coalesce(q, '')) as raw, upper(trim(coalesce(q, ''))) as u)
  select n.civn_id
  from public.vulnerability_notes n, i
  where i.raw <> '' and case
    when i.u ~ '^CIVN-' then n.civn_id like i.u || '%'
    when i.u ~ '^CVE-'  then exists (select 1 from unnest(n.cve_ids) c where c like i.u || '%')
    else n.fts @@ websearch_to_tsquery('english', i.raw)
      or n.title ilike '%' || i.raw || '%'
      or n.vendor_information ilike '%' || i.raw || '%'
      or n.software_affected ilike '%' || i.raw || '%'
  end
  order by n.civn_id
$$;

-- -----------------------------------------------------------------------------
-- 7. Global counts that need the full CVE arrays
-- -----------------------------------------------------------------------------
create or replace function public.index_stats()
returns json language sql stable security invoker set search_path = public as $$
  select json_build_object(
    'advisories',   (select count(*) from public.vulnerability_notes),
    'cve_mentions', (select coalesce(sum(cardinality(cve_ids)), 0) from public.vulnerability_notes),
    'unique_cves',  (select count(distinct c) from public.vulnerability_notes, unnest(cve_ids) c),
    'with_cves',    (select count(*) from public.vulnerability_notes where cardinality(cve_ids) > 0)
  )
$$;

-- -----------------------------------------------------------------------------
-- 8. Security: read-only for browser roles
-- -----------------------------------------------------------------------------
alter table public.vendor_aliases enable row level security;
drop policy if exists "public read vendor aliases" on public.vendor_aliases;
create policy "public read vendor aliases" on public.vendor_aliases for select to anon, authenticated using (true);
revoke insert, update, delete, truncate on public.vendor_aliases from anon, authenticated;

grant select on public.advisory_index, public.vendor_aliases to anon, authenticated;
grant execute on function public.search_advisory_ids(text), public.index_stats() to anon, authenticated;
