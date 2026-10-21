// Network layer: read-only calls to the Supabase REST API (PostgREST).
import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from './config.js';
import { normalizeIndex } from './core.js';

const REST = SUPABASE_URL + '/rest/v1';
const HEADERS = { apikey: SUPABASE_PUBLISHABLE_KEY, Accept: 'application/json' };
const PAGE = 1000; // Supabase's default max rows per request
const INDEX_COLS = 'civn_id,title,published_date,severity,cve_count,vendor_key,vendor,products,categories,first_seen_at,content_changed_at';

export class DataError extends Error {}

async function request(path, { method = 'GET', body, headers = {}, timeout = 20000 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(REST + path, {
      method, signal: ctrl.signal,
      headers: { ...HEADERS, ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let msg = `${res.status} ${res.statusText}`;
      try { const j = await res.json(); msg = j.message || msg; } catch {}
      throw new DataError(`Database request failed (${msg})`);
    }
    return { json: await res.json(), headers: res.headers };
  } catch (e) {
    if (e instanceof DataError) throw e;
    throw new DataError(e.name === 'AbortError' ? 'The database took too long to respond.' : 'Could not reach the database. Check your connection.');
  } finally { clearTimeout(timer); }
}

/** Load every advisory in the compact index, in parallel 1,000-row pages. */
export async function loadIndex() {
  const first = await request(`/advisory_index?select=${INDEX_COLS}&order=civn_id&limit=${PAGE}&offset=0`, { headers: { Prefer: 'count=exact' } });
  const total = parseInt((first.headers.get('content-range') || '').split('/')[1], 10);
  let rows = first.json;
  if (Number.isFinite(total) && total > PAGE) {
    const pages = [];
    for (let off = PAGE; off < total; off += PAGE) pages.push(request(`/advisory_index?select=${INDEX_COLS}&order=civn_id&limit=${PAGE}&offset=${off}`));
    for (const p of await Promise.all(pages)) rows = rows.concat(p.json);
  }
  const norm = normalizeIndex(rows);
  return { ...norm, reportedTotal: Number.isFinite(total) ? total : rows.length };
}

export async function loadLatestSync() {
  const { json } = await request('/latest_sync?select=id,mode,status,started_at,finished_at,notes_listed,notes_new,notes_upserted,notes_failed');
  return json[0] || null;
}

export async function loadLastRun() {
  const { json } = await request('/sync_runs?select=id,mode,status,started_at,finished_at,message&order=id.desc&limit=1');
  return json[0] || null;
}

export async function loadStats() {
  const { json } = await request('/rpc/index_stats', { method: 'POST', body: {} });
  return json;
}

/** All advisory IDs matching a text query (CIVN / CVE prefix or keyword). Paged past the 1,000-row cap. */
export async function searchIds(q) {
  const ids = new Set();
  for (let off = 0; off < 20000; off += PAGE) {
    const { json } = await request(`/rpc/search_advisory_ids?select=civn_id&limit=${PAGE}&offset=${off}`, { method: 'POST', body: { q } });
    json.forEach((r) => ids.add(r.civn_id));
    if (json.length < PAGE) break;
  }
  return ids;
}

export async function loadAdvisory(id) {
  const { json } = await request(`/vulnerability_notes?select=civn_id,title,published_date,severity,software_affected,overview,impact,description,workaround,solution,vendor_information,reference_urls,cve_ids,cwe_ids,other_sections,source_url,first_seen_at,last_scraped_at,content_changed_at&civn_id=eq.${encodeURIComponent(id)}&limit=1`);
  return json[0] || null;
}
