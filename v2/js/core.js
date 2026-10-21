// Pure data logic for Sukhi CVIN Intelligence — no DOM, no network.
// Everything the UI shows (KPIs, charts, result lists) is computed here from one
// canonical array of advisories, so totals always reconcile. Unit-tested in tests/.

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
export const SEV_LABEL = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', UNKNOWN: 'Unknown' };
export const CATEGORIES = [
  'Remote Code Execution', 'Privilege Escalation', 'Authentication Bypass', 'Information Disclosure',
  'Denial of Service', 'Cross-Site Scripting', 'SQL Injection', 'Security Misconfiguration', 'Other', 'Unclassified',
];
export const CERTIN_DETAIL = 'https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=';
const ID_RE = /^CIVN-(\d{4})-(\d{3,})$/;

// ----------------------------------------------------------------- primitives
export function sevKey(s) {
  const u = String(s ?? '').trim().toUpperCase();
  return SEV_RANK[u] !== undefined && u !== 'UNKNOWN' ? u : 'UNKNOWN';
}

/** Strict 'YYYY-MM-DD' validation (rejects 2026-02-30). Returns the ISO date or null. */
export function parseISODate(s) {
  if (typeof s !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(s.trim());
  if (!m) return null;
  const [y, mo, d] = [+m[1], +m[2], +m[3]];
  const dt = new Date(Date.UTC(y, mo - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return null;
  if (y < 1990 || y > 2100) return null;
  return `${m[1]}-${m[2]}-${m[3]}`;
}

export function parseTimestamp(s) {
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

const toUTC = (iso) => { const [y, m, d] = iso.split('-').map(Number); return Date.UTC(y, m - 1, d); };
const fromUTC = (ms) => new Date(ms).toISOString().slice(0, 10);
export function addDays(iso, n) { return fromUTC(toUTC(iso) + n * 864e5); }
export function daysBetween(a, b) { return Math.round((toUTC(b) - toUTC(a)) / 864e5); }
/** Local calendar date of `now` (the viewer's "today"). */
export function todayISO(now = new Date()) {
  const p = (x) => String(x).padStart(2, '0');
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`;
}

/** Only http(s) URLs survive; anything else (javascript:, data:, junk) → null. */
export function safeUrl(u) {
  try {
    const url = new URL(String(u).trim());
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
  } catch { return null; }
}

export function certInUrl(id) { return ID_RE.test(id) ? CERTIN_DETAIL + encodeURIComponent(id) : null; }

// ----------------------------------------------------------------- normalisation
/** Clean + dedupe raw advisory_index rows. Malformed rows are dropped and counted. */
export function normalizeIndex(rows) {
  const byId = new Map();
  let dropped = 0;
  for (const r of rows || []) {
    const id = String(r?.civn_id ?? '').trim().toUpperCase();
    const m = ID_RE.exec(id);
    if (!m) { dropped++; continue; }
    const products = Array.isArray(r.products) ? [...new Set(r.products.filter((p) => typeof p === 'string' && p.trim()).map((p) => p.trim()))] : [];
    const cats = Array.isArray(r.categories) ? r.categories.filter((c) => CATEGORIES.includes(c)) : [];
    byId.set(id, {
      id,
      year: +m[1],
      title: String(r.title ?? '').trim() || id,
      published: parseISODate(r.published_date),
      severity: sevKey(r.severity),
      cveCount: Math.max(0, parseInt(r.cve_count, 10) || 0),
      vendorKey: r.vendor_key ? String(r.vendor_key) : null,
      vendor: r.vendor ? String(r.vendor).trim() : null,
      products,
      categories: cats.length ? cats : ['Unclassified'],
      firstSeen: parseTimestamp(r.first_seen_at),
      changed: parseTimestamp(r.content_changed_at),
    });
  }
  return { rows: [...byId.values()], duplicates: (rows?.length || 0) - dropped - byId.size, dropped };
}

// ----------------------------------------------------------------- filtering & sorting
export const EMPTY_FILTERS = Object.freeze({ q: '', sev: [], from: '', to: '', year: '', vendor: '', product: '', cat: '', changed: '', sort: 'published_desc' });

/**
 * @param rows   normalised advisories
 * @param f      filters (see EMPTY_FILTERS); vendor = vendorKey, product = exact product name
 * @param idSet  Set of IDs matched by the text search, or null when there is no text query
 */
export function applyFilters(rows, f = {}, idSet = null, now = new Date()) {
  const sev = new Set((f.sev || []).map(sevKey));
  const from = parseISODate(f.from || '');
  const to = parseISODate(f.to || '');
  const year = f.year ? +f.year : null;
  const changedDays = f.changed ? +f.changed : null;
  const changedSince = changedDays ? now.getTime() - changedDays * 864e5 : null;
  const product = (f.product || '').toLowerCase();
  return rows.filter((r) =>
    (!idSet || idSet.has(r.id)) &&
    (!sev.size || sev.has(r.severity)) &&
    (!from || (r.published && r.published >= from)) &&
    (!to || (r.published && r.published <= to)) &&
    (!year || r.year === year) &&
    (!f.vendor || (f.vendor === '__none' ? !r.vendorKey : r.vendorKey === f.vendor)) &&
    (!product || r.products.some((p) => p.toLowerCase() === product)) &&
    (!f.cat || r.categories.includes(f.cat)) &&
    (!changedSince || (r.changed && Date.parse(r.changed) >= changedSince)));
}

const cmpStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
export const SORTS = {
  published_desc: { label: 'Newest published', fn: (a, b) => cmpStr(b.published || '', a.published || '') || cmpStr(b.id, a.id) },
  published_asc:  { label: 'Oldest published', fn: (a, b) => cmpStr(a.published || '9999', b.published || '9999') || cmpStr(a.id, b.id) },
  severity:       { label: 'Severity (highest first)', fn: (a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmpStr(b.published || '', a.published || '') || cmpStr(b.id, a.id) },
  changed:        { label: 'Recently changed', fn: (a, b) => cmpStr(b.changed || '', a.changed || '') || cmpStr(b.published || '', a.published || '') || cmpStr(b.id, a.id) },
  cves:           { label: 'Most CVEs', fn: (a, b) => b.cveCount - a.cveCount || cmpStr(b.published || '', a.published || '') },
};
export function sortRows(rows, sort = 'published_desc') { return [...rows].sort((SORTS[sort] || SORTS.published_desc).fn); }

// ----------------------------------------------------------------- aggregation
export function severityDistribution(rows) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  rows.forEach((r) => counts[r.severity]++);
  const total = rows.length;
  return SEVERITIES.map((key) => ({ key, label: SEV_LABEL[key], count: counts[key], pct: total ? (counts[key] / total) * 100 : 0 }));
}

/** Count advisories per value of a (possibly multi-valued) key. Each advisory counts once per distinct value. */
export function countBy(rows, keyFn) {
  const m = new Map();
  for (const r of rows) {
    const ks = keyFn(r);
    for (const k of new Set(Array.isArray(ks) ? ks : [ks])) if (k != null && k !== '') m.set(k, (m.get(k) || 0) + 1);
  }
  return m;
}

export function topN(map, n = 10) {
  return [...map.entries()].sort((a, b) => b[1] - a[1] || cmpStr(String(a[0]), String(b[0]))).slice(0, n);
}

export function vendorTable(rows) {
  const m = new Map();
  for (const r of rows) {
    if (!r.vendorKey) continue;
    const v = m.get(r.vendorKey) || { key: r.vendorKey, name: r.vendor || r.vendorKey, count: 0 };
    v.count++;
    m.set(r.vendorKey, v);
  }
  return [...m.values()].sort((a, b) => b.count - a.count || cmpStr(a.name, b.name));
}

// ----------------------------------------------------------------- time series
export function bucketStart(iso, grain) {
  if (grain === 'month') return iso.slice(0, 7) + '-01';
  if (grain === 'week') { const dow = (new Date(toUTC(iso)).getUTCDay() + 6) % 7; return addDays(iso, -dow); } // ISO week, Monday start
  return iso;
}
export function nextBucket(start, grain) {
  if (grain === 'month') { const [y, m] = start.split('-').map(Number); return fromUTC(Date.UTC(y, m, 1)); }
  return addDays(start, grain === 'week' ? 7 : 1);
}

/** Contiguous buckets from..to (inclusive) with counts of advisories published in each. */
export function trendSeries(rows, { from, to, grain = 'week' }) {
  if (!from || !to || from > to) return [];
  const counts = new Map();
  for (const r of rows) if (r.published && r.published >= from && r.published <= to) {
    const k = bucketStart(r.published, grain);
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  const out = [];
  for (let s = bucketStart(from, grain), guard = 0; s <= to && guard < 10000; s = nextBucket(s, grain), guard++) {
    const end = addDays(nextBucket(s, grain), -1);
    out.push({ start: s, end: end > to ? to : end, from: s < from ? from : s, count: counts.get(s) || 0 });
  }
  return out;
}

/** The equally long period immediately before [from, to]. */
export function previousPeriod(from, to) {
  const len = daysBetween(from, to) + 1;
  return { from: addDays(from, -len), to: addDays(from, -1) };
}

export function countPublished(rows, from, to) {
  return rows.reduce((n, r) => n + (r.published && r.published >= from && r.published <= to ? 1 : 0), 0);
}

export function pctChange(cur, prev) { return prev ? ((cur - prev) / prev) * 100 : null; }

/** Range presets → {from, to}. 'all' spans the data. */
export function resolveRange(range, rows, now = new Date()) {
  const today = todayISO(now);
  if (range && range.includes('..')) {
    const [a, b] = range.split('..').map(parseISODate);
    if (a && b && a <= b) return { from: a, to: b };
  }
  const days = { '7d': 7, '30d': 30, '90d': 90, '180d': 180, '1y': 365, '2y': 730 }[range];
  if (days) return { from: addDays(today, -(days - 1)), to: today };
  const dates = rows.map((r) => r.published).filter(Boolean).sort();
  return { from: dates[0] || today, to: today };
}

export function autoGrain(from, to) {
  const d = daysBetween(from, to);
  return d <= 120 ? 'day' : d <= 900 ? 'week' : 'month';
}

// ----------------------------------------------------------------- KPIs
export function kpis(rows, { now = new Date(), latestSync = null, trackingSince = null } = {}) {
  const today = todayISO(now);
  const last7 = { from: addDays(today, -6), to: today };
  const prev7 = previousPeriod(last7.from, last7.to);
  const last30 = { from: addDays(today, -29), to: today };
  const prev30 = previousPeriod(last30.from, last30.to);
  const bySev = (s, p) => rows.filter((r) => r.severity === s && (!p || (r.published && r.published >= p.from && r.published <= p.to))).length;
  const changed7 = rows.filter((r) => r.changed && Date.parse(r.changed) >= now.getTime() - 7 * 864e5).length;
  const syncAt = latestSync?.finished_at ? Date.parse(latestSync.finished_at) : null;
  return {
    total: { value: rows.length },
    critical: { value: bySev('CRITICAL'), last30: bySev('CRITICAL', last30), prev30: bySev('CRITICAL', prev30), last30Range: last30, prev30Range: prev30 },
    high: { value: bySev('HIGH'), last30: bySev('HIGH', last30), prev30: bySev('HIGH', prev30), last30Range: last30, prev30Range: prev30 },
    published7: { value: countPublished(rows, last7.from, last7.to), prev: countPublished(rows, prev7.from, prev7.to), range: last7, prevRange: prev7 },
    changed7: { value: changed7, trackingSince },
    refresh: { at: syncAt ? new Date(syncAt).toISOString() : null, ageHours: syncAt ? (now.getTime() - syncAt) / 36e5 : null, status: latestSync?.status || null },
    unknownSeverity: bySev('UNKNOWN'),
  };
}

export function coverage(rows) {
  const n = rows.length || 1;
  const pct = (k) => Math.round((rows.filter(k).length / n) * 1000) / 10;
  return {
    severity: pct((r) => r.severity !== 'UNKNOWN'),
    published: pct((r) => !!r.published),
    vendor: pct((r) => !!r.vendorKey),
    products: pct((r) => r.products.length > 0),
    cves: pct((r) => r.cveCount > 0),
    classified: pct((r) => !r.categories.includes('Unclassified')),
  };
}

// ----------------------------------------------------------------- routing state
const LIST_KEYS = new Set(['sev']);
export function parseHash(hash) {
  const h = (hash || '').replace(/^#/, '');
  if (h.startsWith('note=')) return { view: 'advisory', id: decodeURIComponent(h.slice(5)).toUpperCase(), params: {} }; // v1 links
  if (h.startsWith('q=')) return { view: 'explore', params: { q: decodeURIComponent(h.slice(2)) } };                 // v1 links
  const [path, qs = ''] = h.replace(/^\//, '').split('?');
  const [view = 'explore', arg] = path.split('/');
  const params = {};
  for (const [k, v] of new URLSearchParams(qs)) params[k] = LIST_KEYS.has(k) ? v.split(',').filter(Boolean) : v;
  const known = ['explore', 'analytics', 'advisory']; // old #/overview links fall back to the Explorer
  return { view: known.includes(view) ? view : 'explore', id: arg ? decodeURIComponent(arg).toUpperCase() : undefined, params };
}
export function buildHash(view, params = {}, id) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v == null || v === '' || (Array.isArray(v) && !v.length)) continue;
    if (k === 'sort' && v === 'published_desc') continue;
    qs.set(k, Array.isArray(v) ? v.join(',') : String(v));
  }
  const s = qs.toString();
  return `#/${view}${id ? '/' + encodeURIComponent(id) : ''}${s ? '?' + s : ''}`;
}

// ----------------------------------------------------------------- formatting
export function fmtInt(n) { return Number(n || 0).toLocaleString('en-IN'); }
export function fmtPct(p, digits = 1) { return p == null ? '—' : `${p.toFixed(digits)}%`; }
export function fmtDate(iso) {
  if (!iso) return 'Not available';
  const [y, m, d] = iso.slice(0, 10).split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}
export function fmtAge(hours) {
  if (hours == null) return 'unknown';
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))} min ago`;
  if (hours < 36) return `${Math.round(hours)} h ago`;
  return `${Math.round(hours / 24)} days ago`;
}
