// Sukhi CVIN Intelligence — application shell, router and views.
import * as C from './core.js';
import * as D from './data.js';
import { lineChart, hBarChart, dataTable } from './charts.js';
import { TRACKING_SINCE, STALE_AFTER_HOURS } from './config.js';

// ============================================================================ state
const S = { rows: [], byId: new Map(), stats: null, sync: null, lastRun: null, loadedAt: null, error: null, meta: null, search: new Map(), loading: true };
const $ = (id) => document.getElementById(id);

// ============================================================================ DOM helpers (no innerHTML for data)
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k.startsWith('aria-') && typeof v === 'boolean') { e.setAttribute(k, String(v)); continue; } // aria wants "true"/"false"
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(e.dataset, v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c instanceof Node ? c : String(c));
  return e;
}
const ICONS = {
  copy: '<path d="M8 8h11v11H8z"/><path d="M16 8V5H5v11h3"/>',
  ext: '<path d="M14 4h6v6M20 4l-9 9M19 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V6a1 1 0 011-1h5"/>',
  link: '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>',
  print: '<path d="M7 9V3h10v6M7 17H4v-7h16v7h-3"/><path d="M7 14h10v7H7z"/>',
  back: '<path d="M15 18l-6-6 6-6"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
};
function icon(name) {
  const t = document.createElement('template'); // static, trusted markup only
  t.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
  return t.content.firstChild;
}
const sevBadge = (s) => h('span', { class: `sev sev-${s}` }, C.SEV_LABEL[s]);
const term = (label, tip) => h('span', { class: 'term', tabindex: 0, 'data-tip': tip }, label);
const TERMS = {
  CIVN: 'CERT-In Vulnerability Note — an advisory published by the Indian Computer Emergency Response Team (CERT-In).',
  CVE: 'Common Vulnerabilities and Exposures — a public ID for one specific vulnerability. One advisory can list many CVEs.',
  CVSS: 'Common Vulnerability Scoring System — a 0–10 score. CERT-In notes do not publish CVSS, so it is not shown.',
  RCE: 'Remote Code Execution — an attacker can run their own code on the affected system over a network.',
  derived: 'Computed by this app from CERT-In text with transparent keyword rules — not an official CERT-In field.',
};
function toast(msg) {
  document.querySelector('.toast')?.remove();
  const t = h('div', { class: 'toast', role: 'status' }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 2600);
}
async function copy(text, what = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(`${what} to clipboard`); }
  catch { const ta = h('textarea', {}, text); document.body.append(ta); ta.select(); try { document.execCommand('copy'); toast(`${what} to clipboard`); } catch { toast('Copy failed — select and copy manually'); } ta.remove(); }
}
const go = (view, params = {}, id) => { location.hash = C.buildHash(view, params, id); };
const linkTo = (view, params = {}, id) => C.buildHash(view, params, id);

function card(title, sub, ...body) {
  return h('section', { class: 'card chart-card' },
    h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, title), sub ? h('p', { class: 'card-sub' }, sub) : null)),
    ...body);
}
function emptyState(title, text) { return h('div', { class: 'empty' }, h('strong', {}, title), text); }

/** Card with a Chart / Table toggle. drawChart(el) and drawTable(el) render into the body. */
function chartCard({ title, sub, controls, drawChart, drawTable, note, empty }) {
  const body = h('div', { class: 'chart-body' });
  let mode = 'chart';
  const tg = h('div', { class: 'toggle', role: 'group', 'aria-label': 'View as' });
  const bC = h('button', { 'aria-pressed': 'true', onclick: () => set('chart') }, 'Chart');
  const bT = h('button', { 'aria-pressed': 'false', onclick: () => set('table') }, 'Table');
  tg.append(bC, bT);
  function set(m) {
    mode = m; bC.setAttribute('aria-pressed', m === 'chart'); bT.setAttribute('aria-pressed', m === 'table');
    body.replaceChildren();
    if (empty) { body.append(empty); return; }
    (m === 'chart' ? drawChart : drawTable)(body);
  }
  const head = h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, title), sub ? h('p', { class: 'card-sub' }, sub) : null), h('div', { class: 'row' }, controls || null, empty ? null : tg));
  const el = h('section', { class: 'card chart-card' }, head, body, note ? h('p', { class: 'note' }, note) : null);
  queueMicrotask(() => set(mode));
  return el;
}

// ============================================================================ chrome: theme, nav, freshness, banners
function initChrome() {
  const themeBtn = $('theme');
  const paintTheme = () => { themeBtn.textContent = document.documentElement.dataset.theme === 'light' ? 'Dark mode' : 'Light mode'; };
  paintTheme();
  themeBtn.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('cvin:theme', next); } catch {}
    paintTheme(); render();
  });
  const app = $('app'), scrim = $('scrim'), tgl = $('nav-toggle');
  const setNav = (open) => { app.classList.toggle('nav-open', open); scrim.hidden = !open; tgl.setAttribute('aria-expanded', open); };
  tgl.addEventListener('click', () => setNav(!app.classList.contains('nav-open')));
  scrim.addEventListener('click', () => setNav(false));
  $('nav').addEventListener('click', () => setNav(false));
  $('reload').addEventListener('click', () => loadAll(true));
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement?.tagName)) { const q = $('q'); if (q) { e.preventDefault(); q.focus(); } else { go('explore'); } }
  });
}

function syncHealth() {
  const ageH = S.sync?.finished_at ? (Date.now() - Date.parse(S.sync.finished_at)) / 36e5 : null;
  const failedAfter = S.lastRun && S.lastRun.status === 'failed' && (!S.sync || S.lastRun.id > S.sync.id) ? S.lastRun : null;
  const level = ageH == null ? 'bad' : failedAfter || ageH > STALE_AFTER_HOURS * 2.4 ? 'bad' : ageH > STALE_AFTER_HOURS ? 'warn' : 'ok';
  return { ageH, failedAfter, level };
}

function paintFreshness() {
  const el = $('freshness');
  if (S.loading && !S.rows.length) return;
  const { ageH, level, failedAfter } = syncHealth();
  const when = S.sync?.finished_at ? new Date(S.sync.finished_at).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Kolkata' }) + ' IST' : null;
  el.replaceChildren(h('span', { class: `dot ${level}` }), h('span', {},
    h('strong', {}, when ? `Refreshed ${C.fmtAge(ageH)}` : 'No successful refresh recorded'), h('br'),
    when ? h('span', { class: 'faint' }, when) : null,
    failedAfter ? [h('br'), h('span', {}, 'Latest attempt failed')] : null,
    h('br'), h('span', { class: 'faint' }, `${C.fmtInt(S.rows.length)} advisories loaded`)));
}

function paintBanners() {
  const box = $('banners'); box.replaceChildren();
  if (!S.rows.length) return;
  const { ageH, failedAfter } = syncHealth();
  if (failedAfter) box.append(h('div', { class: 'banner bad', role: 'alert' }, h('span', { class: 'ico' }, '!'), h('div', {},
    h('strong', {}, 'Source refresh failed. '), `The most recent sync attempt (${new Date(failedAfter.started_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST) did not complete${failedAfter.message ? ': ' + failedAfter.message.slice(0, 160) : ''}. Showing the last successfully stored data.`)));
  else if (ageH != null && ageH > STALE_AFTER_HOURS) box.append(h('div', { class: 'banner warn', role: 'status' }, h('span', { class: 'ico' }, '!'), h('div', {},
    h('strong', {}, 'Data may be stale. '), `The last successful refresh was ${C.fmtAge(ageH)}; the daily sync normally runs every morning (06:47 IST).`)));
  if (S.meta?.duplicates || S.meta?.dropped) box.append(h('div', { class: 'banner', role: 'status' }, h('span', { class: 'ico' }, 'i'), h('div', {},
    `Data quality: ${S.meta.duplicates} duplicate and ${S.meta.dropped} malformed record(s) were excluded from all counts.`)));
}

// ============================================================================ data loading
async function loadAll(manual = false) {
  S.loading = true; S.error = null;
  if (manual) $('reload').disabled = true;
  try {
    const [idx, sync, stats, lastRun] = await Promise.all([
      D.loadIndex(),
      D.loadLatestSync().catch(() => null),
      D.loadStats().catch(() => null),
      D.loadLastRun().catch(() => null),
    ]);
    S.rows = idx.rows; S.byId = new Map(idx.rows.map((r) => [r.id, r])); S.meta = idx;
    S.sync = sync; S.stats = stats; S.lastRun = lastRun; S.loadedAt = new Date(); S.search.clear();
    if (manual) toast(`Dashboard data reloaded · ${C.fmtInt(S.rows.length)} advisories`);
  } catch (e) {
    S.error = e.message || String(e);
    if (manual && S.rows.length) toast('Reload failed — still showing the previously loaded data');
  } finally {
    S.loading = false;
    if (manual) $('reload').disabled = false;
    paintFreshness(); paintBanners(); render();
  }
}

// ============================================================================ router
let lastView = null;
const NAV = { inApp: -1 };
function render() {
  const route = C.parseHash(location.hash);
  // Canonicalise v1 links (#note=…, #q=…) so refresh/back work with the new scheme.
  if (/^#(note|q)=/.test(location.hash)) { history.replaceState(null, '', C.buildHash(route.view, route.params, route.id)); }
  document.querySelectorAll('#nav a').forEach((a) => a.toggleAttribute('aria-current', a.dataset.view === (route.view === 'advisory' ? 'explore' : route.view)));
  document.querySelectorAll('#nav a[aria-current]').forEach((a) => a.setAttribute('aria-current', 'page'));
  const view = $('view');
  if (S.loading && !S.rows.length) return;
  if (S.error && !S.rows.length) {
    view.replaceChildren(h('div', { class: 'card card-pad' }, emptyState('Could not load vulnerability data', S.error),
      h('div', { class: 'row', style: 'justify-content:center' }, h('button', { class: 'btn btn-primary', onclick: () => loadAll(true) }, 'Try again'))));
    return;
  }
  if (!S.rows.length) { view.replaceChildren(h('div', { class: 'card card-pad' }, emptyState('No advisories indexed yet', 'The database is reachable but empty. Run the daily sync or the historical backfill workflow on GitHub.'))); return; }
  const titles = { explore: 'CVIN Explorer', analytics: 'CVIN Analytics', advisory: route.id || 'Advisory' };
  document.title = `${titles[route.view]} · Sukhi CVIN Intelligence`;
  const changedView = lastView !== route.view; lastView = route.view;
  if (route.view === 'explore') renderExplore(view, route.params, changedView);
  else if (route.view === 'analytics') renderAnalytics(view, route.params);
  else renderAdvisory(view, route.id);
  if (changedView) { window.scrollTo(0, 0); }
}

// ============================================================================ result row (Explorer)
function highlight(text, q) {
  const needle = typeof q === 'string' ? q.trim() : '';
  if (!needle || /^(CIVN|CVE)-/i.test(needle) || needle.length < 2) return text;
  const words = needle.split(/\s+/).filter((w) => w.length > 1).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  if (!words.length) return text;
  const re = new RegExp(`(${words.join('|')})`, 'ig');
  return text.split(re).map((part, i) => (i % 2 ? h('mark', {}, part) : part));
}
function resultRow(r, q = '') {
  return h('li', { class: 'res' },
    h('div', {},
      h('div', { class: 'res-top' }, h('span', { class: 'res-id' }, r.id), sevBadge(r.severity), h('span', {}, C.fmtDate(r.published)),
        r.vendor ? h('span', {}, '· ', r.vendor) : null,
        r.changed ? h('span', { class: 'tag', title: `Content change detected ${new Date(r.changed).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST` }, 'Changed') : null),
      h('a', { class: 'res-title', href: linkTo('advisory', {}, r.id) }, highlight(r.title, q)),
      h('div', { class: 'res-meta' },
        r.cveCount ? h('span', { class: 'tag' }, `${r.cveCount} CVE${r.cveCount > 1 ? 's' : ''}`) : h('span', { class: 'tag' }, 'No CVE listed'),
        r.categories.filter((c) => c !== 'Unclassified' && c !== 'Other').slice(0, 3).map((c) => h('span', { class: 'tag', title: 'Derived category' }, c)))),
    h('div', { class: 'res-actions' },
      h('button', { class: 'btn btn-ghost icon-btn', title: `Copy ${r.id}`, 'aria-label': `Copy ${r.id}`, onclick: () => copy(r.id, `${r.id} copied`) }, icon('copy')),
      h('a', { class: 'btn btn-ghost icon-btn', href: C.certInUrl(r.id), target: '_blank', rel: 'noopener', title: 'Open the official CERT-In advisory', 'aria-label': `Open ${r.id} on CERT-In` }, icon('ext'))));
}

// ============================================================================ EXPLORER
const EX = { limit: 50, key: '' };
function renderExplore(view, params, freshView) {
  const f = { ...C.EMPTY_FILTERS, ...params, sev: params.sev || [] };
  // Always merge into the *current* URL state: controls are built once and must not hold stale filters.
  const set = (patch, replace = true) => {
    const cur = C.parseHash(location.hash).params;
    const next = { ...C.EMPTY_FILTERS, ...cur, sev: cur.sev || [], ...patch };
    const hash = C.buildHash('explore', next);
    if (replace) history.replaceState(null, '', hash); else location.hash = hash;
    render();
  };
  const key = JSON.stringify(f);
  if (key !== EX.key) { EX.limit = 50; EX.key = key; }

  // --- controls (rebuilt only when entering the view, so typing keeps focus)
  let shell = view.querySelector('#explore-shell');
  if (!shell || freshView) {
    shell = h('div', { id: 'explore-shell' });
    view.replaceChildren(shell);
    const vendors = C.vendorTable(S.rows);
    const unknownVendor = S.rows.filter((r) => !r.vendorKey).length;
    const products = C.topN(C.countBy(S.rows, (r) => r.products), 600);
    const years = [...new Set(S.rows.map((r) => r.year))].sort((a, b) => b - a);
    const q = h('input', { id: 'q', class: 'input', type: 'search', value: f.q, autocomplete: 'off', spellcheck: 'false', placeholder: 'Search CIVN-2026-0508, CVE-2026-1022, a vendor, product or keyword…', 'aria-label': 'Search advisories' });
    const mode = h('span', { class: 'mode', id: 'q-mode' });
    let t;
    q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => set({ q: q.value.trim() }), 300); });
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { clearTimeout(t); set({ q: q.value.trim() }); } });
    const sel = (id, label, opts, value, onchange) => h('label', { class: 'field' }, label,
      h('select', { id, class: 'select', onchange: (e) => onchange(e.target.value) }, opts.map(([v, l]) => h('option', { value: v, selected: String(value) === String(v) }, l))));
    const date = (id, label, value, onchange) => h('label', { class: 'field' }, label, h('input', { id, class: 'input', type: 'date', value: value || '', min: '2003-01-01', onchange: (e) => onchange(e.target.value) }));
    const sevPick = h('div', { class: 'sev-pick', role: 'group', 'aria-label': 'Severity' }, C.SEVERITIES.map((s) => {
      const b = h('button', { class: `sev sev-${s}`, 'aria-pressed': f.sev.includes(s), dataset: { sev: s } }, C.SEV_LABEL[s]);
      b.addEventListener('click', () => { const cur = new Set(C.parseHash(location.hash).params.sev || []); cur.has(s) ? cur.delete(s) : cur.add(s); set({ sev: C.SEVERITIES.filter((x) => cur.has(x)) }); });
      return b;
    }));
    const prodInput = h('input', { id: 'f-product', class: 'input', list: 'products', value: f.product, placeholder: 'Any product', onchange: (e) => set({ product: e.target.value.trim() }) });
    shell.append(
      h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'CVIN Explorer'), h('p', {}, 'Search and filter every indexed advisory. Filters combine; the URL keeps your view shareable.'))),
      h('div', { class: 'card' },
        h('div', { class: 'card-pad', style: 'padding-bottom:6px' }, h('div', { class: 'row' }, h('div', { class: 'search' }, icon('search'), q, mode))),
        h('div', { style: 'padding:4px 18px 0' }, h('span', { class: 'kpi-def', style: 'margin-right:8px' }, 'Severity'), sevPick),
        h('div', { class: 'filters' },
          date('f-from', 'Published from', f.from, (v) => set({ from: v })),
          date('f-to', 'Published to', f.to, (v) => set({ to: v })),
          sel('f-year', 'Year', [['', 'Any year'], ...years.map((y) => [y, y])], f.year, (v) => set({ year: v })),
          sel('f-vendor', 'Vendor (derived)', [['', 'Any vendor'], ...vendors.map((v) => [v.key, `${v.name} (${v.count})`]), ...(unknownVendor ? [['__none', `Unknown vendor (${unknownVendor})`]] : [])], f.vendor, (v) => set({ vendor: v })),
          h('label', { class: 'field' }, 'Product (derived)', prodInput, h('datalist', { id: 'products' }, products.map(([p]) => h('option', { value: p })))),
          sel('f-cat', 'Category (derived)', [['', 'Any category'], ...C.CATEGORIES.map((c) => [c, c])], f.cat, (v) => set({ cat: v })),
          sel('f-changed', 'Content changed', [['', 'Any time / never'], ['7', 'In the last 7 days'], ['30', 'In the last 30 days']], f.changed, (v) => set({ changed: v })),
          sel('f-sort', 'Sort by', Object.entries(C.SORTS).map(([k2, s]) => [k2, s.label]), f.sort, (v) => set({ sort: v })),
        ),
        h('div', { id: 'chips', class: 'row', style: 'padding:0 18px 12px' }),
        h('div', { class: 'result-bar' }, h('div', { id: 'count', 'aria-live': 'polite' }), h('div', { class: 'row' }, h('button', { id: 'clear', class: 'btn btn-sm', onclick: () => { $('q').value = ''; set({ ...C.EMPTY_FILTERS }, false); } }, 'Clear all'))),
        h('ul', { id: 'results', class: 'results' }),
        h('div', { id: 'more-wrap', class: 'result-bar', hidden: true }, h('span', { class: 'faint', id: 'more-note' }), h('button', { class: 'btn', id: 'more', onclick: () => { EX.limit += 50; EX.paint?.(); } }, 'Show 50 more'))));
  }
  // keep controls in sync with the URL (back/forward, chips)
  const qEl = $('q'); if (document.activeElement !== qEl && qEl.value !== f.q) qEl.value = f.q;
  $('q-mode').textContent = f.q ? ({ civn: 'CIVN ID', cve: 'CVE ID' }[/^CIVN-/i.test(f.q) ? 'civn' : /^CVE-/i.test(f.q) ? 'cve' : ''] || 'Keyword') : 'All';
  for (const [id, v] of [['f-from', f.from], ['f-to', f.to], ['f-year', f.year], ['f-vendor', f.vendor], ['f-product', f.product], ['f-cat', f.cat], ['f-changed', f.changed], ['f-sort', f.sort]]) { const e = $(id); if (e && e.value !== String(v || (id === 'f-sort' ? 'published_desc' : ''))) e.value = v || (id === 'f-sort' ? 'published_desc' : ''); }
  document.querySelectorAll('.sev-pick button').forEach((b) => b.setAttribute('aria-pressed', f.sev.includes(b.dataset.sev)));

  // chips
  const vendorName = (k2) => (k2 === '__none' ? 'Unknown vendor' : S.rows.find((r) => r.vendorKey === k2)?.vendor || k2);
  const chipDefs = [
    f.q && ['Search', f.q, { q: '' }],
    ...f.sev.map((s) => ['Severity', C.SEV_LABEL[s], { sev: f.sev.filter((x) => x !== s) }]),
    f.from && ['From', C.fmtDate(f.from), { from: '' }], f.to && ['To', C.fmtDate(f.to), { to: '' }],
    f.year && ['Year', f.year, { year: '' }], f.vendor && ['Vendor', vendorName(f.vendor), { vendor: '' }],
    f.product && ['Product', f.product, { product: '' }], f.cat && ['Category', f.cat, { cat: '' }],
    f.changed && ['Changed', `last ${f.changed} days`, { changed: '' }],
  ].filter(Boolean);
  $('chips').replaceChildren(...chipDefs.map(([k2, v, patch]) => h('span', { class: 'chip' }, h('span', { class: 'faint' }, `${k2}:`), v, h('button', { 'aria-label': `Remove ${k2} filter ${v}`, onclick: () => set(patch, false) }, icon('x')))));
  $('clear').hidden = !chipDefs.length && f.sort === 'published_desc';

  // results (text search goes to the database; everything else is local)
  const paintResults = () => {
    const ids = f.q ? S.search.get(f.q.toUpperCase()) : null;
    if (f.q && !ids) return;
    const list = C.sortRows(C.applyFilters(S.rows, f, ids || null), f.sort);
    const cveRefs = list.reduce((n, r) => n + r.cveCount, 0);
    $('count').replaceChildren(h('strong', {}, `${C.fmtInt(list.length)} advisories`), h('span', { class: 'faint' }, ` · ${C.fmtInt(cveRefs)} CVE references`, list.length !== S.rows.length ? ` · of ${C.fmtInt(S.rows.length)} indexed` : ''));
    const ul = $('results');
    if (!list.length) { ul.replaceChildren(h('li', {}, emptyState('No matching advisories', f.q ? 'Try a shorter ID prefix (e.g. CVE-2026-10), a different keyword, or remove a filter.' : 'Remove a filter to widen the results.'))); $('more-wrap').hidden = true; return; }
    ul.replaceChildren(...list.slice(0, EX.limit).map((r) => resultRow(r, f.q)));
    $('more-wrap').hidden = list.length <= EX.limit;
    $('more-note').textContent = `Showing ${C.fmtInt(Math.min(EX.limit, list.length))} of ${C.fmtInt(list.length)}`;
  };
  EX.paint = paintResults;
  if (f.q && !S.search.has(f.q.toUpperCase())) {
    $('count').replaceChildren(h('span', { class: 'faint' }, 'Searching…'));
    $('results').style.opacity = '.5';
    const want = f.q;
    D.searchIds(want).then((ids) => { S.search.set(want.toUpperCase(), ids); })
      .catch((e) => { S.search.delete(want.toUpperCase()); showError(e); })
      .finally(() => { $('results') && ($('results').style.opacity = ''); if (C.parseHash(location.hash).params.q === want) paintResults(); });
  } else { $('results').style.opacity = ''; paintResults(); }
  function showError(e) { $('count').replaceChildren(h('span', {}, `Search failed: ${e.message}. `), h('button', { class: 'btn btn-sm', onclick: () => render() }, 'Retry')); }
}
// ============================================================================ ANALYTICS
const AN = { grain: 'auto', prodVendor: '' };
function renderAnalytics(view, params) {
  const range = params.range || '1y';
  const { from, to } = C.resolveRange(range, S.rows);
  const sev = params.sev || [];
  const base = C.applyFilters(S.rows, { sev });                    // severity scopes everything
  const inRange = C.applyFilters(base, { from, to });
  const prevP = C.previousPeriod(from, to);
  const prevCount = C.countPublished(base, prevP.from, prevP.to);
  const grain = AN.grain === 'auto' ? C.autoGrain(from, to) : AN.grain;
  const scope = { from, to, sev };                                  // click-through filters
  const setP = (patch) => { history.replaceState(null, '', C.buildHash('analytics', { range, sev, ...patch })); render(); };

  // ---- filter row (one row, above everything it scopes)
  const presets = [['30d', '30 days'], ['90d', '90 days'], ['1y', '1 year'], ['2y', '2 years'], ['all', 'All time']];
  const isCustom = range.includes('..');
  const rangeToggle = h('div', { class: 'toggle', role: 'group', 'aria-label': 'Date range' }, presets.map(([v, l]) => h('button', { 'aria-pressed': range === v, onclick: () => setP({ range: v }) }, l)));
  const fromI = h('input', { class: 'input', type: 'date', value: from, 'aria-label': 'Custom range start', min: '2003-01-01' });
  const toI = h('input', { class: 'input', type: 'date', value: to, 'aria-label': 'Custom range end', min: '2003-01-01' });
  const applyCustom = () => { const a = C.parseISODate(fromI.value), b = C.parseISODate(toI.value); if (a && b && a <= b) setP({ range: `${a}..${b}` }); else toast('Choose a valid start and end date'); };
  const sevPick = h('div', { class: 'sev-pick', role: 'group', 'aria-label': 'Severity filter' }, C.SEVERITIES.map((s) =>
    h('button', { class: `sev sev-${s}`, 'aria-pressed': sev.includes(s), onclick: () => { const cur = new Set(sev); cur.has(s) ? cur.delete(s) : cur.add(s); setP({ sev: C.SEVERITIES.filter((x) => cur.has(x)) }); } }, C.SEV_LABEL[s])));
  const filterRow = h('div', { class: 'card card-pad', style: 'margin-bottom:14px' },
    h('div', { class: 'row', style: 'gap:12px' }, rangeToggle,
      h('span', { class: 'row' }, fromI, h('span', { class: 'faint' }, 'to'), toI, h('button', { class: `btn btn-sm${isCustom ? ' btn-primary' : ''}`, onclick: applyCustom }, 'Apply')),
      sevPick),
    h('p', { class: 'card-sub', style: 'margin-top:8px' }, `Showing ${C.fmtDate(from)} – ${C.fmtDate(to)}${sev.length ? ' · ' + sev.map((s) => C.SEV_LABEL[s]).join(', ') : ''}. All charts below use this same slice of ${C.fmtInt(inRange.length)} advisories.`));

  // ---- headline stats for the slice
  const pc = C.pctChange(inRange.length, prevCount);
  const vendorsInRange = new Set(inRange.map((r) => r.vendorKey).filter(Boolean)).size;
  const cveRefs = inRange.reduce((n, r) => n + r.cveCount, 0);
  const stat = (label, value, def) => h('div', { class: 'card kpi', style: 'cursor:default' }, h('span', { class: 'kpi-label' }, label), h('span', { class: 'kpi-value' }, value), h('span', { class: 'kpi-def' }, def));
  const stats = h('div', { class: 'grid grid-kpi4', style: 'margin-bottom:14px' },
    stat('Advisories published', C.fmtInt(inRange.length), `Previous equal period (${C.fmtDate(prevP.from)} – ${C.fmtDate(prevP.to)}): ${C.fmtInt(prevCount)}${pc != null ? ` · ${pc > 0 ? '+' : ''}${pc.toFixed(0)}%` : ''}`),
    stat('CVE references', C.fmtInt(cveRefs), 'Sum of CVEs listed per advisory (a CVE in two advisories counts twice)'),
    stat('Vendors mentioned', C.fmtInt(vendorsInRange), 'Distinct derived vendors in the slice'),
    stat('Unknown severity', C.fmtInt(inRange.filter((r) => r.severity === 'UNKNOWN').length), 'Advisories without a CERT-In severity rating'));

  // ---- 1. publication trend
  const series = C.trendSeries(base, { from, to, grain });
  const prevSeries = C.trendSeries(base, { from: prevP.from, to: prevP.to, grain });
  const bucketLabel = (b) => grain === 'month' ? new Date(b.start + 'T00:00:00Z').toLocaleDateString('en-IN', { month: 'short', year: 'numeric', timeZone: 'UTC' })
    : grain === 'week' ? `Week of ${C.fmtDate(b.from)}` : C.fmtDate(b.start);
  const shortLabel = (b) => grain === 'month' ? new Date(b.start + 'T00:00:00Z').toLocaleDateString('en-IN', { month: 'short', year: '2-digit', timeZone: 'UTC' })
    : new Date(b.start + 'T00:00:00Z').toLocaleDateString('en-IN', { day: 'numeric', month: 'short', timeZone: 'UTC' });
  const grainToggle = h('div', { class: 'toggle', role: 'group', 'aria-label': 'Time grain' }, [['auto', 'Auto'], ['day', 'Daily'], ['week', 'Weekly'], ['month', 'Monthly']].map(([g, l]) =>
    h('button', { 'aria-pressed': AN.grain === g, onclick: () => { if (g === 'day' && C.daysBetween(from, to) > 400) { toast('Daily view is limited to ranges up to ~1 year'); return; } AN.grain = g; render(); } }, l)));
  const trend = chartCard({
    title: 'Publication trend', sub: `Advisories published per ${grain} · previous period shown for comparison`, controls: grainToggle,
    empty: series.length ? null : emptyState('No data in this range', 'Choose a wider date range.'),
    drawChart: (el) => {
      el.append(h('div', { class: 'legend', style: 'padding:0 0 8px' }, h('span', {}, h('i'), 'This period'), h('span', {}, h('i', { class: 'prev' }), `Previous period (${C.fmtDate(prevP.from)} – ${C.fmtDate(prevP.to)})`)));
      const box = h('div'); el.append(box);
      lineChart(box, {
        points: series.map((b) => ({ label: shortLabel(b), sub: `${bucketLabel(b)}${grain !== 'day' ? ` (${C.fmtDate(b.from)} – ${C.fmtDate(b.end)})` : ''}`, value: b.count, data: b })),
        prev: prevSeries.map((b) => ({ value: b.count })),
        onSelect: (p) => go('explore', { from: p.data.from, to: p.data.end, sev }),
      });
    },
    drawTable: (el) => dataTable(el, [{ label: 'Period', get: (b) => `${C.fmtDate(b.from)} – ${C.fmtDate(b.end)}` }, { label: 'Advisories', get: (b) => C.fmtInt(b.count), num: true }, { label: 'Previous period', get: (b) => C.fmtInt(prevSeries[series.indexOf(b)]?.count ?? 0), num: true }], series),
  });

  // ---- 2. severity distribution
  const dist = C.severityDistribution(inRange);
  const sevCard = chartCard({
    title: 'Severity distribution', sub: 'CERT-In rating · count and share of the slice',
    empty: inRange.length ? null : emptyState('No advisories in this slice', ''),
    drawChart: (el) => hBarChart(el, { items: dist.map((d) => ({ key: d.key, label: d.label, value: d.count, color: `var(--sev-${d.key.toLowerCase()})`, note: d.key === 'UNKNOWN' ? 'No severity in the source — never guessed' : null })),
      valueText: (it) => `${C.fmtInt(it.value)} · ${C.fmtPct(dist.find((d) => d.key === it.key).pct)}`, onSelect: (it) => go('explore', { ...scope, sev: [it.key] }), ariaLabel: 'Advisories by severity' }),
    drawTable: (el) => dataTable(el, [{ label: 'Severity', get: (d) => d.label }, { label: 'Advisories', get: (d) => C.fmtInt(d.count), num: true }, { label: 'Share', get: (d) => C.fmtPct(d.pct), num: true }], dist),
    note: 'Shares sum to 100% of advisories in the slice. Severity is never inferred.',
  });

  // ---- 3. top vendors
  const vt = C.vendorTable(inRange).slice(0, 15);
  const vendorCard = chartCard({
    title: 'Top vendors', sub: 'Advisories per vendor (derived from CERT-In vendor information)',
    empty: vt.length ? null : emptyState('No vendor data in this slice', 'Vendor names come from the "Vendor Information" section of each note.'),
    drawChart: (el) => hBarChart(el, { items: vt.map((v) => ({ key: v.key, label: v.name, value: v.count })), onSelect: (it) => go('explore', { ...scope, vendor: it.key }), ariaLabel: 'Advisories per vendor' }),
    drawTable: (el) => dataTable(el, [{ label: 'Vendor', get: (v) => v.name }, { label: 'Advisories', get: (v) => C.fmtInt(v.count), num: true }], vt),
    note: 'Advisory volume reflects how often a vendor appears in CERT-In notes — not how secure its products are, nor your exposure.',
  });

  // ---- 4. most-mentioned products (with vendor drill-down)
  const allVendors = C.vendorTable(inRange);
  if (AN.prodVendor && !allVendors.some((v) => v.key === AN.prodVendor)) AN.prodVendor = '';
  const prodScope = AN.prodVendor ? inRange.filter((r) => r.vendorKey === AN.prodVendor) : inRange;
  const prods = C.topN(C.countBy(prodScope, (r) => r.products), 15);
  const vendorSelect = h('select', { class: 'select', 'aria-label': 'Drill down by vendor', onchange: (e) => { AN.prodVendor = e.target.value; render(); } },
    h('option', { value: '' }, 'All vendors'), allVendors.slice(0, 80).map((v) => h('option', { value: v.key, selected: v.key === AN.prodVendor }, `${v.name} (${v.count})`)));
  const prodCard = chartCard({
    title: 'Most-mentioned products', sub: AN.prodVendor ? `Products in ${allVendors.find((v) => v.key === AN.prodVendor)?.name} advisories` : 'Advisories naming each product (derived from "Software Affected")', controls: vendorSelect,
    empty: prods.length ? null : emptyState('No product data in this slice', ''),
    drawChart: (el) => hBarChart(el, { items: prods.map(([p, n]) => ({ key: p, label: p, value: n })), onSelect: (it) => go('explore', { ...scope, product: it.key, vendor: AN.prodVendor }), ariaLabel: 'Advisories per product' }),
    drawTable: (el) => dataTable(el, [{ label: 'Product', get: (p) => p[0] }, { label: 'Advisories', get: (p) => C.fmtInt(p[1]), num: true }], prods),
    note: 'Product names are extracted from bullet points with version text removed, so close variants (e.g. "Windows 10" and "Microsoft Windows 10") can appear separately.',
  });

  // ---- 5. categories
  const catCounts = C.countBy(inRange, (r) => r.categories);
  const cats = C.CATEGORIES.map((c) => [c, catCounts.get(c) || 0]).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
  const catCard = chartCard({
    title: 'Vulnerability categories', sub: 'Derived with transparent keyword rules over title, overview and description',
    empty: cats.length ? null : emptyState('No advisories in this slice', ''),
    drawChart: (el) => hBarChart(el, { items: cats.map(([c, n]) => ({ key: c, label: c, value: n, note: c === 'Other' ? 'Text present but no rule matched' : c === 'Unclassified' ? 'No descriptive text to classify' : null })),
      valueText: (it) => `${C.fmtInt(it.value)} · ${C.fmtPct(inRange.length ? (it.value / inRange.length) * 100 : 0, 0)}`, onSelect: (it) => go('explore', { ...scope, cat: it.key }), ariaLabel: 'Advisories per category' }),
    drawTable: (el) => dataTable(el, [{ label: 'Category', get: (c) => c[0] }, { label: 'Advisories', get: (c) => C.fmtInt(c[1]), num: true }, { label: 'Share of slice', get: (c) => C.fmtPct(inRange.length ? (c[1] / inRange.length) * 100 : 0), num: true }], cats),
    note: 'One advisory can belong to several categories, so counts add up to more than the total. Rules live in supabase/migrations/002_intelligence.sql.',
  });

  // ---- 6. freshness & update activity
  const { ageH, level, failedAfter } = syncHealth();
  const nowMs = Date.now();
  const changedAll = S.rows.filter((r) => r.changed);
  const changed7 = changedAll.filter((r) => Date.parse(r.changed) >= nowMs - 7 * 864e5);
  const indexed24 = S.rows.filter((r) => r.firstSeen && Date.parse(r.firstSeen) >= nowMs - 864e5).length;
  const pub7 = C.countPublished(S.rows, C.addDays(C.todayISO(), -6), C.todayISO());
  const fresh = h('section', { class: 'card chart-card', id: 'freshness-card' },
    h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'Data freshness & update activity'), h('p', { class: 'card-sub' }, 'Ingestion health and observed changes — independent of the date range above'))),
    h('div', { class: 'grid grid-kpi4', style: 'padding:12px 18px' },
      stat('Last successful refresh', S.sync?.finished_at ? C.fmtAge(ageH) : 'None', S.sync?.finished_at ? `${new Date(S.sync.finished_at).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Kolkata' })} IST · ${level === 'ok' ? 'on schedule' : level === 'warn' ? 'older than expected' : 'stale'}` : 'No successful sync recorded'),
      stat('Newly published (7 days)', C.fmtInt(pub7), 'By CERT-In publication date'),
      stat('Added to the index (24 h)', C.fmtInt(indexed24), 'When this app first stored the note — includes historical backfill, not a publication count'),
      stat('Content changes observed', C.fmtInt(changed7.length), `In the last 7 days · ${C.fmtInt(changedAll.length)} since tracking began ${C.fmtDate(TRACKING_SINCE)}`)),
    failedAfter ? h('p', { class: 'note' }, `Latest sync attempt failed: ${failedAfter.message || 'no details recorded'}.`) : null,
    changedAll.length
      ? h('ul', { class: 'results' }, C.sortRows(changedAll, 'changed').slice(0, 10).map((r) => resultRow(r)))
      : h('p', { class: 'note' }, `No content changes have been observed yet. The daily sync re-checks the newest notes; when CERT-In revises one, it will appear here. Changes before ${C.fmtDate(TRACKING_SINCE)} cannot be known.`));

  view.replaceChildren(
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'CVIN Analytics'), h('p', {}, 'Trends and patterns across CERT-In advisories. Click any bar or point to open the matching advisories.'))),
    filterRow, stats, trend,
    h('div', { class: 'grid grid-2', style: 'margin-top:14px' }, sevCard, catCard, vendorCard, prodCard),
    h('div', { style: 'margin-top:14px' }, fresh));
}

// ============================================================================ ADVISORY DETAIL
async function renderAdvisory(view, id) {
  const idx = S.byId.get(id);
  view.replaceChildren(h('div', { class: 'loading' }, h('div', { class: 'spinner', 'aria-hidden': 'true' }), `Loading ${id}…`));
  let n;
  try { n = await D.loadAdvisory(id); }
  catch (e) { view.replaceChildren(h('div', { class: 'card card-pad' }, emptyState('Could not load this advisory', e.message), h('div', { class: 'row', style: 'justify-content:center' }, h('button', { class: 'btn btn-primary', onclick: () => render() }, 'Try again')))); return; }
  if (C.parseHash(location.hash).id !== id) return; // user navigated away meanwhile
  if (!n) {
    view.replaceChildren(h('div', { class: 'card card-pad' }, emptyState(`${id} is not in the index`, 'It may not be published yet, or the ID may be mistyped.'),
      h('div', { class: 'row', style: 'justify-content:center' }, h('a', { class: 'btn', href: linkTo('explore', { q: id }) }, 'Search for it'), C.certInUrl(id) ? h('a', { class: 'btn', href: C.certInUrl(id), target: '_blank', rel: 'noopener' }, 'Try on CERT-In') : null)));
    return;
  }
  const sev = C.sevKey(n.severity);
  const official = C.safeUrl(n.source_url) || C.certInUrl(n.civn_id);
  const NA = (why) => h('span', { class: 'na' }, why ? `Not available — ${why}` : 'Not available');
  const SRC = () => h('span', { class: 'prov prov-source', title: 'Verbatim from the CERT-In note' }, 'CERT-In');
  const DER = () => h('span', { class: 'prov prov-derived', title: TERMS.derived }, 'Derived');
  const prose = (text) => {
    if (!text) return NA();
    const p = h('p', { class: 'prose' });
    for (const line of String(text).split('\n')) {
      const url = /^https?:\/\/\S+$/.test(line.trim()) ? C.safeUrl(line.trim()) : null;
      p.append(url ? h('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, url) : line, '\n');
    }
    return p;
  };
  const sec = (title, tags, ...body) => h('section', { class: 'sec' }, h('h2', {}, title, ...tags), ...body);
  const cves = (n.cve_ids || []).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c));
  const refs = [...new Set((n.reference_urls || []).map(C.safeUrl).filter(Boolean))];
  const fmtTs = (t) => (t ? new Date(t).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Kolkata' }) + ' IST' : null);
  const related = idx?.vendorKey ? C.sortRows(S.rows.filter((r) => r.vendorKey === idx.vendorKey && r.id !== id), 'published_desc').slice(0, 6) : [];

  view.replaceChildren(
    h('div', { class: 'row no-print', style: 'margin-bottom:10px' },
      h('button', { class: 'btn btn-ghost btn-sm', onclick: () => (NAV.inApp > 0 ? history.back() : go('explore')) }, icon('back'), 'Back')),
    h('div', { class: 'detail' },
      h('article', { class: 'card' },
        h('div', { class: 'sec detail-head' },
          h('div', { class: 'row' }, h('span', { class: 'res-id', style: 'font-size:14px' }, n.civn_id), sevBadge(sev), h('span', { class: 'muted' }, `Published ${C.fmtDate(C.parseISODate(n.published_date))}`)),
          h('h1', {}, n.title),
          h('div', { class: 'row no-print' },
            official ? h('a', { class: 'btn btn-primary', href: official, target: '_blank', rel: 'noopener' }, icon('ext'), 'Open official CERT-In advisory') : null,
            h('button', { class: 'btn', onclick: () => copy(n.civn_id, `${n.civn_id} copied`) }, icon('copy'), 'Copy ID'),
            h('button', { class: 'btn', onclick: () => copy(location.href, 'Link copied') }, icon('link'), 'Copy link'),
            h('button', { class: 'btn', onclick: () => window.print() }, icon('print'), 'Print briefing'))),
        sec('1 · Overview', [SRC()],
          h('dl', { class: 'kv' },
            h('dt', {}, 'Advisory ID'), h('dd', { class: 'mono' }, n.civn_id),
            h('dt', {}, 'Published'), h('dd', {}, C.fmtDate(C.parseISODate(n.published_date))),
            h('dt', {}, 'Last updated by CERT-In'), h('dd', {}, NA('CERT-In does not publish update dates')),
            h('dt', {}, 'Severity'), h('dd', {}, sevBadge(sev), ' ', h('span', { class: 'faint' }, sev === 'UNKNOWN' ? 'No rating in the source' : 'CERT-In severity rating')),
            h('dt', {}, 'Vendor'), h('dd', {}, idx?.vendor || NA('no vendor section in the note'), ' ', idx?.vendor ? DER() : null),
            h('dt', {}, 'Categories'), h('dd', {}, h('span', { class: 'row', style: 'display:inline-flex' }, (idx?.categories || []).map((c) => h('a', { class: 'tag', href: linkTo('explore', { cat: c }) }, c))), ' ', DER())),
          n.overview ? h('h3', {}, 'Summary') : null, n.overview ? prose(n.overview) : null),
        sec('2 · Vulnerability details', [SRC()], prose(n.description), n.impact ? [h('h3', {}, 'Impact'), prose(n.impact)] : null),
        sec('3 · Affected products & versions', [SRC()], prose(n.software_affected),
          idx?.products?.length ? h('div', { style: 'margin-top:10px' }, h('div', { class: 'row', style: 'margin-bottom:6px' }, h('span', { class: 'faint' }, 'Product names'), DER()),
            h('div', { class: 'row' }, idx.products.map((p) => h('a', { class: 'tag', href: linkTo('explore', { product: p }) }, p)))) : null),
        sec('4 · Risk & severity', [],
          h('dl', { class: 'kv' },
            h('dt', {}, 'CERT-In severity'), h('dd', {}, sevBadge(sev)),
            h('dt', {}, term('CVSS', TERMS.CVSS)), h('dd', {}, NA('not published by CERT-In; no enrichment source configured')),
            h('dt', {}, 'Exploitation status'), h('dd', {}, NA('not tracked — this app does not label advisories as exploited')),
            h('dt', {}, term('CVE IDs', TERMS.CVE)), h('dd', {}, cves.length ? h('div', { class: 'cves' }, cves.map((c) => h('a', { class: 'tag tag-cve', href: `https://www.cve.org/CVERecord?id=${c}`, target: '_blank', rel: 'noopener', title: `${c} on cve.org` }, c))) : NA('none listed in the note')),
            (n.cwe_ids || []).length ? [h('dt', {}, 'CWE IDs'), h('dd', {}, h('div', { class: 'cves' }, n.cwe_ids.map((c) => h('span', { class: 'tag tag-cve' }, c))))] : null),
          h('p', { class: 'card-sub', style: 'margin-top:10px' }, 'An advisory is not evidence that your systems are affected — compare the affected versions above with your own inventory.')),
        sec('5 · Remediation', [SRC()], prose(n.solution), n.workaround ? [h('h3', {}, 'Workaround'), prose(n.workaround)] : null,
          n.vendor_information ? [h('h3', {}, 'Vendor information'), prose(n.vendor_information)] : null),
        sec('6 · References & source', [],
          refs.length ? h('ul', { class: 'links' }, refs.map((u) => h('li', {}, h('a', { href: u, target: '_blank', rel: 'noopener noreferrer' }, u)))) : NA('no references listed'),
          h('dl', { class: 'kv', style: 'margin-top:14px' },
            h('dt', {}, 'Official source'), h('dd', {}, official ? h('a', { href: official, target: '_blank', rel: 'noopener' }, 'cert-in.org.in · ', n.civn_id) : NA()),
            h('dt', {}, 'First indexed'), h('dd', {}, fmtTs(n.first_seen_at) || NA()),
            h('dt', {}, 'Last checked'), h('dd', {}, fmtTs(n.last_scraped_at) || NA()),
            h('dt', {}, 'Content change'), h('dd', {}, n.content_changed_at ? `Changed on re-check ${fmtTs(n.content_changed_at)}` : `No change observed since tracking began ${C.fmtDate(TRACKING_SINCE)}`)))),
      h('aside', { class: 'stack no-print' },
        h('section', { class: 'card card-pad' }, h('h3', {}, 'About this data'),
          h('p', { class: 'card-sub', style: 'margin:8px 0' }, SRC(), ' Text copied from the CERT-In note.'),
          h('p', { class: 'card-sub', style: 'margin:8px 0' }, DER(), ' Computed by this app with transparent rules; may be imperfect.'),
          h('p', { class: 'card-sub' }, 'No external enrichment (CVSS, exploitation data) is applied.')),
        related.length ? h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('h3', {}, `More from ${idx.vendor}`)),
          h('ul', { class: 'results', style: 'margin-top:8px' }, related.map((r) => h('li', { class: 'res', style: 'grid-template-columns:1fr' },
            h('div', {}, h('div', { class: 'res-top' }, h('span', { class: 'res-id' }, r.id), sevBadge(r.severity)), h('a', { class: 'res-title', style: 'font-size:13px', href: linkTo('advisory', {}, r.id) }, r.title))))),
          h('div', { class: 'result-bar' }, h('a', { class: 'btn btn-sm', href: linkTo('explore', { vendor: idx.vendorKey }) }, `All ${idx.vendor} advisories`))) : null)));
  document.title = `${n.civn_id} · ${n.title} · Sukhi CVIN Intelligence`;
}

// ============================================================================ boot
initChrome();
window.addEventListener('hashchange', () => { NAV.inApp++; render(); });
NAV.inApp = 0;
loadAll();
