// Run from v2/:  npm test   (Node 18+, no dependencies)
import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../js/core.js';

const raw = [
  { civn_id: 'CIVN-2026-0510', title: 'Critical RCE in PHP', published_date: '2026-10-21', severity: 'CRITICAL', cve_count: 2, vendor_key: 'php', vendor: 'PHP', products: ['PHP'], categories: ['Remote Code Execution'], first_seen_at: '2026-10-21T20:20:00Z', content_changed_at: null },
  { civn_id: 'CIVN-2026-0509', title: 'Info disclosure in Linux', published_date: '2026-10-21', severity: 'high', cve_count: 1, vendor_key: 'linux', vendor: 'Linux', products: ['Linux Kernel'], categories: ['Information Disclosure'], first_seen_at: '2026-10-21T20:20:00Z', content_changed_at: '2026-10-22T01:00:00Z' },
  { civn_id: 'CIVN-2026-0400', title: 'Chrome', published_date: '2026-10-10', severity: 'HIGH', cve_count: 10, vendor_key: 'google', vendor: 'Google', products: ['Google Chrome', 'Google Chrome'], categories: ['Remote Code Execution', 'Denial of Service'] },
  { civn_id: 'CIVN-2025-0001', title: 'Old', published_date: '2025-01-05', severity: null, cve_count: 0, vendor_key: null, vendor: null, products: [], categories: [] },
  { civn_id: 'CIVN-2026-0510', title: 'Critical RCE in PHP (dup)', published_date: '2026-10-21', severity: 'CRITICAL', cve_count: 2, vendor_key: 'php', vendor: 'PHP', products: ['PHP'], categories: ['Remote Code Execution'] },
  { civn_id: 'not-an-id', title: 'junk' },
  { civn_id: 'CIVN-2024-0002', title: 'Bad date', published_date: '2024-02-30', severity: 'MEDIUM', cve_count: -3, products: null, categories: ['Bogus'] },
];
const NOW = new Date('2026-10-22T12:00:00+05:30');
const { rows, duplicates, dropped } = C.normalizeIndex(raw);

test('normalizeIndex dedupes by ID, drops malformed rows, cleans fields', () => {
  assert.equal(rows.length, 5);
  assert.equal(duplicates, 1);
  assert.equal(dropped, 1);
  const php = rows.find((r) => r.id === 'CIVN-2026-0510');
  assert.equal(php.title, 'Critical RCE in PHP (dup)', 'last write wins');
  const chrome = rows.find((r) => r.id === 'CIVN-2026-0400');
  assert.deepEqual(chrome.products, ['Google Chrome'], 'duplicate products collapse');
  const bad = rows.find((r) => r.id === 'CIVN-2024-0002');
  assert.equal(bad.published, null, 'impossible date rejected');
  assert.equal(bad.cveCount, 0, 'negative CVE count clamped');
  assert.deepEqual(bad.categories, ['Unclassified'], 'unknown category → Unclassified');
  assert.equal(rows.find((r) => r.id === 'CIVN-2025-0001').severity, 'UNKNOWN', 'missing severity is Unknown, never guessed');
  assert.equal(rows.find((r) => r.id === 'CIVN-2026-0509').severity, 'HIGH', 'case-insensitive severity');
});

test('date parsing and arithmetic', () => {
  assert.equal(C.parseISODate('2026-10-21'), '2026-10-21');
  assert.equal(C.parseISODate('2026-02-29'), null);
  assert.equal(C.parseISODate('2024-02-29'), '2024-02-29');
  assert.equal(C.parseISODate('garbage'), null);
  assert.equal(C.parseISODate(undefined), null);
  assert.equal(C.addDays('2026-03-01', -1), '2026-02-28');
  assert.equal(C.daysBetween('2026-01-01', '2026-12-31'), 364);
  assert.equal(C.bucketStart('2026-10-22', 'week'), '2026-10-19', 'ISO weeks start Monday');
  assert.equal(C.bucketStart('2026-10-19', 'week'), '2026-10-19');
  assert.equal(C.bucketStart('2026-10-25', 'week'), '2026-10-19', 'Sunday belongs to the previous Monday');
  assert.equal(C.bucketStart('2026-10-22', 'month'), '2026-10-01');
  assert.equal(C.nextBucket('2026-12-01', 'month'), '2027-01-01');
  assert.deepEqual(C.previousPeriod('2026-10-16', '2026-10-22'), { from: '2026-10-09', to: '2026-10-15' });
});

test('filters combine (AND) and clear', () => {
  assert.equal(C.applyFilters(rows, {}).length, 5);
  assert.deepEqual(C.applyFilters(rows, { sev: ['HIGH'] }).map((r) => r.id).sort(), ['CIVN-2026-0400', 'CIVN-2026-0509']);
  assert.deepEqual(C.applyFilters(rows, { sev: ['HIGH'], vendor: 'google' }).map((r) => r.id), ['CIVN-2026-0400']);
  assert.equal(C.applyFilters(rows, { sev: ['HIGH'], vendor: 'php' }).length, 0);
  assert.equal(C.applyFilters(rows, { from: '2026-10-15', to: '2026-10-22' }).length, 2);
  assert.equal(C.applyFilters(rows, { year: '2026' }).length, 3);
  assert.equal(C.applyFilters(rows, { product: 'google chrome' }).length, 1, 'product match is case-insensitive exact');
  assert.equal(C.applyFilters(rows, { cat: 'Remote Code Execution' }).length, 2);
  assert.equal(C.applyFilters(rows, { vendor: '__none' }).length, 2, 'unknown-vendor bucket');
  assert.equal(C.applyFilters(rows, { changed: '7' }, null, NOW).length, 1);
  assert.equal(C.applyFilters(rows, {}, new Set(['CIVN-2026-0400', 'CIVN-9999-0001'])).length, 1, 'search ID set intersects');
  assert.equal(C.applyFilters(rows, { sev: ['UNKNOWN'] }).length, 1);
  assert.equal(C.applyFilters(rows, { ...C.EMPTY_FILTERS }).length, 5);
});

test('sorting', () => {
  assert.equal(C.sortRows(rows, 'published_desc')[0].id, 'CIVN-2026-0510');
  assert.equal(C.sortRows(rows, 'published_asc')[0].id, 'CIVN-2025-0001', 'missing dates sort last ascending');
  assert.deepEqual(C.sortRows(rows, 'severity').map((r) => r.severity), ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'UNKNOWN']);
  assert.equal(C.sortRows(rows, 'changed')[0].id, 'CIVN-2026-0509');
  assert.equal(C.sortRows(rows, 'cves')[0].id, 'CIVN-2026-0400');
});

test('severity distribution reconciles with the total', () => {
  const d = C.severityDistribution(rows);
  assert.deepEqual(d.map((x) => x.key), C.SEVERITIES);
  assert.equal(d.reduce((s, x) => s + x.count, 0), rows.length);
  assert.ok(Math.abs(d.reduce((s, x) => s + x.pct, 0) - 100) < 1e-9);
  assert.equal(d.find((x) => x.key === 'UNKNOWN').count, 1);
  assert.deepEqual(C.severityDistribution([]).map((x) => x.pct), [0, 0, 0, 0, 0]);
});

test('countBy counts each advisory once per value; vendor table', () => {
  const cats = C.countBy(rows, (r) => r.categories);
  assert.equal(cats.get('Remote Code Execution'), 2);
  assert.equal(cats.get('Denial of Service'), 1);
  const prods = C.countBy(rows, (r) => r.products);
  assert.equal(prods.get('Google Chrome'), 1);
  assert.deepEqual(C.topN(C.countBy(rows, (r) => r.severity), 1), [['HIGH', 2]]);
  const vt = C.vendorTable(rows);
  assert.equal(vt.length, 3);
  assert.equal(vt.reduce((s, v) => s + v.count, 0), rows.filter((r) => r.vendorKey).length);
});

test('trend series is contiguous and sums to in-range advisories', () => {
  const s = C.trendSeries(rows, { from: '2026-10-01', to: '2026-10-22', grain: 'day' });
  assert.equal(s.length, 22);
  assert.equal(s.reduce((n, b) => n + b.count, 0), C.countPublished(rows, '2026-10-01', '2026-10-22'));
  assert.equal(s.find((b) => b.start === '2026-10-21').count, 2);
  const w = C.trendSeries(rows, { from: '2026-10-01', to: '2026-10-22', grain: 'week' });
  assert.equal(w[0].start, '2026-09-28');
  assert.equal(w[0].from, '2026-10-01', 'first partial bucket is clipped to the range');
  assert.equal(w.reduce((n, b) => n + b.count, 0), 3);
  const m = C.trendSeries(rows, { from: '2025-01-01', to: '2026-10-22', grain: 'month' });
  assert.equal(m.length, 22);
  assert.equal(m.reduce((n, b) => n + b.count, 0), 4);
  assert.deepEqual(C.trendSeries(rows, { from: '2026-10-22', to: '2026-10-01' }), []);
});

test('KPIs are computed from the data and compare equal periods', () => {
  const k = C.kpis(rows, { now: NOW, latestSync: { finished_at: '2026-10-22T03:00:00Z', status: 'success' } });
  assert.equal(k.total.value, 5);
  assert.equal(k.critical.value, 1);
  assert.equal(k.high.value, 2);
  assert.equal(k.published7.value, 2);
  assert.deepEqual(k.published7.range, { from: '2026-10-16', to: '2026-10-22' });
  assert.deepEqual(k.published7.prevRange, { from: '2026-10-09', to: '2026-10-15' });
  assert.equal(k.published7.prev, 1);
  assert.equal(k.changed7.value, 1);
  assert.equal(k.unknownSeverity, 1);
  assert.equal(k.refresh.status, 'success');
  assert.ok(k.refresh.ageHours > 3 && k.refresh.ageHours < 4);
  assert.equal(C.kpis([], { now: NOW }).refresh.at, null, 'no sync → no invented timestamp');
  assert.equal(C.pctChange(2, 1), 100);
  assert.equal(C.pctChange(2, 0), null, 'no % change from zero');
});

test('range presets and grain', () => {
  assert.deepEqual(C.resolveRange('7d', rows, NOW), { from: '2026-10-16', to: '2026-10-22' });
  assert.deepEqual(C.resolveRange('2026-01-01..2026-03-31', rows, NOW), { from: '2026-01-01', to: '2026-03-31' });
  assert.equal(C.resolveRange('all', rows, NOW).from, '2025-01-05');
  assert.equal(C.autoGrain('2026-10-01', '2026-10-22'), 'day');
  assert.equal(C.autoGrain('2025-01-01', '2026-10-22'), 'week');
  assert.equal(C.autoGrain('2003-01-01', '2026-10-22'), 'month');
});

test('URL safety and source links', () => {
  assert.equal(C.safeUrl('https://example.com/a?b=1'), 'https://example.com/a?b=1');
  assert.equal(C.safeUrl('javascript:alert(1)'), null);
  assert.equal(C.safeUrl('data:text/html,x'), null);
  assert.equal(C.safeUrl('not a url'), null);
  assert.equal(C.certInUrl('CIVN-2026-0508'), 'https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0508');
  assert.equal(C.certInUrl('x"><script>'), null);
});

test('hash routing round-trips and keeps v1 links working', () => {
  const h = C.buildHash('explore', { q: 'chrome os', sev: ['CRITICAL', 'HIGH'], vendor: 'google', sort: 'published_desc', from: '' });
  assert.equal(h, '#/explore?q=chrome+os&sev=CRITICAL%2CHIGH&vendor=google');
  assert.deepEqual(C.parseHash(h), { view: 'explore', id: undefined, params: { q: 'chrome os', sev: ['CRITICAL', 'HIGH'], vendor: 'google' } });
  assert.deepEqual(C.parseHash('#/advisory/civn-2026-0508'), { view: 'advisory', id: 'CIVN-2026-0508', params: {} });
  assert.equal(C.parseHash('#note=CIVN-2026-0508').id, 'CIVN-2026-0508');
  assert.deepEqual(C.parseHash('#q=CVE-2026-1022'), { view: 'explore', params: { q: 'CVE-2026-1022' } });
  assert.equal(C.parseHash('').view, 'overview');
  assert.equal(C.parseHash('#/nonsense').view, 'overview');
});

test('coverage percentages', () => {
  const c = C.coverage(rows);
  assert.equal(c.severity, 80);
  assert.equal(c.published, 80);
  assert.equal(c.vendor, 60);
  assert.equal(c.classified, 60, 'two rows end up Unclassified');
});
