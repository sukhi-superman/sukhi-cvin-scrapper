// End-to-end browser test of v2 against a mocked Supabase REST API (PostgREST semantics).
// Run from v2/:  npm i -D playwright && npx playwright install chromium && node tests/e2e.mjs
// Scenarios: SCEN=normal (default) | down | stale | failed ;  DARK=1 for dark-mode screenshots.
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import * as C from '../js/core.js';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const ROOT = path.resolve(HERE, '..');
const OUT = path.join(HERE, 'screenshots');
fs.mkdirSync(OUT, { recursive: true });
const SCEN = process.env.SCEN || 'normal';

// ---------------- synthetic dataset (deterministic)
let seed = 42; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
const pick = (a) => a[Math.floor(rnd() * a.length)];
const VENDORS = [['google', 'Google', ['Google Chrome', 'Android']], ['microsoft', 'Microsoft', ['Windows 10', 'Windows 11', 'Microsoft Edge', 'Microsoft Office']], ['cisco', 'Cisco', ['Cisco IOS XE', 'Cisco ASA']], ['apple', 'Apple', ['Apple iOS', 'Apple macOS']], ['fortinet', 'Fortinet', ['FortiOS']], ['sonicwall', 'SonicWall', ['SMA 1000']], [null, null, ['Generic Thing']]];
const CATS = ['Remote Code Execution', 'Privilege Escalation', 'Information Disclosure', 'Denial of Service', 'Cross-Site Scripting', 'SQL Injection', 'Other'];
const today = C.todayISO(new Date());
const notes = [];
for (let i = 0; i < 3000; i++) {
  const ageDays = Math.floor(rnd() ** 2 * 3650);
  const pub = C.addDays(today, -ageDays);
  const y = +pub.slice(0, 4);
  const [vk, vn, prods] = pick(VENDORS);
  const sev = rnd() < 0.03 ? null : pick(['CRITICAL', 'HIGH', 'HIGH', 'HIGH', 'MEDIUM', 'LOW']);
  const ncve = Math.floor(rnd() * 6);
  notes.push({
    civn_id: `CIVN-${y}-${String(1000 + i).padStart(4, '0')}`, year: y,
    title: `Multiple vulnerabilities in ${prods[0]} ${i}`, published_date: pub, severity: sev,
    cve_ids: Array.from({ length: ncve }, (_, j) => `CVE-${y}-${20000 + i * 7 + j}`),
    vendor_key: vk, vendor: vn, products: rnd() < 0.5 ? [prods[0]] : prods.slice(0, 2),
    categories: rnd() < 0.05 ? ['Unclassified'] : [...new Set([pick(CATS), pick(CATS)])],
    first_seen_at: new Date(Date.now() - rnd() * 3 * 864e5).toISOString(),
    content_changed_at: i % 97 === 0 ? new Date(Date.now() - 2 * 864e5).toISOString() : null,
  });
}
// edge cases: XSS title, dangerous reference URL, all-missing fields, duplicate ID
notes.push({ civn_id: `CIVN-${today.slice(0, 4)}-9001`, year: +today.slice(0, 4), title: '<img src=x onerror="window.__xss=1"> Script <b>injection</b>', published_date: today, severity: 'CRITICAL', cve_ids: ['CVE-2026-99999'], vendor_key: 'google', vendor: 'Google', products: ['Google Chrome'], categories: ['Remote Code Execution'], first_seen_at: new Date().toISOString(), content_changed_at: null });
notes.push({ civn_id: `CIVN-${today.slice(0, 4)}-9002`, year: +today.slice(0, 4), title: 'Sparse note', published_date: null, severity: null, cve_ids: [], vendor_key: null, vendor: null, products: [], categories: [], first_seen_at: null, content_changed_at: null });
const dupe = { ...notes[5] };
const indexRows = [...notes, dupe].map(({ year, cve_ids, ...r }) => ({ ...r, cve_count: cve_ids.length }));
const detail = (id) => {
  const n = notes.find((x) => x.civn_id === id); if (!n) return null;
  return { civn_id: n.civn_id, title: n.title, published_date: n.published_date, severity: n.severity,
    software_affected: id.endsWith('9002') ? null : `• ${n.products[0]} prior to 1.2.3`, overview: id.endsWith('9002') ? null : 'Overview <script>window.__xss2=1</script> text',
    impact: null, description: id.endsWith('9002') ? null : 'Line one\nLine two', workaround: null, solution: id.endsWith('9002') ? null : 'Apply updates:\nhttps://vendor.example/fix',
    vendor_information: n.vendor ? `${n.vendor}\nhttps://vendor.example` : null,
    reference_urls: ['https://vendor.example/advisory', 'javascript:alert(1)', 'https://vendor.example/advisory'], cve_ids: n.cve_ids, cwe_ids: [],
    other_sections: {}, source_url: C.certInUrl(n.civn_id), first_seen_at: n.first_seen_at, last_scraped_at: n.first_seen_at, content_changed_at: n.content_changed_at };
};
const syncAt = SCEN === 'stale' ? new Date(Date.now() - 80 * 3600e3) : new Date(Date.now() - 2 * 3600e3);
const latestSync = { id: 9, mode: 'incremental', status: 'success', started_at: syncAt.toISOString(), finished_at: syncAt.toISOString(), notes_listed: 510, notes_new: 3, notes_upserted: 8, notes_failed: 0 };
const lastRun = SCEN === 'failed' ? { id: 10, mode: 'incremental', status: 'failed', started_at: new Date().toISOString(), finished_at: new Date().toISOString(), message: 'ConnectionError: cert-in.org.in timed out' } : { ...latestSync };
const allCves = notes.flatMap((n) => n.cve_ids);
const stats = { advisories: notes.length, cve_mentions: allCves.length, unique_cves: new Set(allCves).size, with_cves: notes.filter((n) => n.cve_ids.length).length };
const search = (q) => { const u = q.toUpperCase(); return notes.filter((n) => u.startsWith('CIVN-') ? n.civn_id.startsWith(u) : u.startsWith('CVE-') ? n.cve_ids.some((c) => c.startsWith(u)) : (n.title + ' ' + (n.vendor || '') + ' ' + n.products.join(' ')).toLowerCase().includes(q.toLowerCase())).map((n) => ({ civn_id: n.civn_id })).sort((a, b) => a.civn_id.localeCompare(b.civn_id)); };

// expected values computed independently with the same core library on the mock rows
const expected = C.normalizeIndex(indexRows).rows;
const K = C.kpis(expected, { now: new Date(), latestSync });

const results = []; const errors = [];
const check = (name, ok, info = '') => { results.push([ok ? 'PASS' : 'FAIL', name, info]); };

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH, args: ['--headless=new'], headless: false } : {});
async function setup(ctxOpts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 }, colorScheme: process.env.DARK ? 'dark' : 'light', ...ctxOpts });
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'https://app.test' });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`${SCEN} pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push(`${SCEN} console: ${m.text()}`); });
  const reqLog = [];
  await page.route('**/*', async (route) => {
    const req = route.request(); const url = new URL(req.url());
    if (url.host === 'app.test') {
      const rel = url.pathname.replace(/^\/v2\//, '').replace(/^\/$/, 'index.html') || 'index.html';
      const f = path.join(ROOT, rel === '' ? 'index.html' : rel);
      if (!fs.existsSync(f)) return route.fulfill({ status: 404, body: 'nf' });
      const type = f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html';
      return route.fulfill({ contentType: type, body: fs.readFileSync(f) });
    }
    if (url.host.endsWith('.supabase.co')) {
      const hdr = { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'access-control-allow-headers': '*', 'access-control-expose-headers': 'content-range' };
      if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: hdr });
      reqLog.push(req.method() + ' ' + url.pathname);
      if (SCEN === 'down') return route.fulfill({ status: 503, headers: hdr, body: JSON.stringify({ message: 'Service unavailable' }) });
      const p = url.searchParams; const off = +(p.get('offset') || 0), lim = +(p.get('limit') || 1000);
      const page = (arr) => arr.slice(off, off + lim);
      if (url.pathname.endsWith('/advisory_index')) {
        const sorted = [...indexRows].sort((a, b) => a.civn_id.localeCompare(b.civn_id));
        return route.fulfill({ headers: { ...hdr, 'content-range': `${off}-${off + lim - 1}/${sorted.length}` }, body: JSON.stringify(page(sorted)) });
      }
      if (url.pathname.endsWith('/latest_sync')) return route.fulfill({ headers: hdr, body: JSON.stringify([latestSync]) });
      if (url.pathname.endsWith('/sync_runs')) return route.fulfill({ headers: hdr, body: JSON.stringify([lastRun]) });
      if (url.pathname.endsWith('/rpc/index_stats')) return route.fulfill({ headers: hdr, body: JSON.stringify(stats) });
      if (url.pathname.endsWith('/rpc/search_advisory_ids')) return route.fulfill({ headers: hdr, body: JSON.stringify(page(search(JSON.parse(req.postData()).q))) });
      if (url.pathname.endsWith('/vulnerability_notes')) { const id = (p.get('civn_id') || '').replace('eq.', ''); const d = detail(id); return route.fulfill({ headers: hdr, body: JSON.stringify(d ? [d] : []) }); }
      return route.fulfill({ status: 404, headers: hdr, body: '[]' });
    }
    if (/fonts\.(googleapis|gstatic)\.com/.test(url.host)) return route.fulfill({ status: 200, contentType: 'text/css', body: '' });
    return route.abort();
  });
  return { ctx, page, reqLog };
}
const num = (s) => parseInt(String(s).replace(/[^\d]/g, ''), 10);
const countText = async (page) => num((await page.textContent('#count strong')) || '');
const waitCount = async (page) => { await page.waitForFunction(() => /advisories/.test(document.querySelector('#count strong')?.textContent || '')); };

if (SCEN === 'normal') {
  const { page } = await setup();
  await page.goto('https://app.test/v2/');
  try { await waitCount(page); } catch (e) { console.log('ERRORS', errors, (await page.textContent('#view')).slice(0, 300)); process.exit(1); }
  check('default route = CVIN Explorer', page.url().endsWith('/v2/') && (await page.textContent('.page-head h1')) === 'CVIN Explorer');
  check('nav has only CVIN Explorer + CVIN Analytics', JSON.stringify(await page.$$eval('#nav a', (a) => a.map((x) => x.textContent.trim()))) === JSON.stringify(['CVIN Explorer', 'CVIN Analytics']));
  check('total = deduped rows', (await countText(page)) === expected.length, `${await countText(page)} vs ${expected.length}`);
  check('duplicate excluded & reported', expected.length === notes.length && /1 duplicate/.test(await page.textContent('#banners')));
  check('freshness sidebar ok', (await page.getAttribute('#freshness .dot', 'class')).includes('ok'));
  await page.screenshot({ path: `${OUT}/v2-explorer.png`, fullPage: true });
  await page.goto('https://app.test/v2/#/overview'); await waitCount(page);
  check('old #/overview link → CVIN Explorer', (await page.textContent('.page-head h1')) === 'CVIN Explorer');

  // severity filter via URL
  await page.goto('https://app.test/v2/#/explore?sev=CRITICAL'); await waitCount(page);
  check('Critical filter count', (await countText(page)) === K.critical.value, `${await countText(page)}`);
  check('active chip present', (await page.textContent('#chips')).includes('Critical'));

  // search + filters combine & clear
  await page.fill('#q', 'CVE-2026'); await page.waitForTimeout(500); await waitCount(page);
  await page.waitForFunction(() => document.getElementById('results').style.opacity === '');
  const expCveCrit = C.applyFilters(expected, { sev: ['CRITICAL'] }, new Set(search('CVE-2026').map((r) => r.civn_id))).length;
  check('CVE prefix search ∩ severity', (await countText(page)) === expCveCrit, `${await countText(page)} vs ${expCveCrit}`);
  check('mode badge = CVE ID', (await page.textContent('#q-mode')) === 'CVE ID');
  await page.selectOption('#f-vendor', 'google'); await page.waitForTimeout(300);
  const expG = C.applyFilters(expected, { sev: ['CRITICAL'], vendor: 'google' }, new Set(search('CVE-2026').map((r) => r.civn_id))).length;
  check('+ vendor filter', (await countText(page)) === expG, `${await countText(page)} vs ${expG}`);
  check('URL carries state', /q=CVE-2026/.test(page.url()) && /vendor=google/.test(page.url()) && /sev=CRITICAL/.test(page.url()));
  await page.click('#chips .chip:has-text("Vendor") button'); await page.waitForTimeout(300);
  check('remove one chip', (await countText(page)) === expCveCrit);
  await page.click('#clear'); await page.waitForTimeout(400);
  check('clear all → full list', (await countText(page)) === expected.length);
  check('search box cleared', (await page.inputValue('#q')) === '');

  // keyword + highlight; date range + year; sort severity
  await page.fill('#q', 'chrome'); await page.press('#q', 'Enter'); await page.waitForTimeout(500); await waitCount(page);
  check('keyword search count', (await countText(page)) === C.applyFilters(expected, {}, new Set(search('chrome').map((r) => r.civn_id))).length);
  check('keyword highlighted', (await page.locator('#results mark').count()) > 0);
  check('XSS title rendered inert', (await page.evaluate(() => window.__xss)) === undefined && (await page.locator('#results img').count()) === 0);
  await page.click('#clear'); await page.waitForTimeout(300);
  const y = today.slice(0, 4);
  await page.selectOption('#f-year', y); await page.waitForTimeout(300);
  check('year filter', (await countText(page)) === C.applyFilters(expected, { year: y }).length);
  await page.selectOption('#f-sort', 'severity'); await page.waitForTimeout(300);
  const sevs = await page.$$eval('#results .res .sev', (e) => e.map((x) => x.textContent));
  check('severity sort order', sevs[0] === 'Critical' && sevs.indexOf('Unknown') === -1 || sevs.indexOf('Unknown') > sevs.lastIndexOf('Low'));
  await page.click('#more'); await page.waitForTimeout(200);
  check('show more paginates', (await page.locator('#results .res').count()) === Math.min(100, C.applyFilters(expected, { year: y }).length));
  await page.click('#clear'); await page.waitForTimeout(300);
  await page.fill('#q', 'zzzz-nothing'); await page.press('#q', 'Enter'); await page.waitForTimeout(500);
  check('empty search state', (await page.textContent('#results')).includes('No matching advisories'));

  // analytics reconciles
  await page.goto('https://app.test/v2/#/analytics?range=all'); await page.waitForSelector('#freshness-card');
  const sevTbl = await page.evaluate(() => {
    const card = [...document.querySelectorAll('.chart-card')].find((c) => c.querySelector('h2')?.textContent === 'Severity distribution');
    card.querySelectorAll('.toggle button')[1].click();
    return [...card.querySelectorAll('tbody tr')].map((tr) => [...tr.children].map((td) => td.textContent));
  });
  const sevSum = sevTbl.reduce((s, r) => s + num(r[1]), 0);
  const allRange = C.applyFilters(expected, C.resolveRange('all', expected));
  check('severity table sums to slice total', sevSum === allRange.length, `${sevSum} vs ${allRange.length}`);
  check('severity shares ≈ 100%', Math.abs(sevTbl.reduce((s, r) => s + parseFloat(r[2]), 0) - 100) < 0.6);
  check('Unknown severity shown, not guessed', sevTbl.some((r) => r[0] === 'Unknown' && num(r[1]) === allRange.filter((x) => x.severity === 'UNKNOWN').length));
  const trendTotal = await page.evaluate(() => {
    const card = [...document.querySelectorAll('.chart-card')].find((c) => c.querySelector('h2')?.textContent === 'Publication trend');
    card.querySelectorAll('.toggle')[1].querySelectorAll('button')[1].click();
    return [...card.querySelectorAll('tbody tr')].reduce((s, tr) => s + parseInt(tr.children[1].textContent.replace(/\D/g, ''), 10), 0);
  });
  check('trend buckets sum to published-in-range', trendTotal === allRange.filter((r) => r.published).length, `${trendTotal}`);
  await page.goto('https://app.test/v2/#/analytics'); await page.waitForSelector('#freshness-card');
  check('default range preset marked pressed', (await page.getAttribute('.toggle button:has-text("1 year")', 'aria-pressed')) === 'true');
  await page.screenshot({ path: `${OUT}/v2-analytics.png`, fullPage: true });
  // click a vendor bar → explorer count equals bar value
  const vendorBar = await page.evaluate(() => {
    const card = [...document.querySelectorAll('.chart-card')].find((c) => c.querySelector('h2')?.textContent === 'Top vendors');
    const row = card.querySelector('.row-hit'); const label = row.getAttribute('aria-label'); row.dispatchEvent(new MouseEvent('click', { bubbles: true })); return label;
  });
  await waitCount(page);
  check('vendor bar click-through reconciles', (await countText(page)) === num(vendorBar.split(':')[1]), `${vendorBar} → ${await countText(page)}`);
  // trend point click → explorer with that bucket
  await page.goto('https://app.test/v2/#/analytics?range=90d'); await page.waitForSelector('.chart svg');
  const box = await page.locator('.chart-card').first().locator('svg rect[tabindex="0"]').boundingBox();
  await page.mouse.move(box.x + box.width - 3, box.y + box.height / 2);
  check('trend tooltip on hover', !(await page.locator('.tip').first().isHidden()));
  await page.mouse.click(box.x + box.width - 3, box.y + box.height / 2); await waitCount(page);
  check('trend click opens filtered list', /from=/.test(page.url()) && /to=/.test(page.url()));

  // detail page
  await page.goto(`https://app.test/v2/#/advisory/CIVN-${y}-9001`); await page.waitForSelector('.detail h1');
  const det = await page.textContent('.detail');
  check('detail has 6 sections', ['1 · Overview', '2 · Vulnerability details', '3 · Affected products', '4 · Risk & severity', '5 · Remediation', '6 · References'].every((s) => det.includes(s)));
  check('detail XSS inert', (await page.evaluate(() => window.__xss || window.__xss2)) === undefined && (await page.locator('.detail img').count()) === 0);
  check('javascript: URL not linked', (await page.locator('.detail a[href^="javascript"]').count()) === 0 && (await page.locator('.links li').count()) === 1);
  check('CVSS shown as not available', det.includes('Not available — not published by CERT-In'));
  check('official CERT-In button', (await page.getAttribute('a.btn-primary', 'href')).startsWith('https://www.cert-in.org.in/'));
  await page.click('button:has-text("Copy ID")');
  check('copy ID', (await page.evaluate(() => navigator.clipboard.readText())) === `CIVN-${y}-9001`);
  await page.screenshot({ path: `${OUT}/v2-detail.png`, fullPage: true });
  await page.goto(`https://app.test/v2/#/advisory/CIVN-${y}-9002`); await page.waitForSelector('.detail h1');
  check('sparse advisory renders with Not available states', (await page.locator('.na').count()) >= 4);
  await page.goto('https://app.test/v2/#/advisory/CIVN-1999-0001'); await page.waitForSelector('.empty');
  check('unknown advisory → not-found state', (await page.textContent('.empty')).includes('not in the index'));

  // v1 links
  await page.goto(`https://app.test/v2/#note=CIVN-${y}-9001`); await page.waitForSelector('.detail h1');
  check('v1 #note= link works + canonicalised', page.url().includes('#/advisory/'));
  await page.goto('https://app.test/v2/#q=chrome'); await waitCount(page);
  check('v1 #q= link works', (await page.inputValue('#q')) === 'chrome');

  // theme
  await page.goto('https://app.test/v2/#/explore'); await waitCount(page);
  const theme0 = await page.getAttribute('html', 'data-theme');
  await page.click('#theme');
  const theme1 = await page.getAttribute('html', 'data-theme');
  check('theme toggles + persists', theme0 !== theme1 && (await page.evaluate(() => localStorage.getItem('cvin:theme'))) === theme1, `${theme0}→${theme1}`);
  if (theme1 !== 'light') await page.click('#theme');
  await page.screenshot({ path: `${OUT}/v2-explorer-light.png` });
  await page.click('#theme');

  // mobile
  const m = await setup({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  for (const r of ['#/explore', '#/analytics', `#/advisory/CIVN-${y}-9001`]) {
    await m.page.goto('https://app.test/v2/' + r); await m.page.waitForSelector('.page-head, .detail'); await m.page.waitForTimeout(300);
    check(`mobile no h-scroll ${r}`, await m.page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), String(await m.page.evaluate(() => document.documentElement.scrollWidth)));
  }
  await m.page.goto('https://app.test/v2/#/explore'); await waitCount(m.page);
  await m.page.screenshot({ path: `${OUT}/v2-mobile-explorer.png`, fullPage: true });
  await m.page.click('#nav-toggle'); await m.page.waitForTimeout(250);
  check('mobile nav opens', await m.page.evaluate(() => document.getElementById('app').classList.contains('nav-open')));
  await m.page.screenshot({ path: `${OUT}/v2-mobile-nav.png` });
} else {
  const { page } = await setup();
  await page.goto('https://app.test/v2/'); await page.waitForTimeout(1500);
  const txt = await page.textContent('body');
  if (SCEN === 'down') check('DB down → error state with retry', txt.includes('Could not load vulnerability data') && (await page.locator('button:has-text("Try again")').count()) === 1);
  if (SCEN === 'stale') check('stale banner', txt.includes('Data may be stale') && (await page.getAttribute('#freshness .dot', 'class')).includes('bad'));
  if (SCEN === 'failed') check('failed-source banner', txt.includes('Source refresh failed') && txt.includes('timed out'));
  await page.screenshot({ path: `${OUT}/v2-${SCEN}.png` });
}
await browser.close();
for (const r of results) console.log(r.join('  '));
console.log(`${SCEN}: ${results.filter((r) => r[0] === 'PASS').length}/${results.length} passed`);
console.log('errors:', errors.length ? errors : 'none');
