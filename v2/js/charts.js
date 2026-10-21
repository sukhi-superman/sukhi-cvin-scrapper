// Dependency-free SVG charts. Text is always set with textContent (untrusted data).
// Each chart: thin marks, hairline grid, hover/focus tooltip, click-through, and a
// table-view twin so no value is reachable only by hovering.
const NS = 'http://www.w3.org/2000/svg';
const svgEl = (tag, attrs = {}, parent) => {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) e.setAttribute(k, v);
  if (parent) parent.appendChild(e);
  return e;
};
const h = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

export function niceMax(v) {
  if (v <= 0) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
const compact = (n) => (n >= 1e4 ? `${Math.round(n / 1e3)}K` : n >= 1e3 ? `${(n / 1e3).toFixed(1).replace(/\.0$/, '')}K` : String(n));

function tooltip(container) {
  let tip = container.querySelector(':scope > .tip');
  if (!tip) { tip = h('div', 'tip'); tip.hidden = true; tip.setAttribute('role', 'status'); container.appendChild(tip); }
  return {
    show(lines, x, y) {
      tip.replaceChildren(...lines);
      tip.hidden = false;
      const cw = container.clientWidth, tw = tip.offsetWidth, th = tip.offsetHeight;
      tip.style.left = Math.min(Math.max(4, x + 14), cw - tw - 4) + 'px';
      tip.style.top = Math.max(0, y - th - 10) + 'px';
    },
    hide() { tip.hidden = true; },
  };
}

function observe(container, draw) {
  let last = 0;
  const run = () => { const w = Math.floor(container.clientWidth); if (w && w !== last) { last = w; draw(w); } };
  if (container._ro) container._ro.disconnect();
  container._ro = new ResizeObserver(run);
  container._ro.observe(container);
  run();
}

/**
 * Time-series line chart (single measure) with optional previous-period overlay.
 * points: [{label, sub, value, data}] in time order; prev: [{label, value}] aligned by index.
 */
export function lineChart(container, { points, prev = null, height = 240, valueLabel = 'advisories', onSelect }) {
  container.classList.add('chart');
  observe(container, (W) => {
    container.querySelector('svg')?.remove();
    const M = { t: 10, r: 12, b: 26, l: 38 };
    const iw = Math.max(10, W - M.l - M.r), ih = height - M.t - M.b;
    const maxV = niceMax(Math.max(1, ...points.map((p) => p.value), ...(prev || []).map((p) => p.value)));
    const n = points.length;
    const x = (i) => M.l + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (v) => M.t + ih - (v / maxV) * ih;
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${height}`, width: W, height, role: 'img', 'aria-label': `Line chart of ${valueLabel} over time` });
    container.prepend(svg);
    const g = svgEl('g', { class: 'axis' }, svg);
    for (let i = 0; i <= 4; i++) {
      const v = (maxV / 4) * i, yy = Math.round(y(v)) + 0.5;
      svgEl('line', { class: 'gridline', x1: M.l, x2: W - M.r, y1: yy, y2: yy }, g);
      svgEl('text', { x: M.l - 8, y: yy + 4, 'text-anchor': 'end' }, g).textContent = compact(v);
    }
    const ticks = Math.min(n, Math.max(2, Math.floor(iw / 90)));
    for (let t = 0; t < ticks; t++) {
      const i = ticks === 1 ? 0 : Math.round((t / (ticks - 1)) * (n - 1));
      svgEl('text', { x: x(i), y: height - 6, 'text-anchor': t === 0 ? 'start' : t === ticks - 1 ? 'end' : 'middle' }, g).textContent = points[i]?.label ?? '';
    }
    if (!n) return;
    const path = (arr) => arr.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join('');
    if (prev?.length) svgEl('path', { class: 'line-prev', d: path(prev.slice(0, n)) }, svg);
    svgEl('path', { class: 'area', d: `${path(points)}L${x(n - 1)},${y(0)}L${x(0)},${y(0)}Z` }, svg);
    svgEl('path', { class: 'line', d: path(points) }, svg);
    if (n <= 60) points.forEach((p, i) => svgEl('circle', { class: 'pt', cx: x(i), cy: y(p.value), r: 3.5 }, svg));
    const last = points[n - 1];
    svgEl('circle', { class: 'pt', cx: x(n - 1), cy: y(last.value), r: 4.5 }, svg);

    const cross = svgEl('line', { class: 'crosshair', y1: M.t, y2: M.t + ih, visibility: 'hidden' }, svg);
    const dot = svgEl('circle', { class: 'pt', r: 5, visibility: 'hidden' }, svg);
    const tip = tooltip(container);
    let cur = -1;
    const focusAt = (i) => {
      cur = Math.max(0, Math.min(n - 1, i));
      const p = points[cur];
      cross.setAttribute('x1', x(cur)); cross.setAttribute('x2', x(cur)); cross.setAttribute('visibility', 'visible');
      dot.setAttribute('cx', x(cur)); dot.setAttribute('cy', y(p.value)); dot.setAttribute('visibility', 'visible');
      const lines = [h('div', 'v', `${p.value.toLocaleString('en-IN')} ${valueLabel}`), h('div', 'k', p.sub || p.label)];
      if (prev?.[cur]) { const r = h('div', 'k'); const key = h('span', 'key'); key.style.background = 'var(--text-3)'; r.append(key, `Previous period: ${prev[cur].value.toLocaleString('en-IN')}`); lines.push(r); }
      if (onSelect) lines.push(h('div', 'k faint', 'Click to list these advisories'));
      tip.show(lines, x(cur), y(p.value));
    };
    const hit = svgEl('rect', { x: M.l, y: M.t, width: iw, height: ih, fill: 'transparent', tabindex: 0, style: onSelect ? 'cursor:pointer' : null, 'aria-label': 'Chart: use arrow keys to move between periods, Enter to open' }, svg);
    const idxFrom = (evt) => { const r = svg.getBoundingClientRect(); const px = ((evt.clientX - r.left) / r.width) * W; return n <= 1 ? 0 : Math.round(((px - M.l) / iw) * (n - 1)); };
    hit.addEventListener('pointermove', (e) => focusAt(idxFrom(e)));
    hit.addEventListener('pointerleave', () => { cross.setAttribute('visibility', 'hidden'); dot.setAttribute('visibility', 'hidden'); tip.hide(); });
    hit.addEventListener('click', (e) => onSelect && onSelect(points[idxFrom(e)]));
    hit.addEventListener('focus', () => focusAt(cur < 0 ? n - 1 : cur));
    hit.addEventListener('blur', () => tip.hide());
    hit.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight') { focusAt(cur + 1); e.preventDefault(); }
      if (e.key === 'ArrowLeft') { focusAt(cur - 1); e.preventDefault(); }
      if ((e.key === 'Enter' || e.key === ' ') && onSelect && cur >= 0) { onSelect(points[cur]); e.preventDefault(); }
    });
  });
}

/**
 * Horizontal bar chart. items: [{key, label, value, color?, note?}] (already sorted).
 * One series → one colour (accent) unless an item carries its own status colour.
 */
export function hBarChart(container, { items, valueText = (it) => it.value.toLocaleString('en-IN'), onSelect, ariaLabel = 'Bar chart', rowH = 30 }) {
  container.classList.add('chart');
  observe(container, (W) => {
    container.querySelector('svg')?.remove();
    const labelW = Math.min(Math.max(110, W * 0.34), 220);
    const valW = 92;
    const bw = Math.max(20, W - labelW - valW - 8);
    const height = Math.max(rowH, items.length * rowH);
    const maxV = Math.max(1, ...items.map((i) => i.value));
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${height}`, width: W, height, role: 'list', 'aria-label': ariaLabel });
    container.prepend(svg);
    const tip = tooltip(container);
    const maxChars = Math.floor(labelW / 6.6);
    items.forEach((it, i) => {
      const y0 = i * rowH, cy = y0 + rowH / 2;
      const g = svgEl('g', { role: 'listitem' }, svg);
      const row = svgEl('rect', { class: 'row-hit', x: 0, y: y0 + 1, width: W, height: rowH - 2, rx: 4, tabindex: onSelect ? 0 : null, 'aria-label': `${it.label}: ${valueText(it)}${onSelect ? ' — open list' : ''}` }, g);
      const lab = svgEl('text', { class: 'label', x: 8, y: cy + 4 }, g);
      lab.textContent = it.label.length > maxChars ? it.label.slice(0, maxChars - 1) + '…' : it.label;
      const len = Math.max(it.value ? 3 : 0, (it.value / maxV) * bw);
      const th = Math.min(14, rowH - 12), r = Math.min(4, len / 2);
      const x0 = labelW, yb = cy - th / 2;
      if (len > 0) svgEl('path', { class: 'bar', d: `M${x0},${yb}H${x0 + len - r}Q${x0 + len},${yb} ${x0 + len},${yb + r}V${yb + th - r}Q${x0 + len},${yb + th} ${x0 + len - r},${yb + th}H${x0}Z`, style: it.color ? `fill:${it.color}` : null }, g);
      svgEl('text', { class: 'label-2', x: x0 + len + 8, y: cy + 4 }, g).textContent = valueText(it);
      const show = () => tip.show([h('div', 'v', valueText(it)), h('div', 'k', it.label), ...(it.note ? [h('div', 'k faint', it.note)] : []), ...(onSelect ? [h('div', 'k faint', 'Click to list these advisories')] : [])], x0 + len, y0 + 4);
      row.addEventListener('pointerenter', show); row.addEventListener('focus', show);
      row.addEventListener('pointerleave', () => tip.hide()); row.addEventListener('blur', () => tip.hide());
      if (onSelect) {
        row.addEventListener('click', () => onSelect(it));
        row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { onSelect(it); e.preventDefault(); } });
      }
    });
  });
}

/** Accessible table twin. cols: [{label, get, num?}] */
export function dataTable(container, cols, rows, { caption } = {}) {
  const wrap = h('div', 'tbl-wrap');
  const t = h('table', 'tbl');
  if (caption) { const c = h('caption', 'sr-only', caption); t.appendChild(c); }
  const thead = h('thead'); const trh = h('tr');
  cols.forEach((c) => { const th = h('th', c.num ? 'n' : '', c.label); th.scope = 'col'; trh.appendChild(th); });
  thead.appendChild(trh); t.appendChild(thead);
  const tb = h('tbody');
  rows.forEach((r) => { const tr = h('tr'); cols.forEach((c) => tr.appendChild(h('td', c.num ? 'n' : '', String(c.get(r))))); tb.appendChild(tr); });
  t.appendChild(tb); wrap.appendChild(t);
  container.replaceChildren(wrap);
}
