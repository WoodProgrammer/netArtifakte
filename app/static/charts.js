// pcap-analyzer — dependency-free SVG/HTML charts.
// Rules: thin marks (2px lines, <=24px bars, 4px rounded ends), hairline grid,
// categorical colors are fixed per entity, every chart has a hover/keyboard tooltip,
// text uses the text color, not the data color. The table view lives in the card component in app.js.

const SVG_NS = "http://www.w3.org/2000/svg";

// ---------------------------------------------------------------- formatting
export const fmt = {
  num(v) {
    if (v == null || Number.isNaN(v)) return "–";
    const a = Math.abs(v);
    if (a >= 1e9) return (v / 1e9).toFixed(a >= 1e10 ? 0 : 1).replace(/\.0$/, "") + "B";
    if (a >= 1e6) return (v / 1e6).toFixed(a >= 1e7 ? 0 : 1).replace(/\.0$/, "") + "M";
    if (a >= 1e4) return (v / 1e3).toFixed(a >= 1e5 ? 0 : 1).replace(/\.0$/, "") + "K";
    return Number.isInteger(v) ? v.toLocaleString("en-US-u-hc-h23") : v.toLocaleString("en-US-u-hc-h23", { maximumFractionDigits: 1 });
  },
  bytes(v) {
    if (v == null) return "–";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (Math.abs(v) >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${i ? v.toFixed(v >= 100 ? 0 : 1) : v} ${u[i]}`;
  },
  ms(v) {
    if (v == null) return "–";
    if (v >= 1000) return `${(v / 1000).toFixed(2).replace(/\.?0+$/, "")} s`;
    return `${Number.isInteger(v) || v >= 100 ? Math.round(v) : v.toFixed(1)} ms`;
  },
  pct(v) { return v == null ? "–" : `${(v * 100).toFixed(v < 0.1 && v > 0 ? 1 : 0)}%`; },
  time(ms, span = 0) {
    const d = new Date(ms);
    const o = span < 180e3 ? { hour: "2-digit", minute: "2-digit", second: "2-digit" }
      : span < 2 * 864e5 ? { hour: "2-digit", minute: "2-digit" }
      : { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" };
    return d.toLocaleString("en-US-u-hc-h23", o);
  },
};

// ---------------------------------------------------------------- helpers
function el(tag, attrs = {}, parent) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (parent) parent.appendChild(n);
  return n;
}
function h(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function niceStep(raw) {
  const p = 10 ** Math.floor(Math.log10(raw));
  const f = raw / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}
function niceTicks(max, count = 4) {
  if (max <= 0) return [0, 1];
  const step = niceStep(max / count);
  const ticks = [];
  for (let v = 0; v <= max + step * 0.001; v += step) ticks.push(+v.toFixed(10));
  if (ticks[ticks.length - 1] < max) ticks.push(+(ticks[ticks.length - 1] + step).toFixed(10));
  return ticks;
}
const TIME_STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800]
  .map(s => s * 1000);
function timeTicks(t0, t1, maxTicks) {
  const span = t1 - t0;
  if (span <= 0) return [t0];
  const step = TIME_STEPS.find(s => span / s <= maxTicks) || TIME_STEPS[TIME_STEPS.length - 1];
  const tzOffset = new Date(t0).getTimezoneOffset() * 60e3;
  const first = Math.ceil((t0 - tzOffset) / step) * step + tzOffset;
  const out = [];
  for (let t = first; t <= t1; t += step) out.push(t);
  return out;
}
const cssVar = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const isDark = () => document.documentElement.dataset.theme === "dark";

// ---------------------------------------------------------------- tooltip (single, shared)
let tipEl;
export const tooltip = {
  show(x, y, { title, rows }) {
    if (!tipEl) { tipEl = h("div", "tooltip"); tipEl.setAttribute("role", "status"); document.body.appendChild(tipEl); }
    tipEl.replaceChildren();
    if (title) tipEl.appendChild(h("div", "tt-title", title));
    for (const r of rows) {
      const row = h("div", "tt-row");
      if (r.color) { const k = h("span", r.shape === "x" ? "" : "tt-key"); if (r.shape === "x") { k.textContent = "×"; k.style.color = r.color; k.style.fontWeight = 700; } else k.style.background = r.color; row.appendChild(k); }
      row.appendChild(h("span", "tt-val", r.value));
      if (r.name) row.appendChild(h("span", "tt-name", r.name));
      tipEl.appendChild(row);
    }
    tipEl.style.display = "block";
    const { width, height } = tipEl.getBoundingClientRect();
    let left = x + 14, top = y + 14;
    if (left + width > innerWidth - 8) left = x - width - 14;
    if (top + height > innerHeight - 8) top = y - height - 14;
    tipEl.style.left = `${Math.max(8, left)}px`;
    tipEl.style.top = `${Math.max(8, top)}px`;
  },
  hide() { if (tipEl) tipEl.style.display = "none"; },
};

// ---------------------------------------------------------------- time series (line + area)
/**
 * points: [{t: ms, v: number|null}] — single series.
 * opts: { format, height, markers, color, name, area, onPointClick }
 */
export function timeSeries(container, points, opts = {}) {
  const { format = fmt.num, height = 200, markers = false, color = "var(--s1)", name = "", area = true } = opts;
  container.replaceChildren();
  const W = Math.max(container.clientWidth, 240), H = height;
  const valid = points.filter(p => p.v != null);
  const maxV = Math.max(0, ...valid.map(p => p.v));
  const ticks = niceTicks(maxV);
  const yMax = ticks[ticks.length - 1];
  const yLabelW = Math.max(...ticks.map(t => format(t).length)) * 6.5 + 10;
  const m = { l: Math.max(32, yLabelW), r: markers ? 48 : 16, t: 10, b: 26 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const t0 = points[0]?.t ?? 0, t1 = points[points.length - 1]?.t ?? 1, span = t1 - t0;
  const x = t => m.l + (span ? (t - t0) / span * iw : iw / 2);
  const y = v => m.t + (1 - v / yMax) * ih;

  const svg = el("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, tabindex: 0, role: "img",
    "aria-label": `${name || "Time series"}: ${valid.length} ${valid.length === 1 ? "point" : "points"}, max ${format(maxV)}` }, container);

  for (const t of ticks) {
    el("line", { x1: m.l, x2: W - m.r, y1: y(t), y2: y(t), class: t === 0 ? "baseline" : "gridline" }, svg);
    el("text", { x: m.l - 8, y: y(t) + 4, "text-anchor": "end" }, svg).textContent = format(t);
  }
  const xt = timeTicks(t0, t1, Math.max(2, Math.floor(iw / 90)));
  for (const t of (span ? xt : [t0])) {
    el("text", { x: x(t), y: H - 6, "text-anchor": "middle" }, svg).textContent = fmt.time(t, span);
  }

  // break the line at null values
  const segs = [];
  let cur = [];
  for (const p of points) { if (p.v == null) { if (cur.length) segs.push(cur); cur = []; } else cur.push(p); }
  if (cur.length) segs.push(cur);
  for (const s of segs) {
    const d = s.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join("");
    if (area && s.length > 1) {
      el("path", { d: `${d}L${x(s[s.length - 1].t).toFixed(1)},${y(0)}L${x(s[0].t).toFixed(1)},${y(0)}Z`,
        fill: color, "fill-opacity": 0.1, stroke: "none" }, svg);
    }
    el("path", { d, fill: "none", stroke: color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, svg);
  }
  const surface = cssVar("--chart-surface");
  if (markers || valid.length === 1) {
    for (const p of valid) el("circle", { cx: x(p.t), cy: y(p.v), r: 4, fill: color, stroke: surface, "stroke-width": 2 }, svg);
  }
  // selective direct label: last value
  const last = valid[valid.length - 1];
  if (markers && last) {
    el("text", { x: x(last.t) + 8, y: y(last.v) + 4, style: "fill: var(--text); font-weight: 600" }, svg).textContent = format(last.v);
  }

  // hover / keyboard layer
  const cross = el("line", { y1: m.t, y2: m.t + ih, class: "crosshair", visibility: "hidden" }, svg);
  const dot = el("circle", { r: 5, fill: color, stroke: surface, "stroke-width": 2, visibility: "hidden", "pointer-events": "none" }, svg);
  const hit = el("rect", { x: m.l, y: m.t, width: iw, height: ih, fill: "transparent" }, svg);
  let idx = -1;
  const nearest = px => {
    let best = 0, bd = Infinity;
    points.forEach((p, i) => { const d = Math.abs(x(p.t) - px); if (d < bd) { bd = d; best = i; } });
    return best;
  };
  const show = (i, cx, cy) => {
    idx = i;
    const p = points[i];
    cross.setAttribute("x1", x(p.t)); cross.setAttribute("x2", x(p.t)); cross.setAttribute("visibility", "visible");
    if (p.v != null) { dot.setAttribute("cx", x(p.t)); dot.setAttribute("cy", y(p.v)); dot.setAttribute("visibility", "visible"); }
    else dot.setAttribute("visibility", "hidden");
    const rect = svg.getBoundingClientRect();
    tooltip.show(cx ?? rect.left + x(p.t), cy ?? rect.top + m.t, {
      title: p.label || fmt.time(p.t, span || 1),
      rows: [{ color, value: p.v == null ? "no data" : format(p.v), name }, ...(p.extra || [])],
    });
  };
  const hide = () => { idx = -1; cross.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); tooltip.hide(); };
  hit.addEventListener("pointermove", e => {
    const r = svg.getBoundingClientRect();
    show(nearest(e.clientX - r.left), e.clientX, e.clientY);
  });
  hit.addEventListener("pointerleave", hide);
  if (opts.onPointClick) {
    hit.style.cursor = "pointer";
    hit.addEventListener("click", e => { const r = svg.getBoundingClientRect(); opts.onPointClick(points[nearest(e.clientX - r.left)]); });
  }
  svg.addEventListener("keydown", e => {
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      show(Math.min(points.length - 1, Math.max(0, (idx < 0 ? (e.key === "ArrowRight" ? -1 : points.length) : idx) + (e.key === "ArrowRight" ? 1 : -1))));
    } else if (e.key === "Enter" && idx >= 0 && opts.onPointClick) opts.onPointClick(points[idx]);
  });
  svg.addEventListener("blur", hide);
}

// ---------------------------------------------------------------- ranked bar list
/** items: [{name, value, detail?: [{value, name}]}] — single series, single color. */
export function barList(container, items, { format = fmt.num, color = "var(--s1)" } = {}) {
  container.replaceChildren();
  const max = Math.max(...items.map(i => i.value), 0) || 1;
  const list = h("div", "barlist");
  for (const it of items) {
    const row = h("div", "row");
    row.tabIndex = 0;
    const nm = h("span", "name", it.name);
    nm.title = it.name;
    row.append(nm, h("span", "val", format(it.value)));
    const track = h("div", "track");
    const bar = h("div", "bar");
    bar.style.width = `${(it.value / max) * 100}%`;
    bar.style.background = color;
    track.appendChild(bar);
    row.appendChild(track);
    row.setAttribute("aria-label", `${it.name}: ${format(it.value)}`);
    const tip = e => {
      const r = row.getBoundingClientRect();
      tooltip.show(e?.clientX ?? r.right - 40, e?.clientY ?? r.top, {
        title: it.name, rows: [{ color, value: format(it.value), name: it.unit || "" }, ...(it.detail || [])],
      });
    };
    row.addEventListener("pointermove", tip);
    row.addEventListener("focus", () => tip());
    row.addEventListener("pointerleave", () => tooltip.hide());
    row.addEventListener("blur", () => tooltip.hide());
    list.appendChild(row);
  }
  container.appendChild(list);
}

// ---------------------------------------------------------------- segmented bar (parts of a whole)
/** parts: [{name, value, color}] — colors must be fixed per entity. */
export function segmented(container, parts, { format = fmt.num } = {}) {
  container.replaceChildren();
  const shown = parts.filter(p => p.value > 0);
  const total = shown.reduce((s, p) => s + p.value, 0) || 1;
  const bar = h("div", "segbar");
  bar.setAttribute("role", "img");
  bar.setAttribute("aria-label", shown.map(p => `${p.name} ${format(p.value)} (${fmt.pct(p.value / total)})`).join(", "));
  const W = container.clientWidth || 400;
  const ctx = document.createElement("canvas").getContext("2d");
  ctx.font = "600 12px system-ui, -apple-system, sans-serif";
  for (const p of shown) {
    const seg = h("div", "seg");
    seg.style.flex = `${p.value} 1 0`;
    seg.style.background = p.color;
    seg.tabIndex = 0;
    if (p.inkDark && !isDark()) seg.classList.add("ink-dark");
    const share = fmt.pct(p.value / total);
    const avail = W * (p.value / total) - 2 * (shown.length - 1) / shown.length - 16;
    if (ctx.measureText(share).width <= avail) seg.textContent = share; // skip if it doesn't fit; tooltip + table carry it
    const tip = e => {
      const r = seg.getBoundingClientRect();
      tooltip.show(e?.clientX ?? r.left + r.width / 2, e?.clientY ?? r.bottom, {
        title: p.name, rows: [{ color: p.color, value: format(p.value), name: `· ${share}` }],
      });
    };
    seg.addEventListener("pointermove", tip);
    seg.addEventListener("focus", () => tip());
    seg.addEventListener("pointerleave", () => tooltip.hide());
    seg.addEventListener("blur", () => tooltip.hide());
    bar.appendChild(seg);
  }
  container.appendChild(bar);
  const legend = h("div", "legend");
  for (const p of shown) {
    const k = h("span", "key");
    const sw = h("span", "sw"); sw.style.background = p.color;
    k.append(sw, document.createTextNode(p.name + " "), h("b", "", format(p.value)));
    legend.appendChild(k);
  }
  container.appendChild(legend);
}

// ---------------------------------------------------------------- meter list (one ratio per row)
/** rows: [{name, value, max, fig, flag?}] */
export function meters(container, rows) {
  container.replaceChildren();
  const wrap = h("div", "meters");
  for (const r of rows) {
    const row = h("div", "meter-row");
    const nm = h("span", "name", r.name); nm.title = r.name;
    const m = h("div", "meter");
    m.setAttribute("role", "meter");
    m.setAttribute("aria-valuemin", 0); m.setAttribute("aria-valuemax", r.max); m.setAttribute("aria-valuenow", r.value);
    m.setAttribute("aria-label", `${r.name}: ${r.fig}`);
    const fill = h("div"); fill.style.width = `${r.max ? (r.value / r.max) * 100 : 0}%`;
    m.appendChild(fill);
    const fig = h("span", "fig");
    if (r.flag) {
      const f = h("span", "flag");
      f.innerHTML = ICONS.alert;
      f.appendChild(document.createTextNode(r.flag));
      fig.appendChild(f);
    }
    fig.appendChild(document.createTextNode(r.fig));
    row.append(nm, m, fig);
    wrap.appendChild(row);
  }
  container.appendChild(wrap);
}

// ---------------------------------------------------------------- DNS queries: time × RTT
/** queries: [{t: ms, rtt_ms|null, query, server, rcode}] — unanswered ones drawn as × in a separate lane on top. */
export function dnsScatter(container, queries, { height = 240 } = {}) {
  container.replaceChildren();
  const W = Math.max(container.clientWidth, 260), H = height;
  const answered = queries.filter(q => q.rtt_ms != null);
  const missing = queries.filter(q => q.rtt_ms == null);
  const ticks = niceTicks(Math.max(0, ...answered.map(q => q.rtt_ms)));
  const yMax = ticks[ticks.length - 1];
  const lane = missing.length ? 30 : 0;
  const m = { l: Math.max(44, Math.max(...ticks.map(t => fmt.ms(t).length)) * 6.5 + 10), r: 16, t: 10 + lane, b: 26 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const ts = queries.map(q => q.t);
  const t0 = Math.min(...ts), t1 = Math.max(...ts), span = t1 - t0;
  const pad = span ? span * 0.02 : 1;
  const x = t => m.l + (span ? (t - t0 + pad) / (span + 2 * pad) * iw : iw / 2);
  const y = v => m.t + (1 - v / yMax) * ih;
  const crit = cssVar("--critical"), surface = cssVar("--chart-surface");

  const svg = el("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, tabindex: 0, role: "img",
    "aria-label": `DNS queries: ${answered.length} answered, ${missing.length} unanswered` }, container);
  for (const t of ticks) {
    el("line", { x1: m.l, x2: W - m.r, y1: y(t), y2: y(t), class: t === 0 ? "baseline" : "gridline" }, svg);
    el("text", { x: m.l - 8, y: y(t) + 4, "text-anchor": "end" }, svg).textContent = fmt.ms(t);
  }
  if (lane) {
    el("text", { x: m.l - 8, y: 10 + lane / 2 + 4, "text-anchor": "end" }, svg).textContent = "no response";
    el("line", { x1: m.l, x2: W - m.r, y1: 10 + lane, y2: 10 + lane, class: "gridline" }, svg);
  }
  for (const t of (span ? timeTicks(t0, t1, Math.max(2, Math.floor(iw / 90))) : [t0])) {
    el("text", { x: x(t), y: H - 6, "text-anchor": "middle" }, svg).textContent = fmt.time(t, span);
  }
  const pts = [];
  for (const q of answered) {
    const cx = x(q.t), cy = y(q.rtt_ms);
    el("circle", { cx, cy, r: 4, fill: "var(--s1)", stroke: surface, "stroke-width": 2 }, svg);
    pts.push({ q, cx, cy });
  }
  for (const q of missing) {
    const cx = x(q.t), cy = 10 + lane / 2, s = 4.5;
    el("path", { d: `M${cx - s},${cy - s}L${cx + s},${cy + s}M${cx + s},${cy - s}L${cx - s},${cy + s}`,
      stroke: crit, "stroke-width": 2, "stroke-linecap": "round" }, svg);
    pts.push({ q, cx, cy });
  }
  pts.sort((a, b) => a.q.t - b.q.t);
  const ring = el("circle", { r: 8, fill: "none", stroke: "var(--text-2)", "stroke-width": 1.5, visibility: "hidden", "pointer-events": "none" }, svg);
  const hit = el("rect", { x: 0, y: 0, width: W, height: H - m.b + 6, fill: "transparent" }, svg);
  let idx = -1;
  const show = (i, ex, ey) => {
    idx = i;
    const { q, cx, cy } = pts[i];
    ring.setAttribute("cx", cx); ring.setAttribute("cy", cy); ring.setAttribute("visibility", "visible");
    const r = svg.getBoundingClientRect();
    tooltip.show(ex ?? r.left + cx, ey ?? r.top + cy, {
      title: new Date(q.t).toLocaleTimeString("en-US-u-hc-h23", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      rows: [
        q.rtt_ms != null ? { color: "var(--s1)", value: fmt.ms(q.rtt_ms), name: q.rcode } : { color: crit, shape: "x", value: "no response", name: "" },
        { value: q.query + (q.qtype ? ` (${q.qtype})` : ""), name: "" },
        { value: "→ " + q.server, name: "" },
      ],
    });
  };
  const hide = () => { idx = -1; ring.setAttribute("visibility", "hidden"); tooltip.hide(); };
  hit.addEventListener("pointermove", e => {
    const r = svg.getBoundingClientRect(), px = e.clientX - r.left, py = e.clientY - r.top;
    let best = -1, bd = 24 * 24; // 24px proximity target
    pts.forEach((p, i) => { const d = (p.cx - px) ** 2 + (p.cy - py) ** 2; if (d < bd) { bd = d; best = i; } });
    best >= 0 ? show(best, e.clientX, e.clientY) : hide();
  });
  hit.addEventListener("pointerleave", hide);
  svg.addEventListener("keydown", e => {
    if (!pts.length || (e.key !== "ArrowRight" && e.key !== "ArrowLeft")) return;
    e.preventDefault();
    const step = e.key === "ArrowRight" ? 1 : -1;
    show(idx < 0 ? (step > 0 ? 0 : pts.length - 1) : Math.min(pts.length - 1, Math.max(0, idx + step)));
  });
  svg.addEventListener("blur", hide);

  const legend = h("div", "legend");
  const k1 = h("span", "key"); const sw = h("span", "sw"); sw.style.background = "var(--s1)"; sw.style.borderRadius = "50%";
  k1.append(sw, document.createTextNode("Answered "), h("b", "", fmt.num(answered.length)));
  legend.appendChild(k1);
  if (missing.length) {
    const k2 = h("span", "key"); const xx = h("span", "x", "×"); xx.style.color = crit; xx.style.fontWeight = 700;
    k2.append(xx, document.createTextNode("No response "), h("b", "", fmt.num(missing.length)));
    legend.appendChild(k2);
  }
  container.appendChild(legend);
}

// ---------------------------------------------------------------- sparkline (stat tile)
/** values: array of numbers (oldest to newest). History in gray, last point in the accent color. */
export function sparkline(values, { width = 88, height = 24 } = {}) {
  const v = values.filter(x => x != null);
  if (v.length < 2) return "";
  const max = Math.max(...v), min = Math.min(...v), rng = max - min || 1;
  const x = i => 2 + i / (v.length - 1) * (width - 6);
  const y = val => 3 + (1 - (val - min) / rng) * (height - 6);
  const d = v.map((val, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(val).toFixed(1)}`).join("");
  const last = v.length - 1;
  return `<svg width="${width}" height="${height}" aria-hidden="true"><path d="${d}" fill="none" stroke="var(--axis)" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>` +
    `<circle cx="${x(last)}" cy="${y(v[last])}" r="3" fill="var(--s1)"/></svg>`;
}

// ---------------------------------------------------------------- icons (inline SVG, 16px)
const ic = (d, extra = "") => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" ${extra}>${d}</svg>`;
export const ICONS = {
  home: ic('<path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z"/>'),
  users: ic('<circle cx="9" cy="8" r="4"/><path d="M2 21v-1a6 6 0 0 1 6-6h2a6 6 0 0 1 6 6v1"/><path d="M16 3.5a4 4 0 0 1 0 8M22 21v-1a6 6 0 0 0-4-5.6"/>'),
  folder: ic('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'),
  chart: ic('<path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 5-6"/>'),
  list: ic('<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>'),
  upload: ic('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>'),
  settings: ic('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>'),
  plus: ic('<path d="M12 5v14M5 12h14"/>'),
  sun: ic('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>'),
  moon: ic('<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>'),
  docs: ic('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>'),
  clock: ic('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
  spinner: ic('<path d="M21 12a9 9 0 1 1-6.22-8.56"/>'),
  check: ic('<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>'),
  alert: `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>`,
  x: ic('<circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/>'),
  info: ic('<circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/>'),
  sparkle: ic('<path d="M12 3l1.9 5.8L20 11l-6.1 2.2L12 19l-1.9-5.8L4 11l6.1-2.2z"/>'),
  file: ic('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>'),
  retry: ic('<path d="M3 12a9 9 0 0 1 15.5-6.2L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15.5 6.2L3 16"/><path d="M3 21v-5h5"/>'),
  trash: ic('<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>'),
  table: ic('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 10h18M9 4v16"/>'),
};
