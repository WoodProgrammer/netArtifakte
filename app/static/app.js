import { fmt, tooltip, timeSeries, barList, segmented, meters, dnsScatter, sparkline, ICONS } from "./charts.js";

// ================================================================ constants
const STATUS = {
  queued: { label: "Queued", icon: ICONS.clock },
  running: { label: "Analyzing", icon: ICONS.spinner },
  awaiting_approval: { label: "Awaiting approval", icon: ICONS.alert },
  done: { label: "Done", icon: ICONS.check },
  failed: { label: "Failed", icon: ICONS.x },
};
const STAGES = [
  { key: "queued", label: "Queue" },
  { key: "zeek", label: "zeek" },
  { key: "tshark", label: "tshark" },
  { key: "llm", label: "LLM analysis" },
  { key: "done", label: "Done" },
];
const STAGE_TEXT = { queued: "Waiting in queue", zeek: "Parsing with zeek", tshark: "Parsing with tshark",
  llm: "LLM is thinking", llm_writing: "LLM is writing the response", awaiting_approval: "Waiting for command approval",
  tool: "Running approved command", done: "Done", failed: "Error" };
const TOOL_STATUS = {
  pending: { label: "Awaiting approval", cls: "awaiting_approval", icon: ICONS.alert },
  approved: { label: "Approved", cls: "running", icon: ICONS.spinner },
  executed: { label: "Executed", cls: "done", icon: ICONS.check },
  rejected: { label: "Rejected", cls: "failed", icon: ICONS.x },
  invalid: { label: "Invalid", cls: "failed", icon: ICONS.x },
  limit: { label: "Limit reached", cls: "failed", icon: ICONS.x },
};

// Categorical colors are fixed per entity (not by rank). Anything beyond 6 folds into "Other".
const CONN_STATES = {
  SF: ["SF", "established and closed normally"], S0: ["S0", "attempt seen, no response"], REJ: ["REJ", "rejected"],
  RSTO: ["RSTO", "originator reset"], RSTR: ["RSTR", "responder reset"], S1: ["S1", "established, not closed"],
};
const CONN_STATE_COLORS = { SF: 1, S0: 2, REJ: 3, RSTO: 4, RSTR: 5, S1: 6 };
const RCODE_COLORS = { NOERROR: 1, NO_RESPONSE: 2, NXDOMAIN: 3, SERVFAIL: 4, REFUSED: 5 };
const RCODE_NAMES = { NO_RESPONSE: "No response" };
const slot = i => `var(--s${i})`;
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const META_TEMPLATE = { description: "", capture_point: "", networks: [{ cidr: "10.0.0.0/16", role: "pod_network" }], known_hosts: [], question: "" };

// ================================================================ state
const state = { analyses: [], streams: new Map(), observers: [], charts: [], renderToken: 0 };
const $ = (s, root = document) => root.querySelector(s);

// ================================================================ helpers
async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = body.detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map(x => x.msg).join("; ") : `HTTP ${res.status}`);
  }
  return body;
}
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = msg;
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 4500);
}
function dt(iso) {
  if (!iso) return "–";
  const d = new Date(iso), now = new Date();
  const time = d.toLocaleTimeString("en-US-u-hc-h23", { hour: "2-digit", minute: "2-digit" });
  if (d.toDateString() === now.toDateString()) return `Today ${time}`;
  const y = new Date(now); y.setDate(now.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return `Yesterday ${time}`;
  return d.toLocaleDateString("en-US-u-hc-h23", { day: "numeric", month: "short", year: d.getFullYear() === now.getFullYear() ? undefined : "numeric" }) + ` ${time}`;
}
function duration(sec) {
  if (sec == null) return "–";
  if (sec < 1) return "<1 sec";
  if (sec < 60) return `${Math.round(sec)} sec`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m} min${sec % 60 >= 1 && m < 10 ? ` ${Math.round(sec % 60)} sec` : ""}`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h${m % 60 ? ` ${m % 60} min` : ""}`;
  return `${plural(Math.floor(h / 24), "day")}${h % 24 ? ` ${h % 24} h` : ""}`;
}
function ago(iso) {
  if (!iso) return "–";
  const s = (Date.now() - new Date(iso)) / 1000;
  return s < 45 ? "just now" : `${duration(s)} ago`;
}
const statusBadge = s => `<span class="status ${s}">${STATUS[s].icon}${STATUS[s].label}</span>`;
const isActive = r => r.status === "queued" || r.status === "running" || r.status === "awaiting_approval";
const modeTag = r => `<span class="tag">${r.dry_run ? "parse only" : r.provider === "claude" ? "Claude" : "Local LLM"}</span>`;
const dnsRate = t => (t && t.dns_queries ? t.dns_unanswered / t.dns_queries : null);

// Small, safe markdown: HTML-escape first, then a limited set of transforms.
function md(src) {
  const blocks = [];
  const text = esc(src).replace(/```[^\n]*\n([\s\S]*?)```/g, (_, code) => {
    blocks.push(`<pre><code>${code}</code></pre>`);
    return `\u0000${blocks.length - 1}\u0000`;
  });
  const inline = s => s
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  const out = [], lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let m;
    if (/^\u0000\d+\u0000$/.test(line.trim())) { out.push(line.trim()); continue; }
    if ((m = line.match(/^(#{1,4})\s+(.*)/))) { out.push(`<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`); continue; }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { out.push("<hr>"); continue; }
    if (/^\s*\|.*\|\s*$/.test(line) && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1] || "")) {
      const cells = l => l.trim().replace(/^\||\|$/g, "").split("|").map(c => inline(c.trim()));
      let html = "<table><thead><tr>" + cells(line).map(c => `<th>${c}</th>`).join("") + "</tr></thead><tbody>";
      i += 2;
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { html += "<tr>" + cells(lines[i]).map(c => `<td>${c}</td>`).join("") + "</tr>"; i++; }
      out.push(html + "</tbody></table>"); i--; continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      let html = ordered ? "<ol>" : "<ul>";
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) { html += `<li>${inline(lines[i].replace(/^\s*([-*]|\d+\.)\s+/, ""))}</li>`; i++; }
      out.push(html + (ordered ? "</ol>" : "</ul>")); i--; continue;
    }
    if ((m = line.match(/^&gt;\s?(.*)/))) { out.push(`<blockquote>${inline(m[1])}</blockquote>`); continue; }
    if (line.trim() === "") continue;
    out.push(`<p>${inline(line)}</p>`);
  }
  return out.join("\n").replace(/\u0000(\d+)\u0000/g, (_, n) => blocks[n]);
}

// ================================================================ components
/** Stat tile: value + change vs. previous capture + sparkline. */
function kpi({ label, value, unit = "", cur, prev, goodWhen = null, deltaFmt = fmt.num, points = false, spark = [] }) {
  let delta = "";
  if (prev != null && cur != null) {
    const diff = cur - prev;
    if (Math.abs(diff) < 1e-9) delta = `<span class="delta flat">unchanged</span>`;
    else {
      const up = diff > 0;
      const cls = goodWhen == null ? "flat" : (up === (goodWhen === "up") ? "good" : "bad");
      const txt = points ? `${up ? "+" : "−"}${(Math.abs(diff) * 100).toFixed(1).replace(/\.0$/, "")} pts`
        : prev ? `${up ? "+" : "−"}${fmt.num(Math.abs(diff / prev) * 100)}%` : `${up ? "+" : "−"}${deltaFmt(Math.abs(diff))}`;
      delta = `<span class="delta ${cls}" title="Previous capture: ${esc(points ? fmt.pct(prev) : deltaFmt(prev))}">${up ? "▲" : "▼"} ${txt}</span>`;
    }
  }
  return `<div class="kpi"><div class="label">${esc(label)}</div>
    <div class="value">${esc(value)}${unit ? `<span class="unit">${esc(unit)}</span>` : ""}</div>
    <div class="foot">${delta || '<span class="delta flat">&nbsp;</span>'}${sparkline(spark)}</div></div>`;
}

/**
 * Chart card. Every chart has a table view (for accessibility and low-contrast colors).
 * render(el) draws the chart; it is called again when the width changes.
 */
function chartCard({ title, sub = "", render, table, span = 1 }) {
  const id = `c${state.charts.length}`;
  state.charts.push({ id, render, table });
  return `<div class="card" ${span === 2 ? 'style="grid-column: 1 / -1"' : ""}>
    <div class="card-head"><div><h2>${esc(title)}</h2>${sub ? `<div class="sub">${sub}</div>` : ""}</div>
      ${table ? `<button class="btn ghost sm chart-toggle" data-toggle="${id}" aria-pressed="false">${ICONS.table} Table</button>` : ""}</div>
    <div class="card-body"><div class="chart" data-chart="${id}"></div>
      <div class="table-wrap hidden" data-table="${id}"></div></div></div>`;
}

function renderTable(columns, rows) {
  return `<table class="data"><thead><tr>${columns.map(c => `<th class="${c.num ? "num" : ""}">${esc(c.label)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map(r => `<tr>${columns.map((c, i) => `<td class="${c.num ? "num" : ""}">${esc(r[i])}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

function mountCharts(root) {
  for (const c of state.charts) {
    const host = root.querySelector(`[data-chart="${c.id}"]`);
    if (!host) continue;
    let lastW = 0;
    const draw = () => { const w = host.clientWidth; if (w && w !== lastW) { lastW = w; c.render(host); } };
    draw();
    const ro = new ResizeObserver(() => requestAnimationFrame(draw));
    ro.observe(host);
    state.observers.push(ro);
    const btn = root.querySelector(`[data-toggle="${c.id}"]`);
    if (btn) btn.onclick = () => {
      const tbl = root.querySelector(`[data-table="${c.id}"]`);
      const showTable = tbl.classList.contains("hidden");
      if (showTable && !tbl.innerHTML) tbl.innerHTML = renderTable(c.table.columns, c.table.rows);
      tbl.classList.toggle("hidden", !showTable);
      host.classList.toggle("hidden", showTable);
      btn.innerHTML = showTable ? `${ICONS.chart} Chart` : `${ICONS.table} Table`;
      btn.setAttribute("aria-pressed", showTable);
      if (!showTable) { lastW = 0; draw(); }
    };
  }
}

function emptyState(icon, title, text, action = "") {
  return `<div class="card"><div class="empty-state">${icon.replace('width="16" height="16"', 'width="40" height="40"')}
    <h3>${esc(title)}</h3><p>${text}</p>${action}</div></div>`;
}

// ================================================================ shell: menu, breadcrumb, queue
function setShell({ crumbs = [], analysis = null, nav = "" }) {
  $("#crumbs").innerHTML = [`<a href="#/">Analyses</a>`, ...crumbs.map((c, i) =>
    i === crumbs.length - 1 ? `<span class="current">${esc(c.label)}</span>` : `<a href="${c.href}">${esc(c.label)}</a>`)]
    .join('<span class="sep">/</span>');
  const item = (href, icon, label, key, count = "") =>
    `<a class="nav-item ${nav === key ? "active" : ""}" href="${href}">${icon}<span>${esc(label)}</span>${count !== "" ? `<span class="count">${count}</span>` : ""}</a>`;
  let html;
  if (analysis) {
    const a = analysis, base = `#/a/${a.id}`;
    html = `<a class="nav-item" href="#/">${ICONS.home}<span>All analyses</span></a>
      <div class="nav-section">Analysis</div>
      <div class="nav-scope"><div class="label">Selected analysis</div><div class="name" title="${esc(a.name)}">${esc(a.name)}</div></div>
      ${item(base, ICONS.chart, "Overview", "overview")}
      ${item(`${base}/captures`, ICONS.list, "Captures", "captures", a.runs?.length ?? "")}
      ${item(`${base}/new`, ICONS.upload, "New capture", "new")}
      ${item(`${base}/settings`, ICONS.settings, "Settings", "settings")}`;
  } else {
    html = `<div class="nav-section">Account</div>
      ${item("#/", ICONS.home, "Overview", "home")}
      <div class="nav-section">Analyses</div>
      ${state.analyses.map(a => item(`#/a/${a.id}`, ICONS.folder, a.name, `a${a.id}`, a.run_count)).join("") || '<div class="nav-item muted">None yet</div>'}`;
  }
  $("#nav").innerHTML = html + `<div class="nav-footer"><a href="/docs" target="_blank">API docs</a></div>`;
}

async function refreshQueue() {
  try {
    state.analyses = await api("/analyses");
    const active = state.analyses.reduce((s, a) => s + (a.active_runs || 0), 0);
    const awaiting = state.analyses.reduce((s, a) => s + (a.awaiting_runs || 0), 0);
    const pill = $("#queuePill");
    pill.classList.toggle("active", active > awaiting);
    pill.classList.toggle("awaiting", awaiting > 0);
    $("#queueText").textContent = awaiting ? `${awaiting} awaiting approval${active > awaiting ? ` · ${active - awaiting} active` : ""}`
      : active ? `${plural(active, "active job")}` : "Queue empty";
  } catch { /* server may be restarting */ }
}

// ================================================================ live progress (SSE)
function watchRun(runId, onProgress, onDone) {
  if (state.streams.has(runId)) state.streams.get(runId).close();
  const es = new EventSource(`/runs/${runId}/events`);
  state.streams.set(runId, es);
  es.addEventListener("progress", e => onProgress?.(JSON.parse(e.data)));
  es.addEventListener("done", e => {
    es.close(); state.streams.delete(runId);
    const d = JSON.parse(e.data);
    toast(d.status === "done" ? `Capture #${runId} completed` : `Capture #${runId} failed`);
    refreshQueue();
    onDone?.(d);
  });
}
function closeStreams() { for (const es of state.streams.values()) es.close(); state.streams.clear(); }

// ================================================================ page: overview (all analyses)
async function pageHome() {
  await refreshQueue();
  const list = state.analyses;
  setShell({ nav: "home" });
  const totalRuns = list.reduce((s, a) => s + a.run_count, 0);
  const active = list.reduce((s, a) => s + (a.active_runs || 0), 0);
  const last = list.map(a => a.last_run_at).filter(Boolean).sort().pop();
  const head = `<div class="page-head"><div><h1>Overview</h1><p>Group pcap captures by project, compare them, and analyze them with an LLM.</p></div>
    <div class="actions"><button class="btn primary" data-action="new-analysis">${ICONS.plus} Create analysis</button></div></div>`;
  if (!list.length) {
    return head + emptyState(ICONS.folder, "No analyses yet",
      "An analysis groups captures of the same problem taken at different times.",
      `<button class="btn primary" data-action="new-analysis" style="margin-top:12px">${ICONS.plus} Create your first analysis</button>`);
  }
  return head + `
    <div class="kpis">
      ${kpi({ label: "Analyses", value: fmt.num(list.length) })}
      ${kpi({ label: "Total captures", value: fmt.num(totalRuns) })}
      ${kpi({ label: "Active jobs", value: fmt.num(active) })}
      ${kpi({ label: "Last capture", value: last ? ago(last) : "–" })}
    </div>
    <div class="card"><div class="card-head"><div><h2>Analyses</h2><div class="sub">${plural(list.length, "analysis", "analyses")}</div></div></div>
      <div class="table-wrap" style="margin-top:12px"><table class="data">
        <thead><tr><th>Name</th><th class="num">Captures</th><th>Last capture</th><th>Status</th><th>Created</th></tr></thead>
        <tbody>${list.map(a => `<tr class="clickable" data-href="#/a/${a.id}">
          <td><a href="#/a/${a.id}"><b>${esc(a.name)}</b></a>${a.description ? `<div class="muted" style="font-size:12px">${esc(a.description)}</div>` : ""}</td>
          <td class="num">${a.run_count}</td>
          <td>${a.last_run_at ? `${dt(a.last_run_at)} <span class="muted">· ${ago(a.last_run_at)}</span>` : '<span class="muted">–</span>'}</td>
          <td>${a.awaiting_runs ? statusBadge("awaiting_approval").replace(STATUS.awaiting_approval.label, `${a.awaiting_runs} awaiting approval`) + " " : ""}${a.active_runs > a.awaiting_runs ? statusBadge("running").replace(STATUS.running.label, `${a.active_runs - a.awaiting_runs} active`) : a.awaiting_runs ? "" : '<span class="muted">Idle</span>'}</td>
          <td class="muted">${dt(a.created_at)}</td></tr>`).join("")}</tbody></table></div></div>`;
}

// ================================================================ page: analysis overview
const TRENDS = [
  { key: "dns_rate", title: "DNS unanswered rate", get: dnsRate, format: fmt.pct, goodWhen: "down", points: true },
  { key: "dns_p95", title: "DNS RTT p95", get: t => t?.dns_rtt_p95_ms ?? null, format: fmt.ms, goodWhen: "down" },
  { key: "connections", title: "Connection count", get: t => t?.connections ?? null, format: fmt.num },
  { key: "retrans", title: "Connections with retransmissions", get: t => t?.retrans_connections ?? null, format: fmt.num, goodWhen: "down" },
];

async function pageAnalysis(id) {
  const a = await api(`/analyses/${id}`);
  setShell({ analysis: a, nav: "overview", crumbs: [{ label: a.name }] });
  const head = `<div class="page-head"><div><h1>${esc(a.name)}</h1><p>${esc(a.description) || "Changes across captures and latest status"}</p></div>
    <div class="actions"><a class="btn primary" href="#/a/${id}/new">${ICONS.upload} Yeni capture</a></div></div>`;
  if (!a.runs.length) {
    return head + emptyState(ICONS.upload, "No captures yet", "Submit your first pcap file; the analysis is queued and its progress is shown live.",
      `<a class="btn primary" href="#/a/${id}/new" style="margin-top:12px">${ICONS.upload} Submit capture</a>`);
  }
  const withStats = a.runs.filter(r => r.totals);
  const cur = withStats[withStats.length - 1], prev = withStats[withStats.length - 2];
  const spark = f => withStats.slice(-12).map(r => f(r.totals));
  let html = head;
  const active = a.runs.filter(isActive);
  if (active.length) {
    html += `<div class="alert info" style="margin-bottom:16px">${ICONS.spinner}<div>${plural(active.length, "capture")} processing:
      ${active.map(r => `<a href="#/r/${r.id}">#${r.id}</a> <span class="muted">(${esc(STAGE_TEXT[r.stage] || r.stage)} · ${r.progress}%)</span>`).join(", ")}</div></div>`;
  }
  if (cur) {
    const t = cur.totals, p = prev?.totals;
    html += `<div class="section-title" style="margin-top:0">Latest capture <span class="muted"><a href="#/r/${cur.id}">#${cur.id}</a> · ${dt(cur.submitted_at)}${prev ? ` · vs. previous capture (#${prev.id})` : ""}</span></div>
      <div class="kpis">
        ${kpi({ label: "Connections", value: fmt.num(t.connections), cur: t.connections, prev: p?.connections, spark: spark(x => x.connections) })}
        ${kpi({ label: "Traffic", value: fmt.bytes(t.bytes), cur: t.bytes, prev: p?.bytes, deltaFmt: fmt.bytes, spark: spark(x => x.bytes) })}
        ${kpi({ label: "DNS unanswered rate", value: fmt.pct(dnsRate(t)), cur: dnsRate(t), prev: dnsRate(p), goodWhen: "down", points: true, spark: spark(dnsRate) })}
        ${kpi({ label: "DNS RTT p95", value: fmt.ms(t.dns_rtt_p95_ms), cur: t.dns_rtt_p95_ms, prev: p?.dns_rtt_p95_ms, goodWhen: "down", deltaFmt: fmt.ms, spark: spark(x => x.dns_rtt_p95_ms) })}
        ${kpi({ label: "Retransmission", value: fmt.num(t.retrans_connections), cur: t.retrans_connections, prev: p?.retrans_connections, goodWhen: "down", spark: spark(x => x.retrans_connections) })}
      </div>`;
    html += `<div class="section-title">Trend across captures <span class="muted">${plural(withStats.length, "capture")} · click a point to open the capture</span></div>`;
    if (withStats.length < 2) html += `<div class="alert info" style="margin-bottom:16px">${ICONS.info}<div>A trend line needs at least 2 captures. Showing a single point for now.</div></div>`;
    html += `<div class="grid cols-2">${TRENDS.map(tr => {
      const pts = withStats.map(r => ({ t: new Date(r.submitted_at).getTime(), v: tr.get(r.totals), label: `#${r.id} · ${dt(r.submitted_at)}`, run: r.id }));
      return chartCard({
        title: tr.title, sub: "per capture",
        render: el => timeSeries(el, pts, { format: tr.format, markers: true, height: 190, name: tr.title, area: false,
          onPointClick: p => { location.hash = `#/r/${p.run}`; } }),
        table: { columns: [{ label: "Capture" }, { label: "Submitted" }, { label: tr.title, num: true }],
          rows: withStats.map(r => [`#${r.id}`, dt(r.submitted_at), tr.format(tr.get(r.totals))]) },
      });
    }).join("")}</div>`;
  }
  html += `<div class="section-title">Recent captures <span class="muted"><a href="#/a/${id}/captures">View all</a></span></div>`;
  html += runsTable(a.runs.slice(-5));
  return html;
}

// ================================================================ capture table (timeline)
function runsTable(runs) {
  const rows = [];
  const ordered = [...runs].reverse();
  ordered.forEach((r, i) => {
    const q = r.metadata?.question || "";
    let st = statusBadge(r.status);
    if (r.status === "running") st += `<div class="progress" style="margin-top:6px" data-progress="${r.id}"><div style="width:${r.progress}%"></div></div>
      <div class="muted" style="font-size:12px" data-stage="${r.id}">${esc(STAGE_TEXT[r.stage] || r.stage)} · ${r.progress}%</div>`;
    if (r.status === "awaiting_approval") st += `<div style="font-size:12px; margin-top:4px"><a href="#/r/${r.id}">Review ${plural(r.pending_approvals, "proposed command")} →</a></div>`;
    if (r.status === "queued" && r.queue_position) st += `<div class="muted" style="font-size:12px">#${r.queue_position} in queue</div>`;
    if (r.status === "failed") st += `<div class="muted" style="font-size:12px; max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap" title="${esc(r.error)}">${esc(r.error)}</div>`;
    rows.push(`<tr class="clickable" data-href="#/r/${r.id}" data-run="${r.id}" data-status="${r.status}">
      <td><a href="#/r/${r.id}"><b>#${r.id}</b></a></td>
      <td>${dt(r.submitted_at)}<div class="muted" style="font-size:12px">${ago(r.submitted_at)}</div></td>
      <td>${esc(r.pcap.filename)}<div class="muted" style="font-size:12px">${fmt.bytes(r.pcap.size)}</div></td>
      <td style="max-width:320px">${esc(q.length > 90 ? q.slice(0, 90) + "…" : q)}</td>
      <td>${modeTag(r)}</td>
      <td>${st}</td>
      <td class="num">${duration(r.duration_seconds)}</td></tr>`);
    const next = ordered[i + 1];
    if (next && r.since_previous_seconds != null) {
      rows.push(`<tr class="gap-row"><td colspan="7">↑ ${duration(r.since_previous_seconds)} after previous capture</td></tr>`);
    }
  });
  return `<div class="card"><div class="table-wrap"><table class="data">
    <thead><tr><th>#</th><th>Submitted</th><th>File</th><th>Question</th><th>Mode</th><th>Status</th><th class="num">Processing time</th></tr></thead>
    <tbody>${rows.join("")}</tbody></table></div></div>`;
}

async function pageCaptures(id) {
  const a = await api(`/analyses/${id}`);
  setShell({ analysis: a, nav: "captures", crumbs: [{ label: a.name, href: `#/a/${id}` }, { label: "Captures" }] });
  const head = `<div class="page-head"><div><h1>Captures</h1><p>What was submitted when, how much time passed in between, and the results.</p></div>
    <div class="actions"><a class="btn primary" href="#/a/${id}/new">${ICONS.upload} Yeni capture</a></div></div>`;
  if (!a.runs.length) return head + emptyState(ICONS.list, "No captures yet", "Once you submit your first capture, captures are listed here in chronological order.");
  return head + runsTable(a.runs);
}

// ================================================================ page: new capture
async function pageNew(id) {
  const a = await api(`/analyses/${id}`);
  setShell({ analysis: a, nav: "new", crumbs: [{ label: a.name, href: `#/a/${id}` }, { label: "New capture" }] });
  const meta = JSON.stringify(a.default_metadata || META_TEMPLATE, null, 2);
  const hasDone = a.runs.some(r => r.status === "done");
  const caps = await api("/capabilities").catch(() => ({ tshark: true, zeek: true, max_tool_calls: 5 }));
  return `<div class="page-head"><div><h1>New capture</h1><p>The pcap file is queued; the analysis runs in the background and its progress is shown live.</p></div></div>
  <form id="runForm" class="card" style="max-width:860px">
    <div class="card-body">
      <div class="field"><label>pcap file</label>
        <label class="dropzone" id="dropzone">${ICONS.upload.replace('width="16" height="16"', 'width="28" height="28"')}
          <div>Drag the file here or <span style="color:var(--link)">browse</span></div>
          <div class="muted" style="font-size:12px">.pcap, .pcapng, .cap</div>
          <div class="file" id="fileName"></div>
          <input type="file" name="pcap" accept=".pcap,.pcapng,.cap" hidden required></label></div>
      <div class="field"><label>Analysis mode</label>
        <div class="radio-cards">
          <label class="radio-card"><input type="radio" name="mode" value="claude" checked><div><b>Claude</b><small>The zeek + tshark summary goes to Claude; with your approval it can run extra tshark commands if needed</small></div></label>
          <label class="radio-card"><input type="radio" name="mode" value="local"><div><b>Local LLM</b><small>OpenAI-compatible local model</small></div></label>
          <label class="radio-card"><input type="radio" name="mode" value="dry"><div><b>Parse only</b><small>No LLM, just statistics and the report</small></div></label>
        </div></div>
      ${caps.tshark ? `<div class="alert info" style="margin-bottom:16px">${ICONS.sparkle}<div>During the analysis Claude may propose tshark commands for better dissection (at most ${caps.max_tool_calls}).
          The analysis pauses; you see the command, can edit it, and approve or reject it.</div></div>`
        : `<div class="alert warn" style="margin-bottom:16px">${ICONS.alert}<div>tshark is not installed on the server: TCP statistics are not generated and Claude cannot propose extra commands. <code>brew install wireshark</code></div></div>`}
      ${caps.zeek ? "" : `<div class="alert warn" style="margin-bottom:16px">${ICONS.alert}<div>zeek is not installed on the server: charts and the connection summary are not generated. <code>brew install zeek</code></div></div>`}
      <div class="field"><label class="check"><input type="checkbox" name="compare_previous" checked>
        <span>Compare with previous captures<small>${hasDone ? "The most recent completed captures in this analysis are given to the LLM as context." : "No completed captures yet; the first capture is not compared."}</small></span></label></div>
      <details class="field" ${a.default_metadata ? "" : "open"}>
        <summary style="cursor:pointer; font-weight:500">Metadata ${a.default_metadata ? '<span class="muted" style="font-weight:400">— prefilled from the analysis default; change it for this capture if you like</span>' : '<span class="muted" style="font-weight:400">— required, no default set</span>'}</summary>
        <textarea class="input" name="metadata" rows="14" style="margin-top:8px">${esc(meta)}</textarea>
        <div class="hint">IPs in the report are labeled using this info. <code>question</code> is required.</div></details>
    </div>
    <div class="card-foot"><span class="muted" style="font-size:12px">After submitting, you'll be taken to the capture page.</span>
      <button class="btn primary" type="submit">${ICONS.upload} Submit and analyze</button></div>
  </form>`;
}

function bindNewForm(id) {
  const form = $("#runForm");
  if (!form) return;
  const input = form.pcap, dz = $("#dropzone");
  const showName = () => { const f = input.files[0]; $("#fileName").textContent = f ? `${f.name} · ${fmt.bytes(f.size)}` : ""; };
  input.onchange = showName;
  dz.ondragover = e => { e.preventDefault(); dz.classList.add("over"); };
  dz.ondragleave = () => dz.classList.remove("over");
  dz.ondrop = e => { e.preventDefault(); dz.classList.remove("over"); input.files = e.dataTransfer.files; showName(); };
  form.onsubmit = async e => {
    e.preventDefault();
    if (!input.files[0]) { toast("Select a pcap file"); return; }
    const raw = form.metadata.value.trim();
    if (raw) { try { JSON.parse(raw); } catch { toast("Metadata is not valid JSON"); return; } }
    const mode = form.mode.value;
    const fd = new FormData();
    fd.append("pcap", input.files[0]);
    fd.append("provider", mode === "local" ? "local" : "claude");
    fd.append("dry_run", mode === "dry");
    fd.append("compare_previous", form.compare_previous.checked);
    if (raw) fd.append("metadata", raw);
    const btn = form.querySelector("button[type=submit]");
    btn.disabled = true; btn.textContent = "Uploading…";
    try {
      const run = await api(`/analyses/${id}/runs`, { method: "POST", body: fd });
      toast(`Capture #${run.id} queued`);
      refreshQueue();
      location.hash = `#/r/${run.id}`;
    } catch (err) {
      toast(err.message);
      btn.disabled = false; btn.innerHTML = `${ICONS.upload} Submit and analyze`;
    }
  };
}

// ================================================================ page: settings
async function pageSettings(id) {
  const a = await api(`/analyses/${id}`);
  setShell({ analysis: a, nav: "settings", crumbs: [{ label: a.name, href: `#/a/${id}` }, { label: "Settings" }] });
  return `<div class="page-head"><div><h1>Settings</h1><p>The analysis name, description and default metadata.</p></div></div>
  <form id="settingsForm" class="card" style="max-width:860px">
    <div class="card-head"><div><h2>General</h2><div class="sub">Created: ${dt(a.created_at)} · ID ${a.id}</div></div></div>
    <div class="card-body">
      <div class="field"><label>Name</label><input class="input" name="name" required value="${esc(a.name)}"></div>
      <div class="field"><label>Description</label><input class="input" name="description" value="${esc(a.description)}"></div>
      <div class="field"><label>Default metadata</label>
        <textarea class="input" name="default_metadata" rows="14" placeholder="If left empty, metadata must be submitted with every capture">${esc(a.default_metadata ? JSON.stringify(a.default_metadata, null, 2) : "")}</textarea>
        <div class="hint">Used for new captures submitted without metadata. Existing captures are not affected.</div></div>
    </div>
    <div class="card-foot"><span></span><button class="btn primary" type="submit">Save</button></div>
  </form>
  <div class="card danger-zone" style="max-width:860px">
    <div class="card-head"><div><h2>Delete analysis</h2><div class="sub">The analysis, its ${plural(a.runs.length, "capture")}, their results and the uploaded pcap files will be permanently deleted.</div></div></div>
    <div class="card-foot" style="margin-top:16px"><span></span><button class="btn danger" id="deleteBtn">${ICONS.trash} Delete analysis</button></div>
  </div>`;
}

function bindSettings(id) {
  const form = $("#settingsForm");
  if (!form) return;
  form.onsubmit = async e => {
    e.preventDefault();
    const body = { name: form.name.value.trim(), description: form.description.value.trim(), default_metadata: null };
    const raw = form.default_metadata.value.trim();
    if (raw) { try { body.default_metadata = JSON.parse(raw); } catch { toast("Default metadata is not valid JSON"); return; } }
    try { await api(`/analyses/${id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }); toast("Saved"); render(); }
    catch (err) { toast(err.message); }
  };
  $("#deleteBtn").onclick = async () => {
    const name = form.name.defaultValue;
    if (prompt(`Type the analysis name to delete it: ${name}`) !== name) return;
    await api(`/analyses/${id}`, { method: "DELETE" });
    toast("Analysis deleted");
    location.hash = "#/";
  };
}

// ================================================================ page: capture detail
async function pageRun(id, tab) {
  const r = await api(`/runs/${id}`);
  const a = await api(`/analyses/${r.analysis_id}`);
  setShell({ analysis: a, nav: "captures", crumbs: [{ label: a.name, href: `#/a/${a.id}` }, { label: `Capture #${r.id}` }] });
  const idx = a.runs.findIndex(x => x.id === r.id);
  const prevRun = a.runs[idx - 1], nextRun = a.runs[idx + 1];
  const capSpan = r.stats?.timeline ? r.stats.timeline.end - r.stats.timeline.start : null;
  const tabs = [["analytics", "Analytics"], ["ai", "AI analysis"],
    ...(r.tool_calls.length ? [["commands", `Commands <span class="tag">${r.tool_calls.length}</span>`]] : []),
    ["report", "Raw report"], ["input", "Submitted data"]];
  tab = tabs.some(t => t[0] === tab) ? tab : "analytics";

  let html = `<div class="page-head"><div>
      <h1 style="display:flex; align-items:center; gap:10px">Capture #${r.id} ${statusBadge(r.status)}</h1>
      <p>${esc(r.pcap.filename)} · ${fmt.bytes(r.pcap.size)} · submitted ${dt(r.submitted_at)}${capSpan != null ? ` · capture length ${duration(capSpan)}` : ""}
      ${idx > 0 && a.runs[idx].since_previous_seconds != null ? ` · ${duration(a.runs[idx].since_previous_seconds)} after previous capture` : ""}</p></div>
    <div class="actions">
      ${prevRun ? `<a class="btn" href="#/r/${prevRun.id}/${tab}" title="Previous capture">← #${prevRun.id}</a>` : ""}
      ${nextRun ? `<a class="btn" href="#/r/${nextRun.id}/${tab}" title="Next capture">#${nextRun.id} →</a>` : ""}
      ${r.status === "failed" ? `<button class="btn primary" data-action="retry" data-id="${r.id}">${ICONS.retry} Retry</button>` : ""}
    </div></div>`;

  const pending = r.tool_calls.filter(t => t.status === "pending");
  if (pending.length && r.status === "awaiting_approval") html += approvalPanel(r, pending);
  if (isActive(r)) html += progressCard(r);
  if (r.error) html += `<div class="alert error" style="margin-bottom:16px">${ICONS.x}<div><b>Analysis failed</b><div style="white-space:pre-wrap">${esc(r.error)}</div></div></div>`;

  html += `<div class="tabs">${tabs.map(([k, l]) => `<a class="tab ${k === tab ? "active" : ""}" href="#/r/${r.id}/${k}">${l}</a>`).join("")}</div>`;

  if (tab === "analytics") html += runAnalytics(r, prevRun?.totals ? prevRun : a.runs.slice(0, idx).reverse().find(x => x.totals));
  if (tab === "ai") html += runAI(r);
  if (tab === "report") html += r.report ? `<div class="card"><div class="card-body"><pre class="raw">${esc(r.report)}</pre></div></div>`
    : emptyState(ICONS.file, "No report yet", "It appears here once the zeek/tshark parse stage completes.");
  if (tab === "input") html += runInput(r);
  if (tab === "commands") html += runCommands(r);
  return html;
}

/** Commands proposed by Claude: approve (optionally edit) / reject. */
function approvalPanel(r, pending) {
  return `<div class="card approval" id="approvalPanel">
    <div class="card-head"><div><h2 style="display:flex; align-items:center; gap:8px">${ICONS.sparkle} Claude wants to run ${pending.length > 1 ? `${pending.length} commands` : "a command"}</h2>
      <div class="sub">The analysis is paused. Once you decide on ${pending.length > 1 ? "all of them" : "the command"}, approved commands run against this capture file and the analysis continues with their output.</div></div></div>
    <div class="card-body">${pending.map(t => `
      <div class="proposal" data-call="${t.id}">
        <div class="purpose">${esc(t.purpose) || '<span class="muted">No description given</span>'}</div>
        <label class="muted" style="font-size:12px" for="cmd-${t.id}">Command — you can edit it before running</label>
        <textarea class="input cmd" id="cmd-${t.id}" rows="${Math.min(4, Math.ceil(t.command.length / 90))}" spellcheck="false">${esc(t.command)}</textarea>
        <input class="input" data-note placeholder="Note to Claude (optional) — e.g. 'only look at queries to 1.1.1.1'">
        <div class="row-actions">
          <button class="btn" data-action="reject-call" data-id="${t.id}">${ICONS.x} Reject</button>
          <button class="btn primary" data-action="approve-call" data-id="${t.id}">${ICONS.check} Approve and run</button>
        </div>
      </div>`).join("")}
      <div class="muted" style="font-size:12px">Commands can only read this capture file. Options that write files, capture live traffic or run scripts are blocked on the server.
        A time limit and output truncation are applied.</div>
    </div></div>`;
}

function runCommands(r) {
  return r.tool_calls.map(t => {
    const st = TOOL_STATUS[t.status] || { label: t.status, cls: "queued", icon: ICONS.info };
    return `<div class="card"><div class="card-head"><div style="min-width:0">
        <h2 style="display:flex; align-items:center; gap:8px">#${t.id} <span class="status ${st.cls}">${st.icon}${st.label}</span>
          ${t.duration != null ? `<span class="muted" style="font-weight:400; font-size:12px">${duration(t.duration)} · exit ${t.exit_code}</span>` : ""}</h2>
        <div class="sub">${esc(t.purpose)}</div></div>
        <span class="muted" style="font-size:12px; white-space:nowrap">${dt(t.created_at)}</span></div>
      <div class="card-body">
        <pre class="raw cmdline">${esc(t.edited_command || t.command)}</pre>
        ${t.edited_command ? `<div class="muted" style="font-size:12px; margin-top:6px">Edited. Claude's suggestion: <code>${esc(t.command)}</code></div>` : ""}
        ${t.user_note ? `<div style="font-size:13px; margin-top:8px"><span class="muted">Your note:</span> ${esc(t.user_note)}</div>` : ""}
        ${t.output ? `<details style="margin-top:10px" ${t.status !== "executed" ? "open" : ""}><summary class="muted" style="cursor:pointer">${t.status === "executed" ? "Output" : "Details"}</summary>
          <pre class="raw" style="margin-top:8px; max-height:420px; overflow:auto">${esc(t.output)}</pre></details>` : ""}
      </div></div>`;
  }).join("");
}

function progressCard(r) {
  const order = ["queued", "zeek", "tshark", "llm", "done"];
  const cur = order.indexOf(["llm_writing", "awaiting_approval", "tool"].includes(r.stage) ? "llm" : r.stage);
  const steps = STAGES.filter(s => !(r.dry_run && s.key === "llm"));
  return `<div class="card" id="progressCard"><div class="card-body">
    <div style="display:flex; justify-content:space-between; gap:12px; margin-bottom:10px">
      <div><b data-live="stage">${esc(STAGE_TEXT[r.stage] || r.stage)}</b>
        <span class="muted" data-live="queue">${r.status === "queued" && r.queue_position ? ` · #${r.queue_position} in queue` : ""}</span></div>
      <b class="tnum" data-live="pct">${r.progress}%</b></div>
    <div class="progress" style="height:8px"><div data-live="bar" style="width:${r.progress}%"></div></div>
    <div style="display:flex; gap:20px; margin-top:12px; font-size:12px" data-live="steps">${steps.map(s => {
      const i = order.indexOf(s.key);
      const st = i < cur ? "done" : i === cur ? "current" : "todo";
      return `<span style="display:inline-flex; gap:6px; align-items:center; color:${st === "todo" ? "var(--muted)" : "var(--text)"}; font-weight:${st === "current" ? 600 : 400}">
        <span style="width:8px; height:8px; border-radius:50%; background:${st === "done" ? "var(--good)" : st === "current" ? "var(--primary)" : "var(--border-strong)"}"></span>${s.label}</span>`;
    }).join("")}</div>
    <div class="muted" style="font-size:12px; margin-top:10px">The percentage during the LLM stage is estimated from the length of the generated text.</div>
  </div></div>`;
}

function runAnalytics(r, prev) {
  const s = r.stats;
  if (!s || !s.totals) {
    if (isActive(r)) return emptyState(ICONS.chart, "Preparing statistics", "Charts appear here once the parse stage finishes.");
    return emptyState(ICONS.chart, "No statistics", s && !s.tools?.zeek ? "zeek not found; charts are generated from zeek output." : "No statistics were generated for this capture.");
  }
  const t = s.totals, p = prev?.totals;
  let html = `<div class="kpis">
    ${kpi({ label: "Connections", value: fmt.num(t.connections), cur: t.connections, prev: p?.connections })}
    ${kpi({ label: "Packets", value: fmt.num(t.packets), cur: t.packets, prev: p?.packets })}
    ${kpi({ label: "Traffic", value: fmt.bytes(t.bytes), cur: t.bytes, prev: p?.bytes, deltaFmt: fmt.bytes })}
    ${t.dns_queries ? kpi({ label: "DNS unanswered", value: `${t.dns_unanswered} / ${t.dns_queries}`, cur: dnsRate(t), prev: dnsRate(p), goodWhen: "down", points: true }) : ""}
    ${t.dns_rtt_p95_ms != null ? kpi({ label: "DNS RTT p95", value: fmt.ms(t.dns_rtt_p95_ms), cur: t.dns_rtt_p95_ms, prev: p?.dns_rtt_p95_ms, goodWhen: "down", deltaFmt: fmt.ms }) : ""}
    ${kpi({ label: "Retransmission", value: fmt.num(t.retrans_connections), cur: t.retrans_connections, prev: p?.retrans_connections, goodWhen: "down" })}
  </div>`;
  if (prev) html += `<div class="muted" style="font-size:12px; margin:-8px 0 16px">Changes vs. previous capture: <a href="#/r/${prev.id}">#${prev.id}</a> (${dt(prev.submitted_at)})</div>`;
  if (!s.tools?.tshark) html += `<div class="alert warn" style="margin-bottom:16px">${ICONS.alert}<div>tshark is not installed; TCP RTT and TCP warning charts were not generated. <code>brew install wireshark</code></div></div>`;

  // --- traffic over time
  const tl = s.timeline;
  if (tl && tl.points.length) {
    const bucket = duration(tl.bucket_seconds).replace(/^1 (?=\S+$)/, ""); // "1 sec" -> "sec", "5 sec" stays
    const series = (key, f) => tl.points.map(pt => ({ t: pt.t * 1000, v: pt[key] }));
    const tlTable = (key, label, f) => ({ columns: [{ label: "Time" }, { label, num: true }],
      rows: tl.points.map(pt => [new Date(pt.t * 1000).toLocaleTimeString("en-US-u-hc-h23"), f(pt[key])]) });
    html += `<div class="section-title">Traffic <span class="muted">in ${tl.bucket_seconds}-sec intervals</span></div><div class="grid cols-2">
      ${chartCard({ title: "New connections", sub: `per ${bucket}`, render: el => timeSeries(el, series("connections"), { name: "connections", height: 180 }), table: tlTable("connections", "Connections", fmt.num) })}
      ${chartCard({ title: "Traffic volume", sub: `per ${bucket}, by connection start`, render: el => timeSeries(el, series("bytes"), { name: "traffic", format: fmt.bytes, height: 180 }), table: tlTable("bytes", "Bytes", fmt.bytes) })}
    </div>`;
  }

  // --- DNS
  const d = s.dns;
  if (d) {
    html += `<div class="section-title">DNS <span class="muted">${fmt.num(t.dns_queries)} ${t.dns_queries === 1 ? "query" : "queries"}${t.dns_rtt_avg_ms != null ? ` · avg RTT ${fmt.ms(t.dns_rtt_avg_ms)}` : ""}</span></div>`;
    const qs = d.queries.map(q => ({ ...q, t: q.t * 1000 }));
    html += `<div class="grid cols-2">
      ${chartCard({ title: "DNS queries", sub: `each dot is one query · y: response time${d.queries_truncated ? " · first 500 queries" : ""}`, span: 2,
        render: el => dnsScatter(el, qs),
        table: { columns: [{ label: "Time" }, { label: "Query" }, { label: "Server" }, { label: "Response" }, { label: "RTT", num: true }],
          rows: qs.map(q => [new Date(q.t).toLocaleTimeString("en-US-u-hc-h23"), q.query, q.server, RCODE_NAMES[q.rcode] || q.rcode, fmt.ms(q.rtt_ms)]) } })}
      ${chartCard({ title: "DNS servers", sub: "share of queries answered",
        render: el => meters(el, d.servers.map(sv => ({ name: sv.label, value: sv.answered, max: sv.queries,
          fig: `${sv.answered}/${sv.queries}${sv.avg_rtt_ms != null ? ` · ${fmt.ms(sv.avg_rtt_ms)}` : ""}`, flag: sv.answered === 0 ? "no response" : null }))),
        table: { columns: [{ label: "Server" }, { label: "Queries", num: true }, { label: "Answered", num: true }, { label: "Avg RTT", num: true }],
          rows: d.servers.map(sv => [sv.label, sv.queries, sv.answered, fmt.ms(sv.avg_rtt_ms)]) } })}
      ${chartCard({ title: "Response codes", sub: "distribution of queries",
        render: el => segmented(el, foldParts(d.rcodes, RCODE_COLORS, RCODE_NAMES)),
        table: { columns: [{ label: "Response code" }, { label: "Queries", num: true }], rows: Object.entries(d.rcodes).map(([k, v]) => [RCODE_NAMES[k] || k, v]) } })}
      ${chartCard({ title: "Most queried domains", sub: `top ${d.top_domains.length}`, span: 2,
        render: el => barList(el, d.top_domains.map(x => ({ name: x.name, value: x.count, unit: "queries",
          detail: x.unanswered ? [{ value: fmt.num(x.unanswered), name: "unanswered" }] : [] }))),
        table: { columns: [{ label: "Domain" }, { label: "Queries", num: true }, { label: "Unanswered", num: true }], rows: d.top_domains.map(x => [x.name, x.count, x.unanswered]) } })}
    </div>`;
  }

  // --- connections
  html += `<div class="section-title">Connections <span class="muted">${fmt.num(t.connections)} ${t.connections === 1 ? "connection" : "connections"} · zeek conn.log</span></div><div class="grid cols-2">
    ${chartCard({ title: "Connection states", sub: "zeek conn_state",
      render: el => segmented(el, foldParts(s.conn_states, CONN_STATE_COLORS, Object.fromEntries(Object.entries(CONN_STATES).map(([k, v]) => [k, `${v[0]} — ${v[1]}`])))),
      table: { columns: [{ label: "State" }, { label: "Description" }, { label: "Connections", num: true }],
        rows: Object.entries(s.conn_states).map(([k, v]) => [k, CONN_STATES[k]?.[1] || "", v]) } })}
    ${chartCard({ title: "Protocol / service", sub: "connection count",
      render: el => barList(el, Object.entries(s.services).slice(0, 8).map(([k, v]) => ({ name: k === "-" ? "unknown" : k, value: v, unit: "connections" }))),
      table: { columns: [{ label: "Service" }, { label: "Connections", num: true }], rows: Object.entries(s.services).map(([k, v]) => [k, v]) } })}
    ${chartCard({ title: "Top talkers", sub: "bytes sent + received",
      render: el => barList(el, s.top_talkers.map(x => ({ name: x.label, value: x.bytes, unit: "", detail: [{ value: fmt.num(x.connections), name: "connections" }] })), { format: fmt.bytes }),
      table: { columns: [{ label: "Host" }, { label: "Traffic", num: true }, { label: "Connections", num: true }], rows: s.top_talkers.map(x => [x.label, fmt.bytes(x.bytes), x.connections]) } })}
    ${chartCard({ title: "Destination ports", sub: "connection count",
      render: el => barList(el, s.top_ports.map(x => ({ name: `${x.port}/${x.proto}`, value: x.connections, unit: "connections" }))),
      table: { columns: [{ label: "Port" }, { label: "Connections", num: true }], rows: s.top_ports.map(x => [`${x.port}/${x.proto}`, x.connections]) } })}
  </div>`;

  // --- TCP (tshark)
  if (s.tcp) {
    const iss = Object.entries(s.tcp.issues);
    html += `<div class="section-title">TCP <span class="muted">tshark analysis</span></div><div class="grid cols-2">
      ${iss.length ? chartCard({ title: "TCP warnings", sub: `total ${fmt.num(s.tcp.issue_total)}`,
        render: el => barList(el, iss.map(([k, v]) => ({ name: k, value: v, unit: "packets" }))),
        table: { columns: [{ label: "Warning" }, { label: "Count", num: true }], rows: iss } })
        : `<div class="card"><div class="card-head"><div><h2>TCP warnings</h2></div></div><div class="card-body muted">No warnings.</div></div>`}
      ${s.tcp.rtt_flows.length ? chartCard({ title: "Highest ACK RTT — flows", sub: "average, ms",
        render: el => barList(el, s.tcp.rtt_flows.slice(0, 8).map(f => ({ name: `${f.src} → ${f.dst}`, value: f.avg_ms,
          detail: [{ value: fmt.ms(f.p95_ms), name: "p95" }, { value: fmt.ms(f.max_ms), name: "max" }, { value: fmt.num(f.n), name: "samples" }] })), { format: fmt.ms }),
        table: { columns: [{ label: "Flow" }, { label: "n", num: true }, { label: "Avg", num: true }, { label: "p95", num: true }, { label: "Max", num: true }],
          rows: s.tcp.rtt_flows.map(f => [`${f.src} → ${f.dst}`, f.n, fmt.ms(f.avg_ms), fmt.ms(f.p95_ms), fmt.ms(f.max_ms)]) } })
        : `<div class="card"><div class="card-head"><div><h2>ACK RTT</h2></div></div><div class="card-body muted">No TCP flows.</div></div>`}
    </div>`;
  }
  return html;
}

/** {key: count} → segmented parts; colors are fixed per entity, keys not in the map fold into "Other". */
function foldParts(counts, colorMap, names = {}) {
  const parts = [], other = { name: "Other", value: 0, color: "var(--other)" };
  for (const [k, v] of Object.entries(counts)) {
    if (colorMap[k]) parts.push({ name: names[k] || k, value: v, color: slot(colorMap[k]), inkDark: colorMap[k] === 4, order: colorMap[k] });
    else other.value += v;
  }
  parts.sort((a, b) => a.order - b.order);
  if (other.value) parts.push(other);
  return parts;
}

function runAI(r) {
  let html = "";
  if (r.context_run_ids.length) {
    html += `<div class="alert info" style="margin-bottom:16px">${ICONS.sparkle}<div>This analysis was compared against previous captures:
      ${r.context_run_ids.map(x => `<a href="#/r/${x}">#${x}</a>`).join(", ")}</div></div>`;
  }
  if (r.result) return html + `<div class="card"><div class="card-body md">${md(r.result)}</div></div>`;
  if (r.dry_run) return html + emptyState(ICONS.sparkle, "No LLM analysis", "This capture was submitted in 'parse only' mode.");
  if (isActive(r)) return html + emptyState(ICONS.sparkle, "Analysis in progress", "It appears here once the LLM response is complete.");
  return html + emptyState(ICONS.sparkle, "No result", "The analysis failed; see the error message above.");
}

function runInput(r) {
  return `<div class="grid cols-2" style="align-items:start">
    <div class="card"><div class="card-head"><div><h2>Submission</h2></div></div><div class="card-body"><dl class="kv">
      <dt>File</dt><dd>${esc(r.pcap.filename)}</dd>
      <dt>Size</dt><dd>${fmt.bytes(r.pcap.size)}</dd>
      <dt>SHA-256</dt><dd class="tnum" style="font-size:12px">${esc(r.pcap.sha256)}</dd>
      <dt>Mode</dt><dd>${modeTag(r)}</dd>
      <dt>Comparison</dt><dd>${r.compare_previous ? (r.context_run_ids.length ? r.context_run_ids.map(x => `<a href="#/r/${x}">#${x}</a>`).join(", ") : "on (no previous completed capture)") : "off"}</dd>
      <dt>Submitted</dt><dd>${new Date(r.submitted_at).toLocaleString("en-US-u-hc-h23")}</dd>
      <dt>Started</dt><dd>${r.started_at ? new Date(r.started_at).toLocaleString("en-US-u-hc-h23") : "–"}</dd>
      <dt>Finished</dt><dd>${r.finished_at ? new Date(r.finished_at).toLocaleString("en-US-u-hc-h23") : "–"}</dd>
      <dt>Queue wait</dt><dd>${duration(r.wait_seconds)}</dd>
      <dt>Processing time</dt><dd>${duration(r.duration_seconds)}</dd>
    </dl></div></div>
    <div class="card"><div class="card-head"><div><h2>Metadata</h2><div class="sub">Context used for this capture</div></div></div>
      <div class="card-body"><pre class="raw">${esc(JSON.stringify(r.metadata, null, 2))}</pre></div></div>
  </div>`;
}

// ================================================================ routing
async function render() {
  const token = ++state.renderToken;
  closeStreams();
  state.observers.forEach(o => o.disconnect());
  state.observers = [];
  state.charts = [];
  tooltip.hide();
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  const main = $("#content");
  try {
    let html, after = () => {};
    if (!parts.length) html = await pageHome();
    else if (parts[0] === "a" && parts[1]) {
      const id = Number(parts[1]), sub = parts[2];
      if (!sub) html = await pageAnalysis(id);
      else if (sub === "captures") html = await pageCaptures(id);
      else if (sub === "new") { html = await pageNew(id); after = () => bindNewForm(id); }
      else if (sub === "settings") { html = await pageSettings(id); after = () => bindSettings(id); }
    } else if (parts[0] === "r" && parts[1]) html = await pageRun(Number(parts[1]), parts[2]);
    if (token !== state.renderToken) return; // navigated to another page in the meantime
    if (html == null) { main.innerHTML = emptyState(ICONS.info, "Page not found", `<a href="#/">Back to home</a>`); return; }
    main.innerHTML = html;
    mountCharts(main);
    after();
    liveUpdates(parts);
  } catch (err) {
    if (token !== state.renderToken) return;
    main.innerHTML = emptyState(ICONS.x, "Failed to load", esc(err.message) + ` · <a href="#/">Home</a>`);
  }
}

/** Open SSE streams for active captures on the visible page; re-render when they finish. */
async function liveUpdates(parts) {
  const rerender = () => { const y = scrollY; render().then(() => scrollTo(0, y)); };
  if (parts[0] === "r") {
    const id = Number(parts[1]);
    if (!$("#progressCard")) return;
    let lastStage = null;
    watchRun(id, d => {
      $('[data-live="pct"]').textContent = `${d.progress}%`;
      $('[data-live="bar"]').style.width = `${d.progress}%`;
      $('[data-live="stage"]').textContent = STAGE_TEXT[d.stage] || d.stage;
      $('[data-live="queue"]').textContent = d.queue_position ? ` · #${d.queue_position} in queue` : "";
      // re-render when the stage changes (e.g. parse finished → charts ready)
      const coarse = d.stage === "llm_writing" ? "llm" : d.stage;
      if (lastStage && coarse !== lastStage) {
        if (coarse === "awaiting_approval") toast("Claude proposed a command — awaiting your approval");
        rerender();
      }
      lastStage = coarse;
    }, rerender);
  } else if (parts[0] === "a") {
    $("#content").querySelectorAll("[data-run]").forEach(row => {
      const id = Number(row.dataset.run);
      const shown = row.dataset.status;
      if (!["queued", "running", "awaiting_approval"].includes(shown)) return;
      watchRun(id, d => {
        const bar = row.querySelector(`[data-progress="${id}"] > div`), st = row.querySelector(`[data-stage="${id}"]`);
        if (bar) bar.style.width = `${d.progress}%`;
        if (st) st.textContent = `${STAGE_TEXT[d.stage] || d.stage} · ${d.progress}%`;
        if (d.status !== shown) rerender();
      }, rerender);
    });
  }
}

// ================================================================ global events
document.addEventListener("click", async e => {
  const row = e.target.closest("tr[data-href]");
  if (row && !e.target.closest("a, button")) { location.hash = row.dataset.href; return; }
  const act = e.target.closest("[data-action]");
  if (!act) return;
  if (act.dataset.action === "new-analysis") openNewDialog();
  if (act.dataset.action === "approve-call" || act.dataset.action === "reject-call") {
    const approve = act.dataset.action === "approve-call";
    const box = act.closest(".proposal");
    const body = { note: box.querySelector("[data-note]").value };
    if (approve) body.command = box.querySelector(".cmd").value;
    box.querySelectorAll("button").forEach(b => { b.disabled = true; });
    try {
      const run = await api(`/tool-calls/${act.dataset.id}/${approve ? "approve" : "reject"}`,
        { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      toast(run.status === "queued" ? "Decisions received — the analysis continues" : approve ? "Approved; waiting on the other proposals" : "Rejected; waiting on the other proposals");
      refreshQueue();
      render();
    } catch (err) {
      toast(err.message);
      box.querySelectorAll("button").forEach(b => { b.disabled = false; });
    }
  }
  if (act.dataset.action === "retry") {
    try { await api(`/runs/${act.dataset.id}/retry`, { method: "POST" }); toast("Re-queued"); render(); }
    catch (err) { toast(err.message); }
  }
});

function openNewDialog() {
  const dlg = $("#newDialog"), f = $("#newForm");
  f.reset();
  f.default_metadata.value = JSON.stringify(META_TEMPLATE, null, 2);
  dlg.showModal();
}
$("#newCancel").onclick = () => $("#newDialog").close();
$("#newForm").onsubmit = async e => {
  e.preventDefault();
  const f = e.target;
  const body = { name: f.name.value.trim(), description: f.description.value.trim() };
  const raw = f.default_metadata.value.trim();
  if (raw) {
    try { body.default_metadata = JSON.parse(raw); } catch { toast("Default metadata is not valid JSON"); return; }
    if (!body.default_metadata.question) { toast("Default metadata must have a 'question' (or clear the field entirely)"); return; }
  }
  try {
    const a = await api("/analyses", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    $("#newDialog").close();
    await refreshQueue();
    location.hash = `#/a/${a.id}/new`;
  } catch (err) { toast(err.message); }
};

// theme: user choice > operating system
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $("#themeBtn").innerHTML = t === "dark" ? ICONS.sun : ICONS.moon;
  $("#themeBtn").title = t === "dark" ? "Light theme" : "Dark theme";
}
applyTheme(localStorage.getItem("theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
$("#themeBtn").onclick = () => {
  const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("theme", t);
  applyTheme(t);
  render(); // chart colors are read from CSS variables
};
$("#docsBtn").innerHTML = ICONS.docs;

addEventListener("hashchange", render);
setInterval(refreshQueue, 5000);
refreshQueue().then(render);
