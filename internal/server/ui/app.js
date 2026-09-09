const params = new URLSearchParams(location.search);
const token = params.get("token") || "";
const streamOff = params.get("stream") === "off";
const SVGNS = "http://www.w3.org/2000/svg";
const el = (id) => document.getElementById(id);

const modules = new Map();
let main = "";
let selected = null;
let source = null;
let frame = 0;

function qs(extra) {
  const parts = [];
  if (token) parts.push("token=" + encodeURIComponent(token));
  if (extra) parts.push(extra);
  return parts.length ? "?" + parts.join("&") : "";
}

async function api(path, options) {
  const response = await fetch(path + qs(), options);
  if (!response.ok) throw new Error(response.status);
  return response.json();
}

async function init() {
  try {
    const status = await api("/api/v1/status");
    el("feed-meta").textContent = "reliquary " + status.version;
  } catch (_) {}
  try {
    const scans = await api("/api/v1/scans");
    if (scans.length) load(scans[0]);
  } catch (_) {}
  el("run").addEventListener("click", start);
  el("graph").addEventListener("click", onPick);
  buildLegend();
}

function load(scan) {
  modules.clear();
  main = scan.main || "";
  for (const module of scan.modules || []) modules.set(module.path, module);
  el("main").textContent = main || "no project loaded";
  setBand(scan.band, scan.index, scan.counts);
  setState(scan.status);
  const preselect = params.get("module");
  if (preselect && modules.has(preselect)) select(preselect);
  render();
  if (scan.status === "running" && !streamOff) stream(scan.id);
}

async function start() {
  el("run").disabled = true;
  el("feed").innerHTML = "";
  try {
    const scan = await api("/api/v1/scans", { method: "POST" });
    modules.clear();
    selected = null;
    main = scan.main || "";
    el("main").textContent = main;
    el("detail-body").hidden = true;
    el("detail-empty").hidden = false;
    setState("running");
    stream(scan.id);
  } catch (_) {
    setState("idle");
  }
  el("run").disabled = false;
}

function stream(id) {
  if (source) source.close();
  source = new EventSource("/api/v1/scans/" + id + "/stream" + qs());
  source.onmessage = (event) => {
    const update = JSON.parse(event.data);
    if (update.type === "module" && update.module) {
      modules.set(update.module.path, update.module);
      if (update.module.findings && update.module.findings.length) feed(update.module);
    } else if (update.type === "done") {
      refresh(id);
      source.close();
    }
    schedule();
  };
  source.onerror = () => {};
}

async function refresh(id) {
  try {
    const scan = await api("/api/v1/scans/" + id);
    for (const module of scan.modules || []) modules.set(module.path, module);
    setBand(scan.band, scan.index, scan.counts);
    setState("done");
    schedule();
  } catch (_) {}
}

function schedule() {
  if (frame) return;
  frame = requestAnimationFrame(() => {
    frame = 0;
    render();
    if (selected && modules.has(selected)) renderDetail(modules.get(selected));
  });
}

const rank = { none: 0, unknown: 1, low: 2, medium: 3, high: 4, critical: 5 };

function vulnerable(module) {
  return module.findings && module.findings.length > 0;
}

function layout(list) {
  const cx = 400, cy = 280;
  const positions = new Map();
  const direct = list.filter((m) => !m.indirect);
  const indirect = list.filter((m) => m.indirect);
  const place = (group, radius) => {
    group.forEach((module, index) => {
      const angle = -Math.PI / 2 + (index / Math.max(group.length, 1)) * Math.PI * 2;
      positions.set(module.path, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
    });
  };
  place(direct, 145);
  place(indirect, 236);
  return positions;
}

function render() {
  const graph = el("graph");
  const list = [...modules.values()];
  const positions = layout(list);
  const cx = 400, cy = 280;
  const parts = [];

  for (const module of list) {
    const p = positions.get(module.path);
    if (!p) continue;
    parts.push(`<line class="edge" x1="${cx}" y1="${cy}" x2="${p.x.toFixed(1)}" y2="${p.y.toFixed(1)}"${module.indirect ? ' opacity="0.28"' : ""}/>`);
  }

  for (const module of list) {
    const p = positions.get(module.path);
    if (!p) continue;
    const vuln = vulnerable(module);
    const level = module.worst || "none";
    const radius = 7 + (vuln ? Math.min(module.findings.length, 9) : 0);
    let halo = "";
    if (vuln) {
      const spread = radius + 8 + rank[level] * 5;
      halo =
        `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${spread}" fill="var(--${cvar(level)})" opacity="0.12"/>` +
        `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${(radius + 4).toFixed(1)}" fill="var(--${cvar(level)})" opacity="0.3"/>`;
    }
    const fill = vuln ? `var(--${cvar(level)})` : "var(--bronze)";
    const cls = "node" + (module.path === selected ? " sel" : "");
    const label = vuln
      ? `<text class="node-label vuln" x="${(p.x + radius + 5).toFixed(1)}" y="${(p.y + 4).toFixed(1)}">${escape(tail(module.path))}</text>`
      : "";
    parts.push(
      `<g class="${cls}" data-path="${escapeAttr(module.path)}">${halo}` +
        `<circle class="disc" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${radius}" fill="${fill}" stroke="var(--espresso)" stroke-width="1.5"/>` +
        `${label}</g>`
    );
  }

  parts.push(`<circle cx="${cx}" cy="${cy}" r="13" fill="var(--bronze-lift)" stroke="var(--espresso)" stroke-width="2"/>`);
  parts.push(`<text class="node-label vuln" x="${cx}" y="${cy + 30}" text-anchor="middle">${escape(tail(main) || "project")}</text>`);

  graph.innerHTML = parts.join("");
}

function onPick(event) {
  const group = event.target.closest(".node");
  if (!group) return;
  select(group.getAttribute("data-path"));
}

function select(path) {
  selected = path;
  if (modules.has(path)) renderDetail(modules.get(path));
  render();
}

function renderDetail(module) {
  el("detail-empty").hidden = true;
  el("detail-body").hidden = false;
  const worst = el("d-worst");
  worst.className = "worst " + (module.worst || "none");
  worst.textContent = vulnerable(module) ? module.worst : "clean";
  el("d-path").textContent = module.path;
  el("d-ver").textContent = module.version + (module.indirect ? "  · indirect" : "");

  const findings = el("findings");
  findings.innerHTML = "";
  if (!vulnerable(module)) {
    const clean = document.createElement("div");
    clean.className = "detail-empty";
    clean.textContent = "No known advisories for this module.";
    findings.appendChild(clean);
    return;
  }
  for (const finding of module.findings) findings.appendChild(findingRow(finding));
}

function findingRow(finding) {
  const node = document.createElement("div");
  node.className = "finding";
  const top = document.createElement("div");
  top.className = "finding-top";

  const sev = document.createElement("span");
  sev.className = "sev sev-" + finding.level;
  sev.textContent = finding.level;
  const cvss = document.createElement("span");
  cvss.className = "cvss";
  cvss.textContent = finding.score > 0 ? finding.score.toFixed(1) : "—";
  const cve = document.createElement("span");
  cve.className = "cve";
  cve.textContent = finding.cve;
  top.append(sev, cvss, cve);
  if (finding.fixed) {
    const fix = document.createElement("span");
    fix.className = "fix";
    fix.textContent = "fixed " + finding.fixed;
    top.appendChild(fix);
  }

  const sum = document.createElement("div");
  sum.className = "finding-sum";
  sum.textContent = finding.summary || "";
  node.append(top, sum);
  return node;
}

function feed(module) {
  const line = document.createElement("div");
  const count = module.findings.length;
  line.innerHTML =
    "<b>" + escape(tail(module.path)) + "</b> " +
    "<span class=\"t-" + (module.worst || "none") + "\">" + (module.worst || "clean") + "</span> " +
    count + " advisor" + (count === 1 ? "y" : "ies");
  const node = el("feed");
  node.prepend(line);
  while (node.childElementCount > 200) node.lastChild.remove();
}

function setBand(band, index, counts) {
  const node = el("band");
  node.className = "band " + (band || "idle");
  node.textContent = band || "idle";
  el("meter-fill").style.width = (index || 0) + "%";
  el("tally").textContent = tally(counts);
}

function tally(counts) {
  if (!counts) return "";
  const parts = [];
  for (const level of ["critical", "high", "medium", "low", "unknown"]) {
    if (counts[level]) parts.push(level[0].toUpperCase() + " " + counts[level]);
  }
  return parts.join("   ");
}

function setState(status) {
  const lamp = el("lamp");
  lamp.className = "lamp";
  if (status === "running") { lamp.classList.add("run"); el("state").textContent = "scanning"; }
  else if (status === "done") { lamp.classList.add("done"); el("state").textContent = "done"; }
  else el("state").textContent = "idle";
}

function buildLegend() {
  const levels = [["crit", "critical"], ["high", "high"], ["med", "medium"], ["low", "low"], ["unknown", "unknown"], ["bronze", "clean"]];
  el("legend").innerHTML = levels
    .map(([v, label]) => `<span><i style="background:var(--${v})"></i>${label}</span>`)
    .join("");
}

const cssVar = { critical: "crit", high: "high", medium: "med", low: "low", unknown: "unknown", none: "clean" };

function cvar(level) {
  return cssVar[level] || "clean";
}

function tail(path) {
  if (!path) return "";
  const parts = path.split("/");
  return parts[parts.length - 1];
}

function escape(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function escapeAttr(text) {
  return String(text).replace(/"/g, "&quot;");
}

init();
