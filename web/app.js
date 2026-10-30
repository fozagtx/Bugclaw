const view = document.getElementById("view");
const shell = document.getElementById("shell");
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const parse = (v) => { if (typeof v !== "string") return v; try { return JSON.parse(v); } catch { return v; } };
const short = (id) => esc(String(id ?? "").slice(0, 8));
const when = (iso) => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "";
const clock = (iso) => iso ? new Date(iso).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }) : "";
const ago = (iso) => {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
};
const words = (s) => String(s ?? "").replace(/[-_:]+/g, " ").replace(/^\w/, (c) => c.toUpperCase());
const TONE = {
  g: ["complete", "done", "fix-verified", "not-reproduced", "safe", "up", "confirmed", "supported", "validated", "genuine", "completed"],
  a: ["running", "queued", "inconclusive", "needs-reproduction", "needs-context", "pending", "model-error", "sandbox-error", "not-reproducible", "medium", "tautological"],
  r: ["failed", "incomplete", "reproduced", "fix-failed", "vulnerable", "down", "critical", "high", "invalid-poc", "invalid"],
};
const tone = (s) => Object.keys(TONE).find((k) => TONE[k].includes(String(s).toLowerCase())) ?? "";
const pill = (s, label) => s ? `<span class="pill ${tone(s)}">${esc(label ?? words(s))}</span>` : `<span class="muted">—</span>`;
const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const icon = (d) => `<svg class="i" viewBox="0 0 16 16">${d}</svg>`;
const I = {
  back: icon('<path d="M13 8H3M7 4 3 8l4 4"/>'),
  arrow: icon('<path d="M3 8h10M9 4l4 4-4 4"/>'),
  search: icon('<circle cx="7" cy="7" r="4.5"/><path d="m10.5 10.5 3 3"/>'),
  folder: icon('<path d="M2 4.5h4l1.5 1.5H14v6.5H2z"/>'),
  git: icon('<circle cx="4.5" cy="4" r="1.5"/><circle cx="4.5" cy="12" r="1.5"/><circle cx="11.5" cy="6" r="1.5"/><path d="M4.5 5.5v5M11.5 7.5c0 2-2 2.5-7 3"/>'),
  clock: icon('<circle cx="8" cy="8" r="6"/><path d="M8 4.5V8l2.5 1.5"/>'),
  shield: icon('<path d="M8 1.8 13.5 4v4c0 3.2-2.3 5.3-5.5 6.2C4.8 13.3 2.5 11.2 2.5 8V4z"/>'),
  file: icon('<path d="M4 1.8h5l3 3v9.4H4z"/><path d="M9 1.8v3h3"/>'),
};
let timers = [];
let streams = [];

async function api(path, init) {
  const res = await fetch(path, init && { ...init, headers: { "content-type": "application/json" } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}
function evidenceRel(abs) {
  const i = String(abs ?? "").indexOf("/scans/");
  return i < 0 ? null : abs.slice(i + 7);
}
function scanName(source) {
  const s = String(source ?? "").replace(/\.git$/, "").replace(/\/+$/, "");
  const m = /github\.com[/:]([^/]+\/[^/]+)/.exec(s);
  if (m) return m[1];
  return s.split("/").filter(Boolean).slice(-2).join("/") || s;
}
const isGit = (v) => /^(https?:\/\/|git@)/.test(String(v).trim());

shell.classList.toggle("collapsed", localStorage.getItem("bugclaw.rail") === "collapsed");
document.getElementById("collapse").addEventListener("click", () => {
  const next = !shell.classList.contains("collapsed");
  shell.classList.toggle("collapsed", next);
  localStorage.setItem("bugclaw.rail", next ? "collapsed" : "open");
});
document.addEventListener("click", (e) => {
  const row = e.target.closest("tr[data-href]");
  const link = e.target.closest("a[data-link]");
  const href = link?.getAttribute("href") ?? row?.dataset.href;
  if (!href || e.metaKey || e.ctrlKey) return;
  e.preventDefault();
  go(href);
});
window.addEventListener("popstate", render);
function go(href) { history.pushState(null, "", href); render(); }
function cleanup() { timers.forEach(clearInterval); timers = []; streams.forEach((s) => s.close()); streams = []; }

async function render() {
  cleanup();
  const path = location.pathname.replace(/\/+$/, "") || "/";
  const parts = path.split("/").filter(Boolean);
  const section = parts[0] ?? "overview";
  document.querySelectorAll(".rail nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === section && !(section === "scans" && parts[1] && parts[1] !== "new")));
  recent(parts[0] === "scans" ? parts[1] : null);
  try {
    if (path === "/") await overview();
    else if (path === "/scans") await scans();
    else if (path === "/scans/new") newScan();
    else if (parts[0] === "scans" && parts[1]) await scanDetail(decodeURIComponent(parts[1]), parts[2] ?? "overview");
    else if (path === "/candidates") await findings();
    else if (parts[0] === "candidates" && parts[1]) await candidate(decodeURIComponent(parts[1]));
    else if (path === "/setup") await setup();
    else view.innerHTML = top("Page not found") + `<div class="body"><div class="card dashed"><div class="empty"><b>Nothing here.</b>This page does not exist.</div></div></div>`;
  } catch (err) {
    view.innerHTML = top("Couldn't load this page") + `<div class="body"><div class="card"><div class="pad error">${esc(err.message)}</div></div></div>`;
  }
  view.focus({ preventScroll: true });
}

function top(title, { back, extra = "", crumb = false } = {}) {
  return `<div class="top">${back ? `<a class="back${crumb ? "" : " sq"}" href="${esc(back.href)}" data-link title="Back">${I.back}${crumb ? esc(back.label) : ""}</a>` : ""}${crumb ? `<span class="crumb">${esc(title)}</span>` : `<h1>${esc(title)}</h1>`}${extra}</div>`;
}

async function recent(activeId) {
  const box = document.getElementById("recent");
  const list = await api("/api/scans").catch(() => null);
  if (!list) { box.innerHTML = `<span class="muted" style="padding:6px 10px;font-size:13px">Unavailable</span>`; return; }
  box.innerHTML = list.length ? list.slice(0, 12).map((s) => `<a href="/scans/${encodeURIComponent(s.id)}" data-link class="${s.id === activeId ? "active" : ""}" title="${esc(s.source)}"><span class="dot ${esc(s.status)}"></span><span class="nm">${esc(scanName(s.source))}</span><span class="t">${esc(new Date(s.created_at).toDateString() === new Date().toDateString() ? clock(s.created_at) : ago(s.created_at))}</span></a>`).join("") : `<span class="muted" style="padding:6px 10px;font-size:13px">No scans yet</span>`;
}

async function health() {
  const h = await api("/api/health");
  const ok = h.nebius.keyPresent && h.nebius.modelsAvailable && h.openshell && h.docker && h.engine;
  document.getElementById("rail-health").innerHTML = `<b>Runtime ${pill(ok ? "up" : "down", ok ? "Ready" : "Not ready")}</b>${ok ? "Nemotron, OpenShell and Docker reachable" : `<a href="/setup" data-link>See what's missing</a>`}`;
  return h;
}

function runtimeRows(h) {
  return [
    ["Nebius Token Factory", h.nebius.keyPresent && h.nebius.modelsAvailable, h.nebius.keyPresent ? (h.nebius.modelError ?? "Nemotron models reachable") : "NEBIUS_API_KEY is not set"],
    ["OpenShell gateway", h.openshell, h.openshell ? "Connected" : "Run: openshell gateway start"],
    ["Docker", h.docker, h.docker ? "Daemon reachable" : "Docker daemon not reachable"],
    ["Runner image", h.runnerImage, h.runnerImage ? "Built" : "Built on first reproduction"],
    ["Discovery engine", h.engine, h.engine ? "engine/ present" : "engine/ missing"],
  ];
}
function runtimeTable(h) {
  return `<table><thead><tr><th>Component</th><th style="width:140px">Status</th><th>Detail</th></tr></thead><tbody>${runtimeRows(h).map(([k, ok, note]) => `<tr><td>${esc(k)}</td><td>${pill(ok ? "up" : "down", ok ? "Up" : "Down")}</td><td class="muted">${esc(note)}</td></tr>`).join("")}</tbody></table>`;
}

const ENGINE = new Set(["unvalidated", "rejected", "needs-reproduction", "needs-context", "validated", "supported", "candidate"]);
const sandboxStatus = (c) => ENGINE.has(c.status) ? "not run" : c.status;
const sandboxPill = (c) => sandboxStatus(c) === "not run" ? `<span class="pill plain">Not run</span>` : pill(c.status);

function scanTable(list) {
  if (!list.length) return `<div class="empty"><b>No scans yet</b>Start one with a local path or a public git URL.</div>`;
  return `<table><thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Started</th></tr></thead><tbody>${list.map((s) => `
    <tr data-href="/scans/${encodeURIComponent(s.id)}"><td class="title">${esc(scanName(s.source))}<div class="sub">${esc(s.source)}</div></td><td>${pill(s.status)}</td><td>${s.candidateCount ?? "—"}</td><td class="muted">${esc(ago(s.created_at))}</td></tr>`).join("")}</tbody></table>`;
}

function candidateTable(list, { showScan, scanLive } = {}) {
  if (!list.length) return `<div class="empty"><b>${scanLive ? "Nothing verified yet" : "No findings"}</b>${scanLive ? "Findings appear here once the validator has checked them." : "The engine reported no candidates for this scope."}</div>`;
  const sorted = [...list].sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
  return `<table><thead><tr><th>Finding</th><th>Severity</th><th>Validator</th><th>Sandbox</th>${showScan ? "<th>Scan</th>" : ""}</tr></thead><tbody>${sorted.map((c) => {
    const d = parse(c.data) ?? {};
    return `<tr data-href="/candidates/${encodeURIComponent(c.id)}"><td class="title">${esc(c.title)}<div class="sub">${esc((d.evidence ?? []).map((e) => `${e.path}:${e.startLine}`).join("  "))}</div></td><td>${pill(c.severity)}</td><td>${pill(d.validation ?? d.status)}</td><td>${sandboxPill(c)}</td>${showScan ? `<td class="mono muted">${short(c.scan_id)}</td>` : ""}</tr>`;
  }).join("")}</tbody></table>`;
}

async function overview() {
  const [h, list, cands] = await Promise.all([health(), api("/api/scans"), api("/api/candidates")]);
  const count = (f) => cands.filter(f).length;
  view.innerHTML = top("Overview", { extra: `<span class="src"></span><a class="btn" href="/scans/new" data-link>New scan ${I.arrow}</a>` }) + `
  <div class="body">
    <div class="card"><div class="steps">
      <div><span class="no">Scans</span><b style="font-size:28px;letter-spacing:-.02em">${list.length}</b><p>${count(() => true)} candidates found</p></div>
      <div><span class="no">Reproduced</span><b style="font-size:28px;letter-spacing:-.02em">${count((c) => ["reproduced", "fix-verified", "fix-failed"].includes(c.status))}</b><p>PoC proved it in a sandbox</p></div>
      <div><span class="no">Fix verified</span><b style="font-size:28px;letter-spacing:-.02em">${count((c) => c.status === "fix-verified")}</b><p>Same PoC passes after the fix</p></div>
      <div><span class="no">Not reproduced</span><b style="font-size:28px;letter-spacing:-.02em">${count((c) => ["not-reproduced", "not-reproducible"].includes(c.status))}</b><p>Sandbox could not prove it</p></div>
    </div></div>
    <div class="grid2">
      <div class="card"><div class="hd"><h3>Recent scans</h3><a class="aside" href="/scans" data-link>All scans</a></div>${scanTable(list.slice(0, 6))}</div>
      <div class="card"><div class="hd"><h3>Runtime</h3>${pill(runtimeRows(h).every((r) => r[1] || r[0] === "Runner image") ? "up" : "down", runtimeRows(h).every((r) => r[1] || r[0] === "Runner image") ? "Ready" : "Action needed")}</div><div class="pad"><ul class="stages">${runtimeRows(h).map(([k, ok, note]) => `<li><span>${esc(k)}<div class="muted" style="font-size:12.5px">${esc(note)}</div></span>${pill(ok ? "up" : "down", ok ? "Up" : "Down")}</li>`).join("")}</ul></div></div>
    </div>
  </div>`;
}

async function scans() {
  const list = await api("/api/scans");
  view.innerHTML = top("Scans", { extra: `<span class="src"></span><a class="btn" href="/scans/new" data-link>New scan ${I.arrow}</a>` }) + `
  <div class="body">
    <div class="ph"><h2>All scans</h2><p>Every scan snapshots the source, hashes each file and runs recon, hunt and validation on Nemotron · ${list.length} in total</p></div>
    <div class="card">${scanTable(list)}</div>
  </div>`;
}

function newScan() {
  view.innerHTML = top("New scan", { back: { href: "/scans", label: "Scans" }, crumb: true }) + `
  <div class="body narrow">
    <form id="new-scan">
      <div class="card">
        <div class="hd"><h3>What should we scan?</h3><span class="aside">Source only · runs on your Nebius key</span></div>
        <div class="pad">
          <div class="target">
            <label class="box"><span id="kind-icon" class="muted">${I.folder}</span><input name="source" id="source" required autocomplete="off" placeholder="/path/to/repo or https://github.com/org/repo"><span class="pill plain" id="kind">Local path</span></label>
            <button class="btn lg" type="submit">Start scan ${I.arrow}</button>
          </div>
          <p class="hint">A credential-free git URL is cloned once; a local path is copied. Bugclaw never touches a live system.</p>
          <p class="error" id="scan-error"></p>
        </div>
        <div class="cols" style="border-top:1px solid var(--line)">
          <div><p class="lbl">Covers</p><div>This snapshot only <span class="muted">· up to 200 source files</span></div></div>
          <div><p class="lbl">Domains</p><select name="domains"><option value="web2">Web2 · apps, APIs, libraries</option><option value="web3">Web3 · smart contracts</option><option value="web2,web3">Web2 + Web3</option></select></div>
        </div>
      </div>
      <div class="card">
        <div class="hd"><h3>Authorization</h3><span class="aside">Required</span></div>
        <div class="pad">
          <p class="lbl">Reference <span>Who allowed this review and where it is recorded</span></p>
          <input name="authorization" required placeholder="e.g. Owner approval in ticket SEC-142, or public package under its license">
          <p class="hint">Stored with the scan scope and every piece of evidence.</p>
        </div>
      </div>
      <div class="card">
        <div class="hd"><h3>Options</h3><span class="aside">All optional</span></div>
        <div class="pad">
          <p class="lbl">Files <span>Limit the scan to these paths</span></p>
          <input name="files" placeholder="src/login.js, src/api/users.ts">
          <p class="hint">Comma-separated, relative to the repo root. Leave empty to let Bugclaw pick source files and skip tests, vendor and build output.</p>
        </div>
      </div>
      <div class="card">
        <div class="hd"><h3>How it works</h3></div>
        <div class="steps">
          <div><span class="no">01</span><b>Snapshot</b><p>Copies the source privately and hashes every file</p></div>
          <div><span class="no">02</span><b>Hunt</b><p>Nemotron maps the code and hunts with security lenses</p></div>
          <div><span class="no">03</span><b>Prove</b><p>Runs each PoC in an OpenShell sandbox with no network, then tests a fix</p></div>
          <div><span class="no">04</span><b>Sign off</b><p>Evidence and replay script; only you can confirm a finding</p></div>
        </div>
      </div>
    </form>
  </div>`;
  const src = document.getElementById("source");
  src.addEventListener("input", () => {
    const git = isGit(src.value);
    document.getElementById("kind").textContent = git ? "Git repo" : "Local path";
    document.getElementById("kind-icon").innerHTML = git ? I.git : I.folder;
  });
  src.focus();
  document.getElementById("new-scan").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const split = (v) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);
    const btn = e.target.querySelector("button[type=submit]");
    btn.disabled = true;
    try {
      const body = { source: String(f.get("source")).trim(), authorization: f.get("authorization"), domains: split(f.get("domains")) };
      const files = split(f.get("files"));
      if (files.length) body.files = files;
      const { id } = await api("/api/scans", { method: "POST", body: JSON.stringify(body) });
      go(`/scans/${encodeURIComponent(id)}`);
    } catch (err) {
      document.getElementById("scan-error").textContent = err.message;
      btn.disabled = false;
    }
  });
}

const STAGES = [["recon", "Map the code"], ["trace", "Trace calls"], ["hunt", "Hunt"], ["validate", "Validate"], ["feedback", "Feedback"], ["gapfill", "Gap fill"], ["vvs-dedup", "Deduplicate"]];
function stageOf(t) { return t.stage === "wishlist" ? "feedback" : t.stage; }
function taskTitle(t, cands) {
  const p = t.id.split(":");
  if (t.stage === "recon") return p[1] ? `Map ${words(p[1]).toLowerCase()}` : "Combine recon";
  if (t.stage === "hunt" || t.stage === "gapfill") return `${t.stage === "gapfill" ? "Gap fill · " : ""}${words(p[t.stage === "gapfill" ? 3 : 2] ?? t.id)} lens`;
  if (t.stage === "validate") return `Validate · ${cands.get(p[1]) ?? p[1]?.slice(0, 12)}`;
  if (t.stage === "trace") return "Trace call edges";
  if (t.stage === "feedback") return "Learn from rejected findings";
  if (t.stage === "wishlist") return "Missing context";
  if (t.stage === "vvs-dedup") return p[0] === "vvs-dedup-agent" ? "Merge duplicates" : "Shortlist duplicates";
  return words(t.id);
}
const TASKPILL = { done: ["g", "Completed"], failed: ["r", "Failed"], running: ["a", "Running"], pending: ["", "Queued"] };
const taskPill = (s) => `<span class="pill ${TASKPILL[s]?.[0] ?? ""}">${TASKPILL[s]?.[1] ?? words(s)}</span>`;

async function scanDetail(id, tab) {
  const [s, act] = await Promise.all([api(`/api/scans/${encodeURIComponent(id)}`), api(`/api/scans/${encodeURIComponent(id)}/activity`).catch((e) => ({ error: e.message, tasks: [], files: [] }))]);
  const report = parse(s.report);
  const cands = s.candidates ?? [];
  const live = ["queued", "running"].includes(s.status);
  const tasks = act.tasks ?? [];
  const checks = tasks.filter((t) => t.stage === "hunt" || t.stage === "gapfill");
  const base = `/scans/${encodeURIComponent(id)}`;
  const tabs = [["overview", "Overview"], ["activity", "Activity", tasks.length], ["exploration", "Exploration", checks.length], ["assets", "Assets", act.files?.length], ["findings", "Findings", cands.length], ["report", "Report"]];
  const statusPill = s.status === "running" ? `<span class="pill a">Running</span>` : pill(s.status);
  view.innerHTML = top(scanName(s.source), { back: { href: "/scans" }, extra: `${statusPill}<span class="src" title="${esc(s.source)}">${esc(s.source)}</span><span class="meta">Started ${esc(when(s.created_at))}</span>` }) +
    `<div class="tabs">${tabs.map(([k, label, n]) => `<a href="${base}${k === "overview" ? "" : `/${k}`}" data-link class="${tab === k ? "on" : ""}">${label}${n ? `<span class="n">${n}</span>` : ""}</a>`).join("")}</div><div class="body" id="tab"></div>`;
  const el = document.getElementById("tab");
  const titles = new Map(cands.map((c) => [c.id, c.title]));
  if (act.error && tab !== "overview" && tab !== "findings") el.innerHTML = `<div class="card"><div class="pad error">Engine activity unavailable: ${esc(act.error)}</div></div>`;
  else if (tab === "activity") activityTab(el, tasks, titles);
  else if (tab === "exploration") explorationTab(el, s, tasks, checks, titles);
  else if (tab === "assets") assetsTab(el, act.files ?? [], cands);
  else if (tab === "report") await reportTab(el, s, cands);
  else if (tab === "findings") el.innerHTML = `<div class="card"><div class="hd"><h3>Findings</h3><span class="aside">${live ? "Scan still running" : `${cands.length} candidates`}</span></div>${candidateTable(cands, { scanLive: live })}</div><p class="foot">Validator verdicts are model opinions. Only the sandbox column reflects code that actually ran, and only a person can confirm a finding.</p>`;
  else overviewTab(el, s, report, tasks, act, cands, live);
  if (live) timers.push(setInterval(async () => {
    if (location.pathname.startsWith(base)) render();
  }, 8000));
}

function overviewTab(el, s, report, tasks, act, cands, live) {
  const done = tasks.filter((t) => t.status === "done").length;
  const failed = tasks.filter((t) => t.status === "failed");
  const pct = tasks.length ? Math.round((done / tasks.length) * 100) : 0;
  const C = 2 * Math.PI * 50;
  const hunts = tasks.filter((t) => t.stage === "hunt");
  const vals = tasks.filter((t) => t.stage === "validate");
  const tokens = tasks.reduce((a, t) => [a[0] + (t.inputTokens ?? 0), a[1] + (t.outputTokens ?? 0)], [0, 0]);
  const cited = new Set(cands.flatMap((c) => ((parse(c.data) ?? {}).evidence ?? []).map((e) => e.path)));
  const meter = (label, n, total, g) => `<div class="meter"><div class="top2">${esc(label)}<span>${n} / ${total}</span></div><div class="track"><i class="${g ? "g" : ""}" style="width:${total ? Math.round((n / total) * 100) : 0}%"></i></div></div>`;
  const callout = live
    ? `<div class="card"><div class="pad callout"><span class="ic">${I.clock}</span><div><h3>Scan running</h3><p>${tasks.length ? `${done} of ${tasks.length} engine steps finished. This page refreshes on its own.` : "Snapshotting the source and starting recon."}</p></div></div></div>`
    : s.status === "incomplete" || s.status === "failed"
      ? `<div class="card"><div class="pad callout"><span class="ic">${I.shield}</span><div><h3>Scan ${esc(s.status)}</h3><p>${failed.length} engine step${failed.length === 1 ? "" : "s"} failed (${esc([...new Set(failed.map((t) => t.error).filter(Boolean))].join(", ") || "see Activity")}). The findings it validated before that are still listed.</p></div></div></div>`
      : "";
  const byStage = STAGES.map(([k, label]) => {
    const ts = tasks.filter((t) => stageOf(t) === k);
    if (!ts.length) return "";
    const st = ts.some((t) => t.status === "running") ? "running" : ts.some((t) => t.status === "pending") ? "pending" : ts.every((t) => t.status === "done") ? "done" : ts.some((t) => t.status === "done") ? "done" : "failed";
    return `<li><span>${esc(label)} <span class="muted">· ${ts.filter((t) => t.status === "done").length}/${ts.length}</span></span>${taskPill(st)}</li>`;
  }).join("");
  el.innerHTML = `${callout}
  <div class="grid2">
    <div>
      <div class="card"><div class="hd"><h3>Coverage</h3><span class="aside">From the engine's own task log</span></div>
        <div class="pad cov">
          <div class="ring"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="50" fill="none" stroke="#eef0f3" stroke-width="12"/><circle cx="60" cy="60" r="50" fill="none" stroke="${failed.length && !live ? "#9a6100" : "#1f7a45"}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${(C * pct) / 100} ${C}"/></svg><div class="v">${pct}%</div></div>
          <div>
            ${meter("Hunt lenses finished", hunts.filter((t) => t.status === "done").length, hunts.length, true)}
            ${meter("Candidates validated", vals.filter((t) => t.status === "done").length, vals.length, true)}
            ${meter("Files cited by findings", cited.size, act.files?.length ?? 0)}
          </div>
        </div>
      </div>
      <div class="card"><div class="hd"><h3>Scan plan</h3>${pill(s.status === "complete" ? "done" : s.status, s.status === "complete" ? "Done" : undefined)}</div>
        <div class="pad">
          <p class="lbl">Authorization</p>
          <div class="quote">${esc(s.authorization)}</div>
          <dl class="kv wide" style="margin-top:20px">
            <dt>Target</dt><dd class="mono">${esc(s.source)}</dd>
            ${report?.snapshot?.ref ? `<dt>Ref</dt><dd class="mono">${esc(report.snapshot.ref)}${report.snapshot.commit ? ` · ${esc(String(report.snapshot.commit).slice(0, 12))}` : ""}</dd>` : ""}
            <dt>Snapshot</dt><dd class="mono">${esc(s.snapshot_hash ?? "pending")}</dd>
            ${report?.models ? Object.entries(report.models).map(([k, m]) => `<dt>${esc(words(k))} model</dt><dd class="mono">${esc(m.id)}</dd>`).join("") : ""}
            <dt>Execution</dt><dd>Source-only analysis. PoCs run only in OpenShell with egress denied.</dd>
          </dl>
        </div>
      </div>
    </div>
    <div>
      <div class="card"><div class="hd"><h3>Summary</h3></div>
        <div class="pad">
          <p class="lbl">Findings</p>
          <dl class="kv">
            <dt>Candidates</dt><dd>${cands.length}</dd>
            <dt>Reproduced</dt><dd>${cands.filter((c) => ["reproduced", "fix-verified", "fix-failed"].includes(c.status)).length}</dd>
            <dt>Fix verified</dt><dd>${cands.filter((c) => c.status === "fix-verified").length}</dd>
          </dl>
          <a class="btn ghost sm" style="margin-top:14px" href="/scans/${encodeURIComponent(s.id)}/findings" data-link>${I.file} Open findings</a>
        </div>
        <div class="sec"><p class="lbl">Progress <span>${done} of ${tasks.length}</span></p>${byStage ? `<ul class="stages">${byStage}</ul>` : `<p class="muted" style="margin:0">No engine steps yet.</p>`}</div>
        <div class="sec"><p class="lbl">Scan details</p>
          <dl class="kv">
            <dt>Scan id</dt><dd class="mono">${short(s.id)}</dd>
            <dt>Files</dt><dd>${act.files?.length ?? "—"}</dd>
            <dt>Tokens in</dt><dd>${tokens[0].toLocaleString()}</dd>
            <dt>Tokens out</dt><dd>${tokens[1].toLocaleString()}</dd>
            <dt>Started</dt><dd>${esc(when(s.created_at))}</dd>
          </dl>
        </div>
      </div>
    </div>
  </div>`;
}

async function reportTab(el, s, cands) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const [details, engine] = await Promise.all([
    Promise.all([...cands].sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9)).map((c) => api(`/api/candidates/${encodeURIComponent(c.id)}`).catch(() => c))),
    api(`/api/scans/${encodeURIComponent(s.id)}/report`).catch(() => ({})),
  ]);
  const rows = details.map((c) => {
    const d = parse(c.data) ?? c.data ?? {};
    const fix = [...(c.attempts ?? [])].reverse().map((a) => ({ ...a, result: parse(a.result) })).find((a) => a.step === "fix" && a.result?.summary);
    return { c, d, fix: fix?.result?.summary, where: (d.evidence ?? []).map((e) => `${e.path}:${e.startLine}`).join(", "), human: (c.signoffs ?? []).at(-1)?.decision };
  });
  const proven = rows.filter(({ c }) => ["reproduced", "fix-verified", "fix-failed"].includes(c.status)).length;
  const fixed = rows.filter(({ c }) => c.status === "fix-verified").length;
  const md = [`# Bugclaw report: ${s.source}`, "", `Scan ${s.id}`, "", `${rows.length} findings, ${proven} proven in an OpenShell sandbox, ${fixed} fix verified. Human signoff is required before any finding is confirmed.`, ...(engine?.findings ?? []).map((finding) => finding.markdown)].join("\n\n");
  el.innerHTML = `<div class="card"><div class="hd"><h3>Bug report</h3><div style="display:flex;gap:10px;align-items:center"><span class="aside">${rows.length} findings · ${proven} proven · ${fixed} fix verified</span><button class="btn ghost" id="dl" style="height:32px">Download .md</button></div></div>
    ${rows.length ? rows.map(({ c, d, fix, where, human }) => `<div class="pad" style="border-top:1px solid var(--line)">
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">${pill(c.severity)}<a href="/candidates/${encodeURIComponent(c.id)}" data-link style="font:700 17px/1.25 var(--display);letter-spacing:-.02em;color:var(--ink);text-decoration:none">${esc(c.title)}</a></div>
      <dl class="kv wide" style="margin-top:12px"><dt>Where</dt><dd class="mono">${esc(where || "—")}</dd><dt>Validator</dt><dd>${pill(d.validation ?? d.status)}</dd><dt>Sandbox</dt><dd>${sandboxPill(c)}</dd><dt>Signoff</dt><dd>${human ? pill(human) : `<span class="pill plain">Waiting</span>`}</dd>
      <dt>Root cause</dt><dd class="clamp">${esc(d.rootCause ?? "—")}</dd>${fix ? `<dt>Fix</dt><dd class="clamp">${esc(fix)}</dd>` : ""}</dl></div>`).join("") : `<div class="empty"><b>No findings</b>The engine reported no candidates for this snapshot.</div>`}</div>
    ${engine?.markdown ? `<div class="card"><div class="hd"><h3>Engine notes</h3><button class="btn ghost" id="eng" style="height:32px">Show</button></div><div class="pad" id="engbody" hidden><pre style="max-height:420px"></pre></div></div>` : ""}`;
  document.getElementById("dl").addEventListener("click", () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" })); a.download = `bugclaw-report-${s.id.slice(0, 8)}.md`; a.click(); });
  const eng = document.getElementById("eng");
  if (eng) eng.addEventListener("click", () => { const b = document.getElementById("engbody"); b.hidden = !b.hidden; b.querySelector("pre").textContent = engine.markdown; eng.textContent = b.hidden ? "Show" : "Hide"; });
}

function activityTab(el, tasks, titles) {
  const types = [["all", "All"], ["recon", "Recon"], ["hunt", "Hunts"], ["validate", "Validation"], ["other", "Other"]];
  const typeOf = (t) => t.stage === "recon" || t.stage === "trace" ? "recon" : t.stage === "hunt" || t.stage === "gapfill" ? "hunt" : t.stage === "validate" ? "validate" : "other";
  let filter = "all", q = "", order = "new";
  el.innerHTML = `<div class="ph"><h2>Activity</h2><p>Every step the engine recorded · ${tasks.length} in total</p></div>
    <div class="bar"><div class="seg" id="types">${types.map(([k, l]) => `<button data-k="${k}" class="${k === "all" ? "on" : ""}">${l} <span class="c">${k === "all" ? tasks.length : tasks.filter((t) => typeOf(t) === k).length}</span></button>`).join("")}</div></div>
    <div class="bar"><label class="search">${I.search}<input id="q" placeholder="Search steps and results"></label><div class="seg" id="order"><button data-k="new" class="on">Newest first</button><button data-k="old">Oldest first</button></div></div>
    <div class="card" id="list"></div><p class="foot" id="count"></p>`;
  const draw = () => {
    let rows = tasks.map((t, i) => ({ ...t, i })).filter((t) => (filter === "all" || typeOf(t) === filter) && (!q || `${taskTitle(t, titles)} ${t.summary ?? ""} ${t.error ?? ""}`.toLowerCase().includes(q)));
    if (order === "new") rows = rows.reverse();
    document.getElementById("list").innerHTML = rows.length ? `<table><thead><tr><th style="width:60px">Step</th><th style="width:120px">Type</th><th>Entry</th><th style="width:120px">Status</th><th style="width:130px">Tokens</th></tr></thead><tbody>${rows.map((t) => `<tr><td class="mono muted">${t.i + 1}</td><td><span class="pill plain">${esc(words(typeOf(t) === "other" ? stageOf(t) : typeOf(t)))}</span></td><td><div style="font-weight:500">${esc(taskTitle(t, titles))}</div>${t.summary || t.error ? `<div class="muted" style="font-size:13.5px;margin-top:3px">${esc(t.error ? words(t.error) : t.summary)}</div>` : ""}${t.findings ? `<div class="mono" style="margin-top:6px">Led to ${t.findings} candidate${t.findings === 1 ? "" : "s"}</div>` : ""}${t.verdict ? `<div style="margin-top:6px">${pill(t.verdict)}</div>` : ""}</td><td>${taskPill(t.status)}</td><td class="mono muted">${t.inputTokens != null ? `${t.inputTokens.toLocaleString()} / ${(t.outputTokens ?? 0).toLocaleString()}` : "—"}</td></tr>`).join("")}</tbody></table>` : `<div class="empty"><b>No steps</b>${tasks.length ? "Nothing matches this filter." : "The engine has not recorded any steps yet."}</div>`;
    document.getElementById("count").textContent = `${rows.length} step${rows.length === 1 ? "" : "s"}`;
  };
  el.querySelectorAll("#types button").forEach((b) => b.addEventListener("click", () => { filter = b.dataset.k; el.querySelectorAll("#types button").forEach((x) => x.classList.toggle("on", x === b)); draw(); }));
  el.querySelectorAll("#order button").forEach((b) => b.addEventListener("click", () => { order = b.dataset.k; el.querySelectorAll("#order button").forEach((x) => x.classList.toggle("on", x === b)); draw(); }));
  document.getElementById("q").addEventListener("input", (e) => { q = e.target.value.toLowerCase(); draw(); });
  draw();
}

function explorationTab(el, s, tasks, checks, titles) {
  const recon = tasks.find((t) => t.id === "recon") ?? tasks.find((t) => t.stage === "recon");
  const vals = tasks.filter((t) => t.stage === "validate");
  const extra = tasks.filter((t) => t.stage === "feedback" || t.stage === "wishlist");
  const st = (t) => t.status === "done" ? "done" : t.status;
  const check = (t, kind) => `<div class="check"><span class="st ${st(t)}"></span>
      <div class="hd2"><span class="kind">${kind}</span>${taskPill(t.status)}${t.verdict ? pill(t.verdict) : ""}</div>
      <p class="ttl">${esc(taskTitle(t, titles))}</p>
      ${t.status === "failed" ? `<div class="result bad"><p class="lbl">Result</p><p>Step failed: ${esc(words(t.error ?? "unknown error"))}</p></div>` : t.summary && t.summary !== t.id ? `<div class="result"><p class="lbl">Result</p><p>${esc(t.summary)}</p></div>` : ""}
      ${t.findings ? `<ul class="sub-obs"><li>Led to ${t.findings} candidate${t.findings === 1 ? "" : "s"} for validation</li></ul>` : ""}
    </div>`;
  el.innerHTML = `<div class="card"><div class="hd"><h3>Exploration paths</h3><span class="aside">${checks.length} checks · ${vals.length} validations</span></div>
    <div class="tree">
      <div class="goal"><span class="pill ${tasks.some((t) => t.status === "running" || t.status === "pending") ? "a" : "g"} plain">Goal</span><div><div style="font-weight:500">Find exploitable vulnerabilities in ${esc(scanName(s.source))}, from source only</div>${recon?.summary ? `<div class="muted" style="margin-top:4px">${esc(recon.summary)}</div>` : ""}</div></div>
      ${checks.length ? checks.map((t) => check(t, "Check")).join("") : `<div class="empty"><b>No checks yet</b>Hunt lenses appear here once recon finishes.</div>`}
      ${vals.length ? `<p class="lbl" style="margin-top:28px">Validation</p>${vals.map((t) => check(t, "Validate")).join("")}` : ""}
      ${extra.length ? `<p class="lbl" style="margin-top:28px">What the engine learned</p>${extra.map((t) => check(t, t.stage === "wishlist" ? "Missing context" : "Feedback")).join("")}` : ""}
    </div></div>`;
}

function assetsTab(el, files, cands) {
  const cites = new Map();
  for (const c of cands) for (const e of (parse(c.data) ?? {}).evidence ?? []) cites.set(e.path, (cites.get(e.path) ?? 0) + 1);
  let filter = "all", q = "";
  el.innerHTML = `<div class="ph"><h2>Assets</h2><p>Every file in the private snapshot · ${files.length} in total</p></div>
    <div class="bar"><div class="seg"><button class="on">${I.file} Files <span class="c">${files.length}</span></button></div></div>
    <div class="bar"><label class="search">${I.search}<input id="q" placeholder="Search files by path"></label><div class="seg" id="f"><button data-k="all" class="on">All</button><button data-k="cited">Cited</button><button data-k="none">Not cited</button></div></div>
    <div class="card" id="list"></div><p class="foot" id="count"></p>`;
  const draw = () => {
    const rows = files.filter((f) => (filter === "all" || (filter === "cited") === cites.has(f.path)) && (!q || f.path.toLowerCase().includes(q)));
    document.getElementById("list").innerHTML = rows.length ? `<table><thead><tr><th>File</th><th style="width:190px">Findings</th><th style="width:170px">Source</th><th style="width:150px">SHA-256</th></tr></thead><tbody>${rows.map((f) => `<tr><td class="mono" style="font-size:13.5px;color:var(--ink)">${esc(f.path)}</td><td>${cites.has(f.path) ? `<span class="pill r">Cited by ${cites.get(f.path)}</span>` : `<span class="pill plain">None</span>`}</td><td><span class="pill plain">Snapshot</span></td><td class="mono muted" title="${esc(f.sha256)}">${esc(f.sha256.slice(0, 12))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty"><b>No files</b>${files.length ? "Nothing matches this filter." : "The snapshot has not been written yet."}</div>`;
    document.getElementById("count").textContent = `${rows.length} file${rows.length === 1 ? "" : "s"}`;
  };
  el.querySelectorAll("#f button").forEach((b) => b.addEventListener("click", () => { filter = b.dataset.k; el.querySelectorAll("#f button").forEach((x) => x.classList.toggle("on", x === b)); draw(); }));
  document.getElementById("q").addEventListener("input", (e) => { q = e.target.value.toLowerCase(); draw(); });
  draw();
}

async function findings() {
  const cands = await api("/api/candidates");
  view.innerHTML = top("Findings") + `<div class="body">
    <div class="ph"><h2>All findings</h2><p>Candidates from every scan · ${cands.length} in total</p></div>
    <div class="card">${candidateTable(cands, { showScan: true })}</div>
    <p class="foot">Validator verdicts are model opinions. Only the sandbox column reflects code that actually ran, and only a person can confirm a finding.</p></div>`;
}

async function candidate(id) {
  const c = await api(`/api/candidates/${encodeURIComponent(id)}`);
  const d = c.data ?? {};
  const attempts = (c.attempts ?? []).map((a) => ({ ...a, result: parse(a.result) }));
  const signoffs = c.signoffs ?? [];
  const human = signoffs.at(-1)?.decision;
  const last = (step, pred = () => true) => [...attempts].reverse().find((a) => a.step === step && pred(a));
  const poc = last("poc", (a) => a.result?.evidence);
  const judge = last("judge");
  const fix = last("fix");
  const proved = c.status === "reproduced" || c.status === "fix-verified" || c.status === "fix-failed";
  const stepState = [
    ["Found", pill(d.validation ?? d.status), d.validation === "supported" ? "Validator supports it" : d.validation === "rejected" ? "Validator rejected it" : "Waiting for validator"],
    ["Proved", proved ? `<span class="pill r">Vulnerable</span>` : sandboxStatus(c) === "not run" ? `<span class="pill plain">Not run</span>` : pill(c.status), proved ? "PoC broke it in the sandbox" : sandboxStatus(c) === "not run" ? "Run it in OpenShell" : "Sandbox could not prove it"],
    fix ? ["Fixed", c.status === "fix-verified" ? `<span class="pill g">Fix verified</span>` : c.status === "fix-failed" ? `<span class="pill r">Fix failed</span>` : pill(fix.result?.status), c.status === "fix-verified" ? "Same PoC passes after the fix" : c.status === "fix-failed" ? "PoC still breaks it" : "Fix attempt recorded"] : ["Reported", `<span class="pill plain">Report ready</span>`, "Download it for your fixing agent"],
    ["Signed off", human ? pill(human) : `<span class="pill plain">Waiting</span>`, human ? when(signoffs.at(-1).at) : "Only you can confirm it"],
  ];
  const runs = attempts.filter((a) => a.result?.evidence);
  const tab = new URLSearchParams(location.search).get("tab") ?? "summary";
  const tabs = [["summary", "Summary"], ["evidence", "Evidence", runs.length], ["source", "Source", (d.evidence ?? []).length], ["history", "History", attempts.length]];
  view.innerHTML = top(c.title, { back: { href: `/scans/${encodeURIComponent(c.scan_id)}/findings` }, extra: `${pill(c.severity)}<span class="src"></span><button class="btn ghost sm" id="report">Download report</button><button class="btn sm" id="repro">Run in OpenShell</button>` }) + `
  <div class="tabs">${tabs.map(([k, l, n]) => `<a href="?tab=${k}" data-tab="${k}" class="${tab === k ? "on" : ""}">${l}${n ? `<span class="n">${n}</span>` : ""}</a>`).join("")}</div>
  <div class="body">
    <div class="card verdict">${stepState.map(([label, p, note], i) => `<div><span class="no">0${i + 1}</span><b>${label}</b>${p}<p>${esc(note)}</p>${label === "Proved" && d.lastRun ? `<p>Latest run: ${esc(words(d.lastRun.status))}</p>` : ""}</div>`).join("")}</div>
    <p class="muted" id="repro-msg" style="margin:-8px 0 16px"></p>
    <div id="ctab"></div>
  </div>`;
  const el = document.getElementById("ctab");
  if (tab === "evidence") {
    el.innerHTML = runs.length ? `<div class="card"><div class="hd"><h3>Sandbox runs</h3><div class="seg" id="runsel">${[...runs].reverse().map((a, i) => `<button data-i="${i}" class="${i ? "" : "on"}">${esc(words(a.step))} · ${esc(words(a.result?.status))}</button>`).join("")}</div></div><div class="pad" id="evidence"></div></div>` : `<div class="card dashed"><div class="empty"><b>No sandbox runs yet</b>Use Run in OpenShell to generate and run a PoC.</div></div>`;
    const ordered = [...runs].reverse();
    el.querySelectorAll("#runsel button").forEach((b) => b.addEventListener("click", () => { el.querySelectorAll("#runsel button").forEach((x) => x.classList.toggle("on", x === b)); const a = ordered[Number(b.dataset.i)]; showEvidence(evidenceRel(a.result.evidence), a.step); }));
    if (ordered.length) showEvidence(evidenceRel(ordered[0].result.evidence), ordered[0].step);
  } else if (tab === "source") {
    el.innerHTML = `<div class="card"><div class="hd"><h3>Cited source</h3><span class="aside">Quoted from the private snapshot</span></div><div class="pad">${(d.evidence ?? []).map((e) => `<div class="cite"><div class="path">${esc(e.path)}:${e.startLine}–${e.endLine}</div><pre>${String(e.quote ?? "").split("\n").map((l, i) => `<span class="ln">${e.startLine + i}</span>${esc(l)}`).join("\n")}</pre></div>`).join("") || `<p class="muted" style="margin:0">No citations.</p>`}</div></div>`;
  } else if (tab === "history") {
    el.innerHTML = `<div class="card">${attempts.length ? `<table><thead><tr><th>When</th><th>Step</th><th>Result</th></tr></thead><tbody>${[...attempts].reverse().map((a) => `<tr title="${esc(a.result?.reason ?? a.result?.summary ?? "")}"><td class="muted">${esc(when(a.created_at))}</td><td>${esc(words(a.step))}</td><td>${pill(a.result?.status ?? a.result?.verdict ?? a.status)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty"><b>No runs yet</b>Nothing has been run for this finding.</div>`}</div><p class="foot">Hover a row to see the full reason.</p>`;
  } else {
    el.innerHTML = `<div class="grid2">
      <div class="card"><div class="hd"><h3>What's wrong</h3><span class="aside">${esc(words(d.attackClass))}</span></div>
        <div class="pad"><p class="clamp">${esc(d.rootCause)}</p>
          <dl class="kv wide" style="margin-top:16px"><dt>Who can trigger it</dt><dd class="clamp1">${esc(d.attacker)}</dd><dt>Where</dt><dd class="mono">${esc((d.evidence ?? []).map((e) => `${e.path}:${e.startLine}`).join(", "))}</dd>${fix?.result?.summary ? `<dt>Fix</dt><dd class="clamp1">${esc(fix.result.summary)}</dd>` : ""}</dl>
        </div></div>
      <div class="card"><div class="hd"><h3>Your signoff</h3></div>
        ${human ? `<div class="pad"><div style="display:flex;justify-content:space-between;gap:10px">${pill(human)}<span class="muted">${esc(when(signoffs.at(-1).at))}</span></div><p class="clamp" style="margin:12px 0 0">${esc(signoffs.at(-1).note)}</p></div>` : ""}
        <form id="signoff" class="pad" style="display:grid;gap:10px${human ? ";border-top:1px solid var(--line)" : ""}">
          <select name="decision" required><option value="">Decision…</option><option value="confirmed">Confirm: real vulnerability</option><option value="rejected">Reject: not a vulnerability</option></select>
          <textarea name="note" required placeholder="What you checked"></textarea>
          <div style="display:flex;gap:10px;align-items:center"><button class="btn ghost" type="submit">Record signoff</button><span class="error" id="signoff-error"></span></div>
        </form>
      </div></div>`;
    document.getElementById("signoff").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        await api(`/api/candidates/${encodeURIComponent(id)}/signoff`, { method: "POST", body: JSON.stringify({ decision: f.get("decision"), note: f.get("note") }) });
        render();
      } catch (err) { document.getElementById("signoff-error").textContent = err.message; }
    });
  }
  view.querySelectorAll(".tabs a[data-tab]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); history.pushState(null, "", `${location.pathname}?tab=${a.dataset.tab}`); render(); }));
  document.getElementById("report").addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const report = await api(`/api/candidates/${encodeURIComponent(id)}/report`);
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([report.markdown], { type: "text/markdown" }));
      a.download = `bugclaw-${id.slice(0, 8)}.md`;
      a.click();
    } finally { e.target.disabled = false; }
  });
  document.getElementById("repro").addEventListener("click", async (e) => {
    e.target.disabled = true;
    const msg = document.getElementById("repro-msg");
    try {
      await api(`/api/candidates/${encodeURIComponent(id)}/reproduce`, { method: "POST" });
      msg.textContent = "Running: Nemotron is writing a PoC for a fresh sandbox…";
      const before = attempts.length;
      timers.push(setInterval(async () => {
        const next = await api(`/api/candidates/${encodeURIComponent(id)}`).catch(() => null);
        if (next && next.attempts.length > before) render();
      }, 4000));
    } catch (err) { msg.textContent = err.message; e.target.disabled = false; }
  });
}

async function showEvidence(rel, step) {
  const box = document.getElementById("evidence");
  if (!box || !rel) return;
  const get = (name) => api(`/api/evidence/${encodeURIComponent(`${rel}/${name}`)}`).then((r) => r.content).catch(() => null);
  const command = parse(await get("command.json"));
  const pocFiles = Array.isArray(command) ? command.filter((a) => String(a).startsWith(".bugclaw/")) : [];
  const result = parse(await get("result.json")) ?? {};
  const names = [...pocFiles, "stdout.txt", "stderr.txt", ...(step === "fix" ? ["fix.diff"] : []), "replay.sh"];
  const loaded = (await Promise.all(names.map(async (n) => [n, await get(n)]))).filter(([, v]) => v !== null && v !== "");
  const label = (n) => ({ "stdout.txt": "Output", "stderr.txt": "Errors", "fix.diff": "Fix", "replay.sh": "Replay" })[n] ?? `PoC · ${n.split("/").at(-1)}`;
  box.innerHTML = `<div class="runfacts"><span>Exit code <b>${esc(result.exitCode ?? "—")}</b></span><span>Result ${pill(result.classification)}</span><span>Network <b>blocked</b></span></div>
    <div class="files">${loaded.map(([n], i) => `<button data-i="${i}">${esc(label(n))}</button>`).join("")}</div><pre id="ev-body"></pre>`;
  const body = document.getElementById("ev-body");
  const show = (i) => { body.textContent = loaded[i][1]; box.querySelectorAll(".files button").forEach((b) => b.classList.toggle("on", Number(b.dataset.i) === i)); };
  box.querySelectorAll(".files button").forEach((b) => b.addEventListener("click", () => show(Number(b.dataset.i))));
  if (loaded.length) show(0); else body.textContent = "Evidence files are not readable.";
}

async function setup() {
  const h = await health();
  view.innerHTML = top("Setup") + `<div class="body">
    <div class="ph"><h2>Runtime</h2><p>Bugclaw needs a Nebius Token Factory key and a running OpenShell gateway. Nothing ever runs on the host.</p></div>
    <div class="card">${runtimeTable(h)}</div>
    <div class="grid2" style="grid-template-columns:1fr 1fr">
      <div class="card"><div class="hd"><h3>Environment</h3></div><div class="pad"><dl class="kv wide">
        <dt class="mono">NEBIUS_API_KEY</dt><dd>Required. Token Factory → API keys.</dd>
        <dt class="mono">NEBIUS_BASE_URL</dt><dd>Optional. Default <span class="mono">https://api.tokenfactory.nebius.com/v1</span></dd>
        <dt class="mono">BUGCLAW_DATA</dt><dd>Optional. Default <span class="mono">./data</span>, private (0700)</dd>
      </dl></div></div>
      <div class="card"><div class="hd"><h3>Agents (MCP)</h3></div><div class="pad"><dl class="kv wide">
        <dt>Endpoint</dt><dd class="mono">${esc(location.origin)}/mcp</dd>
        <dt>Tools</dt><dd class="mono">bugclaw_scan, bugclaw_status, bugclaw_candidates, bugclaw_reproduce, bugclaw_evidence</dd>
        <dt>Signoff</dt><dd>Human-only, from this dashboard or the HTTP API. Not exposed to agents.</dd>
      </dl></div></div>
    </div></div>`;
}

health().catch(() => { document.getElementById("rail-health").innerHTML = "<b>Runtime</b>Unknown"; });
render();
