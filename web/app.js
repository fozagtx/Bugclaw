const view = document.getElementById("view");
const shell = document.getElementById("shell");
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const parse = (v) => { if (typeof v !== "string") return v; try { return JSON.parse(v); } catch { return v; } };
const short = (id) => esc(String(id ?? "").slice(0, 8));
const when = (iso) => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "";
const tag = (s) => s ? `<span class="tag ${esc(String(s).toLowerCase())}">${esc(s)}</span>` : `<span class="muted">—</span>`;
const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
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

const collapsed = localStorage.getItem("bugclaw.rail") === "collapsed";
shell.classList.toggle("collapsed", collapsed);
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

function cleanup() {
  timers.forEach(clearInterval); timers = [];
  streams.forEach((s) => s.close()); streams = [];
}

async function render() {
  cleanup();
  const path = location.pathname.replace(/\/+$/, "") || "/";
  const parts = path.split("/").filter(Boolean);
  const section = parts[0] ?? "overview";
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === section));
  try {
    if (path === "/") await overview();
    else if (path === "/scans") await scans();
    else if (parts[0] === "scans" && parts[1]) await scanDetail(decodeURIComponent(parts[1]));
    else if (path === "/candidates") await findings();
    else if (parts[0] === "candidates" && parts[1]) await candidate(decodeURIComponent(parts[1]));
    else if (path === "/setup") await setup();
    else view.innerHTML = `<p class="eyebrow">404</p><h1>Page not found</h1>`;
  } catch (err) {
    view.innerHTML = `<p class="eyebrow">Error</p><h1>Couldn't load this page</h1><p class="error">${esc(err.message)}</p>`;
  }
  view.focus({ preventScroll: true });
}

async function health() {
  const h = await api("/api/health");
  const ok = h.nebius.keyPresent && h.nebius.modelsAvailable && h.openshell && h.docker && h.engine;
  document.getElementById("rail-health").innerHTML = ok ? `${tag("up")} Runtime ready` : `${tag("down")} Runtime not ready`;
  return h;
}

function scanRows(list) {
  if (!list.length) return `<div class="empty"><b>No scans yet.</b>Start one from Scans with a local path or a public git URL and an authorization reference.</div>`;
  return `<table><thead><tr><th>Scan</th><th>Source</th><th>Status</th><th>Findings</th><th>Started</th></tr></thead><tbody>${list.map((s) => `
    <tr data-href="/scans/${encodeURIComponent(s.id)}"><td class="mono">${short(s.id)}</td><td class="mono">${esc(s.source)}</td><td>${tag(s.status)}</td><td class="mono">${s.candidateCount ?? "—"}</td><td class="muted">${when(s.created_at)}</td></tr>`).join("")}</tbody></table>`;
}

function candidateRows(list, { showScan } = {}) {
  if (!list.length) return `<div class="empty"><b>No findings.</b>The engine reported no candidates for this scope.</div>`;
  const sorted = [...list].sort((a, b) => (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
  return `<table><thead><tr><th>Severity</th><th>Finding</th><th>Validator</th><th>Sandbox</th>${showScan ? "<th>Scan</th>" : ""}</tr></thead><tbody>${sorted.map((c) => {
    const d = parse(c.data) ?? {};
    return `<tr data-href="/candidates/${encodeURIComponent(c.id)}"><td>${tag(c.severity)}</td><td class="title">${esc(c.title)}<div class="muted mono">${esc((d.evidence ?? []).map((e) => `${e.path}:${e.startLine}`).join("  "))}</div></td><td>${tag(d.validation ?? d.status)}</td><td>${tag(sandboxStatus(c))}</td>${showScan ? `<td class="mono">${short(c.scan_id)}</td>` : ""}</tr>`;
  }).join("")}</tbody></table>`;
}

const ENGINE = new Set(["unvalidated", "rejected", "needs-reproduction", "validated", "candidate"]);
function sandboxStatus(c) { return ENGINE.has(c.status) ? "not run" : c.status; }

async function overview() {
  const [h, list, cands] = await Promise.all([health(), api("/api/scans"), api("/api/candidates")]);
  const cs = cands.map((c) => ({ ...c, s: sandboxStatus(c) }));
  const count = (f) => cs.filter(f).length;
  view.innerHTML = `
    <p class="eyebrow"><b>01</b> Overview</p>
    <h1>Source-only discovery, sandboxed proof, human signoff.</h1>
    <p class="lede">Nemotron on Nebius Token Factory reads an authorized snapshot. Every candidate is tested in an OpenShell sandbox with egress denied. Nothing is confirmed until a person signs it off.</p>
    <div class="stats" style="margin-top:36px">
      <div class="stat"><div class="k">Scans</div><div class="v">${list.length}</div></div>
      <div class="stat"><div class="k">Candidates</div><div class="v">${cs.length}</div></div>
      <div class="stat"><div class="k">Reproduced</div><div class="v">${count((c) => ["reproduced", "fix-verified", "fix-failed"].includes(c.s))}<small>${count((c) => c.s === "fix-verified")} fix-verified</small></div></div>
      <div class="stat"><div class="k">Sandboxed, not reproduced</div><div class="v">${count((c) => c.s === "not-reproduced")}</div></div>
    </div>
    <h2>Runtime <span>${h.nebius.keyPresent && h.openshell ? "" : "action needed"}</span></h2>
    ${runtimeTable(h)}
    <h2>Recent scans <span>${list.length}</span></h2>
    ${scanRows(list.slice(0, 6))}`;
}

function runtimeTable(h) {
  const rows = [
    ["Nebius Token Factory", h.nebius.keyPresent && h.nebius.modelsAvailable, h.nebius.keyPresent ? (h.nebius.modelError ?? "Models reachable") : "NEBIUS_API_KEY is not set"],
    ["OpenShell gateway", h.openshell, h.openshell ? "Connected" : "Run: openshell gateway start"],
    ["Docker", h.docker, h.docker ? "Daemon reachable" : "Docker daemon not reachable"],
    ["Runner image", h.runnerImage, h.runnerImage ? "Built" : "Built on first reproduction"],
    ["Discovery engine", h.engine, h.engine ? "engine/ present" : "engine/ missing"],
  ];
  return `<table><tbody>${rows.map(([k, ok, note]) => `<tr><td style="width:240px">${esc(k)}</td><td style="width:120px">${tag(ok ? "up" : "down")}</td><td class="muted">${esc(note)}</td></tr>`).join("")}</tbody></table>`;
}

async function scans() {
  const list = await api("/api/scans");
  view.innerHTML = `
    <p class="eyebrow"><b>02</b> Scans</p>
    <h1>Scans</h1>
    <p class="lede">Each scan snapshots the source, hashes every file, and runs recon, hunt and validation on Nemotron.</p>
    <h2>New scan</h2>
    <form class="form" id="new-scan">
      <label for="source">Source<small>Local directory or credential-free git URL</small></label>
      <div class="field"><input id="source" name="source" required placeholder="/path/to/repo or https://github.com/org/repo"></div>
      <label for="authorization">Authorization<small>Who allowed this review and where it is recorded</small></label>
      <div class="field"><input id="authorization" name="authorization" required placeholder="e.g. Owner approval, ticket SEC-142"></div>
      <label for="files">Files<small>Optional, comma-separated</small></label>
      <div class="field"><input id="files" name="files" placeholder="src/login.js, src/api.js"></div>
      <label for="domains">Domains</label>
      <div class="field"><select id="domains" name="domains"><option value="web2">web2</option><option value="web3">web3</option><option value="web2,web3">web2 + web3</option></select></div>
      <div class="actions row"><button class="btn" type="submit">Start scan</button><span class="error" id="scan-error"></span></div>
    </form>
    <h2>All scans <span>${list.length}</span></h2>
    ${scanRows(list)}`;
  document.getElementById("new-scan").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const split = (v) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);
    const btn = e.target.querySelector("button");
    btn.disabled = true;
    try {
      const body = { source: f.get("source"), authorization: f.get("authorization"), domains: split(f.get("domains")) };
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

async function scanDetail(id) {
  const s = await api(`/api/scans/${encodeURIComponent(id)}`);
  const report = parse(s.report);
  const live = ["queued", "running"].includes(s.status);
  view.innerHTML = `
    <p class="eyebrow"><a href="/scans" data-link>Scans</a> / <span class="mono">${short(s.id)}</span></p>
    <h1>${esc(s.source)}</h1>
    <div class="row">${tag(s.status)}<span class="muted">${when(s.created_at)}</span></div>
    <h2>Scope</h2>
    <dl class="kv">
      <dt>Scan id</dt><dd class="mono">${esc(s.id)}</dd>
      <dt>Authorization</dt><dd>${esc(s.authorization)}</dd>
      <dt>Snapshot hash</dt><dd class="mono">${esc(s.snapshot_hash ?? "pending")}</dd>
      ${report?.models ? `<dt>Models</dt><dd class="mono">${Object.entries(report.models).map(([k, m]) => `${esc(k)}: ${esc(m.id)}`).join("<br>")}</dd>` : ""}
    </dl>
    ${live ? `<h2>Live events</h2><div class="log" id="log">Waiting for engine events…</div>` : ""}
    <h2>Findings <span>${(s.candidates ?? []).length}</span></h2>
    ${live && !(s.candidates ?? []).length ? `<div class="empty"><b>Scan in progress.</b>Findings appear here when the engine finishes.</div>` : candidateRows(s.candidates ?? [])}`;
  if (live) {
    const log = document.getElementById("log");
    const es = new EventSource(`/api/scans/${encodeURIComponent(id)}/events`);
    streams.push(es);
    let first = true;
    es.onmessage = (m) => {
      const ev = parse(m.data);
      if (first) { log.textContent = ""; first = false; }
      log.insertAdjacentHTML("beforeend", `<div>${esc(new Date().toLocaleTimeString())}  ${esc(ev.type ?? "event")}  ${esc(ev.message ?? ev.stage ?? "")}</div>`);
      log.scrollTop = log.scrollHeight;
      if (ev.type === "complete" || ev.type === "error") setTimeout(render, 800);
    };
    timers.push(setInterval(async () => {
      const next = await api(`/api/scans/${encodeURIComponent(id)}`).catch(() => null);
      if (next && !["queued", "running"].includes(next.status)) render();
    }, 5000));
  }
}

async function findings() {
  const cands = await api("/api/candidates");
  view.innerHTML = `
    <p class="eyebrow"><b>03</b> Findings</p>
    <h1>Findings</h1>
    <p class="lede">Candidates from every scan. Validator verdicts are model opinions; the sandbox column is what actually ran.</p>
    <h2>All candidates <span>${cands.length}</span></h2>
    ${candidateRows(cands, { showScan: true })}`;
}

async function candidate(id) {
  const c = await api(`/api/candidates/${encodeURIComponent(id)}`);
  const d = c.data ?? {};
  const attempts = (c.attempts ?? []).map((a) => ({ ...a, result: parse(a.result) }));
  const signoffs = c.signoffs ?? [];
  const runs = attempts.filter((a) => a.result?.evidence);
  view.innerHTML = `
    <p class="eyebrow"><a href="/scans/${encodeURIComponent(c.scan_id)}" data-link>Scan ${short(c.scan_id)}</a> / Finding</p>
    <h1>${esc(c.title)}</h1>
    <div class="row">${tag(c.severity)}<span class="muted">Validator</span>${tag(d.validation ?? d.status)}<span class="muted">Sandbox</span>${tag(sandboxStatus(c))}${signoffs.length ? `<span class="muted">Human</span>${tag(signoffs.at(-1).decision)}` : ""}</div>
    ${d.validation === "rejected" && sandboxStatus(c) === "not run" ? `<div class="notice">The validator rejected this candidate. Validators can be wrong, so Bugclaw still lets you test it in the sandbox.</div>` : ""}
    <div class="split">
      <div>
        <h2>Claim</h2>
        <dl class="kv">
          <dt>Attacker</dt><dd>${esc(d.attacker)}</dd>
          <dt>Root cause</dt><dd>${esc(d.rootCause)}</dd>
          <dt>Impact</dt><dd>${esc(d.impact)}</dd>
          <dt>Trust boundary</dt><dd>${esc(d.trustBoundary)}</dd>
          <dt>Class</dt><dd>${esc(d.attackClass)}</dd>
        </dl>
      </div>
      <div>
        <h2>Cited source <span>${(d.evidence ?? []).length}</span></h2>
        ${(d.evidence ?? []).map((e) => `<div class="cite"><div class="path">${esc(e.path)}:${e.startLine}–${e.endLine}</div><pre>${String(e.quote ?? "").split("\n").map((l, i) => `<span class="ln">${e.startLine + i}</span>${esc(l)}`).join("\n")}</pre></div>`).join("")}
      </div>
    </div>
    <h2>Sandbox reproduction <span>${attempts.length} attempts</span></h2>
    <div class="row" style="padding:16px 0"><button class="btn" id="repro">Run in OpenShell</button><span class="muted" id="repro-msg">Egress denied. The generated PoC runs only inside a fresh sandbox, then a fix is tested against the same PoC.</span></div>
    <div class="split">
      <ul class="timeline">${attempts.length ? [...attempts].reverse().map((a) => {
        const reason = a.result?.reason ?? a.result?.summary ?? "";
        const rel = a.result?.evidence ? evidenceRel(a.result.evidence) : null;
        return `<li${rel ? ` data-ev="${esc(rel)}"` : ""}><span class="muted mono">${esc(when(a.created_at))}</span><span class="mono">${esc(a.step)}</span><span>${tag(a.result?.status ?? a.result?.verdict ?? a.status)}${reason ? `<span class="reason" title="${esc(reason)}">${esc(reason)}</span>` : ""}</span><span class="mono muted">${rel ? "view" : ""}</span></li>`;
      }).join("") : `<li><span class="muted">No sandbox runs yet.</span></li>`}</ul>
      <div id="evidence"><div class="empty"><b>No evidence selected.</b>Pick a sandbox run to see its PoC, output and replay script.</div></div>
    </div>
    <h2>Human signoff</h2>
    <div class="split">
      <form id="signoff" style="padding-top:16px;display:grid;gap:10px">
        <select name="decision" required><option value="">Decision…</option><option value="confirmed">Confirm: this is a real vulnerability</option><option value="rejected">Reject: not a vulnerability</option></select>
        <textarea name="note" required placeholder="Why — reference the evidence you checked"></textarea>
        <div class="row"><button class="btn ghost" type="submit">Record signoff</button><span class="error" id="signoff-error"></span></div>
      </form>
      <div>${signoffs.length ? signoffs.map((s) => `<div class="row" style="padding:12px 0;border-bottom:1px solid var(--line)">${tag(s.decision)}<span>${esc(s.note)}</span><span class="muted">${when(s.at)}</span></div>`).join("") : `<div class="empty"><b>Not signed off.</b>Only a person can confirm a finding. Agents cannot.</div>`}</div>
    </div>
    </div>`;
  view.querySelectorAll("li[data-ev]").forEach((li) => li.addEventListener("click", () => { view.querySelectorAll("li[data-ev]").forEach((x) => x.classList.toggle("on", x === li)); showEvidence(li.dataset.ev); }));
  if (runs.length) view.querySelector("li[data-ev]")?.click();
  document.getElementById("repro").addEventListener("click", async (e) => {
    e.target.disabled = true;
    const msg = document.getElementById("repro-msg");
    try {
      await api(`/api/candidates/${encodeURIComponent(id)}/reproduce`, { method: "POST" });
      msg.textContent = "Queued. Generating a PoC with Nemotron and running it in a fresh sandbox…";
      const before = attempts.length;
      timers.push(setInterval(async () => {
        const next = await api(`/api/candidates/${encodeURIComponent(id)}`).catch(() => null);
        if (next && next.attempts.length > before) render();
      }, 4000));
    } catch (err) { msg.textContent = err.message; e.target.disabled = false; }
  });
  document.getElementById("signoff").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api(`/api/candidates/${encodeURIComponent(id)}/signoff`, { method: "POST", body: JSON.stringify({ decision: f.get("decision"), note: f.get("note") }) });
      render();
    } catch (err) { document.getElementById("signoff-error").textContent = err.message; }
  });
}

async function showEvidence(rel) {
  const box = document.getElementById("evidence");
  if (!box || !rel) return;
  const get = (name) => api(`/api/evidence/${encodeURIComponent(`${rel}/${name}`)}`).then((r) => r.content).catch(() => null);
  const command = parse(await get("command.json"));
  const pocFiles = Array.isArray(command) ? command.filter((a) => String(a).startsWith(".bugclaw/")) : [];
  const names = ["result.json", "stdout.txt", "stderr.txt", ...pocFiles, "fix.diff", "meta.json", "replay.sh"];
  const loaded = (await Promise.all(names.map(async (n) => [n, await get(n)]))).filter(([, v]) => v !== null && v !== "");
  box.innerHTML = `<div class="files">${loaded.map(([n], i) => `<button data-i="${i}" class="${i ? "" : "on"}">${esc(n.split("/").at(-1))}</button>`).join("")}</div><pre id="ev-body"></pre><p class="muted mono" style="margin-top:8px">${esc(rel)}</p>`;
  const body = document.getElementById("ev-body");
  const show = (i) => { body.textContent = loaded[i][1]; box.querySelectorAll(".files button").forEach((b) => b.classList.toggle("on", Number(b.dataset.i) === i)); };
  box.querySelectorAll(".files button").forEach((b) => b.addEventListener("click", () => show(Number(b.dataset.i))));
  if (loaded.length) show(0); else body.textContent = "Evidence files are not readable.";
}

async function setup() {
  const h = await health();
  view.innerHTML = `
    <p class="eyebrow"><b>04</b> Setup</p>
    <h1>Setup</h1>
    <p class="lede">Bugclaw needs a Nebius Token Factory key and a running OpenShell gateway. Nothing ever runs on the host.</p>
    <h2>Runtime</h2>
    ${runtimeTable(h)}
    <h2>Environment</h2>
    <dl class="kv">
      <dt>NEBIUS_API_KEY</dt><dd>Required. Token Factory → API keys.</dd>
      <dt>NEBIUS_BASE_URL</dt><dd class="mono">Optional. Default https://api.tokenfactory.nebius.com/v1</dd>
      <dt>BUGCLAW_DATA</dt><dd class="mono">Optional. Default ./data (private, 0700)</dd>
    </dl>
    <h2>Agents</h2>
    <dl class="kv">
      <dt>MCP endpoint</dt><dd class="mono">${esc(location.origin)}/mcp</dd>
      <dt>Tools</dt><dd class="mono">bugclaw_scan, bugclaw_status, bugclaw_candidates, bugclaw_reproduce, bugclaw_evidence</dd>
      <dt>Signoff</dt><dd>Human-only, from this dashboard or the HTTP API. Not exposed to agents.</dd>
    </dl>`;
}

health().catch(() => { document.getElementById("rail-health").textContent = "Runtime unknown"; });
render();
