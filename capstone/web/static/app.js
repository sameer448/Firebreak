// SOC -> IR Agent Console. Vanilla JS, no build step.
// Alert content is attacker-controlled: every dynamic value goes through esc() before it is
// placed in HTML (the SecureBot lesson, OWASP LLM05 - Improper Output Handling).
"use strict";

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pill = (v, cls) => `<span class="pill ${esc(cls || v)}">${esc(v)}</span>`;
const short = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + "…" : s || "");
const time = (iso) => (iso ? iso.replace("T", " ").replace("Z", "") : "");

async function api(path, opts) {
  const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts));
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || res.statusText);
  return body;
}

function toast(msg, err) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (err ? " err" : "");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add("hidden"), 3500);
}

function table(cols, rows, onClick) {
  if (!rows.length) return '<p class="muted">Nothing here yet.</p>';
  const head = cols.map((c) => `<th>${esc(c[0])}</th>`).join("");
  const body = rows.map((r, i) =>
    `<tr class="${onClick ? "click" : ""}" data-i="${i}">${cols.map((c) => `<td class="${c[2] || ""}">${c[1](r)}</td>`).join("")}</tr>`
  ).join("");
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function bindRows(container, rows, onClick) {
  container.querySelectorAll("tr.click").forEach((tr) =>
    tr.addEventListener("click", () => onClick(rows[+tr.dataset.i])));
}

// ------------------------------------------------------------------ navigation
const loaders = {};
function show(view) {
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + view));
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
  location.hash = view;
  if (loaders[view]) loaders[view]();
}
document.querySelectorAll("nav a").forEach((a) => a.addEventListener("click", () => show(a.dataset.view)));
document.querySelectorAll("[data-goto]").forEach((a) => a.addEventListener("click", () => show(a.dataset.goto)));

// ------------------------------------------------------------------ health + badge
async function refreshHealth() {
  try {
    const h = await api("/api/health");
    const mark = (ok) => (ok ? '<span class="ok">●</span>' : '<span class="bad">●</span>');
    $("#health").innerHTML =
      `${mark(h.ollama)} Ollama<br>` +
      Object.entries(h.models).map(([m, ok]) => `${mark(ok)} ${esc(m)}`).join("<br>") +
      `<br>${mark(h.indexes.triage && h.indexes.ir)} vector indexes<br>queue: ${h.queue_depth}`;
    const s = await api("/api/stats");
    const b = $("#badge-approvals");
    b.textContent = s.pending_approvals;
    b.classList.toggle("hidden", !s.pending_approvals);
  } catch (e) {
    $("#health").innerHTML = '<span class="bad">●</span> console API unreachable';
  }
}

// ------------------------------------------------------------------ overview
const DISP_COLORS = { CLOSE: "var(--close)", ASK_HUMAN: "var(--human)", ESCALATE: "var(--esc)" };
const SEV_COLORS = { SEV1: "var(--sev1)", SEV2: "var(--sev2)", SEV3: "var(--sev3)", SEV4: "var(--sev4)" };

function bars(data, colors) {
  const max = Math.max(1, ...Object.values(data));
  return Object.keys(colors).map((k) =>
    `<div class="bar"><div class="name">${esc(k)}</div><div class="track"><div class="fill" style="width:${
      ((data[k] || 0) / max) * 100}%;background:${colors[k]}"></div></div><div class="val">${data[k] || 0}</div></div>`
  ).join("");
}

loaders.overview = async () => {
  const s = await api("/api/stats");
  const cards = [["Alerts processed", s.alerts], ["Auto-closed", s.dispositions.CLOSE || 0],
    ["Sent to a human", s.dispositions.ASK_HUMAN || 0], ["Escalated", s.dispositions.ESCALATE || 0],
    ["Incidents", s.incidents], ["Pending approvals", s.pending_approvals],
    ["Guardrail hits", s.guardrail_hits], ["Deduplicated", s.merged]];
  $("#stat-cards").innerHTML = cards.map(([l, n]) =>
    `<div class="card"><div class="num">${esc(n)}</div><div class="lbl">${esc(l)}</div></div>`).join("");
  $("#disp-bars").innerHTML = bars(s.dispositions, DISP_COLORS);
  $("#sev-bars").innerHTML = bars(s.severity, SEV_COLORS);
  const jobs = await api("/api/jobs");
  $("#jobs-table").innerHTML = table([
    ["Job", (j) => `<span class="mono">${esc(j.job_id)}</span>`], ["Alert", (j) => esc(j.label)],
    ["Status", (j) => pill(j.status)],
    ["Result", (j) => (j.result ? pill(j.result.disposition) + " " + esc(j.result.incident_id || j.result.escalation_id || "") : esc(j.error))],
    ["Submitted", (j) => esc(time(j.created))]], jobs);
};

$("#btn-run-demo").addEventListener("click", async () => {
  const demos = await api("/api/demo-alerts");
  if (!demos.length) return toast("This org pack has no samples/ to run", true);
  for (const d of demos) await api("/api/alerts", { method: "POST", body: JSON.stringify({ text: d.text, label: d.name, source: d.source }) });
  toast(`Queued ${demos.length} demo alerts. Each takes 1-3 minutes; watch the jobs table.`);
  loaders.overview();
});

$("#btn-reset").addEventListener("click", async () => {
  if (!confirm("Clear all alerts, incidents, approvals and the audit log?")) return;
  try { await api("/api/reset", { method: "POST" }); toast("State cleared"); loaders.overview(); refreshHealth(); }
  catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ triage
let demoCache = [];
loaders.triage = async () => {
  if (!demoCache.length) demoCache = await api("/api/demo-alerts");
  $("#demo-list").innerHTML = demoCache.map((d, i) => `<button data-i="${i}">${esc(d.name.replace(".txt", ""))}</button>`).join("");
  $("#demo-list").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    const d = demoCache[+b.dataset.i];
    $("#alert-text").value = d.text;
    $("#alert-label").value = d.name;
    $("#alert-source").value = d.source;
  }));
};

const STEPS = [["ALERT", "Normalize"], ["SOC agent", "SOC triage"], ["GUARDRAIL", "Guardrails"],
  ["DISPOSITION", "Disposition"], ["ESCALATION", "Escalation"], ["IR agent", "IR agent"], ["AUTO", "Auto actions"],
  ["GATED", "Approval gate"]];

function renderFlow(lines, result) {
  const text = lines.join("\n");
  $("#flow").innerHTML = STEPS.map(([key, name]) => {
    let cls = text.includes(key) ? "on" : "";
    if (key === "DISPOSITION" && result) cls += " " + result.disposition;
    if (key === "ESCALATION" && text.includes("DEDUP")) { cls = "on"; name = "Dedup merge"; }
    return `<div class="step ${cls}">${esc(name)}</div>`;
  }).join("");
}

async function pollJob(id) {
  const job = await api("/api/jobs/" + id);
  $("#trace").textContent = job.lines.join("\n") || (job.status === "queued" ? "Queued behind other alerts…" : "Starting…");
  $("#trace").scrollTop = $("#trace").scrollHeight;
  $("#job-status").outerHTML = `<span id="job-status" class="pill ${esc(job.status)}">${esc(job.status)}</span>`;
  renderFlow(job.lines, job.result);
  if (job.status === "queued" || job.status === "running") return setTimeout(() => pollJob(id), 1500);
  $("#btn-submit").disabled = false;
  if (job.result) {
    const r = job.result;
    $("#job-links").innerHTML = `<p>Result: ${pill(r.disposition)} ` +
      `<a data-alert="${esc(r.alert_id)}">view alert</a>` +
      (r.incident_id ? ` · <a data-incident="${esc(r.incident_id)}">view incident ${esc(r.incident_id)}</a>` : "") + "</p>";
    bindLinks($("#job-links"));
  }
  refreshHealth();
}

$("#btn-submit").addEventListener("click", async () => {
  const text = $("#alert-text").value.trim();
  if (!text) return toast("Paste or pick an alert first", true);
  $("#btn-submit").disabled = true;
  $("#job-links").innerHTML = "";
  try {
    const { job_id } = await api("/api/alerts", { method: "POST",
      body: JSON.stringify({ text, label: $("#alert-label").value || "pasted alert", source: $("#alert-source").value }) });
    pollJob(job_id);
  } catch (e) { toast(e.message, true); $("#btn-submit").disabled = false; }
});

function bindLinks(root) {
  root.querySelectorAll("[data-alert]").forEach((a) => a.addEventListener("click", () => { show("alerts"); openAlert(a.dataset.alert); }));
  root.querySelectorAll("[data-incident]").forEach((a) => a.addEventListener("click", () => { show("incidents"); openIncident(a.dataset.incident); }));
}

// ------------------------------------------------------------------ alerts
loaders.alerts = async () => {
  const rows = await api("/api/alerts");
  const el = $("#alerts-table");
  el.innerHTML = table([
    ["Processed", (r) => esc(time(r.processed_at))], ["Alert", (r) => esc(r.label)],
    ["Detection / host", (r) => `${esc(r.detection)}<br><span class="muted">${esc(r.host)} · ${esc(r.user)}</span>`, "wrap"],
    ["Model verdict", (r) => `${esc(r.verdict)}<br><span class="muted">${esc(r.confidence_label)} confidence</span>`],
    ["Guardrails", (r) => r.guardrails.map((g) => pill(g, "guard")).join(" ")],
    ["Disposition", (r) => pill(r.disposition) + (r.merged ? " " + pill("dedup") : "")],
    ["Incident", (r) => esc(r.incident_id || "")]], rows, true);
  bindRows(el, rows, (r) => openAlert(r.alert_id));
};

async function openAlert(id) {
  const a = await api("/api/alerts/" + encodeURIComponent(id));
  const t = a.triage;
  const d = $("#alert-detail");
  d.classList.remove("hidden");
  d.innerHTML = `
    <h2>${esc(a.label)} ${pill(a.disposition)} <span class="muted mono">${esc(a.alert_id)}</span></h2>
    <div class="grid2">
      <div>
        <h3>Why this disposition</h3><p>${esc(a.rationale)}</p>
        ${a.guardrails.map((g) => `<div class="guard-box"><b>${esc(g.rule)}</b> → ${esc(g.effect)}<br>${esc(g.reason)}</div>`).join("")}
        <h3>SOC agent (fine-tuned model)</h3>
        <div class="kv">
          <div>Verdict</div><div>${esc(t.verdict)} (${esc(t.confidence_label)})</div>
          <div>Model severity</div><div>${esc(t.model_severity)}</div>
          <div>ATT&amp;CK</div><div>${esc(t.attack_techniques.join(", "))}</div>
          <div>Summary</div><div>${esc(t.summary)}</div>
          <div>Retrieved docs</div><div>${esc(a.retrieved.join(", "))}</div>
          <div>Escalation</div><div>${esc(a.escalation_id || "-")}${a.merged ? " (deduplicated into existing)" : ""}</div>
          <div>Incident</div><div>${a.incident_id ? `<a data-incident="${esc(a.incident_id)}">${esc(a.incident_id)}</a>` : "-"}</div>
        </div>
        <h3>Key evidence</h3><ul>${t.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>
      </div>
      <div>
        <h3>Raw alert (untrusted input)</h3><div class="box">${esc(a.alert.raw)}</div>
        <h3>Model answer</h3><div class="box">${esc(a.raw_answer)}</div>
      </div>
    </div>`;
  bindLinks(d);
  d.scrollIntoView({ behavior: "smooth" });
}

// ------------------------------------------------------------------ incidents
loaders.incidents = async () => {
  const rows = await api("/api/incidents");
  const el = $("#incidents-table");
  el.innerHTML = table([
    ["Incident", (r) => `<span class="mono">${esc(r.incident_id)}</span>`], ["Severity", (r) => pill(r.severity)],
    ["Hosts", (r) => esc(r.hosts.join(", "))], ["Techniques", (r) => esc(r.attack_techniques.join(", "))],
    ["Playbook", (r) => esc(r.playbook_id)], ["Summary", (r) => esc(short(r.summary, 160)), "wrap"],
    ["Pending", (r) => (r.pending_approvals ? pill(r.pending_approvals + " pending", "pending") : "")]], rows, true);
  bindRows(el, rows, (r) => openIncident(r.incident_id));
};

async function openIncident(id) {
  const i = await api("/api/incidents/" + encodeURIComponent(id));
  const sd = i.severity_detail, b = sd.breakdown, f = i.facts;
  const term = (name, x) => `<div class="term">${esc(name)}<b>${esc(x.points)}</b><span class="muted">${esc(x.value)}</span></div>`;
  const d = $("#incident-detail");
  d.classList.remove("hidden");
  d.innerHTML = `
    <h2>${esc(i.incident_id)} ${pill(i.severity)} <span class="muted">${esc(i.hosts.join(", "))}</span></h2>
    <p>${esc(f.incident_summary)}</p>
    <div class="grid2">
      <div>
        <h3>Severity (IR-SEV-01 rubric, computed in code)</h3>
        <div class="sevcalc">${term("asset", b.asset_criticality)}<span>+</span>${term("impact", b.impact)}<span>+</span>${term("scope", b.scope)}<span>=</span><div class="term">score<b>${esc(sd.score)}</b></div><span>→</span>${pill(i.severity)}</div>
        <ul>${sd.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
        <h3>Facts extracted by the IR agent (llama3.1:8b)</h3>
        <div class="kv">
          <div>Incident?</div><div>${esc(f.is_incident)}${i.forced_by_guardrail ? " (guardrail forced)" : ""}</div>
          <div>Impact</div><div>${esc(f.impact)}${f.impact_llm ? ` <span class="muted">(model said ${esc(f.impact_llm)}; raised by code: ${esc((f.impact_floor_reasons || []).join("; "))})</span>` : ""}</div>
          <div>Scope</div><div>${esc(f.scope)}</div>
          <div>Data exfiltration</div><div>${esc(f.data_exfiltration)}</div>
          <div>Tier-0 involved</div><div>${esc(f.tier0_involved)}</div>
          <div>Playbook</div><div>${esc(i.playbook_id)}</div>
          <div>SLA</div><div>${esc(i.sla)}</div>
          <div>Sources</div><div>${esc(i.sources.join(", "))}</div>
        </div>
        <h3>IR rationale</h3><p>${esc(f.rationale)}</p>
      </div>
      <div>
        <h3>Action plan</h3>
        ${table([["Action", (a) => `<span class="mono">${esc(a.action_id)}</span><br>${esc(a.type)}`],
          ["Target", (a) => esc(a.target)], ["Mode", (a) => (a.gated ? pill("human-gated", "pending") : pill("auto", "executed"))],
          ["Status", (a) => pill(a.status) + (a.by ? `<br><span class="muted">${esc(a.by)}</span>` : "")],
          ["Intent", (a) => esc(a.intent || a.reason), "wrap"]], i.actions)}
        <h3>Escalation package ${esc(i.escalation_id)}</h3>
        <div class="box">${esc(JSON.stringify(i.escalation, null, 2))}</div>
      </div>
    </div>
    <h3>Timeline</h3>
    ${table([["Time", (e) => esc(time(e.ts))], ["Actor", (e) => esc(e.actor)], ["Event", (e) => esc(e.event)],
      ["Subject", (e) => esc(e.subject)], ["Rationale", (e) => esc(short(e.rationale, 220)), "wrap"]], i.timeline)}`;
  d.scrollIntoView({ behavior: "smooth" });
}

// ------------------------------------------------------------------ approvals
$("#approver").value = localStorage.getItem("approver") || "";
$("#approver").addEventListener("change", () => localStorage.setItem("approver", $("#approver").value.trim()));
$("#approval-filter").addEventListener("change", () => loaders.approvals());

loaders.approvals = async () => {
  const items = await api("/api/approvals?status=" + $("#approval-filter").value);
  const el = $("#approvals-list");
  if (!items.length) { el.innerHTML = '<div class="panel"><p class="muted">No actions waiting for approval.</p></div>'; return; }
  el.innerHTML = items.map((a) => `
    <div class="approval ${esc(a.status)}">
      <div>
        <div class="title">${esc(a.type.replace(/_/g, " "))} → ${esc(a.target)} ${pill(a.status)}</div>
        <div class="muted mono">${esc(a.action_id)} · ${a.incident_id ? `<a data-incident="${esc(a.incident_id)}">${esc(a.incident_id)}</a>` : esc(a.escalation_id)} · queued ${esc(time(a.queued_at))}</div>
        <div>Why: ${esc(a.reason)}</div>
        <div class="muted">${esc(short(a.payload, 260))}</div>
        ${a.resolved_by ? `<div class="muted">${esc(a.status)} by ${esc(a.resolved_by)} at ${esc(time(a.resolved_at))}${a.note ? " - " + esc(a.note) : ""}</div>` : ""}
      </div>
      ${a.status === "pending" ? `<div class="act">
        <button class="btn ok small" data-approve="${esc(a.action_id)}">Approve</button>
        <button class="btn no small" data-deny="${esc(a.action_id)}">Deny</button></div>` : ""}
    </div>`).join("");
  bindLinks(el);
  const decide = async (id, verb) => {
    const by = $("#approver").value.trim();
    if (!by) { $("#approver").focus(); return toast("Enter your name: every approval is attributed", true); }
    localStorage.setItem("approver", by);
    try {
      const r = await api(`/api/approvals/${encodeURIComponent(id)}/${verb}`, { method: "POST", body: JSON.stringify({ by, note: "" }) });
      toast(verb === "approve" ? "Approved: " + (r.intent || id) : "Denied " + id);
      loaders.approvals(); refreshHealth();
    } catch (e) { toast(e.message, true); }
  };
  el.querySelectorAll("[data-approve]").forEach((b) => b.addEventListener("click", () => decide(b.dataset.approve, "approve")));
  el.querySelectorAll("[data-deny]").forEach((b) => b.addEventListener("click", () => decide(b.dataset.deny, "deny")));
};

// ------------------------------------------------------------------ audit
loaders.audit = async () => {
  const rows = await api("/api/audit?limit=300");
  $("#audit-table").innerHTML = table([
    ["Time", (e) => esc(time(e.ts))], ["Actor", (e) => esc(e.actor)], ["Event", (e) => esc(e.event)],
    ["Subject", (e) => `<span class="mono">${esc(e.subject)}</span>`],
    ["Rationale", (e) => esc(short(e.rationale, 260)) + (e.intent ? `<br><span class="muted">${esc(e.intent)}</span>` : ""), "wrap"]], rows);
};

// ------------------------------------------------------------------ eval
const pct = (a, b) => (b ? `${a}/${b} (${Math.round((100 * a) / b)}%)` : "-");
loaders.eval = async () => {
  const r = await api("/api/eval");
  const el = $("#eval-body");
  if (!r.available) {
    el.innerHTML = '<div class="panel"><p>No cached results yet. Run <code>python -m capstone.eval_disposition --data data/test.jsonl</code> (about 1-2 min per alert).</p></div>';
    return;
  }
  el.innerHTML = `
    <div class="panel"><h2>Policies on the same ${esc(r.n)} model answers</h2>
    ${table([["Policy", (p) => esc(p.policy) + (p.default ? " " + pill("default", "guard") : "")], ["Close threshold", (p) => esc(p.threshold)],
      ["Disposition accuracy", (p) => esc(pct(p.ok, p.n))], ["TPs escalated", (p) => esc(pct(p.tp_esc, p.tp))],
      ["TPs auto-closed", (p) => (p.tp_closed ? pill(pct(p.tp_closed, p.tp), "ESCALATE") : pill(pct(0, p.tp), "CLOSE"))],
      ["Benign auto-closed", (p) => esc(pct(p.benign_closed, p.benign))], ["Human load", (p) => esc(pct(p.human, p.n))]], r.policies)}
    <p class="muted">TPs auto-closed is the unacceptable error and must be zero. Benign auto-closed is the analyst time the agent saves.</p></div>
    <div class="panel"><h2>Per-alert results (default policy)</h2>
    ${table([["Scenario", (x) => esc(x.scenario)], ["Label", (x) => esc(x.label)], ["Model", (x) => `${esc(x.verdict)} (${esc(x.confidence)})`],
      ["Expected", (x) => pill(x.expected)], ["Got", (x) => pill(x.disposition)], ["", (x) => (x.correct ? "✓" : "✗")],
      ["Guardrails", (x) => esc(x.guardrails)], ["Rationale", (x) => esc(short(x.rationale, 160)), "wrap"]], r.rows)}</div>`;
};

// ------------------------------------------------------------------ organization
const whenText = (w) => Object.entries(w || {}).map(([k, v]) => `${k.replace(/_/g, " ")}: ${Array.isArray(v) ? v.join(", ") : v}`).join(" AND ");
const GATED_ACTIONS = ["page_oncall", "add_stakeholder", "notify_external"];

async function loadOrgChip() {
  const o = await api("/api/org");
  $("#org-chip").innerHTML = `<span class="muted">org pack</span><b>${esc(o.name)}</b>`;
  $("#org-chip").onclick = () => show("org");
  $("#alert-source").innerHTML = o.ingest.sources.map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
  return o;
}

loaders.org = async () => {
  const o = await api("/api/org");
  const origin = location.origin;
  const v = o.validation;
  const counts = ["error", "warning", "ok"].map((l) => `${v.filter((x) => x.level === l).length} ${l}`).join(" · ");
  $("#org-body").innerHTML = `
    <div class="panel"><h2>${esc(o.name)} <span class="muted mono">${esc(o.id)}</span></h2>
      <div class="kv">
        <div>Pack folder</div><div class="mono">${esc(o.dir)}</div>
        <div>Auto-close threshold</div><div>${esc(o.disposition.close_threshold)} (benign verdicts at or above this confidence close automatically)</div>
        <div>Severity levels</div><div>${Object.entries(o.severity.levels).map(([k, n]) => `${pill(k)} score ≥ ${esc(n)}`).join(" ")} ${pill("SEV4")} below</div>
        <div>Validation</div><div>${esc(counts)}</div>
      </div></div>

    <div class="panel"><h2>Alert sources and webhook</h2>
      <p class="muted">Alerting systems POST vendor JSON to the webhook with the <code>X-API-Key</code> header (key: ${esc(o.ingest.key_source)}). Each source's mapping file translates vendor fields into the canonical alert, which is rebuilt into the layout the triage model was trained on. Retries with the same vendor alert id are ignored.</p>
      ${table([["Source", (s) => `<b>${esc(s[0])}</b>`], ["Type", (s) => esc(s[1].type)], ["Description", (s) => esc(s[1].description), "wrap"],
        ["Endpoint", (s) => `<span class="mono">POST ${esc(origin)}/api/ingest/${esc(s[0])}</span>`]], Object.entries(o.sources))}
      <h3>Example</h3><div class="box">curl -X POST ${esc(origin)}/api/ingest/${esc(o.ingest.sources[0] || "<source>")} \\
  -H "Content-Type: application/json" -H "X-API-Key: $KEY" \\
  -d @orgs/${esc(o.id)}/samples/&lt;payload&gt;.json</div></div>

    <div class="panel"><h2>Escalation policy</h2>
      <p class="muted">Actions that reach a person or leave the security team are always human-gated; the engine enforces this whatever the policy says.</p>
      ${table([["Rule", (r) => `<span class="mono">${esc(r.id)}</span>`], ["Action", (r) => esc(r.action)], ["Target", (r) => esc(r.target || "(incident)")],
        ["When", (r) => esc(whenText(r.when)), "wrap"],
        ["Mode", (r) => (GATED_ACTIONS.includes(r.action) || r.mode === "gated" ? pill("human-gated", "pending") : pill("auto", "executed"))],
        ["Reason", (r) => esc(r.reason), "wrap"]], o.escalation_policy)}</div>

    <div class="grid2">
      <div class="panel"><h2>Asset criticality rules</h2>
        ${table([["Match", (r) => esc(Object.entries(r).filter(([k]) => !["level", "tier0"].includes(k)).map(([k, v]) => `${k}: ${[].concat(v).join(", ")}`).join("; ")), "wrap"],
          ["Level", (r) => esc(r.level) + (r.tier0 ? " " + pill("Tier-0", "ESCALATE") : "")]], o.assets.rules || [])}
        <p class="muted">No match → ${esc(o.assets.default || "medium")}. First matching rule wins.</p></div>
      <div class="panel"><h2>Identity</h2>
        <div class="kv">
          <div>Roster</div><div class="mono">${esc(o.identity.roster_file || "none")}</div>
          <div>Privileged prefixes</div><div>${esc((o.identity.privileged_prefixes || []).join(", "))}</div>
          <div>Tier-0 accounts</div><div>${esc((o.identity.tier0_accounts || []).join(", "))}</div>
        </div>
        <h2 style="margin-top:16px">Actuators</h2>
        <div class="kv">${["chat", "pager", "case"].map((c) => `<div>${c}</div><div>${esc((o.actuators[c] || { type: "mock" }).type)}${
          (o.actuators[c] || {}).url_env || (o.actuators[c] || {}).routing_key_env ? ` <span class="muted">($${esc((o.actuators[c].url_env || o.actuators[c].routing_key_env))})</span>` : ""}</div>`).join("")}</div>
      </div>
    </div>

    <div class="grid2">
      <div class="panel"><h2>Knowledge (triage index)</h2><ul>${o.knowledge.triage.map((f) => `<li class="mono">${esc(f)}</li>`).join("")}</ul></div>
      <div class="panel"><h2>Knowledge (IR index)</h2><ul>${o.knowledge.ir.map((f) => `<li class="mono">${esc(f)}</li>`).join("")}</ul></div>
    </div>

    <div class="panel"><h2>Validation</h2>
      ${table([["Level", (x) => `<span class="lvl-${esc(x.level)}">${esc(x.level.toUpperCase())}</span>`], ["Area", (x) => esc(x.area)],
        ["Finding", (x) => esc(x.message), "wrap"]], v)}</div>`;
};

// ------------------------------------------------------------------ boot
loadOrgChip().catch(() => {});
refreshHealth();
setInterval(refreshHealth, 8000);
setInterval(() => { if ($("#view-overview").classList.contains("active")) loaders.overview(); }, 8000);
show((location.hash || "#overview").slice(1));
