const $ = selector => document.querySelector(selector);
let fleet = null;
let connectors = {};
let busy = false;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"
  })[char]);
}

function humanize(value) {
  return String(value ?? "").replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());
}

function shortId(value, width = 36) {
  const text = String(value ?? "");
  return text.length > width ? `${text.slice(0, 16)}…${text.slice(-12)}` : text;
}

function tenant() {
  return $("#tenant").value.trim();
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 4300);
}

function setBusy(value) {
  busy = value;
  document.querySelectorAll("button").forEach(button => button.disabled = value);
}

async function request(path, options = {}) {
  const response = await fetch(path, options);
  let document = {};
  try { document = await response.json(); } catch (_) { /* server returned no JSON */ }
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Session expired");
  }
  if (!response.ok) throw new Error(document.error || `Request failed (${response.status})`);
  return document;
}

async function post(path, body) {
  return request(path, {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(body),
  });
}

function validationSummary(item) {
  const counts = item.validation_counts || {};
  if (counts.confirmed) return ["good", `${counts.confirmed} confirmed`, "Live configuration confirms the finding"];
  if (counts.not_confirmed) return ["good", `${counts.not_confirmed} not confirmed`, "Live configuration no longer reproduces it"];
  if (counts.unavailable) return ["bad", "Evidence unavailable", "The case failed closed"];
  if (counts.unsupported) return ["bad", "Unsupported", "No deterministic evaluator exists"];
  if (item.unsupported_findings) return ["bad", "Unsupported control", "No validation capability is registered"];
  return ["warn", "Awaiting validation", "No live cloud request has been made"];
}

function schedulingSummary(item) {
  const status = item.scheduling_status || "not_schedulable";
  const collision = status === "window_conflict";
  const tone = collision || status === "blocked" ? "bad" : status === "scheduled" ? "good" : "warn";
  return [tone, humanize(status), (item.scheduling_reasons || [])[0] || "No scheduling signal"];
}

function canValidate(item) {
  const ready = connectors[item.provider]?.ready_for_live_validation;
  return item.state === "prioritized" && item.supported_findings > 0 &&
    item.unsupported_findings === 0 && ready;
}

function renderFleet(document) {
  fleet = document;
  const summary = document.summary;
  $("#metric-cases").textContent = summary.total_cases;
  $("#metric-findings").textContent = summary.total_findings;
  $("#metric-supported").textContent = `${summary.supported_findings} supported · ${summary.unsupported_findings} unsupported`;
  $("#case-count").textContent = `${summary.total_cases} case${summary.total_cases === 1 ? "" : "s"}`;
  const stateText = Object.entries(summary.case_state_counts).map(([key, value]) => `${value} ${humanize(key)}`).join(" · ");
  $("#metric-states").textContent = stateText || "No cases";
  const validated = document.cases.reduce((total, item) => total + Object.values(item.validation_counts || {}).reduce((a,b) => a+b, 0), 0);
  $("#metric-validated").textContent = validated;
  const highest = document.cases[0];
  $("#metric-risk").textContent = highest ? Math.round(highest.risk_score) : "—";
  $("#metric-urgency").textContent = highest ? `${humanize(highest.urgency)} · ${highest.provider.toUpperCase()}` : "Not assessed";
  $("#mission").textContent = summary.total_cases ? `${summary.total_cases} cases ranked for ${document.tenant_id}` : `${document.tenant_id} is ready for intake`;
  $("#mission-detail").textContent = summary.total_cases ? "Validate supported findings to separate confirmed risk from stale scanner state." : "Import an AWS Security Hub or OCSF export to build the portfolio.";

  if (!document.cases.length) {
    $("#fleet-body").innerHTML = '<tr><td colspan="6" class="empty">No findings have been ingested for this tenant.</td></tr>';
    return;
  }
  $("#fleet-body").innerHTML = document.cases.map(item => {
    const [validationTone, validationLabel, validationReason] = validationSummary(item);
    const [scheduleTone, scheduleLabel, scheduleReason] = schedulingSummary(item);
    const title = item.finding_titles.find(Boolean) || item.rule_ids[0] || "Untitled finding";
    const rank = item.portfolio_rank ? `#${item.portfolio_rank}` : "—";
    return `<tr>
      <td><span class="risk">${escapeHtml(Math.round(item.risk_score))}</span><span class="urgency">${escapeHtml(item.urgency)} · ${rank}</span></td>
      <td><span class="title">${escapeHtml(title)}</span><span class="asset" title="${escapeHtml(item.resource_uids[0])}">${escapeHtml(shortId(item.resource_uids[0]))}</span></td>
      <td><span class="provider">${escapeHtml(item.provider)}</span><span class="state">${escapeHtml(humanize(item.state))}</span></td>
      <td><span class="status ${validationTone}"><i></i>${escapeHtml(validationLabel)}</span><span class="reason">${escapeHtml(validationReason)}</span></td>
      <td><span class="status ${scheduleTone}"><i></i>${escapeHtml(scheduleLabel)}</span><span class="reason">${escapeHtml(scheduleReason)}</span></td>
      <td><div class="row-actions">${canValidate(item) ? `<button class="primary small" data-validate="${escapeHtml(item.case_id)}">Validate live</button>` : ""}<button class="ghost small" data-case="${escapeHtml(item.case_id)}">Inspect</button></div></td>
    </tr>`;
  }).join("");
}

function renderConnectors(document) {
  connectors = document;
  $("#connectors").innerHTML = Object.values(document).map(item => {
    const ready = item.ready_for_live_validation;
    const explanation = ready ? "Ready for bounded live configuration reads." :
      item.executable_available ? `Missing ${item.missing_environment.length} scanner credential value(s).` : `${item.executable || "Cloud"} CLI is unavailable.`;
    return `<article class="connector"><header><strong>${escapeHtml(item.provider)}</strong><span class="${ready ? "ready" : "not-ready"}">${ready ? "● READY" : "○ OFFLINE"}</span></header><p>${escapeHtml(explanation)}</p><code>${escapeHtml(item.supported_rule_ids.join(" · ") || "No registered controls")}</code></article>`;
  }).join("");
  if (fleet) renderFleet(fleet);
}

async function loadConnectors() {
  renderConnectors(await request("/api/connectors"));
}

async function loadFleet() {
  const selected = tenant();
  if (!selected) throw new Error("Enter a customer tenant identifier");
  try { window.localStorage.setItem("elcapitan-shadow-tenant", selected); } catch (_) { /* optional */ }
  renderFleet(await request(`/api/fleet?tenant=${encodeURIComponent(selected)}`));
}

function fact(label, value) {
  return `<div class="fact"><span>${escapeHtml(label)}</span><span>${escapeHtml(value ?? "—")}</span></div>`;
}

function renderRecords(records) {
  if (!records.length) return '<p class="empty compact">No validation product records yet.</p>';
  return records.map(record => {
    const findings = record.body?.findings || [];
    const decision = findings.map(item => `${humanize(item.status)}: ${item.reason}`).join(" · ") || "Evidence record captured";
    return `<div class="record"><strong>${escapeHtml(record.record_type)}</strong><p>${escapeHtml(decision)}</p><code>${escapeHtml(shortId(record.record_id))} · ${escapeHtml(record.created_at)}</code></div>`;
  }).join("");
}

async function openCase(caseId) {
  const detail = await request(`/api/cases/${encodeURIComponent(caseId)}?tenant=${encodeURIComponent(tenant())}`);
  const item = fleet?.cases.find(candidate => candidate.case_id === caseId);
  const caseDoc = detail.case;
  const finding = detail.findings[0] || {};
  const ocsf = finding.record?.ocsf || {};
  const [tone, validation] = validationSummary(item || {validation_counts:{}, unsupported_findings:0});
  const safety = detail.safety_boundary;
  const promotion = detail.promotion || {};
  $("#detail-content").innerHTML = `
    <div class="detail-hero"><div><span class="status ${tone}"><i></i>${escapeHtml(validation)}</span><h2>${escapeHtml(ocsf.title || item?.finding_titles?.[0] || "Remediation case")}</h2></div><div class="detail-meta"><strong>${escapeHtml(Math.round(caseDoc.priority?.score || 0))}</strong><span>${escapeHtml(humanize(caseDoc.priority?.urgency || "unassessed"))} risk</span></div></div>
    <div class="detail-actions">${item && canValidate(item) ? `<button class="primary" data-validate="${escapeHtml(caseId)}">Validate against live ${escapeHtml(item.provider.toUpperCase())}</button>` : ""}<span class="pill">${escapeHtml(humanize(caseDoc.state))}</span></div>
    <div class="detail-grid">
      <section class="detail-section"><h3>Case identity</h3>${fact("Case", caseDoc.case_id)}${fact("Tenant", caseDoc.tenant_id)}${fact("Provider", finding.provider)}${fact("Account", finding.account)}${fact("Service", (caseDoc.service_ids || []).join(", ") || "Unmapped")}</section>
      <section class="detail-section"><h3>Control & target</h3>${fact("Rule", ocsf.rule_id)}${fact("Resource", finding.resource_uid)}${fact("Severity", ocsf.severity)}${fact("Findings", caseDoc.finding_ids.length)}</section>
      <section class="detail-section"><h3>Risk rationale</h3>${(caseDoc.priority?.factors || []).map(value => `<div class="record"><p>${escapeHtml(value)}</p></div>`).join("") || '<p class="empty compact">Not assessed.</p>'}</section>
      <section class="detail-section"><h3>Shadow safety boundary</h3>${fact("Live validation", safety.mode === "shadow" ? "Allowed" : "Unknown")}${fact("External models", safety.external_models ? "Allowed" : "Disabled")}${fact("Approval", safety.approval ? "Allowed" : "Unavailable")}${fact("Scheduling", safety.scheduling ? "Allowed" : "Unavailable")}${fact("Execution", safety.execution ? "Allowed" : "Unavailable")}</section>
      <section class="detail-section full"><h3>Pre-approval promotion</h3>${fact("Status", humanize(promotion.status))}${fact("Promotion token", shortId(promotion.promotion_token, 48))}${fact("Confirmed controls", (promotion.confirmed_rule_ids || []).join(", ") || "None")}${(promotion.blockers || []).map(value => `<div class="record"><p>${escapeHtml(value)}</p></div>`).join("")}${promotion.eligible ? (promotion.required_inputs || []).map(value => `<div class="record"><p>${escapeHtml(value)}</p></div>`).join("") : ""}</section>
      <section class="detail-section full"><h3>Evidence & decision records</h3>${renderRecords(detail.records)}</section>
      <section class="detail-section full"><h3>Immutable case timeline</h3>${detail.events.map(event => `<div class="record"><strong>${escapeHtml(humanize(event.transition))}</strong><p>${escapeHtml(humanize(event.from_state))} → ${escapeHtml(humanize(event.to_state))} · ${escapeHtml(event.actor)}</p><code>${escapeHtml(event.occurred_at)} · ${escapeHtml(shortId(event.event_id))}</code></div>`).join("")}</section>
    </div>`;
  $("#detail-dialog").showModal();
}

async function validateCase(caseId) {
  setBusy(true);
  try {
    const result = await post("/api/validate", {tenant_id:tenant(), case_id:caseId});
    renderFleet(result.fleet);
    showToast(`Live validation completed: ${humanize(result.case.state)}`);
    if ($("#detail-dialog").open) await openCase(caseId);
  } finally { setBusy(false); }
}

async function validateEligible() {
  const caseIds = (fleet?.cases || []).filter(canValidate).map(item => item.case_id);
  if (!caseIds.length) throw new Error("No cases currently have a ready connector and supported live evaluator");
  if (caseIds.length > 100) throw new Error("Select at most 100 cases per validation batch");
  setBusy(true);
  try {
    const result = await post("/api/validate-batch", {tenant_id:tenant(), case_ids:caseIds});
    renderFleet(result.fleet);
    showToast(`${result.processed} case(s) validated against live cloud configuration`);
  } finally { setBusy(false); }
}

function parsedFindings() {
  let document;
  try { document = JSON.parse($("#finding-json").value); }
  catch (_) { throw new Error("Finding input is not valid JSON"); }
  if (Array.isArray(document)) return document;
  if (document && Array.isArray(document.Findings)) return document.Findings;
  if (document && typeof document === "object") return [document];
  throw new Error("Finding input must be an object or array");
}

async function submitIntake(event) {
  event.preventDefault();
  const services = $("#service-ids").value.split(",").map(value => value.trim()).filter(Boolean);
  setBusy(true);
  try {
    const result = await post("/api/intake", {
      tenant_id:tenant(), findings:parsedFindings(), identity:"authenticated-shadow-upload",
      context:{
        asset_criticality:Number($("#asset-criticality").value),
        exploit_probability:Number($("#exploit-probability").value),
        reachable:$("#reachable").checked,
        service_ids:services,
      },
    });
    renderFleet(result.fleet);
    $("#intake-dialog").close();
    showToast(`${result.received} finding(s) accepted · ${result.created_cases} new case(s) · ${result.duplicates} duplicate(s)`);
  } finally { setBusy(false); }
}

function loadSample() {
  const id = globalThis.crypto?.randomUUID?.() || String(Date.now());
  const resource = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/customer-shadow/providers/Microsoft.Storage/storageAccounts/shadowdemo123";
  $("#finding-json").value = JSON.stringify({
    class_uid:2004,severity:"High",time_dt:new Date().toISOString(),
    metadata:{version:"1.5.0",event_code:"storage_account_public_network_access_disabled",product:{name:"Customer scanner",version:"1"}},
    cloud:{provider:"azure",region:"westus2",account:{uid:"00000000-0000-0000-0000-000000000000"}},
    finding_info:{uid:`shadow-sample-${id}`,title:"Storage public network access is enabled",analytic:{uid:"storage_account_public_network_access_disabled"}},
    resources:[{uid:resource,type:"microsoft.storage/storageaccounts",name:"shadowdemo123"}],
    status_code:"FAIL",unmapped:{categories:["internet-exposed"]},
  }, null, 2);
  $("#file-label").textContent = "Safe synthetic Azure sample loaded";
}

document.addEventListener("click", async event => {
  try {
    const close = event.target.closest("[data-close]")?.dataset.close;
    if (close) { $("#" + close).close(); return; }
    const caseId = event.target.closest("[data-case]")?.dataset.case;
    if (caseId) { await openCase(caseId); return; }
    const validateId = event.target.closest("[data-validate]")?.dataset.validate;
    if (validateId) { await validateCase(validateId); return; }
    if (event.target.closest("#open-intake")) { $("#intake-dialog").showModal(); return; }
    if (event.target.closest("#load-sample")) { loadSample(); return; }
    if (event.target.closest("#validate-eligible")) { await validateEligible(); return; }
    if (event.target.closest("#load-fleet") || event.target.closest("#refresh")) {
      setBusy(true); try { await loadFleet(); } finally { setBusy(false); }
    }
  } catch (error) { showToast(error.message, true); setBusy(false); }
});

$("#finding-file").addEventListener("change", async event => {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 10 * 1024 * 1024) { showToast("File exceeds the 10 MiB request limit", true); return; }
  $("#finding-json").value = await file.text();
  $("#file-label").textContent = `${file.name} · ${Math.ceil(file.size / 1024)} KiB`;
});

$("#intake-form").addEventListener("submit", event => submitIntake(event).catch(error => { showToast(error.message, true); setBusy(false); }));
$("#tenant").addEventListener("keydown", event => { if (event.key === "Enter") $("#load-fleet").click(); });

async function start() {
  try {
    const saved = window.localStorage.getItem("elcapitan-shadow-tenant");
    if (saved) $("#tenant").value = saved;
  } catch (_) { /* optional */ }
  try {
    await loadConnectors();
    await loadFleet();
  } catch (error) { showToast(error.message, true); }
}

start();
