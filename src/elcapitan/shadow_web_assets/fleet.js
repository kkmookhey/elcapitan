const $ = selector => document.querySelector(selector);
let fleet = null;
let connectors = {};
let busy = false;

const controlTitles = {
  storage_account_public_network_access_disabled: "Storage public network access must be disabled",
  storage_blob_public_access_level_is_disabled: "Anonymous blob access must be disabled",
  storage_blob_versioning_is_enabled: "Blob versioning must be enabled",
  sqlserver_tde_encrypted_with_cmk: "SQL Server must use CMK-backed TDE for every user database",
  s3_bucket_object_versioning: "S3 object versioning must be enabled",
};

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

function controlTitle(ruleId, sourceTitle) {
  return controlTitles[ruleId] || sourceTitle || ruleId || "Untitled finding";
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
  if (counts.not_confirmed) return ["good", `${counts.not_confirmed} cleared`, "Live configuration no longer reproduces the scanner finding"];
  if (counts.unavailable) return ["bad", "Evidence unavailable", "The case failed closed"];
  if (counts.unsupported) return ["bad", "Unsupported", "No deterministic evaluator exists"];
  if (item.unsupported_findings) return ["bad", "Unsupported control", "No validation capability is registered"];
  return ["warn", "Awaiting validation", "No live cloud request has been made"];
}

function evidenceGrade(value) {
  return ({
    e2e_measured:"E2E measured",
    contract_tested_export_observed:"Contract tested + export observed",
    contract_tested:"Contract tested",
    export_observed:"Export observed",
    unverified:"Unverified",
  })[value] || "Unverified";
}

function capabilitySummary(item) {
  const capabilities = item.capabilities || [];
  if (!capabilities.length) return "Validation 0 · planning 0 · execution 0 · evidence unverified";
  const grades = [...new Set(capabilities.map(value => evidenceGrade(value.evidence_grade)))];
  return `Validation ${capabilities.length} · planning ${capabilities.filter(value => value.remediation_planning).length} · execution ${capabilities.filter(value => value.live_execution).length} · evidence ${grades.join(" / ")}`;
}

function schedulingSummary(item) {
  const status = item.scheduling_status || "not_schedulable";
  const collision = status === "window_conflict" || status === "candidate_window_conflict";
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
  const validationOutcomes = document.cases.reduce((totals, item) => {
    Object.entries(item.validation_counts || {}).forEach(([status, count]) => {
      totals[status] = (totals[status] || 0) + count;
    });
    return totals;
  }, {});
  const validatedCases = document.cases.filter(item => {
    const counts = item.validation_counts || {};
    return (counts.confirmed || counts.not_confirmed) &&
      !(counts.unavailable || counts.unsupported);
  }).length;
  $("#metric-validated").textContent = validatedCases;
  const outcomeText = Object.entries(validationOutcomes).map(([status, count]) => `${count} ${humanize(status)}`).join(" · ");
  $("#metric-validation-detail").textContent = outcomeText || "No live evidence outcomes";
  const highest = document.cases[0];
  $("#metric-risk").textContent = highest ? Math.round(highest.risk_score) : "—";
  $("#metric-urgency").textContent = highest ? `${humanize(highest.urgency)} · ${highest.provider.toUpperCase()}` : "Not assessed";
  const caseWord = summary.total_cases === 1 ? "case" : "cases";
  $("#mission").textContent = summary.total_cases ? `${summary.total_cases} ${caseWord} tracked for ${document.tenant_id}` : `${document.tenant_id} is ready for intake`;
  $("#mission-detail").textContent = summary.total_cases ? "Validate supported findings to separate confirmed risk from stale scanner state." : "Import an AWS Security Hub or OCSF export to build the portfolio.";

  if (!document.cases.length) {
    $("#fleet-body").innerHTML = '<tr><td colspan="6" class="empty">No findings have been ingested for this tenant.</td></tr>';
    return;
  }
  $("#fleet-body").innerHTML = document.cases.map(item => {
    const [validationTone, validationLabel, validationReason] = validationSummary(item);
    const [scheduleTone, scheduleLabel, scheduleReason] = schedulingSummary(item);
    const title = controlTitle(item.rule_ids[0], item.finding_titles.find(Boolean));
    const rank = item.portfolio_rank ? `#${item.portfolio_rank}` : "—";
    return `<tr>
      <td><span class="risk">${escapeHtml(Math.round(item.risk_score))}</span><span class="urgency">${escapeHtml(item.urgency)} · ${rank}</span></td>
      <td><span class="title">${item.synthetic ? '<span class="sample-tag">SYNTHETIC INPUT</span>' : '<span class="sample-tag">REAL INPUT</span>'}${escapeHtml(title)}</span><span class="asset" title="${escapeHtml(item.resource_uids[0])}">${escapeHtml(shortId(item.resource_uids[0]))}</span></td>
      <td><span class="provider">${escapeHtml(item.provider)}</span><span class="state">${escapeHtml(humanize(item.state))}</span><span class="reason">${escapeHtml(capabilitySummary(item))}</span></td>
      <td><span class="status ${validationTone}"><i></i>${escapeHtml(validationLabel)}</span><span class="reason">${escapeHtml(validationReason)}</span></td>
      <td><span class="status ${scheduleTone}"><i></i>${escapeHtml(scheduleLabel)}</span><span class="reason">${escapeHtml(scheduleReason)}</span></td>
      <td><div class="row-actions">${canValidate(item) ? `<button type="button" class="primary small" data-validate="${escapeHtml(item.case_id)}">Validate live</button>` : ""}<button type="button" class="ghost small" data-case="${escapeHtml(item.case_id)}">Inspect</button></div></td>
    </tr>`;
  }).join("");
}

function renderConnectors(document) {
  connectors = document;
  $("#connectors").innerHTML = Object.values(document).map(item => {
    const ready = item.ready_for_live_validation;
    const explanation = ready ? "Ready for bounded live configuration reads." :
      item.configuration_errors?.length ? item.configuration_errors[0] :
      item.executable === "azure-arm-rest" ? "Managed identity is not available to the validator." :
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

function recordSummary(record) {
  const body = record.body || {};
  const findings = body.findings || [];
  if (findings.length) {
    const counts = findings.reduce((totals, item) => {
      const status = humanize(item.status || "unknown");
      totals[status] = (totals[status] || 0) + 1;
      return totals;
    }, {});
    const outcomes = Object.entries(counts).map(([status, count]) => `${count} ${status.toLowerCase()}`);
    const reasons = [...new Set(findings.map(item => item.reason).filter(Boolean))];
    return `${outcomes.join(" · ")}${reasons.length ? ` · ${reasons.join(" · ")}` : ""}`;
  }
  if (record.record_type === "IaCLink.v1") return `Linked ${body.link?.resource_address || body.link?.source_path || "Terraform resource"}`;
  if (record.record_type === "RemediationPlan.v1") return `${humanize(body.status)}: ${body.plan?.objective || "Remediation plan"}`;
  if (record.record_type === "SREReview.v1") return `${humanize(body.decision)}: ${body.summary}`;
  if (record.record_type === "ChangeWindowRecommendation.v1") return `Candidate ${body.selected?.local_start || body.selected?.starts_at || "window selected"}`;
  if (record.record_type === "RollbackReview.v1") return `${humanize(body.decision)}: ${body.summary}`;
  if (record.record_type === "PolicyDecision.v1") return `${humanize(body.decision)} · ${(body.checks || []).length} policy checks passed`;
  if (record.record_type === "HumanReviewPackage.v1") return `${humanize(body.requested_human_decision)} · execution ${humanize(body.execution_status)}`;
  return "Evidence record captured";
}

const packageRecordKeys = [
  ["validation_result_id", "Live validation"],
  ["iac_link_id", "IaC target"],
  ["change_plan_id", "Remediation plan"],
  ["sre_review_id", "SRE review"],
  ["change_window_id", "Change window"],
  ["rollback_review_id", "Rollback review"],
  ["policy_decision_id", "Policy gate"],
  ["human_review_package_id", "Human decision"],
];

function recordBadge(record, current, stage) {
  if (current) return `<span class="record-badge current">CURRENT · ${escapeHtml(stage)}</span>`;
  const decision = String(record.body?.decision || "").toLowerCase();
  if (decision === "reject") return '<span class="record-badge rejected">REJECTED · SUPERSEDED</span>';
  return '<span class="record-badge superseded">SUPERSEDED</span>';
}

function renderRecord(record, {current = false, stage = ""} = {}) {
  return `<div class="record ${current ? "current-record" : "history-record"}"><header><strong>${escapeHtml(record.record_type)}</strong>${recordBadge(record, current, stage)}</header><p>${escapeHtml(recordSummary(record))}</p><code>${escapeHtml(shortId(record.record_id))} · ${escapeHtml(record.created_at)}</code></div>`;
}

function partitionRecords(records, caseDoc) {
  const byId = new Map(records.map(record => [record.record_id, record]));
  const currentIds = new Set();
  const current = packageRecordKeys.flatMap(([key, stage]) => {
    const recordId = caseDoc.record_ids?.[key];
    const record = recordId ? byId.get(recordId) : null;
    if (!record) return [];
    currentIds.add(recordId);
    return [{record, stage}];
  });
  const history = records.filter(record => !currentIds.has(record.record_id)).reverse();
  return {current, history};
}

function renderEvidenceRecords(records, caseDoc) {
  if (!records.length) return '<p class="empty compact">No validation product records yet.</p>';
  const {current, history} = partitionRecords(records, caseDoc);
  const packageRecord = current.find(item => item.record.record_type === "HumanReviewPackage.v1")?.record;
  const executionStatus = humanize(packageRecord?.body?.execution_status || "not started");
  const currentMarkup = current.length ? current.map(item => renderRecord(item.record, {current:true, stage:item.stage})).join("") : '<p class="empty compact">No authoritative package has been assembled yet.</p>';
  const historyMarkup = history.length ? `<details class="record-history"><summary>Superseded history <span>${history.length} record${history.length === 1 ? "" : "s"}</span></summary><p class="history-note">These records are accurate historical evidence, but they are not part of the current approval package.</p>${history.map(record => renderRecord(record)).join("")}</details>` : "";
  return `<div class="package-banner"><div><strong>Authoritative package</strong><p>Only records marked CURRENT govern the next human decision.</p></div><span class="execution-state">Execution ${escapeHtml(executionStatus)}</span></div>${currentMarkup}${historyMarkup}`;
}

async function openCase(caseId) {
  const detail = await request(`/api/cases/${encodeURIComponent(caseId)}?tenant=${encodeURIComponent(tenant())}`);
  const item = fleet?.cases.find(candidate => candidate.case_id === caseId);
  const caseDoc = detail.case;
  const finding = detail.findings[0] || {};
  const ocsf = finding.record?.ocsf || {};
  const displayTitle = controlTitle(ocsf.rule_id, ocsf.title || item?.finding_titles?.[0]);
  const [tone, validation] = validationSummary(item || {validation_counts:{}, unsupported_findings:0});
  const safety = detail.safety_boundary;
  const promotion = detail.promotion || {};
  const capability = (item?.capabilities || []).find(value => value.rule_id === ocsf.rule_id);
  $("#detail-content").innerHTML = `
    <div class="detail-hero"><div><span class="status ${tone}"><i></i>${escapeHtml(validation)}</span><h2 id="detail-title">${escapeHtml(displayTitle)}</h2></div><div class="detail-meta"><strong>${escapeHtml(Math.round(caseDoc.priority?.score || 0))}</strong><span>${escapeHtml(humanize(caseDoc.priority?.urgency || "unassessed"))} risk</span></div></div>
    <div class="detail-actions">${item && canValidate(item) ? `<button type="button" class="primary" data-validate="${escapeHtml(caseId)}">Validate against live ${escapeHtml(item.provider.toUpperCase())}</button>` : ""}<span class="pill">${escapeHtml(humanize(caseDoc.state))}</span><span class="pill sample-pill">${item?.synthetic ? "Synthetic input" : "Real scanner input"}</span></div>
    <div class="detail-grid">
      <section class="detail-section"><h3>Case identity</h3>${fact("Case", caseDoc.case_id)}${fact("Tenant", caseDoc.tenant_id)}${fact("Provider", finding.provider)}${fact("Account", finding.account)}${fact("Service", (caseDoc.service_ids || []).join(", ") || "Unmapped")}</section>
      <section class="detail-section"><h3>Control & target</h3>${fact("Rule", ocsf.rule_id)}${fact("Resource", finding.resource_uid)}${fact("Severity", finding.record?.severity)}${fact("Scanner observations", caseDoc.finding_ids.length)}${fact("Confirmed controls", (promotion.confirmed_rule_ids || []).length)}</section>
      <section class="detail-section"><h3>Capability contract</h3>${fact("Live validation", capability?.live_validation ? "Registered" : "Unsupported")}${fact("Remediation planning", capability?.remediation_planning ? "Registered" : "Unavailable")}${fact("Live execution", capability?.live_execution ? "Separately gated" : "Unavailable")}${fact("Evidence grade", evidenceGrade(capability?.evidence_grade))}</section>
      <section class="detail-section"><h3>Risk rationale</h3>${(caseDoc.priority?.factors || []).map(value => `<div class="record"><p>${escapeHtml(value)}</p></div>`).join("") || '<p class="empty compact">Not assessed.</p>'}</section>
      <section class="detail-section"><h3>Shadow safety boundary</h3>${fact("Live validation", safety.mode === "shadow" ? "Allowed" : "Unknown")}${fact("External models", safety.external_models ? "Allowed" : "Disabled")}${fact("Approval", safety.approval ? "Allowed" : "Unavailable")}${fact("Scheduling", safety.scheduling ? "Allowed" : "Unavailable")}${fact("Execution", safety.execution ? "Allowed" : "Unavailable")}</section>
      <section class="detail-section full"><h3>Operational review</h3>${fact("Status", humanize(promotion.status))}${fact("Promotion token", shortId(promotion.promotion_token, 48))}${fact("Confirmed controls", (promotion.confirmed_rule_ids || []).join(", ") || "None")}${(promotion.blockers || []).map(value => `<div class="record"><p>${escapeHtml(value)}</p></div>`).join("")}${promotion.status === "ready_for_preapproval" ? (promotion.required_inputs || []).map(value => `<div class="record"><p>${escapeHtml(value)}</p></div>`).join("") : ""}</section>
      <section class="detail-section full"><h3>${caseDoc.state === "awaiting_approval" ? "Current approval package" : "Current evidence chain"}</h3>${renderEvidenceRecords(detail.records, caseDoc)}</section>
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
    const skipped = result.skipped || {pass:0, manual:0};
    showToast(`${result.received} failing finding(s) accepted · ${skipped.pass} passing and ${skipped.manual} manual skipped · ${result.created_cases} new case(s) · ${result.duplicates} duplicate(s)`);
  } finally { setBusy(false); }
}

function loadSample() {
  const id = globalThis.crypto?.randomUUID?.() || String(Date.now());
  const resource = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/customer-shadow/providers/Microsoft.Storage/storageAccounts/shadowdemo123";
  $("#finding-json").value = JSON.stringify({
    class_uid:2004,severity:"High",time_dt:new Date().toISOString(),
    metadata:{version:"1.5.0",event_code:"storage_account_public_network_access_disabled",product:{name:"El Capitan synthetic sample",version:"1"}},
    cloud:{provider:"azure",region:"westus2",account:{uid:"00000000-0000-0000-0000-000000000000"}},
    finding_info:{uid:`shadow-sample-${id}`,title:"Storage public network access is enabled",analytic:{uid:"storage_account_public_network_access_disabled"}},
    resources:[{uid:resource,type:"microsoft.storage/storageaccounts",name:"shadowdemo123"}],
    status_code:"FAIL",unmapped:{categories:["internet-exposed"],elcapitan_synthetic:true},
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
