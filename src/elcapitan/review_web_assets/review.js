const $ = selector => document.querySelector(selector);
let queue = null;
let selected = null;
let busy = false;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[char]);
}

function humanize(value) {
  return String(value ?? "").replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());
}

function shortId(value, width = 40) {
  const text = String(value ?? "");
  return text.length > width ? `${text.slice(0, 18)}…${text.slice(-14)}` : text;
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 4500);
}

function setBusy(value) {
  busy = value;
  document.querySelectorAll("button").forEach(button => button.disabled = value);
}

async function request(path, options = {}) {
  const response = await fetch(path, options);
  let document = {};
  try { document = await response.json(); } catch (_) { /* no JSON */ }
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Session expired");
  }
  if (!response.ok) throw new Error(document.error || `Request failed (${response.status})`);
  return document;
}

function tenant() { return $("#tenant").value.trim(); }

function record(type) {
  return selected?.current_records?.find(item => item.record_type === type) || {body:{}};
}

function renderQueue(document) {
  queue = document;
  $("#queue-count").textContent = `${document.cases.length} case${document.cases.length === 1 ? "" : "s"}`;
  if (!document.cases.length) {
    $("#queue-list").innerHTML = '<p class="empty">No human-review packages exist for this tenant.</p>';
    return;
  }
  $("#queue-list").innerHTML = document.cases.map(item => `<button class="queue-item ${selected?.case?.case_id === item.case_id ? "selected" : ""}" data-case="${escapeHtml(item.case_id)}"><header><strong>${escapeHtml(Math.round(item.risk_score))} · ${escapeHtml(humanize(item.urgency))}</strong><span class="state ${escapeHtml(item.state)}">${escapeHtml(humanize(item.state))}</span></header><p>${escapeHtml(shortId(item.resource_uid, 56))}</p><code>${escapeHtml(shortId(item.review_package_id))}</code></button>`).join("");
}

function list(items, empty = "None") {
  return items?.length ? `<ul class="list">${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : `<p>${escapeHtml(empty)}</p>`;
}

function checks(items) {
  return items?.length ? items.map(item => `<div class="check-row"><i>${item.passed ? "✓" : "×"}</i><span><strong>${escapeHtml(humanize(item.check || item.name))}</strong> · ${escapeHtml(item.detail || (item.passed ? "passed" : "failed"))}</span></div>`).join("") : '<p>No checks recorded.</p>';
}

function formatDiff(value) {
  if (!value) return "Verified hashes are available; source text is not present in this service replica.";
  return value.split("\n").map(line => {
    const tone = line.startsWith("+") && !line.startsWith("+++") ? "diff-add" : line.startsWith("-") && !line.startsWith("---") ? "diff-del" : "";
    return `<span class="${tone}">${escapeHtml(line)}</span>`;
  }).join("\n");
}

function renderDetail(document) {
  selected = document;
  if (queue) renderQueue(queue);
  const caseDoc = document.case;
  const finding = document.findings[0] || {};
  const validation = record("ValidationResult.v1");
  const plan = record("RemediationPlan.v1");
  const sre = record("SREReview.v1");
  const windowRecord = record("ChangeWindowRecommendation.v1");
  const rollback = record("RollbackReview.v1");
  const policy = record("PolicyDecision.v1");
  const findings = validation.body.findings || [];
  const confirmed = findings.filter(item => item.status === "confirmed").length;
  const selectedWindow = windowRecord.body.selected || {};
  const models = document.current_records.map(item => item.body?.task).filter(Boolean);
  const terminal = caseDoc.state !== "awaiting_approval";
  $("#review-panel").innerHTML = `
    <div class="review-header"><div class="review-title"><div><p class="section-label">Current approval package</p><h2>${escapeHtml(humanize(finding.rule_id || "Remediation case"))}</h2></div><div class="risk"><strong>${escapeHtml(Math.round(caseDoc.priority?.score || 0))}</strong><span>${escapeHtml(humanize(caseDoc.priority?.urgency || "unassessed"))} risk</span></div></div><p class="review-subtitle">${escapeHtml(finding.resource_uid)}</p><div class="package-binding"><div><strong>${escapeHtml(document.review_package_id)}</strong><code>sha256:${escapeHtml(document.review_package_sha256)}</code></div><span class="verified">8 CURRENT RECORDS</span></div></div>
    <div class="review-body">
      <div class="facts"><div class="fact"><small>State</small><strong>${escapeHtml(humanize(caseDoc.state))}</strong></div><div class="fact"><small>Scanner observations</small><strong>${escapeHtml(caseDoc.finding_ids.length)}</strong></div><div class="fact"><small>Confirmed control</small><strong>${escapeHtml(confirmed ? "Yes" : "No")}</strong></div><div class="fact"><small>History retained</small><strong>${escapeHtml(document.superseded_record_count)} superseded</strong></div></div>
      <section class="section"><header><h3>Exact verified change</h3><span class="badge ${document.change.verified ? "" : "warn"}">${document.change.verified ? "Hashes verified" : "Metadata only"}</span></header><p>${escapeHtml(plan.body.plan?.objective || "No objective recorded")}</p><div class="facts"><div class="fact"><small>Source</small><strong>${escapeHtml(document.change.source_path)}</strong></div><div class="fact"><small>Before</small><strong>${escapeHtml(shortId(document.change.before_sha256, 22))}</strong></div><div class="fact"><small>After</small><strong>${escapeHtml(shortId(document.change.after_sha256, 22))}</strong></div><div class="fact"><small>Terraform checks</small><strong>${escapeHtml((plan.body.checks || []).filter(item => item.passed).length)}/${escapeHtml((plan.body.checks || []).length)} passed</strong></div></div><pre class="diff">${formatDiff(document.change.unified_diff)}</pre></section>
      <div class="section-grid">
        <section class="section"><header><h3>Live validation</h3><span class="badge">${escapeHtml(confirmed)} confirmed</span></header>${list([...new Set(findings.map(item => item.reason).filter(Boolean))])}</section>
        <section class="section"><header><h3>SRE decision</h3><span class="badge">${escapeHtml(humanize(sre.body.decision))}</span></header><p>${escapeHtml(sre.body.summary || "No summary")}</p>${list(sre.body.required_controls || [], "No additional controls")}</section>
        <section class="section"><header><h3>Change window</h3><span class="badge">${escapeHtml(Math.round((windowRecord.body.confidence || 0) * 100))}% confidence</span></header><p><strong>${escapeHtml(selectedWindow.local_start || selectedWindow.starts_at || "Not selected")}</strong><br>through ${escapeHtml(selectedWindow.ends_at || caseDoc.change_window?.ends_at || "—")}</p>${list(windowRecord.body.rationale || [])}</section>
        <section class="section"><header><h3>Rollback review</h3><span class="badge">${escapeHtml(humanize(rollback.body.decision))}</span></header><p>${escapeHtml(rollback.body.summary || "No summary")}</p>${list(plan.body.plan?.rollback_triggers || [], "No triggers")}</section>
      </div>
      <section class="section"><header><h3>Deterministic policy gate</h3><span class="badge">${escapeHtml(humanize(policy.body.decision))}</span></header>${checks(policy.body.checks || [])}</section>
      <section class="section"><header><h3>Maker / checker provenance</h3><span class="badge">${escapeHtml(new Set(models.map(item => `${item.runtime}:${item.model}`)).size)} model identities</span></header><div class="models">${models.map(item => `<span class="model">${escapeHtml(item.runtime)} · ${escapeHtml(item.model)}</span>`).join("")}</div></section>
      ${terminal ? `<div class="decision-bar terminal"><div><strong>Decision recorded: ${escapeHtml(humanize(caseDoc.state))}</strong><p>This package can no longer accept another decision.</p></div></div>` : `<div class="decision-bar"><div><strong>Human decision required</strong><p>Both actions bind to this exact package hash. Neither endpoint can execute infrastructure.</p></div><div class="decision-actions"><button class="ghost" data-action="reject">Reject package</button><button class="primary" data-action="approve">Review approval</button></div></div>`}
    </div>`;
}

async function loadQueue() {
  if (!tenant()) throw new Error("Enter a customer tenant identifier");
  try { window.localStorage.setItem("elcapitan-review-tenant", tenant()); } catch (_) { /* optional */ }
  renderQueue(await request(`/api/reviews?tenant=${encodeURIComponent(tenant())}`));
}

async function openCase(caseId) {
  renderDetail(await request(`/api/reviews/${encodeURIComponent(caseId)}?tenant=${encodeURIComponent(tenant())}`));
}

function decisionBody(verb) {
  return {
    tenant_id:tenant(), case_id:selected.case.case_id,
    review_package_id:selected.review_package_id,
    review_package_sha256:selected.review_package_sha256,
    approver:$(`#${verb}-name`).value,
    confirmation:$(`#${verb}-confirmation`).value,
    ...(verb === "reject" ? {reason:$("#reject-reason").value} : {}),
  };
}

async function submitDecision(verb) {
  setBusy(true);
  try {
    await request(`/api/decisions/${verb}`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(decisionBody(verb))});
    $(`#${verb}-dialog`).close();
    showToast(verb === "approve" ? "Approval recorded and scheduled; execution has not started." : "Rejection recorded; no execution job was created.");
    await loadQueue();
    await openCase(selected.case.case_id);
  } finally { setBusy(false); }
}

document.addEventListener("click", async event => {
  try {
    const close = event.target.closest("[data-close]")?.dataset.close;
    if (close) { $("#" + close).close(); return; }
    const caseId = event.target.closest("[data-case]")?.dataset.case;
    if (caseId) { await openCase(caseId); return; }
    const action = event.target.closest("[data-action]")?.dataset.action;
    if (action && selected) {
      const phrase = `${action.toUpperCase()} ${selected.review_package_id}`;
      $(`#${action}-phrase`).textContent = phrase;
      $(`#${action}-confirmation`).value = "";
      $(`#${action}-dialog`).showModal();
      return;
    }
    if (event.target.closest("#load-queue")) { setBusy(true); try { await loadQueue(); } finally { setBusy(false); } }
  } catch (error) { showToast(error.message, true); setBusy(false); }
});

$("#approve-form").addEventListener("submit", event => { event.preventDefault(); submitDecision("approve").catch(error => { showToast(error.message, true); setBusy(false); }); });
$("#reject-form").addEventListener("submit", event => { event.preventDefault(); submitDecision("reject").catch(error => { showToast(error.message, true); setBusy(false); }); });
$("#tenant").addEventListener("keydown", event => { if (event.key === "Enter") $("#load-queue").click(); });

async function start() {
  try { const saved = window.localStorage.getItem("elcapitan-review-tenant"); if (saved) $("#tenant").value = saved; } catch (_) { /* optional */ }
  try { await loadQueue(); if (queue.cases[0]) await openCase(queue.cases[0].case_id); } catch (error) { showToast(error.message, true); }
}
start();
