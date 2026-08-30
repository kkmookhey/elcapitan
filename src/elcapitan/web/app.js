const $ = (selector) => document.querySelector(selector);
let currentState = null;
let busy = false;

const labels = {
  ready: "Ready",
  awaiting_approval: "Awaiting human",
  approved: "Scheduled",
  remediated: "Remediated",
  rolled_back: "Rolled back",
};

const stageRecords = {
  open: [],
  prioritized: [],
  validated: ["ValidationResult.v1"],
  plan_ready: ["IaCLink.v1", "RemediationPlan.v1"],
  sre_approved: ["SREReview.v1"],
  window_selected: ["ChangeWindowRecommendation.v1"],
  rollback_ready: ["RollbackReview.v1"],
  awaiting_approval: ["PolicyDecision.v1", "HumanReviewPackage.v1"],
  approved: ["ChangeApproval.v1", "ExecutionSchedule.v1"],
  executing: ["ExecutionStart.v1", "ExecutionResult.v1", "RollbackExecution.v1"],
  verifying: ["PostChangeVerification.v1", "RollbackVerification.v1"],
  remediated: ["RemediationCertificate.v1", "OriginatorHandoff.v1"],
};

const stageNarrative = {
  open: "Scanner finding normalized, correlated to an asset, and admitted as a durable remediation case.",
  prioritized: "Risk calculated from severity, reachability, exposure, asset criticality, and confidence.",
  validated: "The reported control was re-evaluated against captured configuration evidence.",
  plan_ready: "The fleet linked the asset to infrastructure as code and verified the bounded change.",
  sre_approved: "An independent SRE reviewer evaluated dependencies, failure modes, and health controls.",
  window_selected: "Historical service usage and policy produced a bounded maintenance window.",
  rollback_ready: "An independent checker verified rollback steps, triggers, and recovery coverage.",
  awaiting_approval: "Deterministic policy assembled the exact evidence-bound package for a human decision.",
  approved: "Human approval is cryptographically bound to this package and durably scheduled.",
  executing: "The action plane checkpoints, deploys, monitors, and rolls back on policy failure.",
  verifying: "Independent probes revalidate the vulnerability, artifact, UI/API, and health state.",
  remediated: "Completion proof and the final operational handoff close the case.",
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[char]);
}

function humanize(value) {
  return String(value ?? "").replaceAll("_", " ").replace(/\b\w/g, c => c.toUpperCase());
}

function shortId(value) {
  const text = String(value ?? "");
  return text.length > 22 ? `${text.slice(0, 12)}…${text.slice(-7)}` : text;
}

function record(type) {
  return currentState?.records?.find(item => item.record_type === type);
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 4200);
}

async function api(path, body = {}) {
  if (busy) return;
  busy = true;
  $("#status-orb").classList.add("busy");
  document.querySelectorAll("button").forEach(button => button.disabled = true);
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    const document = await response.json();
    if (!response.ok) throw new Error(document.error || "Action failed");
    render(document);
    showToast(document.demo.message);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    busy = false;
    $("#status-orb").classList.remove("busy");
    document.querySelectorAll("button").forEach(button => button.disabled = false);
  }
}

function actionButtons(phase) {
  if (phase === "ready") {
    return `<button class="primary" data-action="prepare">Run agent fleet</button>`;
  }
  if (phase === "awaiting_approval") {
    return `<button class="primary" data-action="approve">Review & approve</button>`;
  }
  if (phase === "approved") {
    return `<button class="primary" data-action="success">Deploy healthy change</button>
      <button class="danger" data-action="rollback">Simulate SLO failure</button>`;
  }
  return `<button class="ghost" data-action="new-run">Start another run</button>`;
}

function renderPipeline(stages) {
  $("#pipeline").innerHTML = stages.map((stage, index) => `
    <button type="button" class="stage ${stage.status}" ${stage.status !== "pending" ? `data-stage="${stage.state}"` : "aria-disabled=\"true\""}>
      <span>${stage.status === "complete" ? "✓" : index + 1}</span>
      <strong>${escapeHtml(stage.label)}</strong>
    </button>`).join("");
}

function renderDetailValue(value, depth = 0) {
  if (value === null || value === undefined || value === "") return `<span class="detail-empty">Not supplied</span>`;
  if (typeof value === "boolean") return `<span class="detail-value ${value ? "good" : "warn"}">${value ? "Yes" : "No"}</span>`;
  if (typeof value === "number") return `<span class="detail-value">${escapeHtml(value)}</span>`;
  if (typeof value === "string") {
    const tone = ["passed", "approve", "approved", "verified", "healthy", "remediated", "succeeded", "accept"].includes(value.toLowerCase()) ? "good" : "";
    return `<span class="detail-value ${tone}">${escapeHtml(value)}</span>`;
  }
  if (Array.isArray(value)) {
    if (!value.length) return `<span class="detail-empty">None</span>`;
    const compact = value.every(item => item === null || typeof item !== "object");
    return `<ul class="detail-list${compact ? " compact" : ""}">${value.map(item => `<li>${renderDetailValue(item, depth + 1)}</li>`).join("")}</ul>`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (!entries.length) return `<span class="detail-empty">None</span>`;
    return `<div class="detail-object">${entries.map(([key, child]) => `
      <div class="detail-row"><div class="detail-key">${escapeHtml(humanize(key))}</div><div>${renderDetailValue(child, depth + 1)}</div></div>`).join("")}</div>`;
  }
  return `<span class="detail-value">${escapeHtml(value)}</span>`;
}

function evidenceSummary(evidenceIds = []) {
  return {
    count: evidenceIds.length,
    sample_ids: evidenceIds.slice(0, 4),
    additional_ids: Math.max(0, evidenceIds.length - 4),
  };
}

function summarizeRecordBody(item) {
  const body = item.body || {};
  if (item.record_type !== "HumanReviewPackage.v1") return body;
  const boundRecords = {};
  [
    ["validation", body.validation],
    ["iac_link", body.iac_link],
    ["remediation_plan", body.remediation_plan],
    ["sre_review", body.sre_review],
    ["change_window", body.change_window],
    ["rollback_review", body.rollback_review],
    ["policy_decision", body.policy_decision],
  ].forEach(([name, record]) => {
    if (record?.record_id) boundRecords[name] = record.record_id;
  });
  return {
    review_package_id: body.review_package_id,
    requested_human_decision: body.requested_human_decision,
    execution_status: body.execution_status,
    case: {
      case_id: body.case?.case_id,
      tenant_id: body.case?.tenant_id,
      state: body.case?.state,
    },
    risk: {
      score: body.risk_assessment?.score,
      urgency: body.risk_assessment?.urgency,
      confidence: body.risk_assessment?.confidence,
    },
    bound_records: boundRecords,
  };
}

function detailSection(title, identifier, document) {
  return `<section class="detail-section"><header><strong>${escapeHtml(title)}</strong><code>${escapeHtml(shortId(identifier))}</code></header><div class="detail-document">${renderDetailValue(document)}</div></section>`;
}

function showDetails({label = "Stage evidence", title, subtitle, sections}) {
  $("#detail-label").textContent = label;
  $("#detail-title").textContent = title;
  $("#detail-subtitle").textContent = subtitle || "";
  $("#detail-content").innerHTML = sections.join("");
  $("#detail-dialog").showModal();
}

function showStage(stageName) {
  const stage = currentState.stages.find(item => item.state === stageName);
  const types = stageRecords[stageName] || [];
  const records = currentState.records.filter(item => types.includes(item.record_type));
  const sections = [];
  if (stageName === "open") {
    sections.push(detailSection("Case intake", currentState.case.case_id, {
      case_id: currentState.case.case_id,
      tenant_id: currentState.case.tenant_id,
      finding_ids: currentState.case.finding_ids,
      asset_ids: currentState.case.asset_ids,
      service_ids: currentState.case.service_ids,
      created_at: currentState.case.created_at,
    }));
  }
  if (stageName === "prioritized") {
    sections.push(detailSection("Risk assessment", currentState.case.priority?.assessment_id || "", currentState.case.priority));
  }
  records.forEach(item => sections.push(detailSection(item.record_type, item.record_id, {
    created_at: item.created_at,
    record: summarizeRecordBody(item),
    evidence: evidenceSummary(item.evidence_ids),
  })));
  const relatedEvents = currentState.events.filter(event => event.to_state === stageName);
  relatedEvents.forEach(event => sections.push(detailSection("Audit transition", event.event_id, event)));
  if (!sections.length) sections.push(detailSection("Stage status", stageName, {status: stage?.status || "pending"}));
  showDetails({title: stage?.label || humanize(stageName), subtitle: stageNarrative[stageName], sections});
}

function showEvent(index) {
  const event = currentState.events[index];
  if (!event) return;
  const recordIds = new Set(Object.values(event.record_ids || {}));
  const associated = currentState.records.filter(item => recordIds.has(item.record_id));
  showDetails({
    label: "Audit event",
    title: humanize(event.transition),
    subtitle: `${humanize(event.from_state)} → ${humanize(event.to_state)} · ${event.actor}`,
    sections: [
      detailSection("Immutable transition", event.event_id, event),
      ...associated.map(item => detailSection(item.record_type, item.record_id, {
        record: summarizeRecordBody(item),
        evidence: evidenceSummary(item.evidence_ids),
      })),
    ],
  });
}

function showRecordIndex() {
  showDetails({
    label: "Case record index",
    title: `${currentState.records.length} immutable product records`,
    subtitle: "Every material decision is typed, case-bound, timestamped, and linked to its evidence.",
    sections: currentState.records.map(item => detailSection(item.record_type, item.record_id, {
      created_at: item.created_at,
      evidence: evidenceSummary(item.evidence_ids),
      record: summarizeRecordBody(item),
    })),
  });
}

function renderMetrics(state) {
  const priority = state.case?.priority;
  $("#risk-score").textContent = priority ? Math.round(priority.score) : "—";
  $("#urgency").textContent = priority ? humanize(priority.urgency) : "Not assessed";
  const evidence = new Set(state.records.flatMap(item => item.evidence_ids || []));
  $("#evidence-count").textContent = evidence.size;
  const checks = state.demo.terraform_checks || [];
  $("#check-count").textContent = checks.length;
  $("#check-status").textContent = checks.length && checks.every(check => check.passed) ? "All passed" : "Waiting";
  const blast = state.case?.change_plan?.blast_radius || [];
  $("#blast-radius").textContent = blast.length || "—";
}

function renderReview(state) {
  const hasReview = Boolean(state.review_package);
  $("#review-empty").hidden = hasReview;
  $("#review-content").hidden = !hasReview;
  $("#case-state").textContent = state.case ? humanize(state.case.state) : "No case";
  if (!hasReview) return;
  const plan = state.case.change_plan;
  const window = state.case.change_window;
  $("#facts").innerHTML = [
    ["Case", shortId(state.case.case_id)],
    ["Tenant", state.case.tenant_id],
    ["Window", window ? new Date(window.starts_at).toLocaleString() : "—"],
    ["Confidence", window ? `${Math.round(window.confidence * 100)}%` : "—"],
  ].map(([term, value]) => `<div><dt>${escapeHtml(term)}</dt><dd title="${escapeHtml(value)}">${escapeHtml(value)}</dd></div>`).join("");
  $("#implementation-steps").innerHTML = (plan?.steps || []).map(item => `<li>${escapeHtml(item)}</li>`).join("");
  $("#rollback-triggers").innerHTML = (plan?.rollback_triggers || []).map(item => `<li>${escapeHtml(item)}</li>`).join("");
  $("#change-diff").textContent = state.change_diff || "Verified artifact diff unavailable.";
}

function renderTimeline(state) {
  $("#record-count").textContent = `${state.records.length} records`;
  if (!state.events.length) {
    $("#timeline").innerHTML = `<div class="empty-state">No workflow events yet.</div>`;
    return;
  }
  $("#timeline").innerHTML = [...state.events].map((event, index) => ({event, index})).reverse().map(({event, index}) => `
    <button type="button" class="timeline-item" data-event-index="${index}">
      <span class="timeline-dot">✓</span>
      <div class="timeline-copy">
        <strong>${escapeHtml(humanize(event.transition))}</strong>
        <span>${escapeHtml(event.actor)} · ${escapeHtml(new Date(event.occurred_at).toLocaleString())}</span>
        <code>${escapeHtml(shortId(event.event_id))}</code>
      </div>
    </button>`).join("");
}

function renderProof(state) {
  const certificate = record("RemediationCertificate.v1");
  const handoff = record("OriginatorHandoff.v1");
  const rollback = record("RollbackVerification.v1");
  const visible = Boolean(certificate || rollback);
  $("#proof-card").hidden = !visible;
  if (!visible) return;
  if (rollback) {
    $("#proof-title").textContent = "Verified automatic rollback";
    $("#proof-grid").innerHTML = [
      ["Final state", "Service restored"],
      ["Checkpoint", rollback.body.checkpoint_restored ? "Restored" : "Failed"],
      ["Health", rollback.body.service_recovered ? "Recovered" : "Unhealthy"],
      ["Evidence", `${rollback.evidence_ids.length} bound objects`],
    ].map(([key, value]) => `<div><small>${key}</small><strong>${escapeHtml(value)}</strong></div>`).join("");
  } else {
    $("#proof-title").textContent = "Remediation certificate & handoff";
    $("#proof-grid").innerHTML = [
      ["Certificate", shortId(certificate.record_id)],
      ["Status", certificate.body.completed_status],
      ["Originator", handoff?.body.recipient || "—"],
      ["Evidence", `${certificate.evidence_ids.length} bound objects`],
    ].map(([key, value]) => `<div><small>${key}</small><strong>${escapeHtml(value)}</strong></div>`).join("");
  }
}

function mission(phase) {
  const messages = {
    ready: ["Prepare the remediation fleet", "Create an isolated Azure Storage finding and run it through every pre-approval control."],
    awaiting_approval: ["Human decision required", "The plan passed validation, SRE review, timing analysis, and rollback verification. Inspect the package before approving."],
    approved: ["Scheduled and ready to execute", "The exact package is approval-bound. Choose a healthy deployment or demonstrate automatic rollback on an SLO breach."],
    remediated: ["Remediation complete", "All deterministic probes and the release audit passed. A certificate was issued and handed back to the finding originator."],
    rolled_back: ["Service safely restored", "The post-deployment health policy failed. The fleet restored the checkpoint and verified service recovery."],
  };
  return messages[phase] || [humanize(phase), "The case is progressing through the controlled remediation lifecycle."];
}

function render(state) {
  currentState = state;
  const phase = state.demo.phase;
  const [title, message] = mission(phase);
  $("#fleet-status").textContent = labels[phase] || humanize(phase);
  $("#mission-title").textContent = title;
  $("#mission-message").textContent = message;
  $("#actions").innerHTML = actionButtons(phase);
  renderPipeline(state.stages);
  renderMetrics(state);
  renderReview(state);
  renderTimeline(state);
  renderProof(state);
}

document.addEventListener("click", event => {
  const stageName = event.target.closest("[data-stage]")?.dataset.stage;
  if (stageName) {
    showStage(stageName);
    return;
  }
  const eventIndex = event.target.closest("[data-event-index]")?.dataset.eventIndex;
  if (eventIndex !== undefined) {
    showEvent(Number(eventIndex));
    return;
  }
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (!action) return;
  if (action === "prepare") api("/api/prepare");
  if (action === "approve") $("#approval-dialog").showModal();
  if (action === "success") api("/api/execute", {outcome: "success"});
  if (action === "rollback") api("/api/execute", {outcome: "rollback"});
  if (action === "new-run") api("/api/reset");
  if (action === "records") showRecordIndex();
});

$("#reset-button").addEventListener("click", () => api("/api/reset"));
$("#detail-close").addEventListener("click", () => $("#detail-dialog").close());
$("#approval-form").addEventListener("submit", event => {
  if (event.submitter?.value !== "default") return;
  event.preventDefault();
  if (!$("#attestation").checked) {
    showToast("Review attestation is required.", true);
    return;
  }
  $("#approval-dialog").close();
  api("/api/approve", {approver: $("#approver").value});
});

fetch("/api/state")
  .then(response => response.json())
  .then(render)
  .catch(() => showToast("Could not load demo state.", true));
