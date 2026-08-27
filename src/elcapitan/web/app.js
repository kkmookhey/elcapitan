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
    <div class="stage ${stage.status}">
      <span>${stage.status === "complete" ? "✓" : index + 1}</span>
      <strong>${escapeHtml(stage.label)}</strong>
    </div>`).join("");
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
  $("#timeline").innerHTML = [...state.events].reverse().map(event => `
    <div class="timeline-item">
      <span class="timeline-dot">✓</span>
      <div class="timeline-copy">
        <strong>${escapeHtml(humanize(event.transition))}</strong>
        <span>${escapeHtml(event.actor)} · ${escapeHtml(new Date(event.occurred_at).toLocaleString())}</span>
        <code>${escapeHtml(shortId(event.event_id))}</code>
      </div>
    </div>`).join("");
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
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (!action) return;
  if (action === "prepare") api("/api/prepare");
  if (action === "approve") $("#approval-dialog").showModal();
  if (action === "success") api("/api/execute", {outcome: "success"});
  if (action === "rollback") api("/api/execute", {outcome: "rollback"});
  if (action === "new-run") api("/api/reset");
});

$("#reset-button").addEventListener("click", () => api("/api/reset"));
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
