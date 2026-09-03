const $ = selector => document.querySelector(selector);
let fleet = null;
let connectors = {};
let busy = false;
let intakePreview = null;

const controlTitles = {
  storage_account_public_network_access_disabled: "Storage public network access must be disabled",
  storage_blob_public_access_level_is_disabled: "Anonymous blob access must be disabled",
  storage_blob_versioning_is_enabled: "Blob versioning must be enabled",
  sqlserver_tde_encrypted_with_cmk: "SQL Server must use CMK-backed TDE for every user database",
  s3_bucket_object_versioning: "S3 object versioning must be enabled",
  s3_bucket_kms_encryption: "S3 default encryption must use AWS KMS",
  s3_bucket_server_access_logging_enabled: "S3 server access logging must be enabled",
  s3_bucket_event_notifications_enabled: "S3 event notifications must be enabled",
  s3_bucket_lifecycle_enabled: "S3 lifecycle configuration must be enabled",
  s3_bucket_object_lock: "S3 Object Lock must be enabled",
  s3_bucket_no_mfa_delete: "S3 MFA Delete must be enabled",
  ec2_ebs_volume_encryption: "EBS volume encryption must be enabled",
  ec2_ebs_volume_snapshots_exists: "EBS volume must have an owned snapshot",
  rds_instance_backup_enabled: "RDS automated backups must be enabled",
  rds_instance_copy_tags_to_snapshots: "RDS must copy tags to snapshots",
  rds_instance_enhanced_monitoring_enabled: "RDS enhanced monitoring must be enabled",
  rds_instance_iam_authentication_enabled: "RDS IAM database authentication must be enabled",
  rds_instance_inside_vpc: "RDS instance must be deployed inside a VPC",
  rds_instance_integration_cloudwatch_logs: "RDS database logs must be exported to CloudWatch Logs",
  rds_instance_minor_version_upgrade_enabled: "RDS automatic minor version upgrades must be enabled",
  rds_instance_storage_encrypted: "RDS storage encryption must be enabled",
  ec2_securitygroup_allow_ingress_from_internet_to_all_ports: "EC2 security group must not expose all ports to the internet",
  ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports: "EC2 security group must not expose high-risk TCP ports",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22: "EC2 security group must not expose SSH port 22",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389: "EC2 security group must not expose RDP port 3389",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888: "EC2 security group must not expose Cassandra ports",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601: "EC2 security group must not expose Elasticsearch or Kibana ports",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21: "EC2 security group must not expose FTP ports",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092: "EC2 security group must not expose Kafka port 9092",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211: "EC2 security group must not expose Memcached port 11211",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018: "EC2 security group must not expose MongoDB ports",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306: "EC2 security group must not expose MySQL port 3306",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483: "EC2 security group must not expose Oracle ports",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432: "EC2 security group must not expose PostgreSQL port 5432",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379: "EC2 security group must not expose Redis port 6379",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434: "EC2 security group must not expose SQL Server ports",
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23: "EC2 security group must not expose Telnet port 23",
  ec2_securitygroup_allow_wide_open_public_ipv4: "EC2 security group must not contain broad public IPv4 ranges",
  ec2_securitygroup_default_restrict_traffic: "Default EC2 security group must not allow traffic",
  ec2_securitygroup_from_launch_wizard: "EC2 security group must not be a Launch Wizard group",
  ec2_securitygroup_with_many_ingress_egress_rules: "EC2 security group must not exceed 50 ingress or egress entries",
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({
    "&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"
  })[char]);
}

function humanize(value) {
  return String(value ?? "").replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());
}

function friendlyState(value) {
  return ({
    open:"Preparing", prioritized:"Awaiting cloud check", validated:"Confirmed risk",
    closed_no_action:"No longer detected", blocked:"Needs attention",
    plan_ready:"Ready for separate review", awaiting_approval:"Awaiting human review",
    approved:"Approved outside shadow mode", remediated:"Resolved", rolled_back:"Rolled back",
  })[value] || humanize(value);
}

function shortId(value, width = 36) {
  const text = String(value ?? "");
  return text.length > width ? `${text.slice(0, 16)}…${text.slice(-12)}` : text;
}

function tenant() {
  return $("#tenant").value.trim();
}

function rememberTenant(value) {
  try { window.localStorage.setItem("elcapitan-shadow-tenant", value); }
  catch (_) { /* optional */ }
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

function clearToast() {
  const toast = $("#toast");
  toast.classList.remove("show", "error");
  toast.textContent = "";
}

function setBusy(value) {
  busy = value;
  document.querySelectorAll("button").forEach(button => {
    button.disabled = value || button.dataset.availabilityDisabled === "true";
  });
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
  if (counts.confirmed) return ["bad", "Confirmed in cloud", `${counts.confirmed} finding${counts.confirmed === 1 ? "" : "s"} still present`];
  if (counts.not_confirmed) return ["good", "No longer detected", "Current configuration does not reproduce the finding"];
  if (counts.unavailable) return ["bad", "Could not check", "Access was denied, incomplete, or unavailable"];
  if (counts.unsupported) return ["warn", "Not supported yet", "Kept visible without inferring a result"];
  if (item.unsupported_findings && !item.supported_findings) return ["warn", "Not supported yet", "No deterministic check is registered"];
  if (!connectors[item.provider]?.ready_for_live_validation) return ["warn", "Cloud access needed", "Import is complete; read-only connector is offline"];
  return ["warn", "Ready to check", "No cloud request has been made"];
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
  if (!capabilities.length) return "Not supported yet · no cloud conclusion inferred";
  const grades = [...new Set(capabilities.map(value => evidenceGrade(value.evidence_grade)))];
  const planning = capabilities.some(value => value.remediation_planning) ? "available separately" : "unavailable";
  const execution = capabilities.some(value => value.live_execution) ? "separately gated" : "unavailable";
  return `Cloud check available · plan ${planning} · cloud change ${execution} · evidence ${grades.join(" / ")}`;
}

function nextStepSummary(item) {
  const counts = item.validation_counts || {};
  if (counts.confirmed) return ["good", "Review evidence", "Decide whether this should enter a separate planning review"];
  if (counts.not_confirmed) return ["good", "No action indicated", "Keep the evidence and reconcile the scanner result"];
  if (counts.unavailable) return ["bad", "Resolve access and retry", "No conclusion was inferred from incomplete evidence"];
  if (counts.unsupported || (!item.supported_findings && item.unsupported_findings)) return ["warn", "Keep in scanner workflow", "El Capitan cannot check this control yet"];
  if (canValidate(item)) return ["warn", "Run read-only check", "Compare the finding with current cloud configuration"];
  return ["warn", "Connect when ready", "Import review is available without cloud access"];
}

function canValidate(item) {
  const ready = connectors[item.provider]?.ready_for_live_validation;
  return item.state === "prioritized" && item.supported_findings > 0 && ready;
}

function renderLifecycle(document) {
  const summary = document.summary || {};
  const validation = summary.validation_outcome_counts || {};
  const checked = Object.values(validation).reduce((total, value) => total + value, 0);
  const checkedCases = document.cases.filter(
    item => Object.keys(item.validation_counts || {}).length).length;
  const validatedCases = document.cases.filter(
    item => (item.validation_counts || {}).confirmed > 0).length;
  const confirmed = validation.confirmed || 0;
  const cleared = validation.not_confirmed || 0;
  const unavailable = validation.unavailable || 0;
  const priorities = summary.priority_counts || {};
  const sources = Object.entries(summary.source_counts || {});
  const formats = Object.entries(summary.format_counts || {});
  const sourceText = sources.length ? sources.map(([name, count]) => `${name} · ${count}`).join(" / ") : "Source unavailable";
  const formatText = formats.length ? formats.map(([name, count]) => `${name} · ${count}`).join(" / ") : "Normalized schema unavailable";
  const readyForPlan = summary.review_ready_cases || 0;
  const planningCapable = summary.planning_capable_cases || 0;
  const executionCapable = summary.execution_capable_cases || 0;
  const supportedProviders = [...new Set(document.cases
    .filter(item => item.supported_findings > 0)
    .map(item => item.provider.toUpperCase()))];
  const readyProviders = supportedProviders.filter(
    provider => connectors[provider.toLowerCase()]?.ready_for_live_validation);
  const connectorState = supportedProviders.length ?
    `${supportedProviders.join(" / ")} read-only connector ${readyProviders.length ? "ready" : "offline"}` :
    "No supported cloud check is registered";
  const packaged = document.cases.filter(item => ["awaiting_approval", "approved", "remediated", "rolled_back"].includes(item.state)).length;
  const awaitingReview = document.cases.filter(item => item.state === "awaiting_approval").length;
  const approved = document.cases.filter(item => item.state === "approved").length;
  const monitored = document.cases.filter(item => ["remediated", "rolled_back"].includes(item.state)).length;

  $("#stage-findings-value").textContent = summary.total_findings || 0;
  $("#stage-findings-detail").textContent = sourceText;
  $("#stage-normalized-value").textContent = summary.total_findings || 0;
  $("#stage-normalized-detail").textContent = `${formatText} · ${summary.total_cases || 0} exact resources`;
  $("#stage-validated-value").textContent = checkedCases ? `${validatedCases} cases` : "Not run";
  $("#stage-validated-detail").textContent = checked ?
    `${checkedCases} resource cases checked · ${confirmed}/${summary.supported_findings || 0} supported findings confirmed · ${unavailable} unavailable` :
    `${summary.supported_findings || 0} supported and waiting · ${connectorState}`;
  $("#stage-prioritized-value").textContent = summary.total_cases || 0;
  $("#stage-prioritized-detail").textContent = `${priorities.urgent || 0} urgent · ${priorities.high || 0} high · ${priorities.normal || 0} normal · ${priorities.low || 0} low`;
  $("#stage-outcome-value").textContent = confirmed ? `${confirmed} confirmed` : `${summary.total_cases || 0} to review`;
  $("#stage-outcome-detail").textContent = checked ?
    `${cleared} no longer detected · ${unavailable} need evidence` :
    "Prioritized queue ready; cloud confirmation pending";
  $("#stage-plan-value").textContent = readyForPlan ? `${readyForPlan} candidates` : "0 candidates";
  $("#stage-plan-detail").textContent = readyForPlan ?
    "Validated evidence is ready; authoritative IaC and human routes are still required" :
    `${planningCapable} case${planningCapable === 1 ? "" : "s"} include a planning-capable control`;
  $("#stage-package-value").textContent = packaged;
  $("#stage-review-value").textContent = awaitingReview;
  $("#stage-deploy-value").textContent = approved ? `${approved} approved` : "Locked";
  $("#stage-deploy-detail").textContent = executionCapable ?
    `${executionCapable} case${executionCapable === 1 ? "" : "s"} contain a separately gated action control` :
    "No executable control in this queue";
  $("#stage-monitor-value").textContent = monitored || "—";
  $("#lifecycle-foot-detail").textContent = `${summary.supported_findings || 0} findings have deterministic validation support; ${planningCapable} resource cases contain a planning-capable control; ${executionCapable} contain a separately gated live-action control.`;

  const validationStage = $("#stage-validated-value").closest(".stage");
  validationStage.classList.toggle("complete", checked > 0);
  validationStage.classList.toggle("current", checked === 0);
}

function renderFleet(document) {
  fleet = document;
  clearToast();
  $("#tenant").value = document.tenant_id;
  rememberTenant(document.tenant_id);
  const summary = document.summary;
  const hasCases = summary.total_cases > 0;
  $("#welcome-panel").classList.toggle("hidden", hasCases);
  $("#fleet-controls").classList.toggle("hidden", !hasCases);
  $("#lifecycle-board").classList.toggle("hidden", !hasCases);
  $("#fleet-metrics").classList.toggle("hidden", !hasCases);
  $("#fleet-card").classList.toggle("hidden", !hasCases);
  const readyCases = document.cases.filter(canValidate);
  const readyFindings = readyCases.reduce(
    (total, item) => total + item.supported_findings, 0);
  const validateAll = $("#validate-eligible");
  validateAll.dataset.availabilityDisabled = String(readyCases.length === 0);
  validateAll.disabled = busy || readyCases.length === 0;
  validateAll.textContent = readyCases.length ?
    `Check ${readyCases.length} ready` : "No cloud checks ready";
  validateAll.title = readyCases.length ?
    `Run bounded read-only checks for ${readyCases.length} ready resource${readyCases.length === 1 ? "" : "s"}` :
    "Connect a read-only cloud account before running supported checks";
  $("#metric-cases").textContent = summary.total_cases;
  $("#metric-findings").textContent = summary.total_findings;
  $("#metric-supported").textContent = `${summary.supported_findings} supported · ${readyFindings} ready now · ${summary.unsupported_findings} not supported`;
  $("#case-count").textContent = `${summary.total_cases} resource${summary.total_cases === 1 ? "" : "s"} · ${summary.total_findings} observation${summary.total_findings === 1 ? "" : "s"}`;
  const stateText = Object.entries(summary.case_state_counts).map(([key, value]) => `${value} ${friendlyState(key).toLowerCase()}`).join(" · ");
  $("#metric-states").textContent = stateText || "No resources";
  const validationOutcomes = document.cases.reduce((totals, item) => {
    Object.entries(item.validation_counts || {}).forEach(([status, count]) => {
      totals[status] = (totals[status] || 0) + count;
    });
    return totals;
  }, {});
  const checkedCases = document.cases.filter(item => Object.keys(item.validation_counts || {}).length).length;
  $("#metric-validated").textContent = checkedCases || "Not run";
  const outcomeText = Object.entries(validationOutcomes).map(([status, count]) => `${count} ${humanize(status)}`).join(" · ");
  $("#metric-validation-detail").textContent = outcomeText ||
    `${summary.supported_findings} supported findings are waiting for read-only cloud access`;
  const highest = document.cases[0];
  $("#metric-risk").textContent = highest ? Math.round(highest.risk_score) : "—";
  $("#metric-urgency").textContent = highest ? `${humanize(highest.urgency)} · ${highest.provider.toUpperCase()}` : "Not assessed";
  const resourceWord = summary.total_cases === 1 ? "resource" : "resources";
  $("#mission").textContent = `${summary.total_cases} ${resourceWord} in the evidence-to-outcome journey`;
  $("#mission-detail").textContent = "Trace every result from scanner source through normalization, validation, priority, and the next human decision.";
  renderLifecycle(document);

  if (!document.cases.length) {
    $("#fleet-body").innerHTML = '<tr><td colspan="6" class="empty">No findings have been ingested for this tenant.</td></tr>';
    return;
  }
  $("#fleet-body").innerHTML = document.cases.map(item => {
    const [validationTone, validationLabel, validationReason] = validationSummary(item);
    const [nextTone, nextLabel, nextReason] = nextStepSummary(item);
    const title = controlTitle(item.rule_ids[0], item.finding_titles.find(Boolean));
    const rank = item.portfolio_rank ? ` · #${item.portfolio_rank}` : "";
    const context = item.asset_context || {};
    const contextSummary = context.environment ?
      `${humanize(context.environment)} · ${context.owner || "owner not supplied"}${context.synthetic_business_context ? " · synthetic business label" : ""}` :
      "No per-resource business context";
    const sources = [...new Set(item.finding_sources || [])];
    const formats = [...new Set(item.finding_formats || [])];
    const sourceSummary = `${sources.join(" / ") || "Unknown scanner"} · ${formats.join(" / ") || "normalized record"}`;
    return `<tr>
      <td data-label="Priority"><span class="risk">${escapeHtml(Math.round(item.risk_score))}</span><span class="urgency">${escapeHtml(item.urgency)}${escapeHtml(rank)}</span></td>
      <td data-label="Finding and source"><span class="source-chip">${escapeHtml(sourceSummary)}</span><span class="title">${item.synthetic ? '<span class="sample-tag">SYNTHETIC INPUT</span>' : '<span class="sample-tag">REAL INPUT</span>'}${escapeHtml(title)}</span><span class="reason">${item.finding_ids.length} scanner observation${item.finding_ids.length === 1 ? "" : "s"} grouped on this resource</span></td>
      <td data-label="Normalized scope"><span class="provider">${escapeHtml(item.provider)}</span><span class="asset" title="${escapeHtml(item.resource_uids[0])}">${escapeHtml(shortId(item.resource_uids[0]))}</span><span class="state">${escapeHtml(friendlyState(item.state))}</span><span class="reason">${escapeHtml(contextSummary)} · ${escapeHtml(capabilitySummary(item))}</span></td>
      <td data-label="Validation"><span class="status ${validationTone}"><i></i>${escapeHtml(validationLabel)}</span><span class="reason">${escapeHtml(validationReason)}</span></td>
      <td data-label="Outcome"><span class="status ${nextTone}"><i></i>${escapeHtml(nextLabel)}</span><span class="reason">${escapeHtml(nextReason)}</span></td>
      <td data-label="Actions"><div class="row-actions">${canValidate(item) ? `<button type="button" class="primary small" data-validate="${escapeHtml(item.case_id)}">Check cloud state</button>` : ""}<button type="button" class="ghost small" data-case="${escapeHtml(item.case_id)}">View result</button></div></td>
    </tr>`;
  }).join("");
}

function renderConnectors(document) {
  connectors = document;
  $("#connectors").innerHTML = Object.values(document).map(item => {
    const ready = item.ready_for_live_validation;
    const explanation = ready ? "Ready for bounded read-only cloud checks." :
      item.configuration_errors?.length ? item.configuration_errors[0] :
      item.executable === "azure-arm-rest" ? "Managed identity is not available to the validator." :
      item.executable_available ? `${item.missing_environment.length} read-only credential setting(s) missing. Configure them outside this browser.` : `${item.executable || "Cloud"} CLI is unavailable on the server.`;
    const controls = item.supported_rule_ids.length;
    return `<article class="connector"><header><strong>${escapeHtml(item.provider)}</strong><span class="${ready ? "ready" : "not-ready"}">${ready ? "● READY" : "○ OFFLINE"}</span></header><p>${escapeHtml(explanation)}</p><code>${controls} deterministic control${controls === 1 ? "" : "s"} available · no write permissions</code></article>`;
  }).join("");
  if (fleet) renderFleet(fleet);
}

async function loadConnectors() {
  renderConnectors(await request("/api/connectors"));
}

async function loadFleet() {
  const selected = tenant();
  if (!selected) throw new Error("Enter a workspace name");
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

function friendlyBlocker(value, supportsValidation = true) {
  const message = String(value || "");
  if (message.includes("outside the preapproval workflow")) {
    return supportsValidation ?
      "Run a supported cloud check before considering a separate planning review." :
      "Keep this finding in the scanner workflow until a deterministic check is available.";
  }
  if (message.includes("no bound validation result")) {
    return supportsValidation ?
      "No confirmed cloud evidence exists yet." :
      "No confirmed cloud evidence can be collected for this control yet.";
  }
  return message;
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

function renderGroupedFindings(findings) {
  return findings.map((finding, index) => {
    const ocsf = finding.record?.ocsf || {};
    const title = controlTitle(ocsf.rule_id, ocsf.title);
    const score = Math.round(finding.priority?.score || 0);
    return `<div class="record"><header><strong>${escapeHtml(title)}</strong><span class="record-badge ${index === 0 ? "current" : "superseded"}">${index === 0 ? "SCORE-DRIVING" : `SCORE ${score}`}</span></header><p>${escapeHtml(humanize(finding.record?.severity || "unknown"))} severity · ${escapeHtml(ocsf.rule_id || "unidentified control")}</p></div>`;
  }).join("");
}

async function openCase(caseId) {
  const detail = await request(`/api/cases/${encodeURIComponent(caseId)}?tenant=${encodeURIComponent(tenant())}`);
  const item = fleet?.cases.find(candidate => candidate.case_id === caseId);
  const caseDoc = detail.case;
  const finding = detail.findings[0] || {};
  const assetContext = item?.asset_context || finding.record?.vendor_extensions?.elcapitan_asset_context || {};
  const ocsf = finding.record?.ocsf || {};
  const displayTitle = controlTitle(ocsf.rule_id, ocsf.title || item?.finding_titles?.[0]);
  const source = finding.record?.provenance || {};
  const sourceFormat = item?.finding_formats?.[0] || "OCSF";
  const [tone, validation] = validationSummary(item || {validation_counts:{}, unsupported_findings:0});
  const safety = detail.safety_boundary;
  const promotion = detail.promotion || {};
  const capability = (item?.capabilities || []).find(value => value.rule_id === ocsf.rule_id);
  const supportsValidation = Boolean(capability?.live_validation);
  const connectorReady = Boolean(connectors[item?.provider]?.ready_for_live_validation);
  const planningStatus = promotion.status === "ready_for_preapproval" ?
    "Ready for separate review" : !supportsValidation ?
      "Not available for this control" : item?.state === "prioritized" ?
      "Cloud check required" : "Not ready";
  const resultCounts = item?.validation_counts || {};
  const resultStatus = resultCounts.confirmed ? "confirmed" :
    resultCounts.not_confirmed ? "not_confirmed" :
    resultCounts.unavailable ? "unavailable" :
    resultCounts.unsupported ? "unsupported" : "awaiting";
  const resultExplanation = ({
    confirmed:"The current cloud configuration still matches the scanner finding.",
    not_confirmed:"The current cloud configuration no longer reproduces the scanner finding.",
    unavailable:"El Capitan could not collect complete evidence, so it did not infer a result.",
    unsupported:"This finding remains visible, but El Capitan does not support a deterministic check for it yet.",
  })[resultStatus] || "This finding has been imported but has not made a cloud request.";
  $("#detail-content").innerHTML = `
    <div class="detail-hero"><div><span class="status ${tone}"><i></i>${escapeHtml(validation)}</span><h2 id="detail-title">${escapeHtml(displayTitle)}</h2></div><div class="detail-meta"><strong>${escapeHtml(Math.round(caseDoc.priority?.score || 0))}</strong><span>${escapeHtml(humanize(caseDoc.priority?.urgency || "unassessed"))} risk</span></div></div>
    <div class="detail-actions">${item && canValidate(item) ? `<button type="button" class="primary" data-validate="${escapeHtml(caseId)}">Check ${escapeHtml(item.provider.toUpperCase())} cloud state</button>` : ""}<span class="pill">${escapeHtml(friendlyState(caseDoc.state))}</span><span class="pill sample-pill">${item?.synthetic ? "Synthetic input" : "Real scanner input"}</span></div>
    <div class="detail-grid">
      <section class="detail-section full outcome-summary"><h3>What this result means</h3><p>${escapeHtml(resultExplanation)}</p></section>
      <section class="detail-section"><h3>Finding source</h3>${fact("Scanner", source.product || item?.finding_sources?.[0] || "Unknown")}${fact("Scanner version", source.product_version || "Not supplied")}${fact("Source format", sourceFormat)}${fact("Normalized schema", `OCSF ${ocsf.version || "unknown"}`)}${fact("Observed", source.observed_at || "Not supplied")}</section>
      <section class="detail-section"><h3>Score-driving observation</h3>${fact("Control", displayTitle)}${fact("Severity", finding.record?.severity)}${fact("Observation score", finding.priority?.score ?? "Unknown")}${fact("Grouped observations", caseDoc.finding_ids.length)}${fact("Rule ID", ocsf.rule_id)}</section>
      <section class="detail-section"><h3>Cloud scope</h3>${fact("Provider", finding.provider?.toUpperCase())}${fact("Account", finding.account)}${fact("Resource", finding.resource_uid)}${fact("Service", (caseDoc.service_ids || []).join(", ") || "Not supplied")}</section>
      <section class="detail-section"><h3>Asset context</h3>${fact("Environment", assetContext.environment ? humanize(assetContext.environment) : "Not supplied")}${fact("Owner", assetContext.owner || "Not supplied")}${fact("Criticality", assetContext.asset_criticality ?? "Unknown")}${fact("Internet exposure", assetContext.internet_exposed === true ? "Observed internet-facing" : assetContext.internet_exposed === false ? "Observed internal" : "Unknown")}${fact("Context source", assetContext.context_source || "Not supplied")}${fact("Business labels", assetContext.synthetic_business_context ? "Synthetic trial assignment" : assetContext.environment ? "Supplied context" : "Not supplied")}${fact("Context digest", assetContext.context_digest ? shortId(assetContext.context_digest) : "Not supplied")}</section>
      <section class="detail-section"><h3>What El Capitan can do</h3>${fact("Check cloud state", capability?.live_validation ? (connectorReady ? "Ready" : "Available after connector setup") : "Not supported")}${fact("Prepare a plan", capability?.remediation_planning ? "Available separately" : "Not available")}${fact("Change cloud state", capability?.live_execution ? "Separately gated" : "Not available")}${fact("Evidence grade", evidenceGrade(capability?.evidence_grade))}</section>
      <section class="detail-section"><h3>Why this score</h3><p class="history-note">The resource case uses its highest observation score. Findings are not added together.</p>${(finding.priority?.factors || []).map(value => `<div class="record"><p>${escapeHtml(value)}</p></div>`).join("") || '<p class="empty compact">No additional context supplied.</p>'}</section>
      <details class="detail-section full evidence-disclosure"><summary>All ${caseDoc.finding_ids.length} scanner observations on this resource</summary><div>${renderGroupedFindings(detail.findings)}</div></details>
      <section class="detail-section"><h3>Read-only safety boundary</h3>${fact("Cloud checks", safety.mode === "shadow" ? "Allowed for supported controls" : "Unknown")}${fact("External models", safety.external_models ? "Allowed" : "Disabled")}${fact("Approval", safety.approval ? "Allowed" : "Unavailable")}${fact("Scheduling", safety.scheduling ? "Allowed" : "Unavailable")}${fact("Cloud changes", safety.execution ? "Allowed" : "Unavailable")}</section>
      <section class="detail-section full"><h3>What happens next</h3>${fact("Planning readiness", planningStatus)}${fact("Exact planning scope", (promotion.confirmed_rule_ids || []).join(", ") || "None")}${fact("Scanner findings outside this plan", (promotion.excluded_finding_ids || []).length)}${(promotion.blockers || []).map(value => `<div class="record"><p>${escapeHtml(friendlyBlocker(value, supportsValidation))}</p></div>`).join("")}${promotion.status === "ready_for_preapproval" ? `<p class="history-note">Still needed before a plan can be prepared:</p>${(promotion.required_inputs || []).map(value => `<div class="record"><p>${escapeHtml(value)}</p></div>`).join("")}` : ""}</section>
      <details class="detail-section full evidence-disclosure"><summary>Evidence details and immutable history</summary><div><h3>${caseDoc.state === "awaiting_approval" ? "Current approval package" : "Current evidence chain"}</h3>${renderEvidenceRecords(detail.records, caseDoc)}<h3 class="timeline-heading">Immutable timeline</h3>${detail.events.map(event => `<div class="record"><strong>${escapeHtml(humanize(event.transition))}</strong><p>${escapeHtml(friendlyState(event.from_state))} → ${escapeHtml(friendlyState(event.to_state))} · ${escapeHtml(event.actor)}</p><code>${escapeHtml(event.occurred_at)} · ${escapeHtml(shortId(event.event_id))}</code></div>`).join("")}</div></details>
    </div>`;
  $("#detail-dialog").showModal();
}

async function validateCase(caseId) {
  setBusy(true);
  try {
    const result = await post("/api/validate", {tenant_id:tenant(), case_id:caseId});
    renderFleet(result.fleet);
    showToast(`Cloud check completed: ${friendlyState(result.case.state)}`);
    if ($("#detail-dialog").open) await openCase(caseId);
  } finally { setBusy(false); }
}

async function validateEligible() {
  const caseIds = (fleet?.cases || []).filter(canValidate).map(item => item.case_id);
  if (!caseIds.length) throw new Error("No findings are ready for a read-only cloud check");
  if (caseIds.length > 100) throw new Error("Check at most 100 resources at a time");
  setBusy(true);
  try {
    const result = await post("/api/validate-batch", {tenant_id:tenant(), case_ids:caseIds});
    renderFleet(result.fleet);
    showToast(`${result.processed} resource${result.processed === 1 ? "" : "s"} checked against current cloud configuration`);
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

function parsedAssets() {
  const text = $("#asset-json").value.trim();
  if (!text) return [];
  let document;
  try { document = JSON.parse(text); }
  catch (_) { throw new Error("Asset context is not valid JSON"); }
  const assets = Array.isArray(document) ? document : document?.assets;
  if (!Array.isArray(assets)) throw new Error("Asset context must be an array or an object with an assets array");
  return assets;
}

function intakeContext() {
  return {
    asset_criticality:Number($("#asset-criticality").value),
    exploit_probability:Number($("#exploit-probability").value),
    reachable:$("#reachable").checked,
    service_ids:$("#service-ids").value.split(",").map(value => value.trim()).filter(Boolean),
  };
}

function invalidatePreview() {
  intakePreview = null;
  $("#import-preview").classList.add("hidden");
  $("#import-preview").innerHTML = "";
  $("#preview-intake").classList.remove("hidden");
  $("#confirm-intake").classList.add("hidden");
}

function renderIntakePreview(document) {
  intakePreview = document;
  const accepted = document.accepted_failures;
  const formats = Object.entries(document.format_counts).map(([name, count]) => `${count} ${name}`).join(" · ");
  const providers = Object.entries(document.provider_counts).map(([name, count]) => `${count} ${name.toUpperCase()}`).join(" · ") || "No failing findings";
  const skipped = document.skipped.pass + document.skipped.manual;
  const unsupported = document.unsupported_findings;
  const destination = tenant() || "Unnamed workspace";
  const assets = document.asset_context || {};
  const contextNote = assets.rows ?
    `<br><strong>${assets.matched_resources} of ${document.resource_count} resources matched asset context.</strong> ${assets.unmatched_resources} finding resource${assets.unmatched_resources === 1 ? "" : "s"} without context · ${assets.unmatched_rows} asset row${assets.unmatched_rows === 1 ? "" : "s"} without a failing finding.<br>${assets.critical_resources} critical · ${assets.internet_exposed_resources} observed internet-facing · ${assets.synthetic_context_resources} with synthetic business labels.` :
    `<br><strong>No asset manifest supplied.</strong> Ordering uses scanner evidence and fallback values only.`;
  $("#import-preview").innerHTML = `<header><div><h3>${accepted ? `${accepted} failing finding${accepted === 1 ? "" : "s"} ready` : "No failing findings to import"}</h3><p>${escapeHtml(formats)} · ${escapeHtml(providers)} · Workspace ${escapeHtml(destination)}</p></div><span class="preview-ready">${accepted ? "Ready to import" : "Nothing to import"}</span></header>
    <div class="preview-stats"><div><strong>${accepted}</strong><span>Failing findings</span></div><div><strong>${document.supported_findings}</strong><span>Supported findings</span></div><div><strong>${document.resource_count}</strong><span>Resources</span></div><div><strong>${document.account_count}</strong><span>Cloud accounts</span></div></div>
    <p class="preview-notes"><strong>${document.supported_findings} supported for read-only checking · ${unsupported} not supported yet.</strong><br>Cloud readiness is shown after import.${contextNote}<br>${skipped} non-failing skipped: ${document.skipped.pass} passing · ${document.skipped.manual} manual.</p>`;
  $("#import-preview").classList.remove("hidden");
  $("#import-preview").scrollIntoView({block:"nearest"});
  $("#preview-intake").classList.add("hidden");
  $("#confirm-intake").textContent = `Import ${accepted} finding${accepted === 1 ? "" : "s"}`;
  $("#confirm-intake").classList.toggle("hidden", accepted === 0);
}

async function previewIntake() {
  setBusy(true);
  try {
    renderIntakePreview(await post("/api/intake-preview", {
      findings:parsedFindings(), assets:parsedAssets(), context:intakeContext(),
    }));
  } finally { setBusy(false); }
}

async function submitIntake(event) {
  event.preventDefault();
  if (!tenant()) throw new Error("Enter a workspace name before importing findings");
  if (!intakePreview?.accepted_failures) throw new Error("Review the import before saving findings");
  setBusy(true);
  try {
    const result = await post("/api/intake", {
      tenant_id:tenant(), findings:parsedFindings(), identity:"authenticated-shadow-upload",
      assets:parsedAssets(), context:intakeContext(),
    });
    renderFleet(result.fleet);
    $("#intake-dialog").close();
    invalidatePreview();
    const skipped = result.skipped || {pass:0, manual:0};
    const newObservations = result.received - result.duplicates;
    const placement = [
      result.created_cases ? `${result.created_cases} new resource${result.created_cases === 1 ? "" : "s"}` : "",
      result.attached_findings ? `${result.attached_findings} added to existing resource${result.attached_findings === 1 ? "" : "s"}` : "",
      result.duplicates ? `${result.duplicates} already present` : "",
    ].filter(Boolean).join(" · ");
    showToast(`${newObservations} new scanner observation${newObservations === 1 ? "" : "s"} · ${placement} · ${skipped.pass + skipped.manual} non-failing skipped`);
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
  $("#asset-json").value = JSON.stringify([{resource_uid:resource,environment:"test",owner:"security-lab",asset_criticality:.8,internet_exposed:true,reachable:true,runtime_dependency:false,compensating_control_strength:0,service_ids:["shadow-demo"],context_source:"synthetic-safe-sample",observed_at:new Date().toISOString(),evidence_references:["synthetic sample declaration"],synthetic_business_context:true}], null, 2);
  $("#file-label").textContent = "Safe synthetic Azure sample loaded";
  $("#asset-file-label").textContent = "Synthetic asset context loaded";
  $("#asset-context-status").textContent = "1 synthetic row";
  invalidatePreview();
}

function openIntake() {
  $("#finding-file").value = "";
  $("#asset-file").value = "";
  $("#finding-json").value = "";
  $("#asset-json").value = "";
  $("#file-label").textContent = "JSON only · maximum 10 MiB / 1,000 findings";
  $("#asset-file-label").textContent = 'JSON array or {"assets": [...]}';
  $("#asset-context-status").textContent = "Optional";
  $(".paste-input").open = false;
  $(".asset-context-input").open = false;
  invalidatePreview();
  $("#intake-dialog").showModal();
}

function showWorkspaceChooser() {
  clearToast();
  $("#welcome-panel").classList.remove("hidden");
  $("#fleet-controls").classList.add("hidden");
  $("#lifecycle-board").classList.add("hidden");
  $("#fleet-metrics").classList.add("hidden");
  $("#fleet-card").classList.add("hidden");
  if (fleet?.tenant_id) {
    $("#workspace-help").textContent = `Current workspace: ${fleet.tenant_id}. Keep this name to add findings here, or change it and choose Open existing.`;
  }
  $("#tenant").focus();
}

document.addEventListener("click", async event => {
  try {
    const close = event.target.closest("[data-close]")?.dataset.close;
    if (close) { $("#" + close).close(); return; }
    const caseId = event.target.closest("[data-case]")?.dataset.case;
    if (caseId) { await openCase(caseId); return; }
    const validateId = event.target.closest("[data-validate]")?.dataset.validate;
    if (validateId) { await validateCase(validateId); return; }
    if (event.target.closest("#open-intake")) { openIntake(); return; }
    if (event.target.closest("#start-upload")) { openIntake(); $("#finding-file").click(); return; }
    if (event.target.closest("#start-sample")) { openIntake(); loadSample(); await previewIntake(); return; }
    if (event.target.closest("#view-connectors")) { $("#connector-card").scrollIntoView({block:"start"}); return; }
    if (event.target.closest("#switch-workspace")) { showWorkspaceChooser(); return; }
    if (event.target.closest("#load-sample")) { loadSample(); await previewIntake(); return; }
    if (event.target.closest("#preview-intake")) { await previewIntake(); return; }
    if (event.target.closest("#validate-eligible")) { await validateEligible(); return; }
    if (event.target.closest("#load-fleet") || event.target.closest("#refresh")) {
      setBusy(true); try { await loadFleet(); } finally { setBusy(false); }
    }
  } catch (error) { showToast(error.message, true); setBusy(false); }
});

$("#finding-file").addEventListener("change", async event => {
  try {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) { showToast("File exceeds the 10 MiB request limit", true); return; }
    $("#finding-json").value = await file.text();
    $("#file-label").textContent = `${file.name} · ${Math.ceil(file.size / 1024)} KiB`;
    invalidatePreview();
    await previewIntake();
  } catch (error) { showToast(error.message, true); setBusy(false); }
});

$("#asset-file").addEventListener("change", async event => {
  try {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) { showToast("Asset context exceeds the 2 MiB limit", true); return; }
    $("#asset-json").value = await file.text();
    $("#asset-file-label").textContent = `${file.name} · ${Math.ceil(file.size / 1024)} KiB`;
    const rows = parsedAssets().length;
    $("#asset-context-status").textContent = `${rows} row${rows === 1 ? "" : "s"} attached`;
    $(".asset-context-input").open = false;
    invalidatePreview();
    if ($("#finding-json").value.trim()) await previewIntake();
  } catch (error) { showToast(error.message, true); setBusy(false); }
});

$("#intake-form").addEventListener("submit", event => submitIntake(event).catch(error => { showToast(error.message, true); setBusy(false); }));
$("#finding-json").addEventListener("input", invalidatePreview);
$("#asset-json").addEventListener("input", invalidatePreview);
$(".advanced-context").addEventListener("input", invalidatePreview);
$("#tenant").addEventListener("keydown", event => { if (event.key === "Enter") $("#load-fleet").click(); });

async function start() {
  try {
    const requested = new URLSearchParams(window.location.search).get("tenant");
    const saved = window.localStorage.getItem("elcapitan-shadow-tenant");
    if (requested && requested.length <= 100) $("#tenant").value = requested;
    else if (saved) $("#tenant").value = saved;
  } catch (_) { /* optional */ }
  try {
    await loadConnectors();
    await loadFleet();
  } catch (error) { showToast(error.message, true); }
}

start();
