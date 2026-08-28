"""Local-only customer shadow intake and portfolio reporting."""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path

from .finding import prowler_outcome
from .intake import IntakeContext
from .shadow_control import ShadowFleetControlPlane


def _restricted_write(path: Path, content: str) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)


def _documents(path: Path) -> tuple[list[dict], bytes]:
    payload = path.read_bytes()
    document = json.loads(payload)
    documents = document if isinstance(document, list) else [document]
    if not documents or any(not isinstance(item, dict) for item in documents):
        raise ValueError("offline input must contain one or more JSON finding objects")
    return documents, payload


def generate_offline_report(*, input_path: Path, tenant_id: str,
                            workdir: Path) -> dict:
    documents, payload = _documents(input_path)
    if workdir.exists() and any(workdir.iterdir()):
        raise ValueError("offline workdir must be empty")
    control = ShadowFleetControlPlane(workdir, host_env={})
    intake = control.intake(
        tenant_id=tenant_id, documents=documents,
        context=IntakeContext(internet_exposed=None),
        identity="offline-customer-shadow-report",
    )
    snapshot = control.snapshot(tenant_id=tenant_id)
    registry = control.registry
    outcomes = Counter()
    failure_severities = Counter()
    for document in documents:
        outcome = prowler_outcome(document) or "NON_PROWLER"
        outcomes[outcome] += 1
        if outcome == "FAIL":
            failure_severities[str(document.get("severity") or "Unknown").title()] += 1

    rule_counts = Counter()
    resource_type_counts = Counter()
    supported_rule_counts = Counter()
    unsupported_rule_counts = Counter()
    complete_cases = []
    supported_cases = 0
    for case in snapshot["cases"]:
        findings = control.findings.list_for_case(case["case_id"])
        stored_case = control.cases.get(case["case_id"])
        severities = Counter()
        for finding in findings:
            rule = str(finding.record["ocsf"].get("rule_id", ""))
            resource_type = str(finding.record["resource"].get("type", "") or "Unknown")
            severity = str(finding.record.get("severity") or "Unknown").title()
            rule_counts[rule] += 1
            resource_type_counts[resource_type] += 1
            severities[severity] += 1
            destination = (
                supported_rule_counts
                if registry.get(finding.provider, rule)
                else unsupported_rule_counts)
            destination[rule] += 1
        if case["supported_findings"]:
            supported_cases += 1
        complete_cases.append({
            **case,
            "severity_counts": dict(sorted(severities.items())),
            "risk_factors": (
                list(stored_case.priority.factors) if stored_case.priority else []),
        })

    return {
        "report_version": "OfflineShadowPortfolio.v1",
        "tenant_id": tenant_id,
        "source": {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
            "records": len(documents),
        },
        "safety_boundary": {
            "mode": "offline_shadow",
            "cloud_requests": False,
            "external_models": False,
            "approval": False,
            "scheduling": False,
            "execution": False,
        },
        "intake": {
            "submitted": intake.submitted,
            "accepted_failures": intake.received,
            "skipped_pass": intake.skipped_pass,
            "skipped_manual": intake.skipped_manual,
            "created_cases": intake.created_cases,
            "duplicates": intake.duplicates,
            "outcome_counts": dict(sorted(outcomes.items())),
            "failure_severity_counts": dict(sorted(failure_severities.items())),
        },
        "coverage": {
            "supported_findings": snapshot["summary"]["supported_findings"],
            "unsupported_findings": snapshot["summary"]["unsupported_findings"],
            "cases_with_supported_controls": supported_cases,
            "unsupported_only_cases": len(complete_cases) - supported_cases,
            "supported_rules": dict(supported_rule_counts.most_common()),
            "unsupported_rules": dict(unsupported_rule_counts.most_common()),
            "resource_types": dict(resource_type_counts.most_common()),
        },
        "priority": {
            "classification": "scanner_evidence_provisional",
            "limitations": [
                "no customer asset criticality is supplied",
                "no exploit probability or known-exploited enrichment is supplied",
                "no service ownership, dependency, or business-impact context is supplied",
                "unvalidated scanner findings are not schedulable remediation work",
            ],
            "cases": complete_cases,
        },
        "top_rules": [
            {"rule_id": rule, "findings": count}
            for rule, count in rule_counts.most_common()
        ],
    }


def markdown_summary(report: dict) -> str:
    intake, coverage = report["intake"], report["coverage"]
    cases = report["priority"]["cases"]
    lines = [
        "# Offline customer shadow report",
        "",
        f"Tenant: `{report['tenant_id']}`",
        "",
        "This is a scanner-evidence provisional portfolio. It makes no cloud "
        "requests, model calls, approval decisions, schedules, or changes.",
        "",
        "## Intake accounting",
        "",
        f"- Submitted records: {intake['submitted']}",
        f"- Accepted explicit FAIL records: {intake['accepted_failures']}",
        f"- Skipped PASS records: {intake['skipped_pass']}",
        f"- Skipped MANUAL records: {intake['skipped_manual']}",
        f"- Resource cases created: {intake['created_cases']}",
        "",
        "## Deterministic coverage",
        "",
        f"- Supported findings: {coverage['supported_findings']}",
        f"- Unsupported findings: {coverage['unsupported_findings']}",
        f"- Cases with at least one supported control: "
        f"{coverage['cases_with_supported_controls']}",
        f"- Unsupported-only cases: {coverage['unsupported_only_cases']}",
        "",
        "## Severity of accepted failures",
        "",
        "| Severity | Findings |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {severity} | {count} |"
        for severity, count in intake["failure_severity_counts"].items())
    lines.extend([
        "", "## Most frequent failing controls", "",
        "Prowler titles describe the desired control. Because this report accepts "
        "only explicit `FAIL` records, the stated condition was not satisfied at "
        "scan time.",
        "", "| Rule | Findings | Supported |", "|---|---:|:---:|",
    ])
    supported = coverage["supported_rules"]
    lines.extend(
        f"| `{item['rule_id']}` | {item['findings']} | "
        f"{'yes' if item['rule_id'] in supported else 'no'} |"
        for item in report["top_rules"][:25])
    candidates = [case for case in cases if case["supported_findings"]]
    lines.extend([
        "", "## Deterministic live-validation candidates", "",
        "| Resource | Risk | Supported | Unsupported siblings | Rules |",
        "|---|---:|---:|---:|---|",
    ])
    for case in candidates:
        resource = (case["resource_uids"][0].rstrip("/").rsplit("/", 1)[-1]
                    if case["resource_uids"] else "")
        supported_rules = [
            rule for rule in case["rule_ids"] if rule in supported]
        lines.append(
            f"| `{resource}` | {case['risk_score']:.0f} | "
            f"{case['supported_findings']} | {case['unsupported_findings']} | "
            f"{', '.join(f'`{rule}`' for rule in supported_rules)} |")
    lines.extend([
        "", "## Highest scanner-evidence cases", "",
        "| Risk | Severity | Findings | Supported | Primary title |",
        "|---:|---|---:|---:|---|",
    ])
    for case in cases[:25]:
        title = (case["finding_titles"][0] if case["finding_titles"] else "").replace(
            "|", "\\|")
        severities = ", ".join(
            f"{name}:{count}" for name, count in case["severity_counts"].items())
        lines.append(
            f"| {case['risk_score']:.0f} | {severities} | "
            f"{len(case['finding_ids'])} | {case['supported_findings']} | {title} |")
    lines.extend([
        "",
        "A risk score can include scanner-provided exposure categories. The full "
        "JSON report records each case's deterministic `risk_factors`.",
    ])
    lines.extend(["", "## Missing context before customer-grade prioritization", ""])
    lines.extend(f"- {item}" for item in report["priority"]["limitations"])
    lines.append("")
    return "\n".join(lines)


def write_offline_report(*, input_path: Path, tenant_id: str, workdir: Path,
                         json_output: Path, markdown_output: Path) -> dict:
    report = generate_offline_report(
        input_path=input_path, tenant_id=tenant_id, workdir=workdir)
    _restricted_write(
        json_output, json.dumps(report, indent=2, sort_keys=True) + "\n")
    _restricted_write(markdown_output, markdown_summary(report))
    return report
