"""Local product CLI. No agent runtime or Hermes process is required."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .agents import RecordedContractRuntime
from .asff import asff_to_ocsf
from .case_store import SqliteCaseStore
from .case_validation import CaseValidationService
from .cases import case_to_dict
from .cloud import CloudState
from .evidence import Collector
from .finding_store import SqliteFindingStore
from .intake import IntakeContext, RemediationIntake
from .observability import (
    UsageSample, WindowPolicy, capture_azure_monitor_usage, load_usage_samples,
    utc_text,
)
from .openai_runtime import OpenAIResponsesRuntime
from .orchestration import PreApprovalOrchestrator
from .product_records import SqliteProductRecordStore, product_record_to_dict
from .remediation_planning import (
    RecordedAgentRuntime, RemediationPlanningService, SubprocessTerraformRunner,
    TerraformChecksFailed,
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="elcapitan")
    sub = parser.add_subparsers(dest="command", required=True)
    intake = sub.add_parser("intake", help="ingest OCSF or ASFF findings")
    intake.add_argument("input", type=Path)
    intake.add_argument("--tenant", required=True)
    intake.add_argument("--db", type=Path, required=True)
    intake.add_argument("--artifacts", type=Path, required=True)
    intake.add_argument("--identity", default="local-intake")
    intake.add_argument("--asset-criticality", type=float, default=0.0)
    intake.add_argument("--exploit-probability", type=float, default=0.0)
    intake.add_argument("--internet-exposed", action="store_true", default=None)
    intake.add_argument("--reachable", action="store_true")
    intake.add_argument("--known-exploited", action="store_true")
    intake.add_argument("--active-exploitation", action="store_true")
    intake.add_argument("--runtime-dependency", action="store_true")
    intake.add_argument("--compensating-control-strength", type=float, default=0.0)
    intake.add_argument("--service-id", action="append", default=[])
    validate = sub.add_parser("validate", help="validate a prioritized case live")
    validate.add_argument("--case", required=True)
    validate.add_argument("--db", type=Path, required=True)
    validate.add_argument("--artifacts", type=Path, required=True)
    plan = sub.add_parser("plan", help="prepare and verify a Terraform remediation")
    plan.add_argument("--case", required=True)
    plan.add_argument("--db", type=Path, required=True)
    plan.add_argument("--artifacts", type=Path, required=True)
    plan.add_argument("--repo", type=Path, required=True)
    plan.add_argument(
        "--agent-result", type=Path, required=True,
        help="recorded TerraformRemediationProposal.v1 agent result",
    )
    plan.add_argument(
        "--state-json", type=Path,
        help="optional terraform show -json output for computed resource names",
    )
    plan.add_argument("--terraform-bin", default="terraform")
    plan.add_argument("--terraform-timeout", type=float, default=300)
    review = sub.add_parser(
        "prepare-review",
        help="run a validated case through planning and stop at human approval",
    )
    review.add_argument("--case", required=True)
    review.add_argument("--db", type=Path, required=True)
    review.add_argument("--artifacts", type=Path, required=True)
    review.add_argument("--repo", type=Path, required=True)
    usage = review.add_mutually_exclusive_group(required=True)
    usage.add_argument("--usage-json", type=Path)
    usage.add_argument(
        "--azure-monitor", action="store_true",
        help="read request history using the dedicated Azure observer identity",
    )
    review.add_argument("--azure-metric", default="Transactions")
    review.add_argument("--usage-days", type=int, default=28)
    review.add_argument("--service-context-json", type=Path, required=True)
    review.add_argument("--state-json", type=Path)
    review.add_argument("--window-policy-json", type=Path)
    review.add_argument("--runtime", choices=("recorded", "openai"), default="recorded")
    review.add_argument(
        "--agent-results", type=Path,
        help="directory containing one recorded JSON result per agent contract",
    )
    review.add_argument("--model", help="explicit OpenAI model for --runtime openai")
    review.add_argument("--openai-base-url", default="https://api.openai.com/v1")
    review.add_argument("--openai-timeout", type=float, default=180)
    review.add_argument("--terraform-bin", default="terraform")
    review.add_argument("--terraform-timeout", type=float, default=300)
    demo = sub.add_parser(
        "demo-review", help="run a safe local end-to-end demo through human review")
    demo.add_argument("--workdir", type=Path)
    demo.add_argument("--terraform-bin", default="terraform")
    demo.add_argument("--terraform-timeout", type=float, default=120)
    show = sub.add_parser("show-review", help="print a case's human review package")
    show.add_argument("--case", required=True)
    show.add_argument("--db", type=Path, required=True)
    return parser


_RESULT_FILES = {
    "TerraformRemediationProposal.v1": "terraform-remediation-proposal.json",
    "SREReview.v1": "sre-review.json",
    "ChangeWindowSelection.v1": "change-window-selection.json",
    "RollbackReview.v1": "rollback-review.json",
}


def _recorded_runtime(directory: Path) -> RecordedContractRuntime:
    if directory is None:
        raise ValueError("--agent-results is required for --runtime recorded")
    documents = {}
    for contract, filename in _RESULT_FILES.items():
        path = directory / filename
        if not path.is_file():
            raise ValueError(f"recorded result is missing: {path}")
        documents[contract] = json.loads(path.read_text(encoding="utf-8"))
    return RecordedContractRuntime(documents, now=_now)


def _window_policy(path: Path | None) -> WindowPolicy:
    if path is None:
        return WindowPolicy()
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("window policy JSON must be an object")
    for name in ("allowed_weekdays", "allowed_start_hours"):
        if name in document:
            document[name] = tuple(document[name])
    return WindowPolicy(**document)


def _prepare_review(args) -> int:
    if args.runtime == "recorded":
        runtime = _recorded_runtime(args.agent_results)
    else:
        if not args.model:
            raise ValueError("--model is required for --runtime openai")
        runtime = OpenAIResponsesRuntime.from_environment(
            model=args.model, now=_now, base_url=args.openai_base_url,
            timeout_seconds=args.openai_timeout)
    state = json.loads(args.state_json.read_text()) if args.state_json else None
    service_context = json.loads(args.service_context_json.read_text())
    if not isinstance(service_context, dict):
        raise ValueError("service context JSON must be an object")
    cases, records = SqliteCaseStore(args.db), SqliteProductRecordStore(args.db)
    findings = SqliteFindingStore(args.db)
    if args.usage_json:
        usage_samples = load_usage_samples(args.usage_json)
    else:
        if args.usage_days < 7 or args.usage_days > 90:
            raise ValueError("--usage-days must be between 7 and 90")
        identities = {
            (finding.provider, finding.resource_uid)
            for finding in findings.list_for_case(args.case)
        }
        if len(identities) != 1:
            raise ValueError("Azure Monitor usage requires one case resource")
        provider, resource_uid = next(iter(identities))
        if provider != "azure":
            raise ValueError("--azure-monitor requires an Azure case")
        end = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
        start = end - timedelta(days=args.usage_days)
        usage_samples = capture_azure_monitor_usage(
            resource_uid, start=utc_text(start), end=utc_text(end),
            host_env=os.environ, metric=args.azure_metric)
    outcome = PreApprovalOrchestrator(
        case_store=cases, finding_store=findings,
        record_store=records, artifact_root=args.artifacts, runtime=runtime,
        runner=SubprocessTerraformRunner(
            args.terraform_bin, timeout_seconds=args.terraform_timeout),
        now=_now,
    ).prepare(
        args.case, repository=args.repo, state_document=state,
        service_context=service_context,
        usage_samples=usage_samples,
        window_policy=_window_policy(args.window_policy_json),
    )
    json.dump({
        "status": outcome.human_review.case.state.value,
        "case": case_to_dict(outcome.human_review.case),
        "review_package": product_record_to_dict(outcome.human_review.review_package),
        "safety_boundary": "No infrastructure change has been applied.",
    }, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _demo_finding(resource_uid: str) -> dict:
    return {
        "class_uid": 2004, "severity": "High",
        "time_dt": "2026-08-26T12:00:00Z",
        "metadata": {
            "version": "1.5.0", "event_code":
            "storage_account_public_network_access_disabled",
            "product": {"name": "El Capitan demo scanner", "version": "1.0"},
        },
        "cloud": {
            "provider": "azure", "region": "westus2",
            "account": {"uid": "demo-subscription"},
        },
        "finding_info": {
            "uid": "demo-public-storage-001",
            "title": "Storage public network access is enabled",
            "analytic": {"uid": "storage_account_public_network_access_disabled"},
        },
        "resources": [{"uid": resource_uid, "type": "microsoft.storage/storageaccounts"}],
        "unmapped": {"categories": ["internet-exposed"]},
    }


def _demo_review(args) -> int:
    root = (args.workdir.resolve() if args.workdir else
            Path(tempfile.mkdtemp(prefix="elcapitan-demo-")))
    if args.workdir and root.exists() and any(root.iterdir()):
        raise ValueError("--workdir must be empty so the demo cannot overwrite prior data")
    root.mkdir(parents=True, exist_ok=True)
    db, artifacts, repository = root / "product.db", root / "artifacts", root / "customer-repo"
    source = repository / "infra" / "main.tf"
    source.parent.mkdir(parents=True, exist_ok=True)
    resource_uid = (
        "/subscriptions/demo-subscription/resourceGroups/demo-rg/providers/"
        "Microsoft.Storage/storageAccounts/demostorage")
    original = f'''terraform {{
  required_version = ">= 1.4.0"
}}

resource "terraform_data" "storage_policy" {{
  input = {{
    resource_id           = "{resource_uid}"
    public_network_access = true
  }}
}}
'''
    source.write_text(original, encoding="utf-8")
    replacement = original.replace("public_network_access = true",
                                   "public_network_access = false")
    now_value = datetime.now(UTC).replace(microsecond=0)
    now = lambda: now_value.isoformat().replace("+00:00", "Z")
    cases, findings, records = (
        SqliteCaseStore(db), SqliteFindingStore(db), SqliteProductRecordStore(db))
    intake = RemediationIntake(
        case_store=cases, finding_store=findings, artifact_root=artifacts,
        collector=Collector("demo-scanner", "1.0", "local-demo"), now=now)
    ingested = intake.ingest(
        _demo_finding(resource_uid), tenant_id="TEN-DEMO",
        context=IntakeContext(asset_criticality=0.8, reachable=True,
                              internet_exposed=True,
                              service_ids=("demo-storage-service",)))
    CaseValidationService(
        case_store=cases, finding_store=findings, record_store=records,
        artifact_root=artifacts, now=now,
        reader=lambda finding, env: CloudState(
            provider="azure", resource_uid=resource_uid, region="westus2",
            config=(("public_network_access", '"Enabled"'),)),
    ).validate(ingested.case.case_id, host_env={})
    documents = {
        "TerraformRemediationProposal.v1": {"output": {
            "objective": "disable public network access for the validated storage service",
            "files": [{"path": "infra/main.tf", "content": replacement}],
            "prerequisites": ["confirm private connectivity before an eventual apply"],
            "steps": ["set public_network_access to false in the linked Terraform resource"],
            "rollout_steps": ["apply in the approved window after explicit human approval"],
            "verification_steps": ["re-run the read-only control and service health checks"],
            "rollback_steps": ["restore public_network_access to true and apply the prior source"],
            "rollback_triggers": ["private connectivity or storage health checks fail"],
            "blast_radius": ["clients of demo-storage-service"],
        }},
        "SREReview.v1": {"output": {
            "decision": "approve", "risk_level": "medium",
            "summary": "The plan is bounded and has explicit health and rollback controls.",
            "dependencies": ["private endpoint connectivity"],
            "failure_modes": ["clients still use the public endpoint"],
            "required_controls": ["human approval", "pre-change health baseline"],
            "verification_requirements": ["storage success rate remains healthy"],
        }},
        "ChangeWindowSelection.v1": {"output": {
            "selected_candidate_id": "CAND-001",
            "rationale": ["lowest historically observed request volume"],
            "confidence": 0.9, "risks": ["synthetic telemetry is demo-only"],
        }},
        "RollbackReview.v1": {"output": {
            "decision": "approve", "summary": "The prior value is explicit and reversible.",
            "verified_steps": ["restore the exact prior Terraform value"],
            "trigger_coverage": ["connectivity failure maps to rollback"],
            "failure_modes": ["rollback apply could fail and requires operator escalation"],
            "required_changes": [],
        }},
    }
    samples = []
    for days_ago in range(1, 29):
        base = now_value - timedelta(days=days_ago)
        for hour, requests in ((2, 5), (3, 20), (4, 40)):
            stamp = base.replace(hour=hour, minute=0, second=0)
            samples.append(UsageSample(
                timestamp=stamp.isoformat().replace("+00:00", "Z"),
                requests=requests, errors=0, p95_latency_ms=50 + requests))
    state = {"values": {"root_module": {"resources": [{
        "address": "terraform_data.storage_policy", "mode": "managed",
        "type": "terraform_data", "name": "storage_policy",
        "values": {"id": resource_uid},
    }]}}}
    outcome = PreApprovalOrchestrator(
        case_store=cases, finding_store=findings, record_store=records,
        artifact_root=artifacts,
        runtime=RecordedContractRuntime(documents, now=now),
        runner=SubprocessTerraformRunner(
            args.terraform_bin, timeout_seconds=args.terraform_timeout), now=now,
    ).prepare(
        ingested.case.case_id, repository=repository, state_document=state,
        service_context={
            "service": "demo-storage-service", "environment": "non-production",
            "health_signals": ["request success rate", "p95 latency"],
            "dependencies": ["private endpoint"], "owner": "demo-platform-team",
        }, usage_samples=tuple(samples),
        window_policy=WindowPolicy(timezone="UTC", notice_hours=24,
                                   allowed_start_hours=(2, 3, 4)),
    )
    json.dump({
        "status": outcome.human_review.case.state.value,
        "case_id": ingested.case.case_id, "workdir": str(root),
        "database": str(db), "artifacts": str(artifacts),
        "review_package_id": outcome.human_review.review_package.record_id,
        "selected_window": case_to_dict(outcome.human_review.case)["change_window"],
        "terraform_checks": [check.to_dict() for check in outcome.planning.checks],
        "source_repository_unchanged": source.read_text(encoding="utf-8") == original,
        "execution_status": "not_started",
        "next_command": (
            f"elcapitan show-review --case {ingested.case.case_id} --db {db}"),
    }, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _show_review(args) -> int:
    case = SqliteCaseStore(args.db).get(args.case)
    record_id = case.record_ids.get("human_review_package_id")
    if not record_id:
        raise ValueError(f"case {args.case} has no human review package")
    json.dump(product_record_to_dict(
        SqliteProductRecordStore(args.db).get(record_id)), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _intake(args) -> int:
    document = json.loads(args.input.read_text())
    documents = document if isinstance(document, list) else [document]
    case_store = SqliteCaseStore(args.db)
    finding_store = SqliteFindingStore(args.db)
    service = RemediationIntake(
        case_store=case_store, finding_store=finding_store,
        artifact_root=args.artifacts,
        collector=Collector(tool="elcapitan-intake", version="0.1.0",
                            identity=args.identity), now=_now)
    context = IntakeContext(
        asset_criticality=args.asset_criticality,
        exploit_probability=args.exploit_probability,
        internet_exposed=args.internet_exposed,
        reachable=args.reachable,
        known_exploited=args.known_exploited,
        active_exploitation=args.active_exploitation,
        runtime_dependency=args.runtime_dependency,
        compensating_control_strength=args.compensating_control_strength,
        service_ids=tuple(args.service_id))
    outcomes = []
    for raw in documents:
        if isinstance(raw, dict) and "SchemaVersion" in raw:
            raw = asff_to_ocsf(raw)
        outcome = service.ingest(raw, tenant_id=args.tenant, context=context)
        outcomes.append({
            "finding_id": outcome.finding.finding_id,
            "case_id": outcome.case.case_id,
            "duplicate": outcome.duplicate,
            "case_created": outcome.case_created,
            "finding_attached": outcome.finding_attached,
            "priority_changed": outcome.priority_changed,
            "case": case_to_dict(outcome.case),
        })
    json.dump(outcomes, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "intake":
        return _intake(args)
    if args.command == "validate":
        case_store = SqliteCaseStore(args.db)
        service = CaseValidationService(
            case_store=case_store,
            finding_store=SqliteFindingStore(args.db),
            record_store=SqliteProductRecordStore(args.db),
            artifact_root=args.artifacts, now=_now)
        outcome = service.validate(args.case, host_env=os.environ)
        json.dump({
            "case": case_to_dict(outcome.case),
            "record": product_record_to_dict(outcome.record),
            "findings": [finding.to_dict() for finding in outcome.findings],
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.command == "plan":
        document = json.loads(args.agent_result.read_text())
        now = _now
        service = RemediationPlanningService(
            case_store=SqliteCaseStore(args.db),
            finding_store=SqliteFindingStore(args.db),
            record_store=SqliteProductRecordStore(args.db),
            artifact_root=args.artifacts,
            runtime=RecordedAgentRuntime(document, now=now),
            runner=SubprocessTerraformRunner(
                args.terraform_bin, timeout_seconds=args.terraform_timeout,
            ),
            now=now,
        )
        try:
            state_document = (
                json.loads(args.state_json.read_text()) if args.state_json else None
            )
            outcome = service.prepare(
                args.case, repository=args.repo, state_document=state_document,
            )
        except TerraformChecksFailed as exc:
            json.dump({
                "status": "rejected",
                "record": product_record_to_dict(exc.record),
                "checks": [check.to_dict() for check in exc.checks],
            }, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 2
        json.dump({
            "status": "plan_ready",
            "case": case_to_dict(outcome.case),
            "link": outcome.link.to_dict(),
            "link_record": product_record_to_dict(outcome.link_record),
            "plan_record": product_record_to_dict(outcome.plan_record),
            "checks": [check.to_dict() for check in outcome.checks],
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.command == "prepare-review":
        return _prepare_review(args)
    if args.command == "demo-review":
        return _demo_review(args)
    if args.command == "show-review":
        return _show_review(args)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
