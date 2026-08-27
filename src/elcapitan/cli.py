"""Local product CLI. No agent runtime or Hermes process is required."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .action_plane import (
    ApprovalService, ExecutionService, FileHashProbe, FilesystemChangeDriver,
    HealthObservation, RecordedHealthMonitor, RecordedVerificationProbe,
    VerifiedApproval,
)
from .agents import AgentRole, AgentTask, RecordedContractRuntime, RoleRoutedRuntime
from .asff import asff_to_ocsf
from .azure_action import (
    AzureStorageAccountClient, AzureStorageBlobPublicAccessDriver,
    AzureStorageBlobPublicAccessProbe, AzureStorageHealthMonitor,
    AzureStoragePublicNetworkDriver, AzureStoragePublicNetworkProbe,
    ManagedIdentityAzureCommandRunner, SubprocessAzureCommandRunner,
)
from .case_store import SqliteCaseStore
from .case_validation import CaseValidationService
from .cases import (
    CaseState, ChangePlan, ChangeWindow, RemediationCase, case_to_dict,
)
from .cloud import CloudState
from .evidence import Collector
from .finding_store import SqliteFindingStore
from .fleet import CapabilityRegistry, FleetSnapshotService, connector_readiness
from .intake import IntakeContext, RemediationIntake
from .model_egress import ModelEgressRuntime
from .observability import (
    UsageSample, WindowPolicy, capture_azure_monitor_usage, load_usage_samples,
    utc_text,
)
from .openai_runtime import OpenAIResponsesRuntime
from .orchestration import PreApprovalOrchestrator
from .portfolio import PortfolioPolicy, PortfolioService
from .promotion import PromotionReadinessService
from .provider_runtimes import AnthropicMessagesRuntime, GeminiGenerateContentRuntime
from .product_records import (
    ProductRecord, SqliteProductRecordStore, product_record_to_dict,
)
from .remediation_planning import (
    RecordedAgentRuntime, RemediationPlanningService, SubprocessTerraformRunner,
    TerraformChecksFailed,
)
from .scheduler import (
    ExecutionScheduler, ScheduledExecutionWorker, SqliteExecutionJobStore,
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
    review.add_argument(
        "--promotion-token", required=True,
        help="exact token from promotion-manifest for the current validation boundary")
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
    review.add_argument("--runtime", choices=("recorded", "live", "openai"),
                        default="recorded")
    review.add_argument(
        "--agent-results", type=Path,
        help="directory containing one recorded JSON result per agent contract",
    )
    review.add_argument("--model", help="default explicit model for --runtime live")
    review.add_argument("--provider", choices=("openai", "anthropic", "gemini"),
                        default="openai")
    review.add_argument("--remediation-provider", choices=("openai", "anthropic", "gemini"))
    review.add_argument("--sre-provider", choices=("openai", "anthropic", "gemini"))
    review.add_argument("--window-provider", choices=("openai", "anthropic", "gemini"))
    review.add_argument("--rollback-provider", choices=("openai", "anthropic", "gemini"))
    review.add_argument("--remediation-model")
    review.add_argument("--sre-model")
    review.add_argument("--window-model")
    review.add_argument("--rollback-model")
    review.add_argument("--minimum-distinct-models", type=int, default=1)
    review.add_argument("--openai-base-url", default="https://api.openai.com/v1")
    review.add_argument("--openai-timeout", type=float, default=180)
    review.add_argument("--anthropic-base-url", default="https://api.anthropic.com")
    review.add_argument(
        "--gemini-base-url", default="https://generativelanguage.googleapis.com/v1beta")
    review.add_argument(
        "--env-file", type=Path,
        help="optional ignored dotenv file from which only provider API keys are loaded")
    review.add_argument("--terraform-bin", default="terraform")
    review.add_argument("--terraform-timeout", type=float, default=300)
    demo = sub.add_parser(
        "demo-review", help="run a safe local end-to-end demo through human review")
    demo.add_argument("--workdir", type=Path)
    demo.add_argument("--terraform-bin", default="terraform")
    demo.add_argument("--terraform-timeout", type=float, default=120)
    lifecycle = sub.add_parser(
        "demo-lifecycle",
        help="run the complete safe lifecycle through success or automatic rollback")
    lifecycle.add_argument("--workdir", type=Path)
    lifecycle.add_argument("--terraform-bin", default="terraform")
    lifecycle.add_argument("--terraform-timeout", type=float, default=120)
    lifecycle.add_argument("--outcome", choices=("success", "rollback"),
                           default="success")
    serve = sub.add_parser(
        "serve-demo", help="serve the staged browser demonstration")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--workdir", type=Path, default=Path(".elcapitan-demo"))
    serve.add_argument("--terraform-bin", default="terraform")
    serve.add_argument("--terraform-timeout", type=float, default=120)
    serve.add_argument(
        "--prepare", action="store_true",
        help="prepare the review package before accepting browser requests")
    shadow = sub.add_parser(
        "serve-shadow", help="serve the authenticated read-only fleet API")
    shadow.add_argument("--host", default="127.0.0.1")
    shadow.add_argument("--port", type=int, default=8770)
    shadow.add_argument("--workdir", type=Path, default=Path(".elcapitan-shadow"))
    show = sub.add_parser("show-review", help="print a case's human review package")
    show.add_argument("--case", required=True)
    show.add_argument("--db", type=Path, required=True)
    portfolio = sub.add_parser(
        "portfolio", help="rank validated cases and detect fleet scheduling collisions")
    portfolio.add_argument("--tenant", required=True)
    portfolio.add_argument("--db", type=Path, required=True)
    portfolio.add_argument("--maximum-parallel", type=int, default=1)
    snapshot = sub.add_parser(
        "fleet-snapshot",
        help="report every tenant case and its shadow-mode validation coverage")
    snapshot.add_argument("--tenant", required=True)
    snapshot.add_argument("--db", type=Path, required=True)
    capabilities = sub.add_parser(
        "capabilities", help="report explicitly supported cloud control capabilities")
    capabilities.add_argument("--provider", choices=("aws", "azure"))
    preflight = sub.add_parser(
        "connector-preflight",
        help="check a read-only scanner connector without making a cloud request")
    preflight.add_argument("--provider", choices=("aws", "azure"), required=True)
    promotion = sub.add_parser(
        "promotion-manifest",
        help="export an evidence-minimized handoff from shadow to preapproval")
    promotion.add_argument("--tenant", required=True)
    promotion.add_argument("--case", required=True)
    promotion.add_argument("--db", type=Path, required=True)
    smoke = sub.add_parser(
        "model-smoke", help="verify one live provider's strict agent contract")
    smoke.add_argument("--provider", choices=("openai", "anthropic", "gemini"),
                       required=True)
    smoke.add_argument("--model", required=True)
    smoke.add_argument("--env-file", type=Path)
    smoke.add_argument("--openai-base-url", default="https://api.openai.com/v1")
    smoke.add_argument("--anthropic-base-url", default="https://api.anthropic.com")
    smoke.add_argument(
        "--gemini-base-url", default="https://generativelanguage.googleapis.com/v1beta")
    smoke.add_argument("--openai-timeout", type=float, default=180)
    azure_lab = sub.add_parser(
        "azure-storage-lifecycle",
        help="exercise scheduled deployment and rollback on an explicitly tagged Azure lab target",
    )
    azure_lab.add_argument("--resource-id", required=True)
    azure_lab.add_argument("--subscription", required=True)
    azure_lab.add_argument(
        "--confirm-resource-id", required=True,
        help="must exactly repeat --resource-id to authorize this lab mutation",
    )
    azure_lab.add_argument(
        "--confirm-subscription", required=True,
        help="must exactly repeat --subscription to pin the mutation boundary",
    )
    azure_lab.add_argument("--originator", default="azure-lab-operator")
    azure_lab.add_argument("--workdir", type=Path)
    azure_lab.add_argument("--az-bin", default="az")
    azure_lab.add_argument("--azure-timeout", type=float, default=180)
    azure_lab.add_argument(
        "--managed-identity-client-id",
        help="use an attached Azure user-assigned managed identity in an isolated CLI session",
    )
    azure_lab.add_argument("--outcome", choices=("success", "rollback"),
                           default="rollback")
    azure_lab.add_argument(
        "--control", choices=("public-network-access", "blob-public-access"),
        default="public-network-access")
    azure_lab.add_argument("--provider", choices=("openai", "anthropic", "gemini"))
    azure_lab.add_argument("--model")
    azure_lab.add_argument("--env-file", type=Path)
    azure_lab.add_argument("--openai-base-url", default="https://api.openai.com/v1")
    azure_lab.add_argument("--anthropic-base-url", default="https://api.anthropic.com")
    azure_lab.add_argument(
        "--gemini-base-url", default="https://generativelanguage.googleapis.com/v1beta")
    azure_lab.add_argument("--openai-timeout", type=float, default=180)
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


def _load_provider_keys(path: Path | None) -> None:
    if path is None:
        return
    allowed = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        key, value = key.strip(), value.strip()
        if key not in allowed:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if value:
            os.environ.setdefault(key, value)


def _live_runtime(provider: str, model: str, args):
    if provider == "openai":
        return OpenAIResponsesRuntime.from_environment(
            model=model, now=_now, base_url=args.openai_base_url,
            timeout_seconds=args.openai_timeout)
    if provider == "anthropic":
        return AnthropicMessagesRuntime.from_environment(
            model=model, now=_now, base_url=args.anthropic_base_url,
            timeout_seconds=args.openai_timeout)
    if provider == "gemini":
        return GeminiGenerateContentRuntime.from_environment(
            model=model, now=_now, base_url=args.gemini_base_url,
            timeout_seconds=args.openai_timeout)
    raise AssertionError(provider)


def _prepare_review(args) -> int:
    cases, records = SqliteCaseStore(args.db), SqliteProductRecordStore(args.db)
    findings = SqliteFindingStore(args.db)
    promotion = PromotionReadinessService(
        case_store=cases, finding_store=findings, record_store=records,
    ).require(
        tenant_id=cases.get(args.case).tenant_id,
        case_id=args.case,
        promotion_token=args.promotion_token,
    )
    _load_provider_keys(args.env_file)
    if args.runtime == "recorded":
        runtime = _recorded_runtime(args.agent_results)
    else:
        selected = {
            AgentRole.REMEDIATION_ENGINEER: (
                args.remediation_provider or args.provider, args.remediation_model or args.model),
            AgentRole.SRE_REVIEWER: (
                args.sre_provider or args.provider, args.sre_model or args.model),
            AgentRole.WINDOW_PLANNER: (
                args.window_provider or args.provider, args.window_model or args.model),
            AgentRole.ROLLBACK_VERIFIER: (
                args.rollback_provider or args.provider, args.rollback_model or args.model),
        }
        missing = [role.value for role, (_, model) in selected.items() if not model]
        if missing:
            raise ValueError(
                "--model or role-specific models are required for: " + ", ".join(missing))
        runtime = ModelEgressRuntime(RoleRoutedRuntime({
            role: _live_runtime(provider, model, args)
            for role, (provider, model) in selected.items()
        }))
    state = json.loads(args.state_json.read_text()) if args.state_json else None
    service_context = json.loads(args.service_context_json.read_text())
    if not isinstance(service_context, dict):
        raise ValueError("service context JSON must be an object")
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
        now=_now, minimum_distinct_agent_models=args.minimum_distinct_models,
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
        "promotion_token": promotion.promotion_token,
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
    promotion_service = PromotionReadinessService(
        case_store=cases, finding_store=findings, record_store=records)
    promotion = promotion_service.inspect(
        tenant_id="TEN-DEMO", case_id=ingested.case.case_id)
    promotion_service.require(
        tenant_id="TEN-DEMO", case_id=ingested.case.case_id,
        promotion_token=promotion.promotion_token)
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
        "promotion_token": promotion.promotion_token,
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


def _portfolio(args) -> int:
    items = PortfolioService(
        case_store=SqliteCaseStore(args.db),
        policy=PortfolioPolicy(maximum_parallel_changes=args.maximum_parallel),
    ).queue(tenant_id=args.tenant)
    json.dump({"tenant_id": args.tenant, "cases": [item.to_dict() for item in items]},
              sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _model_smoke(args) -> int:
    _load_provider_keys(args.env_file)
    runtime = _live_runtime(args.provider, args.model, args)
    task = AgentTask(
        task_id="TASK-MODEL-SMOKE", case_id="CASE-MODEL-SMOKE",
        role=AgentRole.RELEASE_AUDITOR,
        objective="Verify strict structured output for a completed synthetic change",
        output_contract="PostChangeReview.v1",
        input_record_ids=("EXRES-MODEL-SMOKE",),
        evidence_ids=("EVD-MODEL-SMOKE",),
        constraints=("accept because the supplied deterministic probe passed",
                     "cite EVD-MODEL-SMOKE"),
        metadata={"probes": [{"probe": "synthetic", "passed": True,
                              "detail": "deterministic provider smoke check"}]})
    result = runtime.run(task)
    json.dump({
        "provider_runtime": result.runtime, "model": result.model,
        "status": result.status.value, "decision": result.output.get("decision"),
        "evidence_cited": list(result.evidence_cited), "usage": dict(result.usage),
    }, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _demo_lifecycle(args) -> int:
    root = (args.workdir.resolve() if args.workdir else
            Path(tempfile.mkdtemp(prefix="elcapitan-lifecycle-")))
    if args.workdir and root.exists() and any(root.iterdir()):
        raise ValueError("--workdir must be empty so the demo cannot overwrite prior data")
    root.mkdir(parents=True, exist_ok=True)
    demo_args = argparse.Namespace(
        workdir=root, terraform_bin=args.terraform_bin,
        terraform_timeout=args.terraform_timeout)
    capture = io.StringIO()
    with contextlib.redirect_stdout(capture):
        _demo_review(demo_args)
    prepared = json.loads(capture.getvalue())
    case_id, db, artifacts = (
        prepared["case_id"], Path(prepared["database"]), Path(prepared["artifacts"]))
    cases, records = SqliteCaseStore(db), SqliteProductRecordStore(db)
    case = cases.get(case_id)
    target = root / "deployment-target"
    shutil.copytree(root / "customer-repo", target)
    target_source = target / "infra" / "main.tf"
    original_sha256 = hashlib.sha256(target_source.read_bytes()).hexdigest()
    window_start = datetime.fromisoformat(
        case.change_window.starts_at.replace("Z", "+00:00"))
    approval_time = window_start - timedelta(minutes=1)
    execution_time = window_start + timedelta(minutes=1)
    approval_now = lambda: approval_time.isoformat().replace("+00:00", "Z")
    approval = VerifiedApproval(
        approval_id=f"APPROVAL-{case_id.split('-', 1)[-1]}", case_id=case_id,
        review_package_id=case.record_ids["human_review_package_id"],
        approver="local-demo-human", authenticated_at=approval_now(),
        expires_at=case.change_window.ends_at,
        authentication_method="local-demo-explicit-approval",
        statement="I approve this exact review package for its selected window.")
    ApprovalService(
        case_store=cases, record_store=records, artifact_root=artifacts,
        now=approval_now).approve(approval)
    jobs = SqliteExecutionJobStore(db)
    scheduled = ExecutionScheduler(
        case_store=cases, record_store=records, job_store=jobs,
        now=approval_now).schedule(case_id)
    healthy = HealthObservation(True, ("all required health signals pass",),
                                {"success_rate": 1.0, "p95_latency_ms": 50})
    unhealthy = HealthObservation(False, ("injected post-deploy SLO breach",),
                                  {"success_rate": 0.7, "p95_latency_ms": 900})
    monitor = RecordedHealthMonitor({
        "baseline": healthy,
        "after_deploy": healthy if args.outcome == "success" else unhealthy,
        "rollback": healthy,
    })
    release_runtime = RecordedContractRuntime({
        "PostChangeReview.v1": {"output": {
            "decision": "accept",
            "summary": "The approved change is deployed, healthy, and independently verified.",
            "validated_outcomes": ["approved file hash deployed",
                                   "original vulnerability no longer confirmed"],
            "residual_risks": [],
            "handoff_notes": ["continue normal service monitoring"],
        }}
    }, now=lambda: execution_time.isoformat().replace("+00:00", "Z"))
    execution_service = ExecutionService(
        case_store=cases, record_store=records, artifact_root=artifacts,
        driver=FilesystemChangeDriver(target), monitor=monitor,
        probes=(
            FileHashProbe(target),
            RecordedVerificationProbe(
                name="live-vulnerability-revalidation", target="demo-storage",
                passed=True, detail="public network finding is no longer confirmed",
                payload={"status": "not_confirmed"}),
            RecordedVerificationProbe(
                name="ui-and-api-smoke", target="demo-service", passed=True,
                detail="UI and API smoke checks pass"),
        ), runtime=release_runtime,
        now=lambda: execution_time.isoformat().replace("+00:00", "Z"),
    )
    dispatched = ScheduledExecutionWorker(
        job_store=jobs, worker_id="demo-execution-worker",
        execute=lambda due_job: execution_service.execute(
            due_job.case_id, originator="demo-scanner-originator",
            execution_job_id=due_job.job_id),
    ).run_once(now=execution_time.isoformat().replace("+00:00", "Z"))
    if dispatched is None or dispatched.job.job_id != scheduled.job.job_id:
        raise RuntimeError("demo scheduler did not release the approved job")
    outcome = dispatched.result
    final_sha256 = hashlib.sha256(target_source.read_bytes()).hexdigest()
    events = [event.transition.value for event in cases.events(case_id)]
    json.dump({
        "status": outcome.case.state.value, "case_id": case_id,
        "workdir": str(root), "outcome_requested": args.outcome,
        "rolled_back": outcome.rolled_back,
        "deployment_target_changed": final_sha256 != original_sha256,
        "deployment_target_restored": final_sha256 == original_sha256,
        "handoff": (product_record_to_dict(outcome.handoff_record)
                    if outcome.handoff_record else None),
        "verification": (product_record_to_dict(outcome.verification_record)
                         if outcome.verification_record else None),
        "workflow_transitions": events,
        "source_repository_unchanged": prepared["source_repository_unchanged"],
    }, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _azure_storage_lifecycle(args) -> int:
    """Run the real action plane against one disposable, tagged Azure target."""
    if args.resource_id != args.confirm_resource_id:
        raise ValueError("--confirm-resource-id must exactly match --resource-id")
    if args.subscription != args.confirm_subscription:
        raise ValueError("--confirm-subscription must exactly match --subscription")
    root = (args.workdir.resolve() if args.workdir else
            Path(tempfile.mkdtemp(prefix="elcapitan-azure-lifecycle-")))
    if args.workdir and root.exists() and any(root.iterdir()):
        raise ValueError("--workdir must be empty so prior evidence cannot be overwritten")
    root.mkdir(parents=True, exist_ok=True)
    db, artifacts = root / "product.db", root / "artifacts"
    namespace = "cases/CASE-AZURE-LAB/planning/PLAN-AZURE-LAB"
    source_path = "main.tf"
    if args.control == "public-network-access":
        terraform_attribute = "public_network_access_enabled"
        live_property = "publicNetworkAccess"
        objective = "disable Azure Storage public network access"
    else:
        terraform_attribute = "allow_nested_items_to_be_public"
        live_property = "allowBlobPublicAccess"
        objective = "disable Azure Storage blob public access"
    original = f'''resource "azurerm_storage_account" "lab" {{
  name                          = "{args.resource_id.rsplit('/', 1)[-1]}"
  resource_group_name           = "{args.resource_id.split('/')[4]}"
  {terraform_attribute} = true
}}
'''
    replacement = original.replace("= true", "= false")
    original_path = root / "approved-source" / source_path
    replacement_path = artifacts / namespace / "workspace" / source_path
    original_path.parent.mkdir(parents=True)
    replacement_path.parent.mkdir(parents=True)
    original_path.write_text(original, encoding="utf-8")
    replacement_path.write_text(replacement, encoding="utf-8")
    now_value = datetime.now(UTC).replace(microsecond=0)
    now = lambda: now_value.isoformat().replace("+00:00", "Z")
    starts = (now_value - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    ends = (now_value + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    case_id = "CASE-AZURE-LAB"
    plan_id, link_id, approval_id, window_id = (
        "PLAN-AZURE-LAB", "LINK-AZURE-LAB", "APPROVAL-AZURE-LAB", "WIN-AZURE-LAB")
    change_plan = ChangePlan(
        plan_id=plan_id, objective=objective,
        change_ref=f"{namespace}/workspace/{source_path}",
        prerequisites=("target is explicitly tagged as an El Capitan nonproduction lab",),
        steps=(objective + " on the pinned storage account",),
        rollout_steps=("apply one Azure control-plane property update",),
        verification_steps=("read the live Azure property and control-plane health",),
        rollback_steps=("restore the exact checkpointed public network access value",),
        rollback_triggers=("deployment, health, verification, or release audit failure",),
        blast_radius=(args.resource_id,), evidence_ids=())
    window = ChangeWindow(
        window_id, starts, ends, "UTC", ("operator-invoked isolated lab window",), (), 1.0)
    case = RemediationCase(
        case_id=case_id, tenant_id="TEN-AZURE-LAB", finding_ids=("FIND-AZURE-PNA",),
        asset_ids=(args.resource_id,), service_ids=("azure-storage-lab",),
        state=CaseState.APPROVED, version=0, created_at=now(), updated_at=now(),
        change_plan=change_plan, change_window=window,
        record_ids={"change_plan_id": plan_id, "iac_link_id": link_id,
                    "approval_id": approval_id, "change_window_id": window_id})
    cases, records = SqliteCaseStore(db), SqliteProductRecordStore(db)
    cases.create(case)
    plan = ProductRecord(
        plan_id, case_id, "RemediationPlan.v1", 1, now(),
        {"status": "verified", "plan": {"objective": change_plan.objective},
         "artifact_namespace": namespace,
         "change": {"source_path": source_path,
                    "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
                    "after_sha256": hashlib.sha256(replacement.encode()).hexdigest()}}, ())
    link = ProductRecord(
        link_id, case_id, "IaCLink.v1", 1, now(),
        {"link": {"resource_uid": args.resource_id,
                  "resource_type": "azurerm_storage_account",
                  "resource_name": "lab"}}, ())
    approval = ProductRecord(
        approval_id, case_id, "ChangeApproval.v1", 1, now(),
        {"approver": args.originator, "expires_at": ends,
         "authentication_method": "explicit-azure-lab-cli-confirmation",
         "statement": "approved only for the pinned tagged lab resource"}, ())
    window_record = ProductRecord(
        window_id, case_id, "ChangeWindowRecommendation.v1", 1, now(),
        {"window_id": window_id, "selected": {"starts_at": starts, "ends_at": ends}}, ())
    for record in (plan, link, approval, window_record):
        records.put(record)
    azure_runner = (
        ManagedIdentityAzureCommandRunner(
            identity_client_id=args.managed_identity_client_id,
            expected_subscription=args.subscription, executable=args.az_bin,
            timeout_seconds=args.azure_timeout)
        if args.managed_identity_client_id else
        SubprocessAzureCommandRunner(args.az_bin, timeout_seconds=args.azure_timeout)
    )
    client = AzureStorageAccountClient(
        args.resource_id, expected_subscription=args.subscription,
        required_tags={"elcapitan_scope": "lab", "environment": "nonproduction"},
        runner=azure_runner)
    before = client.read().get(live_property)
    if args.provider or args.model:
        if not args.provider or not args.model:
            raise ValueError("--provider and --model must be supplied together")
        _load_provider_keys(args.env_file)
        release_runtime = _live_runtime(args.provider, args.model, args)
    else:
        release_runtime = RecordedContractRuntime({
            "PostChangeReview.v1": {"output": {
                "decision": "accept",
                "summary": (
                    "The pinned Azure lab resource is healthy and the selected "
                    f"{args.control} control is remediated."),
                "validated_outcomes": [
                    f"Azure {args.control} control matches the approved secure state"],
                "residual_risks": [],
                "handoff_notes": ["retain the immutable execution evidence"],
            }}}, now=now)
    jobs = SqliteExecutionJobStore(db)
    scheduled = ExecutionScheduler(
        case_store=cases, record_store=records, job_store=jobs, now=now).schedule(case_id)
    if args.control == "public-network-access":
        driver = AzureStoragePublicNetworkDriver(client)
        probes = [AzureStoragePublicNetworkProbe(client)]
    else:
        driver = AzureStorageBlobPublicAccessDriver(client)
        probes = [AzureStorageBlobPublicAccessProbe(client)]
    if args.outcome == "rollback":
        probes.append(RecordedVerificationProbe(
            name="injected-lab-rollback-trigger", target=args.resource_id,
            passed=False, detail="operator requested automatic rollback-path validation"))
    service = ExecutionService(
        case_store=cases, record_store=records, artifact_root=artifacts,
        driver=driver,
        monitor=AzureStorageHealthMonitor(client), probes=tuple(probes),
        runtime=release_runtime, now=now)
    dispatched = ScheduledExecutionWorker(
        job_store=jobs, worker_id="azure-lab-worker",
        execute=lambda job: service.execute(
            job.case_id, originator=args.originator, execution_job_id=job.job_id),
    ).run_once(now=now())
    if dispatched is None or dispatched.job.job_id != scheduled.job.job_id:
        raise RuntimeError("Azure lab scheduler did not release the pinned job")
    outcome = dispatched.result
    after = client.read().get(live_property)
    if isinstance(azure_runner, ManagedIdentityAzureCommandRunner):
        azure_runner.close()
    json.dump({
        "status": outcome.case.state.value, "case_id": case_id,
        "resource_id": args.resource_id, "subscription": args.subscription,
        "requested_outcome": args.outcome, "before": before, "after": after,
        "control": args.control,
        "rolled_back": outcome.rolled_back,
        "job_state": dispatched.job.state.value,
        "verification": (product_record_to_dict(outcome.verification_record)
                         if outcome.verification_record else None),
        "handoff": (product_record_to_dict(outcome.handoff_record)
                    if outcome.handoff_record else None),
        "workdir": str(root),
    }, sys.stdout, indent=2)
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
    if args.command == "demo-lifecycle":
        return _demo_lifecycle(args)
    if args.command == "serve-demo":
        if not 0 <= args.port <= 65535:
            raise ValueError("--port must be between 0 and 65535")
        from .demo_web import run_demo_server
        run_demo_server(
            host=args.host,
            port=args.port,
            workdir=args.workdir,
            terraform_bin=args.terraform_bin,
            terraform_timeout=args.terraform_timeout,
            prepare=args.prepare,
        )
        return 0
    if args.command == "serve-shadow":
        if not 0 <= args.port <= 65535:
            raise ValueError("--port must be between 0 and 65535")
        from .shadow_web import run_shadow_server
        run_shadow_server(host=args.host, port=args.port, workdir=args.workdir)
        return 0
    if args.command == "show-review":
        return _show_review(args)
    if args.command == "portfolio":
        return _portfolio(args)
    if args.command == "fleet-snapshot":
        snapshot = FleetSnapshotService(
            case_store=SqliteCaseStore(args.db),
            finding_store=SqliteFindingStore(args.db),
            record_store=SqliteProductRecordStore(args.db),
        ).snapshot(tenant_id=args.tenant)
        json.dump(snapshot.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.command == "capabilities":
        capabilities = CapabilityRegistry().list(provider=args.provider)
        json.dump({
            "provider": args.provider or "all",
            "capabilities": [item.to_dict() for item in capabilities],
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.command == "connector-preflight":
        json.dump(
            connector_readiness(args.provider, host_env=os.environ).to_dict(),
            sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.command == "promotion-manifest":
        manifest = PromotionReadinessService(
            case_store=SqliteCaseStore(args.db),
            finding_store=SqliteFindingStore(args.db),
            record_store=SqliteProductRecordStore(args.db),
        ).inspect(tenant_id=args.tenant, case_id=args.case)
        json.dump(manifest.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.command == "model-smoke":
        return _model_smoke(args)
    if args.command == "azure-storage-lifecycle":
        return _azure_storage_lifecycle(args)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
