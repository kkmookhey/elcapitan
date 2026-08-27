"""One-shot operational review worker for the isolated preapproval boundary."""
from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping

from .agents import AgentRole, RoleRoutedRuntime, validate_result
from .cases import CaseState, case_to_dict
from .model_egress import ModelEgressRuntime
from .observability import WindowPolicy, load_usage_samples
from .openai_runtime import OpenAIResponsesRuntime
from .orchestration import PreApprovalOrchestrator
from .postgres_store import (
    PostgresArtifactStore, PostgresCaseStore, PostgresFindingStore,
    PostgresProductRecordStore,
)
from .product_records import product_record_to_dict
from .promotion import PromotionReadinessService
from .provider_runtimes import AnthropicMessagesRuntime
from .remediation_planning import SubprocessTerraformRunner


class ReviewWorkerError(RuntimeError):
    pass


class _SemanticRetryRuntime:
    """Retry once when a provider satisfies JSON schema but violates semantics."""

    def __init__(self, runtime) -> None:
        self.runtime = runtime

    @property
    def name(self) -> str:
        return f"semantic-retry:{self.runtime.name}"

    def run(self, task):
        result = self.runtime.run(task)
        failures = validate_result(task, result)
        if not failures:
            return result
        retry = replace(task, constraints=tuple((*task.constraints,
            "Correct these semantic contract failures from the previous response: "
            + "; ".join(failures),
            "If status is succeeded, missing_evidence must be empty.",
        )))
        return self.runtime.run(retry)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json_object(path, *, label: str) -> dict:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewWorkerError(f"could not read {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise ReviewWorkerError(f"{label} must be a JSON object")
    return document


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ReviewWorkerError(f"required environment variable {name} is not set")
    return value


def _runtime(now=_now):
    routes = {
        AgentRole.REMEDIATION_ENGINEER: _SemanticRetryRuntime(
            OpenAIResponsesRuntime.from_environment(
                model=_required_env("ELCAP_REMEDIATION_MODEL"), now=now)),
        AgentRole.SRE_REVIEWER: _SemanticRetryRuntime(
            AnthropicMessagesRuntime.from_environment(
                model=_required_env("ELCAP_SRE_MODEL"), now=now)),
        AgentRole.WINDOW_PLANNER: _SemanticRetryRuntime(
            OpenAIResponsesRuntime.from_environment(
                model=_required_env("ELCAP_WINDOW_MODEL"), now=now)),
        AgentRole.ROLLBACK_VERIFIER: _SemanticRetryRuntime(
            AnthropicMessagesRuntime.from_environment(
                model=_required_env("ELCAP_ROLLBACK_MODEL"), now=now)),
    }
    return ModelEgressRuntime(RoleRoutedRuntime(routes))


def prepare_review(*, tenant_id: str, case_id: str, promotion_token: str,
                   repository, state_json, service_context_json, usage_json,
                   artifact_root, terraform_bin: str = "terraform",
                   terraform_timeout: float = 300,
                   minimum_distinct_models: int = 2,
                   database_url: str | None = None) -> Mapping:
    if not promotion_token:
        raise ReviewWorkerError("a promotion token is required")
    dsn = database_url or _required_env("ELCAPITAN_DATABASE_URL")
    cases = PostgresCaseStore(dsn)
    findings = PostgresFindingStore(dsn)
    records = PostgresProductRecordStore(dsn)
    artifacts = Path(artifact_root).resolve()
    artifact_store = PostgresArtifactStore(dsn)
    artifact_store.hydrate(artifacts)
    case = cases.get(case_id)
    if case.tenant_id != tenant_id:
        raise ReviewWorkerError("case does not belong to the requested tenant")
    if case.state is CaseState.AWAITING_APPROVAL:
        package_id = case.record_ids.get("human_review_package_id", "")
        package = records.get(package_id)
        return {
            "status": "already_awaiting_approval",
            "case": case_to_dict(case),
            "review_package": product_record_to_dict(package),
            "safety_boundary": "No infrastructure change has been applied.",
        }
    PromotionReadinessService(
        case_store=cases, finding_store=findings, record_store=records,
    ).require(
        tenant_id=tenant_id, case_id=case_id,
        promotion_token=promotion_token,
    )
    state = _json_object(state_json, label="Terraform state JSON")
    service_context = _json_object(
        service_context_json, label="service context JSON")
    usage_samples = load_usage_samples(usage_json)
    try:
        outcome = PreApprovalOrchestrator(
            case_store=cases, finding_store=findings, record_store=records,
            artifact_root=artifacts, runtime=_runtime(),
            runner=SubprocessTerraformRunner(
                terraform_bin, timeout_seconds=terraform_timeout),
            now=_now, minimum_distinct_agent_models=minimum_distinct_models,
            require_state_grounded_plan=True,
        ).advance_to_human_review(
            case_id, repository=repository, state_document=state,
            service_context=service_context, usage_samples=usage_samples,
            window_policy=WindowPolicy(
                timezone="America/Los_Angeles", duration_minutes=60,
                notice_hours=24, allowed_weekdays=(0, 1, 2, 3, 4),
                allowed_start_hours=(0, 1, 2, 3, 4, 5),
                candidate_count=3, minimum_profile_samples=2),
        )
    finally:
        artifact_store.sync(artifacts)
    return {
        "status": outcome.case.state.value,
        "case": case_to_dict(outcome.case),
        "review_package": product_record_to_dict(
            outcome.review_package),
        "agent_routes": {
            "maker": "openai:" + _required_env("ELCAP_REMEDIATION_MODEL"),
            "sre_checker": "anthropic:" + _required_env("ELCAP_SRE_MODEL"),
            "window_reviewer": "openai:" + _required_env("ELCAP_WINDOW_MODEL"),
            "rollback_reviewer": "anthropic:" + _required_env(
                "ELCAP_ROLLBACK_MODEL"),
        },
        "safety_boundary": "No infrastructure change has been applied.",
    }
