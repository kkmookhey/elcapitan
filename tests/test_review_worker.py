from elcapitan.agents import (
    AgentResult, AgentResultStatus, AgentRole, AgentTask,
)
from elcapitan.cases import CaseState, RemediationCase
from elcapitan.product_records import ProductRecord
from elcapitan.review_worker import (
    _policy_stop_payload, _SemanticRetryRuntime, _window_policy,
    ReviewWorkerError,
)
from elcapitan.provider_runtimes import ProviderRuntimeError


NOW = "2026-08-27T18:00:00Z"


def test_review_runtime_retries_a_schema_valid_semantic_violation_once():
    task = AgentTask(
        task_id="TASK-1", case_id="CASE-1",
        role=AgentRole.REMEDIATION_ENGINEER, objective="prepare plan",
        output_contract="TerraformRemediationProposal.v1",
        input_record_ids=("VAL-1",), evidence_ids=("EVD-1",),
    )

    class Runtime:
        name = "provider"

        def __init__(self):
            self.tasks = []

        def run(self, dispatched):
            self.tasks.append(dispatched)
            missing = ("private connectivity",) if len(self.tasks) == 1 else ()
            return AgentResult(
                task_id=dispatched.task_id, case_id=dispatched.case_id,
                role=dispatched.role, status=AgentResultStatus.SUCCEEDED,
                output={}, evidence_cited=(), missing_evidence=missing,
                runtime=self.name, model="model", started_at=NOW,
                completed_at=NOW,
            )

    provider = Runtime()
    result = _SemanticRetryRuntime(provider).run(task)

    assert result.missing_evidence == ()
    assert len(provider.tasks) == 2
    assert "previous response" in provider.tasks[1].constraints[-2]


def test_review_runtime_retries_a_provider_structured_output_violation_once():
    dispatched = AgentTask(
        task_id="TASK-2", case_id="CASE-2", role=AgentRole.SRE_REVIEWER,
        objective="review plan", output_contract="SREReview.v1",
        input_record_ids=("PLAN-1",), evidence_ids=("EVD-1",),
    )

    class Runtime:
        name = "provider"

        def __init__(self):
            self.tasks = []

        def run(self, candidate):
            self.tasks.append(candidate)
            if len(self.tasks) == 1:
                raise ProviderRuntimeError(
                    "model output violated SREReview.v1: output/summary: "
                    "'' should be non-empty")
            return AgentResult(
                task_id=candidate.task_id, case_id=candidate.case_id,
                role=candidate.role, status=AgentResultStatus.SUCCEEDED,
                output={"decision": "approve"}, evidence_cited=("EVD-1",),
                missing_evidence=(), runtime=self.name, model="model",
                started_at=NOW, completed_at=NOW,
            )

    provider = Runtime()
    result = _SemanticRetryRuntime(provider).run(dispatched)

    assert result.status is AgentResultStatus.SUCCEEDED
    assert len(provider.tasks) == 2
    assert "structured-output contract failure" in provider.tasks[1].constraints[-2]
    assert "output.summary" in provider.tasks[1].constraints[-1]
    assert "never replace them with empty strings" in provider.tasks[1].constraints[-1]


def test_review_runtime_retries_a_provider_token_limit_once_with_compact_bounds():
    dispatched = AgentTask(
        task_id="TASK-3", case_id="CASE-3",
        role=AgentRole.ROLLBACK_VERIFIER,
        objective="review rollback", output_contract="RollbackReview.v1",
        input_record_ids=("PLAN-1",), evidence_ids=("EVD-1",),
    )

    class Runtime:
        name = "provider"

        def __init__(self):
            self.tasks = []

        def run(self, candidate):
            self.tasks.append(candidate)
            if len(self.tasks) == 1:
                raise ProviderRuntimeError(
                    "Anthropic response stopped with max_tokens")
            return AgentResult(
                task_id=candidate.task_id, case_id=candidate.case_id,
                role=candidate.role, status=AgentResultStatus.SUCCEEDED,
                output={"decision": "approve"}, evidence_cited=("EVD-1",),
                missing_evidence=(), runtime=self.name, model="model",
                started_at=NOW, completed_at=NOW,
            )

    provider = Runtime()
    result = _SemanticRetryRuntime(provider).run(dispatched)

    assert result.status is AgentResultStatus.SUCCEEDED
    assert len(provider.tasks) == 2
    assert "at most 5 items per array" in provider.tasks[1].constraints[-2]


def test_review_runtime_handles_schema_then_token_correction_within_bound():
    dispatched = AgentTask(
        task_id="TASK-4", case_id="CASE-4",
        role=AgentRole.ROLLBACK_VERIFIER,
        objective="review rollback", output_contract="RollbackReview.v1",
        input_record_ids=("PLAN-1",), evidence_ids=("EVD-1",),
    )

    class Runtime:
        name = "provider"

        def __init__(self):
            self.tasks = []

        def run(self, candidate):
            self.tasks.append(candidate)
            if len(self.tasks) == 1:
                raise ProviderRuntimeError(
                    "model output violated RollbackReview.v1: output/summary: "
                    "'' should be non-empty")
            if len(self.tasks) == 2:
                raise ProviderRuntimeError(
                    "Anthropic response stopped with max_tokens")
            return AgentResult(
                task_id=candidate.task_id, case_id=candidate.case_id,
                role=candidate.role, status=AgentResultStatus.SUCCEEDED,
                output={"decision": "approve"}, evidence_cited=("EVD-1",),
                missing_evidence=(), runtime=self.name, model="model",
                started_at=NOW, completed_at=NOW,
            )

    provider = Runtime()
    result = _SemanticRetryRuntime(provider).run(dispatched)

    assert result.status is AgentResultStatus.SUCCEEDED
    assert len(provider.tasks) == 3
    assert "output.summary" in provider.tasks[1].constraints[-1]
    assert "at most 5 items per array" in provider.tasks[1].constraints[-1]
    assert "output-token limit" in provider.tasks[2].constraints[-2]


def test_policy_rejection_is_a_structured_successful_worker_outcome(monkeypatch):
    case = RemediationCase(
        case_id="CASE-1", tenant_id="TENANT-1", finding_ids=("FIND-1",),
        asset_ids=(), service_ids=(), state=CaseState.REJECTED, version=4,
        created_at=NOW, updated_at=NOW,
        record_ids={"sre_review_id": "SRE-1"},
    )
    record = ProductRecord(
        record_id="SRE-1", case_id="CASE-1", record_type="SREReview.v1",
        schema_version=1, created_at=NOW,
        body={"decision": "reject", "summary": "Unsafe dependency path."},
    )

    class Records:
        def get(self, record_id):
            assert record_id == "SRE-1"
            return record

    monkeypatch.setenv("ELCAP_REMEDIATION_MODEL", "maker")
    monkeypatch.setenv("ELCAP_SRE_MODEL", "checker")
    monkeypatch.setenv("ELCAP_WINDOW_MODEL", "window")
    monkeypatch.setenv("ELCAP_ROLLBACK_MODEL", "rollback")
    result = _policy_stop_payload(case, Records())

    assert result["status"] == "policy_stopped"
    assert result["case"]["state"] == "rejected"
    assert result["decision_record"]["record_id"] == "SRE-1"
    assert result["review_package"] is None
    assert result["safety_boundary"] == "No infrastructure change has been applied."


def test_review_worker_accepts_an_explicit_validated_window_policy():
    policy = _window_policy({"window_policy": {
        "timezone": "UTC", "duration_minutes": 30, "notice_hours": 0,
        "allowed_weekdays": [0, 1, 2, 3, 4, 5, 6],
        "allowed_start_hours": list(range(24)),
        "candidate_count": 1, "minimum_profile_samples": 2,
        "fixed_start_delay_minutes": 5,
    }})

    assert policy.timezone == "UTC"
    assert policy.duration_minutes == 30
    assert policy.allowed_start_hours == tuple(range(24))
    assert policy.fixed_start_delay_minutes == 5


def test_review_worker_rejects_unknown_window_policy_fields():
    try:
        _window_policy({"window_policy": {"timezone": "UTC", "execute_now": True}})
    except ReviewWorkerError as exc:
        assert "unknown fields: execute_now" in str(exc)
    else:
        raise AssertionError("unknown policy fields must fail closed")
