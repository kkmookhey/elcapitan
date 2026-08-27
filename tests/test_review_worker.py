from elcapitan.agents import (
    AgentResult, AgentResultStatus, AgentRole, AgentTask,
)
from elcapitan.review_worker import _SemanticRetryRuntime
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
