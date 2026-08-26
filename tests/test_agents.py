from elcapitan.agents import (
    AgentResult, AgentResultStatus, AgentRole, AgentTask, validate_result,
)

NOW = "2026-08-25T12:00:00Z"


def task():
    return AgentTask(
        task_id="TASK-001", case_id="CASE-001", role=AgentRole.SRE_REVIEWER,
        objective="assess availability risk", output_contract="SREReview.v1",
        input_record_ids=("PLAN-001",), evidence_ids=("EVD-001", "EVD-002"),
    )


def result(**overrides):
    values = dict(
        task_id="TASK-001", case_id="CASE-001", role=AgentRole.SRE_REVIEWER,
        status=AgentResultStatus.SUCCEEDED, output={"decision": "approve"},
        evidence_cited=("EVD-002",), missing_evidence=(), runtime="direct-model",
        model="provider/model", started_at=NOW, completed_at=NOW, usage={"input": 10},
    )
    values.update(overrides)
    return AgentResult(**values)


def test_valid_result_is_runtime_independent():
    assert validate_result(task(), result()) == []


def test_agent_cannot_cite_evidence_outside_its_bundle():
    failures = validate_result(task(), result(evidence_cited=("EVD-999",)))
    assert failures == ["agent result cites evidence it was not supplied: EVD-999"]


def test_needs_evidence_must_name_what_is_missing():
    failures = validate_result(
        task(), result(status=AgentResultStatus.NEEDS_MORE_EVIDENCE,
                       output={}, evidence_cited=(), missing_evidence=()))
    assert failures == ["needs_more_evidence must name the missing evidence"]


def test_runtime_output_and_usage_are_immutable_copies():
    output = {"decision": "approve", "checks": ["health", {"slo": "ok"}]}
    usage = {"input": 10}
    produced = result(output=output, usage=usage)
    output["decision"] = "reject"
    usage["input"] = 999
    assert produced.output["decision"] == "approve"
    assert produced.usage["input"] == 10
    output["checks"][1]["slo"] = "bad"
    assert produced.output["checks"][1]["slo"] == "ok"
