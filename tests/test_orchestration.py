from types import SimpleNamespace

from elcapitan.agents import (
    AgentResult, AgentResultStatus, AgentRole, AgentTask,
)
from elcapitan.cases import CaseState
from elcapitan.orchestration import PreApprovalOrchestrator
from elcapitan.preapproval import _AgentStage


class Cases:
    def __init__(self, state):
        self.state = state

    def get(self, case_id):
        return SimpleNamespace(case_id=case_id, state=self.state)


class Stage:
    def __init__(self, cases, next_state, calls, name):
        self.cases, self.next_state = cases, next_state
        self.calls, self.name = calls, name

    def prepare(self, case_id, **kwargs):
        self.calls.append(self.name)
        self.cases.state = self.next_state

    def review(self, case_id, **kwargs):
        self.calls.append(self.name)
        self.cases.state = self.next_state
        return SimpleNamespace(case=SimpleNamespace(state=self.next_state))

    def select(self, case_id, **kwargs):
        self.calls.append(self.name)
        self.cases.state = self.next_state


def test_durable_preapproval_resumes_after_completed_planning_stage():
    cases, calls = Cases(CaseState.PLAN_READY), []
    orchestrator = object.__new__(PreApprovalOrchestrator)
    orchestrator.case_store = cases
    orchestrator.planning = Stage(cases, CaseState.PLAN_READY, calls, "planning")
    orchestrator.sre = Stage(cases, CaseState.SRE_APPROVED, calls, "sre")
    orchestrator.window = Stage(cases, CaseState.WINDOW_SELECTED, calls, "window")
    orchestrator.rollback = Stage(cases, CaseState.ROLLBACK_READY, calls, "rollback")
    expected = object()

    class Gate:
        @staticmethod
        def prepare(case_id):
            calls.append("gate")
            return expected

    orchestrator.gate = Gate()
    outcome = orchestrator.advance_to_human_review(
        "CASE-1", repository="repo", state_document={}, service_context={},
        usage_samples=(), window_policy=object())

    assert outcome is expected
    assert calls == ["sre", "window", "rollback", "gate"]


def test_agent_stage_retries_once_when_mandatory_citations_are_omitted(tmp_path):
    task = AgentTask(
        task_id="TASK-1", case_id="CASE-1", role=AgentRole.WINDOW_PLANNER,
        objective="select window", output_contract="ChangeWindowSelection.v1",
        input_record_ids=("PLAN-1",), evidence_ids=("EVD-001", "EVD-002"),
    )

    class Runtime:
        def __init__(self):
            self.tasks = []

        def run(self, dispatched):
            self.tasks.append(dispatched)
            cited = (("EVD-001",) if len(self.tasks) == 1
                     else ("EVD-001", "EVD-002"))
            return AgentResult(
                task_id=dispatched.task_id, case_id=dispatched.case_id,
                role=dispatched.role, status=AgentResultStatus.SUCCEEDED,
                output={
                    "selected_candidate_id": "CAND-1",
                    "rationale": ["bounded policy window"],
                    "confidence": 1.0,
                    "risks": [],
                },
                evidence_cited=cited, missing_evidence=(),
                runtime="test", model="test", started_at="2026-08-27T19:00:00Z",
                completed_at="2026-08-27T19:00:01Z",
            )

    runtime = Runtime()
    stage = _AgentStage(
        case_store=None, record_store=None, artifact_root=tmp_path,
        runtime=runtime, now=lambda: "2026-08-27T19:00:02Z",
        id_factory=lambda prefix: f"{prefix}-999",
    )
    result, evidence_id = stage._run(
        task, run_dir=tmp_path / "run",
        required_citations=("EVD-001", "EVD-002"),
    )

    assert result.evidence_cited == ("EVD-001", "EVD-002")
    assert evidence_id == "EVD-999"
    assert len(runtime.tasks) == 2
    assert "previous response omitted" in runtime.tasks[1].constraints[-1]
