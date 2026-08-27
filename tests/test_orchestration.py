from types import SimpleNamespace

from elcapitan.cases import CaseState
from elcapitan.orchestration import PreApprovalOrchestrator


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
