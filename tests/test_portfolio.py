from elcapitan.cases import (
    CaseTransition, ChangePlan, ChangeWindow, RiskAssessment,
)
from elcapitan.portfolio import PortfolioService
from elcapitan.workflow import InMemoryCaseStore, WorkflowCoordinator


NOW = "2026-08-26T12:00:00Z"


def planned_case(workflow, case_id, score):
    case = workflow.open(
        case_id=case_id, tenant_id="TEN-001", finding_ids=(f"FIND-{case_id}",),
        asset_ids=(f"asset-{case_id}",), service_ids=("payments",), now=NOW)
    risk = RiskAssessment(
        f"RISK-{case_id}", score, "urgent", ("internet exposed",), .9,
        (f"EVD-{case_id}",))
    common = {"occurred_at": NOW, "actor": "test"}
    case = workflow.advance(
        case_id, CaseTransition.PRIORITIZE, event_id=f"EVT-{case_id}-1",
        record_ids={"risk_assessment_id": risk.assessment_id}, priority=risk, **common)
    case = workflow.advance(
        case_id, CaseTransition.VALIDATE, event_id=f"EVT-{case_id}-2",
        record_ids={"validation_result_id": f"VAL-{case_id}"}, **common)
    plan = ChangePlan(
        f"PLAN-{case_id}", "fix", "ref", (), ("change",), ("roll out",),
        ("verify",), ("restore",), ("health fails",), (), (f"EVD-{case_id}",))
    case = workflow.advance(
        case_id, CaseTransition.PREPARE_PLAN, event_id=f"EVT-{case_id}-3",
        record_ids={"change_plan_id": plan.plan_id}, change_plan=plan, **common)
    case = workflow.advance(
        case_id, CaseTransition.APPROVE_SRE, event_id=f"EVT-{case_id}-4",
        record_ids={"sre_review_id": f"SRE-{case_id}"}, **common)
    window = ChangeWindow(
        f"WIN-{case_id}", "2026-09-01T02:00:00Z", "2026-09-01T03:00:00Z",
        "UTC", ("low usage",), (f"EVD-{case_id}",), .9)
    return workflow.advance(
        case_id, CaseTransition.SELECT_WINDOW, event_id=f"EVT-{case_id}-5",
        record_ids={"change_window_id": window.window_id}, change_window=window, **common)


def test_portfolio_orders_validated_risk_and_flags_window_collision():
    store = InMemoryCaseStore()
    workflow = WorkflowCoordinator(store)
    planned_case(workflow, "HIGH", 90)
    planned_case(workflow, "MEDIUM", 70)
    items = PortfolioService(case_store=store).queue(tenant_id="TEN-001")
    assert [item.case_id for item in items] == ["HIGH", "MEDIUM"]
    assert items[0].scheduling_status == "scheduled"
    assert items[1].scheduling_status == "window_conflict"
    assert "HIGH" in items[1].reasons[-1]
