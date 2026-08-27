import pytest

from elcapitan.cases import (
    CaseState, CaseTransition, ChangePlan, ChangeWindow, RiskAssessment,
    case_from_dict, case_to_dict, event_from_dict, event_to_dict,
    open_case, transition_case,
)

NOW = "2026-08-25T12:00:00Z"


def case():
    return open_case(case_id="CASE-001", tenant_id="TEN-001",
                     finding_ids=("FIND-001",), asset_ids=("asset-1",), now=NOW)


def risk():
    return RiskAssessment("RISK-001", 87.5, "urgent", ("internet exposed",),
                          0.9, ("EVD-001",))


def plan():
    return ChangePlan(
        plan_id="PLAN-001", objective="remove public access", change_ref="PATCH-001",
        prerequisites=("backup current configuration",), steps=("apply patch",),
        rollout_steps=("deploy to canary",), verification_steps=("check SLO",),
        rollback_steps=("restore previous revision",),
        rollback_triggers=("error rate exceeds 1%",), blast_radius=("corpus reader",),
        evidence_ids=("EVD-002",),
    )


def window():
    return ChangeWindow("WIN-001", "2026-08-26T08:00:00Z",
                        "2026-08-26T09:00:00Z", "America/Los_Angeles",
                        ("lowest request volume",), ("EVD-003",), 0.8)


def advance(current, transition, n, **kwargs):
    return transition_case(current, transition, event_id=f"EVT-{n:03d}",
                           occurred_at=NOW, actor="test", **kwargs)[0]


def test_happy_path_is_explicit_through_execution_and_verification():
    current = case()
    current = advance(current, CaseTransition.PRIORITIZE, 1,
                      record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    current = advance(current, CaseTransition.VALIDATE, 2,
                      record_ids={"validation_result_id": "VAL-001"})
    current = advance(current, CaseTransition.PREPARE_PLAN, 3,
                      record_ids={"change_plan_id": "PLAN-001"}, change_plan=plan())
    current = advance(current, CaseTransition.APPROVE_SRE, 4,
                      record_ids={"sre_review_id": "SRE-001"})
    current = advance(current, CaseTransition.SELECT_WINDOW, 5,
                      record_ids={"change_window_id": "WIN-001"}, change_window=window())
    current = advance(current, CaseTransition.REVIEW_ROLLBACK, 6,
                      record_ids={"rollback_review_id": "ROLLBACK-001"})
    current = advance(current, CaseTransition.REQUEST_APPROVAL, 7,
                      record_ids={"policy_decision_id": "POLICY-001"})
    current = advance(current, CaseTransition.APPROVE_CHANGE, 8,
                      record_ids={"approval_id": "APR-001"})
    current = advance(current, CaseTransition.SCHEDULE_EXECUTION, 9,
                      record_ids={"schedule_id": "SCHEDULE-001"})
    current = advance(current, CaseTransition.START_EXECUTION, 10,
                      record_ids={"execution_id": "EXEC-001"})
    current = advance(current, CaseTransition.START_VERIFICATION, 11,
                      record_ids={"execution_result_id": "EXECRES-001"})
    current = advance(current, CaseTransition.COMPLETE_REMEDIATION, 12,
                      record_ids={"verification_result_id": "VERIFY-001"})

    assert current.state is CaseState.REMEDIATED
    assert current.terminal
    assert current.version == 12
    assert current.change_plan.rollback_steps == ("restore previous revision",)


def test_a_stage_cannot_be_skipped():
    with pytest.raises(ValueError, match="not allowed"):
        advance(case(), CaseTransition.PREPARE_PLAN, 1,
                record_ids={"change_plan_id": "PLAN-001"}, change_plan=plan())


def test_required_stage_record_cannot_be_replaced_by_agent_prose():
    with pytest.raises(ValueError, match="risk_assessment_id"):
        advance(case(), CaseTransition.PRIORITIZE, 1, priority=risk(),
                detail="I assessed the risk")


def test_block_and_resume_return_to_the_exact_previous_state():
    prioritized = advance(case(), CaseTransition.PRIORITIZE, 1,
                          record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    blocked = advance(prioritized, CaseTransition.BLOCK, 2,
                      detail="repository access is unavailable")
    resumed = advance(blocked, CaseTransition.RESUME, 3)
    assert blocked.state is CaseState.BLOCKED
    assert resumed.state is CaseState.PRIORITIZED
    assert resumed.blocked_from is None


def test_terminal_case_cannot_be_reopened_by_transition():
    prioritized = advance(case(), CaseTransition.PRIORITIZE, 1,
                          record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    closed = advance(prioritized, CaseTransition.CLOSE_NO_ACTION, 2,
                     detail="validated false positive")
    with pytest.raises(ValueError, match="terminal"):
        advance(closed, CaseTransition.BLOCK, 3, detail="late concern")


def test_checker_rework_returns_to_validated_and_clears_superseded_projection():
    current = case()
    current = advance(current, CaseTransition.PRIORITIZE, 1,
                      record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    current = advance(current, CaseTransition.VALIDATE, 2,
                      record_ids={"validation_result_id": "VAL-001"})
    current = advance(current, CaseTransition.PREPARE_PLAN, 3,
                      record_ids={"change_plan_id": "PLAN-001",
                                  "iac_link_id": "LINK-001"}, change_plan=plan())
    current = advance(current, CaseTransition.APPROVE_SRE, 4,
                      record_ids={"sre_review_id": "SRE-001"})
    current = advance(current, CaseTransition.SELECT_WINDOW, 5,
                      record_ids={"change_window_id": "WIN-001"},
                      change_window=window())

    reworked, event = transition_case(
        current, CaseTransition.REQUEST_REWORK, event_id="EVT-006",
        occurred_at=NOW, actor="rollback-reviewer",
        record_ids={"review_feedback_id": "RBK-001"},
        detail="map failed verification to automatic rollback")

    assert reworked.state is CaseState.VALIDATED
    assert reworked.change_plan is None
    assert reworked.change_window is None
    assert reworked.record_ids["validation_result_id"] == "VAL-001"
    assert reworked.record_ids["review_feedback_id"] == "RBK-001"
    assert "change_plan_id" not in reworked.record_ids
    assert event.from_state is CaseState.WINDOW_SELECTED
    assert event.to_state is CaseState.VALIDATED


def test_invalid_sre_approval_can_retry_without_replanning():
    current = case()
    current = advance(current, CaseTransition.PRIORITIZE, 1,
                      record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    current = advance(current, CaseTransition.VALIDATE, 2,
                      record_ids={"validation_result_id": "VAL-001"})
    current = advance(current, CaseTransition.PREPARE_PLAN, 3,
                      record_ids={"change_plan_id": "PLAN-001",
                                  "iac_link_id": "LINK-001"}, change_plan=plan())
    current = advance(current, CaseTransition.APPROVE_SRE, 4,
                      record_ids={"sre_review_id": "SRE-BAD"})

    retried, event = transition_case(
        current, CaseTransition.RETRY_SRE, event_id="EVT-005",
        occurred_at=NOW, actor="policy",
        record_ids={"review_feedback_id": "SRE-BAD"},
        detail="verification_requirements contains a placeholder")

    assert retried.state is CaseState.PLAN_READY
    assert retried.change_plan == current.change_plan
    assert retried.record_ids["review_feedback_id"] == "SRE-BAD"
    assert "sre_review_id" not in retried.record_ids
    assert event.to_state is CaseState.PLAN_READY


def test_invalid_sre_approval_retry_clears_dependent_window():
    current = case()
    current = advance(current, CaseTransition.PRIORITIZE, 1,
                      record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    current = advance(current, CaseTransition.VALIDATE, 2,
                      record_ids={"validation_result_id": "VAL-001"})
    current = advance(current, CaseTransition.PREPARE_PLAN, 3,
                      record_ids={"change_plan_id": "PLAN-001",
                                  "iac_link_id": "LINK-001"}, change_plan=plan())
    current = advance(current, CaseTransition.APPROVE_SRE, 4,
                      record_ids={"sre_review_id": "SRE-BAD"})
    current = advance(current, CaseTransition.SELECT_WINDOW, 5,
                      record_ids={"change_window_id": "WIN-STALE"},
                      change_window=window())

    retried, _ = transition_case(
        current, CaseTransition.RETRY_SRE, event_id="EVT-006",
        occurred_at=NOW, actor="policy",
        record_ids={"review_feedback_id": "SRE-BAD"},
        detail="verification_requirements contains a placeholder")

    assert retried.state is CaseState.PLAN_READY
    assert retried.change_window is None
    assert "sre_review_id" not in retried.record_ids
    assert "change_window_id" not in retried.record_ids


def test_records_are_copied_into_immutable_mappings():
    records = {"risk_assessment_id": "RISK-001"}
    updated, event = transition_case(
        case(), CaseTransition.PRIORITIZE, event_id="EVT-001", occurred_at=NOW,
        actor="test", record_ids=records, priority=risk())
    records["risk_assessment_id"] = "tampered"
    assert updated.record_ids["risk_assessment_id"] == "RISK-001"
    assert event.record_ids["risk_assessment_id"] == "RISK-001"


def test_stage_artifacts_cannot_be_replaced_during_a_later_transition():
    prioritized = advance(case(), CaseTransition.PRIORITIZE, 1,
                          record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    with pytest.raises(ValueError, match="priority may be attached only"):
        advance(prioritized, CaseTransition.VALIDATE, 2,
                record_ids={"validation_result_id": "VAL-001"}, priority=risk())


def test_change_plan_requires_a_progressive_rollout():
    with pytest.raises(ValueError, match="rollout_steps"):
        ChangePlan(
            plan_id="PLAN-001", objective="fix", change_ref="PATCH-001",
            prerequisites=(), steps=("change",), rollout_steps=(),
            verification_steps=("verify",), rollback_steps=("undo",),
            rollback_triggers=("errors",), blast_radius=(), evidence_ids=(),
        )


def test_case_and_event_serialization_round_trip_nested_product_records():
    current = advance(case(), CaseTransition.PRIORITIZE, 1,
                      record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    current = advance(current, CaseTransition.VALIDATE, 2,
                      record_ids={"validation_result_id": "VAL-001"})
    current, event = transition_case(
        current, CaseTransition.PREPARE_PLAN, event_id="EVT-003",
        occurred_at=NOW, actor="engineer",
        record_ids={"change_plan_id": "PLAN-001"}, change_plan=plan())

    assert case_from_dict(case_to_dict(current)) == current
    assert event_from_dict(event_to_dict(event)) == event


def test_new_finding_is_an_audited_same_state_transition():
    prioritized = advance(case(), CaseTransition.PRIORITIZE, 1,
                          record_ids={"risk_assessment_id": "RISK-001"}, priority=risk())
    updated, event = transition_case(
        prioritized, CaseTransition.ADD_FINDING, event_id="EVT-002",
        occurred_at=NOW, actor="intake", new_finding_ids=("FIND-002",),
        record_ids={"finding_id": "FIND-002"})
    assert updated.state is CaseState.PRIORITIZED
    assert updated.finding_ids == ("FIND-001", "FIND-002")
    assert event.from_state is event.to_state is CaseState.PRIORITIZED


def test_duplicate_finding_does_not_create_a_fake_event():
    with pytest.raises(ValueError, match="new finding"):
        transition_case(
            case(), CaseTransition.ADD_FINDING, event_id="EVT-001",
            occurred_at=NOW, actor="intake", new_finding_ids=("FIND-001",),
            record_ids={"finding_id": "FIND-001"})
