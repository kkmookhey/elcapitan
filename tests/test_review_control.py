from pathlib import Path

import pytest

from elcapitan.cases import (
    CaseState, ChangePlan, ChangeWindow, RemediationCase, RiskAssessment,
)
from elcapitan.hashing import sha256_bytes
from elcapitan.product_records import ProductRecord
from elcapitan.review_control import ReviewControlError, ReviewControlPlane


NOW = "2026-08-27T12:00:00Z"


def prepared_review(root: Path) -> ReviewControlPlane:
    control = ReviewControlPlane(root, host_env={})
    namespace = "cases/CASE-REVIEW/planning/PLAN-1"
    source = b'resource "azurerm_storage_account" "assurance" {\n  public_network_access_enabled = true\n}\n'
    replacement = source.replace(b"= true", b"= false")
    run = root / "artifacts" / namespace
    (run / "evidence").mkdir(parents=True)
    (run / "workspace" / "infra").mkdir(parents=True)
    (run / "evidence" / "EVD-100.bin").write_bytes(source)
    (run / "workspace" / "infra" / "storage.tf").write_bytes(replacement)
    risk = RiskAssessment(
        "RISK-1", 68, "high", ("internet exposed",), 1, ("EVD-1",))
    plan = ChangePlan(
        "PLAN-1", "Disable public network access", "change-ref",
        prerequisites=("confirm scope",), steps=("change one attribute",),
        rollout_steps=("apply Terraform",), verification_steps=("read live state",),
        rollback_steps=("restore checkpoint",),
        rollback_triggers=("operational harm",),
        blast_radius=("one lab storage account",), evidence_ids=("EVD-100",))
    window = ChangeWindow(
        "WIN-1", "2099-08-28T04:00:00Z", "2099-08-28T16:00:00Z", "UTC",
        ("lowest observed usage",), ("EVD-200",), .96)
    record_ids = {
        "risk_assessment_id": "RISK-1",
        "validation_result_id": "VAL-1",
        "iac_link_id": "LINK-1",
        "change_plan_id": "PLAN-1",
        "sre_review_id": "SRE-1",
        "change_window_id": "WIN-1",
        "rollback_review_id": "RBK-1",
        "policy_decision_id": "POL-1",
        "human_review_package_id": "REVIEW-1",
    }
    case = RemediationCase(
        case_id="CASE-REVIEW", tenant_id="TEN-REVIEW",
        finding_ids=("FIND-1",), asset_ids=("azure:storage",),
        service_ids=("training",), state=CaseState.AWAITING_APPROVAL,
        version=7, created_at=NOW, updated_at=NOW, priority=risk,
        change_plan=plan, change_window=window, record_ids=record_ids)
    control.cases.create(case)
    records = (
        ProductRecord("VAL-1", case.case_id, "ValidationResult.v1", 1, NOW,
                      {"findings": [{"status": "confirmed", "reason": "Enabled"}]}),
        ProductRecord("LINK-1", case.case_id, "IaCLink.v1", 1, NOW,
                      {"link": {"resource_address": "azurerm_storage_account.assurance"}},
                      ("EVD-100", "EVD-101")),
        ProductRecord("PLAN-1", case.case_id, "RemediationPlan.v1", 1, NOW,
                      {"status": "verified", "artifact_namespace": namespace,
                       "change": {"source_path": "infra/storage.tf",
                                  "before_sha256": sha256_bytes(source),
                                  "after_sha256": sha256_bytes(replacement)},
                       "plan": {"objective": plan.objective,
                                "rollback_steps": list(plan.rollback_steps),
                                "rollback_triggers": list(plan.rollback_triggers)},
                       "checks": [{"name": "plan_scope", "passed": True,
                                   "detail": "one attribute"}]}),
        ProductRecord("SRE-1", case.case_id, "SREReview.v1", 1, NOW,
                      {"decision": "approve", "summary": "Low operational risk.",
                       "required_controls": ["capture checkpoint"],
                       "task": {"runtime": "anthropic", "model": "checker"}}),
        ProductRecord("WIN-1", case.case_id,
                      "ChangeWindowRecommendation.v1", 1, NOW,
                      {"confidence": .96,
                       "selected": {"starts_at": window.starts_at,
                                    "ends_at": window.ends_at},
                       "rationale": list(window.rationale),
                       "task": {"runtime": "openai", "model": "window"}}),
        ProductRecord("RBK-1", case.case_id, "RollbackReview.v1", 1, NOW,
                      {"decision": "approve", "summary": "Rollback is executable.",
                       "task": {"runtime": "anthropic", "model": "checker"}}),
        ProductRecord("POL-1", case.case_id, "PolicyDecision.v1", 1, NOW,
                      {"decision": "allow_human_review",
                       "checks": [{"check": "evidence_chain", "passed": True,
                                   "detail": "complete"}]}),
        ProductRecord("REVIEW-1", case.case_id, "HumanReviewPackage.v1", 1, NOW,
                      {"review_package_id": "REVIEW-1",
                       "requested_human_decision": "approve_or_reject_change",
                       "execution_status": "not_started"}),
    )
    for record in records:
        control.records.put(record)
    return control


def decision(detail, verb, **extra):
    return {
        "tenant_id": "TEN-REVIEW",
        "case_id": "CASE-REVIEW",
        "review_package_id": detail["review_package_id"],
        "review_package_sha256": detail["review_package_sha256"],
        "approver": "Security Change Manager",
        "confirmation": f"{verb} {detail['review_package_id']}",
        **extra,
    }


def test_review_detail_exposes_only_the_authoritative_package_and_verified_diff(tmp_path):
    control = prepared_review(tmp_path)
    detail = control.detail(tenant_id="TEN-REVIEW", case_id="CASE-REVIEW")

    assert len(detail["current_records"]) == 8
    assert detail["change"]["verified"] is True
    assert "-  public_network_access_enabled = true" in detail["change"]["unified_diff"]
    assert "+  public_network_access_enabled = false" in detail["change"]["unified_diff"]
    assert detail["capabilities"] == {"approve": True, "reject": True, "execute": False}
    assert detail["authentication"]["production_ready"] is False


def test_approval_is_package_bound_and_schedules_without_executing(tmp_path):
    control = prepared_review(tmp_path)
    detail = control.detail(tenant_id="TEN-REVIEW", case_id="CASE-REVIEW")

    result = control.approve(decision(detail, "APPROVE"))

    assert result["case"]["state"] == "approved"
    assert result["job"]["state"] == "scheduled"
    assert result["execution_started"] is False
    records = control.records.list_for_case("CASE-REVIEW")
    assert {record.record_type for record in records} >= {
        "ChangeApproval.v1", "ExecutionSchedule.v1"}


def test_rejection_is_package_bound_and_creates_no_execution_job(tmp_path):
    control = prepared_review(tmp_path)
    detail = control.detail(tenant_id="TEN-REVIEW", case_id="CASE-REVIEW")

    result = control.reject(decision(
        detail, "REJECT", reason="The dependency evidence requires additional review."))

    assert result["case"]["state"] == "rejected"
    assert result["execution_started"] is False
    assert result["rejection"]["record_type"] == "ChangeRejection.v1"
    with pytest.raises(KeyError):
        control.jobs.get("JOB-DOES-NOT-EXIST")


def test_stale_or_mistyped_decisions_fail_closed(tmp_path):
    control = prepared_review(tmp_path)
    detail = control.detail(tenant_id="TEN-REVIEW", case_id="CASE-REVIEW")
    stale = decision(detail, "APPROVE")
    stale["review_package_sha256"] = "0" * 64
    with pytest.raises(ReviewControlError, match="stale"):
        control.approve(stale)
    mistyped = decision(detail, "APPROVE")
    mistyped["confirmation"] = "APPROVE"
    with pytest.raises(ReviewControlError, match="exactly match"):
        control.approve(mistyped)
