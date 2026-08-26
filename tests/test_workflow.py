import pytest

from elcapitan.cases import CaseState, CaseTransition, RiskAssessment
from elcapitan.workflow import (
    ConcurrentCaseUpdate, InMemoryCaseStore, WorkflowCoordinator,
)

NOW = "2026-08-25T12:00:00Z"


def risk():
    return RiskAssessment("RISK-001", 80, "urgent", ("known exploitation",),
                          0.95, ("EVD-001",))


def test_coordinator_persists_projection_and_append_only_event():
    store = InMemoryCaseStore()
    workflow = WorkflowCoordinator(store)
    workflow.open(case_id="CASE-001", tenant_id="TEN-001",
                  finding_ids=("FIND-001",), now=NOW)
    updated = workflow.advance(
        "CASE-001", CaseTransition.PRIORITIZE, event_id="EVT-001",
        occurred_at=NOW, actor="prioritizer", priority=risk(),
        record_ids={"risk_assessment_id": "RISK-001"}, evidence_ids=("EVD-001",))

    assert store.get("CASE-001") == updated
    assert updated.state is CaseState.PRIORITIZED
    assert [event.transition for event in store.events("CASE-001")] == [
        CaseTransition.PRIORITIZE]


def test_store_rejects_a_stale_writer():
    store = InMemoryCaseStore()
    workflow = WorkflowCoordinator(store)
    original = workflow.open(case_id="CASE-001", tenant_id="TEN-001",
                             finding_ids=("FIND-001",), now=NOW)
    updated = workflow.advance(
        "CASE-001", CaseTransition.PRIORITIZE, event_id="EVT-001",
        occurred_at=NOW, actor="prioritizer", priority=risk(),
        record_ids={"risk_assessment_id": "RISK-001"})
    event = store.events("CASE-001")[0]

    with pytest.raises(ConcurrentCaseUpdate, match="expected 0"):
        store.append(updated, event, expected_version=original.version)


def test_active_case_can_be_found_by_tenant_and_asset():
    store = InMemoryCaseStore()
    workflow = WorkflowCoordinator(store)
    opened = workflow.open(case_id="CASE-001", tenant_id="TEN-001",
                           finding_ids=("FIND-001",), asset_ids=("asset-1",), now=NOW)
    assert store.find_active_by_asset("TEN-001", "asset-1") == opened
    assert store.find_active_by_asset("another-tenant", "asset-1") is None


def test_store_prevents_two_active_cases_for_same_tenant_asset():
    store = InMemoryCaseStore()
    workflow = WorkflowCoordinator(store)
    workflow.open(case_id="CASE-001", tenant_id="TEN-001",
                  finding_ids=("FIND-001",), asset_ids=("asset-1",), now=NOW)
    with pytest.raises(ConcurrentCaseUpdate, match="active case"):
        workflow.open(case_id="CASE-002", tenant_id="TEN-001",
                      finding_ids=("FIND-002",), asset_ids=("asset-1",), now=NOW)
