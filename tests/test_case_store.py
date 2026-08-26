import sqlite3

import pytest

from elcapitan.case_store import SqliteCaseStore
from elcapitan.cases import (
    CaseState, CaseTransition, RiskAssessment, transition_case,
)
from elcapitan.workflow import ConcurrentCaseUpdate, WorkflowCoordinator

NOW = "2026-08-25T12:00:00Z"


def risk():
    return RiskAssessment("RISK-001", 90, "urgent", ("active exploit",),
                          0.9, ("EVD-001",))


def test_case_and_events_survive_reopening_the_store(tmp_path):
    path = tmp_path / "cases.db"
    first = WorkflowCoordinator(SqliteCaseStore(path))
    first.open(case_id="CASE-001", tenant_id="TEN-001",
               finding_ids=("FIND-001",), now=NOW)
    first.advance(
        "CASE-001", CaseTransition.PRIORITIZE, event_id="EVT-001",
        occurred_at=NOW, actor="prioritizer", priority=risk(),
        record_ids={"risk_assessment_id": "RISK-001"}, evidence_ids=("EVD-001",))

    reopened = SqliteCaseStore(path)
    restored = reopened.get("CASE-001")
    assert restored.state is CaseState.PRIORITIZED
    assert restored.priority == risk()
    assert reopened.events("CASE-001")[0].transition is CaseTransition.PRIORITIZE


def test_stale_update_changes_neither_projection_nor_event_log(tmp_path):
    store = SqliteCaseStore(tmp_path / "cases.db")
    workflow = WorkflowCoordinator(store)
    original = workflow.open(case_id="CASE-001", tenant_id="TEN-001",
                             finding_ids=("FIND-001",), now=NOW)
    current = workflow.advance(
        "CASE-001", CaseTransition.PRIORITIZE, event_id="EVT-001",
        occurred_at=NOW, actor="prioritizer", priority=risk(),
        record_ids={"risk_assessment_id": "RISK-001"})
    stale_projection, stale_event = transition_case(
        original, CaseTransition.PRIORITIZE, event_id="EVT-STALE",
        occurred_at=NOW, actor="stale-writer", priority=risk(),
        record_ids={"risk_assessment_id": "RISK-STALE"})

    with pytest.raises(ConcurrentCaseUpdate):
        store.append(stale_projection, stale_event, expected_version=0)
    assert store.get("CASE-001") == current
    assert [event.event_id for event in store.events("CASE-001")] == ["EVT-001"]


def test_duplicate_event_id_rolls_back_projection_update(tmp_path):
    store = SqliteCaseStore(tmp_path / "cases.db")
    workflow = WorkflowCoordinator(store)
    workflow.open(case_id="CASE-001", tenant_id="TEN-001",
                  finding_ids=("FIND-001",), now=NOW)
    prioritized = workflow.advance(
        "CASE-001", CaseTransition.PRIORITIZE, event_id="EVT-001",
        occurred_at=NOW, actor="prioritizer", priority=risk(),
        record_ids={"risk_assessment_id": "RISK-001"})
    validated, duplicate = transition_case(
        prioritized, CaseTransition.VALIDATE, event_id="EVT-001",
        occurred_at=NOW, actor="validator",
        record_ids={"validation_result_id": "VAL-001"})

    with pytest.raises(sqlite3.IntegrityError):
        store.append(validated, duplicate, expected_version=1)
    assert store.get("CASE-001").state is CaseState.PRIORITIZED
    assert len(store.events("CASE-001")) == 1


def test_database_uses_wal_for_resilient_local_concurrency(tmp_path):
    path = tmp_path / "cases.db"
    SqliteCaseStore(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_durable_store_finds_only_active_case_for_tenant_and_asset(tmp_path):
    store = SqliteCaseStore(tmp_path / "cases.db")
    workflow = WorkflowCoordinator(store)
    opened = workflow.open(
        case_id="CASE-001", tenant_id="TEN-001", finding_ids=("FIND-001",),
        asset_ids=("asset-1",), now=NOW)
    assert store.find_active_by_asset("TEN-001", "asset-1") == opened
    assert store.find_active_by_asset("TEN-002", "asset-1") is None


def test_durable_store_enforces_one_active_case_per_tenant_asset(tmp_path):
    store = SqliteCaseStore(tmp_path / "cases.db")
    workflow = WorkflowCoordinator(store)
    workflow.open(case_id="CASE-001", tenant_id="TEN-001",
                  finding_ids=("FIND-001",), asset_ids=("asset-1",), now=NOW)
    with pytest.raises(ConcurrentCaseUpdate, match="active case"):
        workflow.open(case_id="CASE-002", tenant_id="TEN-001",
                      finding_ids=("FIND-002",), asset_ids=("asset-1",), now=NOW)


def test_terminal_case_releases_asset_for_a_future_case(tmp_path):
    store = SqliteCaseStore(tmp_path / "cases.db")
    workflow = WorkflowCoordinator(store)
    workflow.open(case_id="CASE-001", tenant_id="TEN-001",
                  finding_ids=("FIND-001",), asset_ids=("asset-1",), now=NOW)
    workflow.advance(
        "CASE-001", CaseTransition.PRIORITIZE, event_id="EVT-001",
        occurred_at=NOW, actor="priority", priority=risk(),
        record_ids={"risk_assessment_id": "RISK-001"})
    workflow.advance(
        "CASE-001", CaseTransition.CLOSE_NO_ACTION, event_id="EVT-002",
        occurred_at=NOW, actor="validator", detail="false positive")

    next_case = workflow.open(
        case_id="CASE-002", tenant_id="TEN-001", finding_ids=("FIND-002",),
        asset_ids=("asset-1",), now=NOW)
    assert store.find_active_by_asset("TEN-001", "asset-1") == next_case
