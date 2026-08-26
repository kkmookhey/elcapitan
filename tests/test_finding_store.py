import pytest

from elcapitan.finding_store import (
    DuplicateFinding, FindingNotFound, SqliteFindingStore, StoredFinding,
)
from elcapitan.priority import PrioritySignals


def finding(finding_id="FIND-001", case_id=None):
    return StoredFinding(
        tenant_id="TEN-001", finding_id=finding_id, provider="azure",
        account="sub-1", original_uid="source-1", resource_uid="resource-1",
        record={"finding_id": finding_id},
        priority_signals=PrioritySignals(
            severity="high", asset_criticality=0.5, exploit_probability=0,
            internet_exposed=True, reachable=False, known_exploited=False,
            active_exploitation=False, runtime_dependency=False,
            compensating_control_strength=0, evidence_ids=("EVD-001",)),
        artifact_namespace=f"findings/{finding_id}", case_id=case_id)


def test_finding_round_trips_and_source_lookup_survives_restart(tmp_path):
    path = tmp_path / "product.db"
    SqliteFindingStore(path).put(finding())
    reopened = SqliteFindingStore(path)
    assert reopened.get("FIND-001") == finding()
    assert reopened.get_by_source("TEN-001", "azure", "sub-1", "source-1") == finding()


def test_duplicate_source_identity_is_rejected_even_with_another_local_id(tmp_path):
    store = SqliteFindingStore(tmp_path / "product.db")
    store.put(finding())
    with pytest.raises(DuplicateFinding):
        store.put(finding("FIND-002"))


def test_case_assignment_is_idempotent_but_cannot_be_moved(tmp_path):
    store = SqliteFindingStore(tmp_path / "product.db")
    store.put(finding())
    assert store.assign_case("FIND-001", "CASE-001").case_id == "CASE-001"
    assert store.assign_case("FIND-001", "CASE-001").case_id == "CASE-001"
    with pytest.raises(DuplicateFinding, match="CASE-001"):
        store.assign_case("FIND-001", "CASE-002")


def test_missing_finding_is_named(tmp_path):
    store = SqliteFindingStore(tmp_path / "product.db")
    with pytest.raises(FindingNotFound):
        store.get("FIND-999")
