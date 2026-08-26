import json
from pathlib import Path

import pytest

from elcapitan.case_store import SqliteCaseStore
from elcapitan.cases import CaseState, CaseTransition
from elcapitan.evidence import Collector
from elcapitan.finding_store import SqliteFindingStore
from elcapitan.intake import IntakeContext, RemediationIntake, canonical_asset_id

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"
NOW = "2026-08-25T12:00:00Z"


class Ids:
    def __init__(self):
        self.counts = {}

    def __call__(self, prefix):
        self.counts[prefix] = self.counts.get(prefix, 0) + 1
        return f"{prefix}-{self.counts[prefix]:03d}"


@pytest.fixture
def intake(tmp_path):
    db = tmp_path / "product.db"
    case_store = SqliteCaseStore(db)
    finding_store = SqliteFindingStore(db)
    service = RemediationIntake(
        case_store=case_store, finding_store=finding_store,
        artifact_root=tmp_path / "artifacts",
        collector=Collector("prowler", "5.37.1", "scanner-reader"),
        now=lambda: NOW, id_factory=Ids())
    return service, case_store, finding_store, tmp_path / "artifacts"


def raw_finding(uid=None, severity=None):
    raw = json.loads(FIXTURE.read_text())
    if uid:
        raw["finding_info"]["uid"] = uid
    if severity:
        raw["severity"] = severity
    return raw


def test_first_finding_opens_and_prioritizes_a_durable_case(intake):
    service, case_store, finding_store, artifacts = intake
    outcome = service.ingest(
        raw_finding(), tenant_id="TEN-001",
        context=IntakeContext(asset_criticality=0.8))

    assert outcome.case_created and outcome.priority_changed
    assert outcome.case.state is CaseState.PRIORITIZED
    assert outcome.case.finding_ids == (outcome.finding.finding_id,)
    assert outcome.case.priority.score == 56
    assert case_store.get(outcome.case.case_id) == outcome.case
    assert finding_store.get(outcome.finding.finding_id).case_id == outcome.case.case_id
    raw_ref = outcome.finding.record["raw_event"]
    assert (artifacts / outcome.finding.artifact_namespace /
            raw_ref["artifact_path"]).is_file()


def test_replaying_same_source_finding_is_idempotent(intake):
    service, case_store, _, artifacts = intake
    first = service.ingest(raw_finding(), tenant_id="TEN-001")
    second = service.ingest(raw_finding(), tenant_id="TEN-001")

    assert second.duplicate
    assert second.finding.finding_id == first.finding.finding_id
    assert second.case.version == first.case.version
    assert len(case_store.events(first.case.case_id)) == 1
    assert len(list((artifacts / "findings").iterdir())) == 1


def test_second_finding_on_asset_is_correlated_and_can_raise_priority(intake):
    service, case_store, _, _ = intake
    first = service.ingest(raw_finding(), tenant_id="TEN-001")
    second = service.ingest(
        raw_finding(uid="a-different-check", severity="Critical"),
        tenant_id="TEN-001",
        context=IntakeContext(known_exploited=True, active_exploitation=True))

    assert second.case.case_id == first.case.case_id
    assert second.finding_attached and second.priority_changed
    assert len(second.case.finding_ids) == 2
    assert second.case.priority.score > first.case.priority.score
    assert [event.transition for event in case_store.events(first.case.case_id)] == [
        CaseTransition.PRIORITIZE,
        CaseTransition.ADD_FINDING,
        CaseTransition.REPRIORITIZE,
    ]


def test_same_cloud_resource_in_another_tenant_is_not_correlated(intake):
    service, _, _, _ = intake
    first = service.ingest(raw_finding(), tenant_id="TEN-001")
    second = service.ingest(raw_finding(), tenant_id="TEN-002")
    assert second.case.case_id != first.case.case_id


def test_canonical_asset_identity_includes_cloud_account_boundary():
    assert canonical_asset_id("aws", "1111", "bucket") != canonical_asset_id(
        "aws", "2222", "bucket")


def test_missing_source_identity_fails_before_creating_artifacts(intake):
    service, _, _, artifacts = intake
    raw = raw_finding()
    raw["finding_info"]["uid"] = ""
    with pytest.raises(ValueError, match="original_uid"):
        service.ingest(raw, tenant_id="TEN-001")
    assert not artifacts.exists()
