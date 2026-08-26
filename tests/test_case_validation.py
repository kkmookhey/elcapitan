import json
from pathlib import Path

import pytest

from elcapitan.case_store import SqliteCaseStore
from elcapitan.case_validation import (
    CaseValidationService, FindingValidationStatus,
)
from elcapitan.cases import CaseState
from elcapitan.cloud import CloudState
from elcapitan.evidence import Collector
from elcapitan.finding_store import SqliteFindingStore
from elcapitan.intake import RemediationIntake
from elcapitan.product_records import SqliteProductRecordStore

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"
NOW = "2026-08-25T12:00:00Z"


class Ids:
    def __init__(self): self.counts = {}
    def __call__(self, prefix):
        self.counts[prefix] = self.counts.get(prefix, 0) + 1
        return f"{prefix}-{self.counts[prefix]:03d}"


@pytest.fixture
def product(tmp_path):
    path = tmp_path / "product.db"
    cases = SqliteCaseStore(path)
    findings = SqliteFindingStore(path)
    records = SqliteProductRecordStore(path)
    ids = Ids()
    intake = RemediationIntake(
        case_store=cases, finding_store=findings, artifact_root=tmp_path / "artifacts",
        collector=Collector("prowler", "5.37.1", "scanner"),
        now=lambda: NOW, id_factory=ids)
    return tmp_path, cases, findings, records, ids, intake


def raw(rule_id="storage_account_public_network_access_disabled"):
    document = json.loads(FIXTURE.read_text())
    document["finding_info"]["analytic"]["uid"] = rule_id
    return document


def state(public_network_access="Enabled"):
    return CloudState(
        provider="azure",
        resource_uid=("/subscriptions/8cd2b4cc-c789-466d-a8f7-8f51fb20985d/"
                      "resourceGroups/eiger-rg/providers/Microsoft.Storage/"
                      "storageAccounts/eigercorpus8dlub3zy"),
        config=(("public_network_access", json.dumps(public_network_access)),))


def validator(product, reader):
    tmp_path, cases, findings, records, ids, _ = product
    return CaseValidationService(
        case_store=cases, finding_store=findings, record_store=records,
        artifact_root=tmp_path / "artifacts", now=lambda: NOW,
        id_factory=ids, reader=reader)


def test_confirmed_live_finding_advances_case_and_persists_evidence(product):
    tmp_path, cases, _, records, _, intake = product
    opened = intake.ingest(raw(), tenant_id="TEN-001")
    outcome = validator(product, lambda finding, env: state()).validate(
        opened.case.case_id, host_env={})

    assert outcome.case.state is CaseState.VALIDATED
    assert outcome.findings[0].status is FindingValidationStatus.CONFIRMED
    assert records.get(outcome.record.record_id) == outcome.record
    assert outcome.record.body["artifact_namespace"].endswith(outcome.record.record_id)
    assert outcome.record.body["evidence"][0]["evidence_id"] == "EVD-001"
    artifact = (tmp_path / "artifacts" / "cases" / outcome.case.case_id /
                "validation" / outcome.record.record_id / "evidence" / "EVD-001.bin")
    assert artifact.is_file()


def test_finding_absent_from_live_state_closes_without_action(product):
    *_, intake = product
    opened = intake.ingest(raw(), tenant_id="TEN-001")
    outcome = validator(
        product, lambda finding, env: state("Disabled")).validate(
            opened.case.case_id, host_env={})
    assert outcome.case.state is CaseState.CLOSED_NO_ACTION
    assert outcome.findings[0].status is FindingValidationStatus.NOT_CONFIRMED


def test_unsupported_rule_blocks_instead_of_guessing(product):
    *_, intake = product
    opened = intake.ingest(raw("unknown_rule"), tenant_id="TEN-001")
    outcome = validator(product, lambda finding, env: state()).validate(
        opened.case.case_id, host_env={})
    assert outcome.case.state is CaseState.BLOCKED
    assert outcome.findings[0].status is FindingValidationStatus.UNSUPPORTED


def test_cloud_read_failure_is_a_recorded_blocker(product):
    *_, intake = product
    opened = intake.ingest(raw(), tenant_id="TEN-001")

    def unavailable(finding, env):
        raise ValueError("read-only identity was denied")

    outcome = validator(product, unavailable).validate(
        opened.case.case_id, host_env={})
    assert outcome.case.state is CaseState.BLOCKED
    assert outcome.findings[0].status is FindingValidationStatus.UNAVAILABLE
    assert outcome.record.evidence_ids == ("EVD-001",)


def test_reader_cannot_validate_a_different_resource(product):
    *_, intake = product
    opened = intake.ingest(raw(), tenant_id="TEN-001")
    wrong = CloudState(
        provider="azure", resource_uid="/subscriptions/other/resource",
        config=(("public_network_access", '"Enabled"'),))
    outcome = validator(product, lambda finding, env: wrong).validate(
        opened.case.case_id, host_env={})
    assert outcome.case.state is CaseState.BLOCKED
    assert "different resource" in outcome.findings[0].reason
