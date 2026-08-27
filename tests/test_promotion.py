import json
from pathlib import Path

import pytest

from elcapitan.case_store import SqliteCaseStore
from elcapitan.case_validation import CaseValidationService
from elcapitan.cloud import CloudState
from elcapitan.evidence import Collector
from elcapitan.finding_store import SqliteFindingStore
from elcapitan.intake import RemediationIntake
from elcapitan.product_records import SqliteProductRecordStore
from elcapitan.promotion import PromotionReadinessService


FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"
NOW = "2026-08-27T12:00:00Z"


def product(tmp_path):
    database = tmp_path / "product.db"
    cases = SqliteCaseStore(database)
    findings = SqliteFindingStore(database)
    records = SqliteProductRecordStore(database)
    opened = RemediationIntake(
        case_store=cases, finding_store=findings,
        artifact_root=tmp_path / "artifacts",
        collector=Collector("test", "1", "scanner"), now=lambda: NOW,
    ).ingest(json.loads(FIXTURE.read_text()), tenant_id="TEN-PROMOTION")
    service = PromotionReadinessService(
        case_store=cases, finding_store=findings, record_store=records)
    return cases, findings, records, opened.case.case_id, service


def validate(tmp_path, cases, findings, records, case_id, value):
    resource_uid = findings.list_for_case(case_id)[0].resource_uid
    return CaseValidationService(
        case_store=cases, finding_store=findings, record_store=records,
        artifact_root=tmp_path / "artifacts", now=lambda: NOW,
        reader=lambda finding, env: CloudState(
            provider="azure", resource_uid=resource_uid,
            config=(("public_network_access", json.dumps(value)),)),
    ).validate(case_id, host_env={})


def test_promotion_is_blocked_until_live_validation(tmp_path):
    *_, case_id, service = product(tmp_path)
    readiness = service.inspect(tenant_id="TEN-PROMOTION", case_id=case_id)
    assert readiness.eligible is False
    assert readiness.status == "blocked"
    assert "must be validated" in readiness.blockers[0]


def test_confirmed_case_gets_stable_evidence_minimized_promotion(tmp_path):
    cases, findings, records, case_id, service = product(tmp_path)
    validate(tmp_path, cases, findings, records, case_id, "Enabled")

    first = service.inspect(tenant_id="TEN-PROMOTION", case_id=case_id).to_dict()
    second = service.inspect(tenant_id="TEN-PROMOTION", case_id=case_id).to_dict()

    assert first["eligible"] is True
    assert first["status"] == "ready_for_preapproval"
    assert first["confirmed_rule_ids"] == [
        "storage_account_public_network_access_disabled"]
    assert first["promotion_token"] == second["promotion_token"]
    assert first["safety_boundary"]["raw_finding_payload_included"] is False
    assert "record" not in first and "finding" not in first
    assert first["target_state"] == "awaiting_approval"
    required = service.require(
        tenant_id="TEN-PROMOTION", case_id=case_id,
        promotion_token=first["promotion_token"])
    assert required.eligible is True
    with pytest.raises(ValueError, match="does not match"):
        service.require(
            tenant_id="TEN-PROMOTION", case_id=case_id,
            promotion_token="0" * 64)


def test_cleared_case_cannot_be_promoted_and_tenant_is_enforced(tmp_path):
    cases, findings, records, case_id, service = product(tmp_path)
    validate(tmp_path, cases, findings, records, case_id, "Disabled")
    readiness = service.inspect(tenant_id="TEN-PROMOTION", case_id=case_id)
    assert readiness.eligible is False
    assert any("confirms no finding" in item for item in readiness.blockers)
    with pytest.raises(ValueError, match="does not belong"):
        service.inspect(tenant_id="OTHER", case_id=case_id)
