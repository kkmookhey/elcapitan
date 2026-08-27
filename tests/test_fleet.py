from pathlib import Path

import pytest

from elcapitan.cases import CaseTransition
from elcapitan.fleet import (
    CapabilityRegistry, FleetSnapshotService, ShadowModePolicy, connector_readiness,
)
from elcapitan.finding_store import SqliteFindingStore
from elcapitan.intake import IntakeContext, RemediationIntake
from elcapitan.evidence import Collector
from elcapitan.case_store import SqliteCaseStore
from elcapitan.product_records import ProductRecord, SqliteProductRecordStore
from elcapitan.workflow import WorkflowCoordinator


def finding(uid, resource, *, rule="storage_account_public_network_access_disabled",
            severity="High"):
    return {
        "class_uid": 2004,
        "severity": severity,
        "time_dt": "2026-08-27T12:00:00Z",
        "metadata": {"version": "1.5.0", "event_code": rule,
                     "product": {"name": "scanner", "version": "1"}},
        "cloud": {"provider": "azure", "region": "westus2",
                  "account": {"uid": "sub-1"}},
        "finding_info": {"uid": uid, "title": f"Finding {uid}",
                         "analytic": {"uid": rule}},
        "resources": [{"uid": resource, "type": "microsoft.storage/storageaccounts"}],
    }


def stores(tmp_path):
    db = tmp_path / "product.db"
    return (SqliteCaseStore(db), SqliteFindingStore(db), SqliteProductRecordStore(db))


def test_capability_registry_is_explicit_and_fail_closed():
    registry = CapabilityRegistry()
    capability = registry.get("azure", "storage_account_public_network_access_disabled")
    assert capability.live_validation is True
    assert capability.live_execution is True
    assert registry.get("azure", "invented_control") is None
    assert registry.get("gcp", "anything") is None


def test_connector_preflight_never_claims_ready_without_binary_and_credentials():
    result = connector_readiness("aws", host_env={}, which=lambda _: None)
    assert result.ready_for_live_validation is False
    assert result.executable_available is False
    assert set(result.missing_environment) == {
        "ELCAP_SCANNER_AWS_ACCESS_KEY_ID",
        "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY",
        "ELCAP_SCANNER_AWS_SESSION_TOKEN",
    }


def test_connector_preflight_reports_supported_scope_with_complete_inputs():
    environment = {
        "ELCAP_SCANNER_AZURE_CLIENT_ID": "client",
        "ELCAP_SCANNER_AZURE_CLIENT_SECRET": "secret",
        "ELCAP_SCANNER_AZURE_TENANT_ID": "tenant",
    }
    result = connector_readiness("azure", host_env=environment, which=lambda _: "/bin/az")
    assert result.ready_for_live_validation is True
    assert "storage_blob_versioning_is_enabled" in result.supported_rule_ids


def test_shadow_mode_refuses_approval_scheduling_and_execution():
    assert ShadowModePolicy().allow_external_models is False
    for values in ({"allow_approval": True}, {"allow_scheduling": True},
                   {"allow_execution": True}):
        with pytest.raises(ValueError, match="shadow mode"):
            ShadowModePolicy(**values)


def test_fleet_snapshot_includes_supported_and_unsupported_cases(tmp_path):
    cases, findings, records = stores(tmp_path)
    counter = iter(range(100, 999))
    ids = lambda prefix: f"{prefix}-{next(counter):03d}"
    service = RemediationIntake(
        case_store=cases, finding_store=findings,
        artifact_root=tmp_path / "artifacts",
        collector=Collector("test", "1", "scanner"),
        now=lambda: "2026-08-27T12:00:00Z", id_factory=ids,
    )
    first = service.ingest(
        finding("F-1", "/subscriptions/sub-1/resourceGroups/rg/providers/"
                "Microsoft.Storage/storageAccounts/one"),
        tenant_id="TEN-1", context=IntakeContext(asset_criticality=.9))
    second = service.ingest(
        finding("F-2", "/subscriptions/sub-1/resourceGroups/rg/providers/"
                "Microsoft.Storage/storageAccounts/two", rule="unsupported_rule",
                severity="Medium"),
        tenant_id="TEN-1", context=IntakeContext(asset_criticality=.2))

    records.put(ProductRecord(
        "VAL-900", first.case.case_id, "ValidationResult.v1", 1,
        "2026-08-27T12:01:00Z",
        {"findings": [{"status": "confirmed"}]}, ("EVD-900",)))
    WorkflowCoordinator(cases).advance(
        first.case.case_id, CaseTransition.VALIDATE,
        event_id="EVT-900", occurred_at="2026-08-27T12:01:00Z",
        actor="validator", record_ids={"validation_result_id": "VAL-900"},
        evidence_ids=("EVD-900",))

    snapshot = FleetSnapshotService(
        case_store=cases, finding_store=findings, record_store=records).snapshot(
            tenant_id="TEN-1")
    document = snapshot.to_dict()
    assert document["summary"] == {
        "total_cases": 2,
        "total_findings": 2,
        "supported_findings": 1,
        "unsupported_findings": 1,
        "case_state_counts": {"prioritized": 1, "validated": 1},
        "provider_counts": {"azure": 2},
    }
    assert document["cases"][0]["validation_counts"] == {"confirmed": 1}
    assert document["cases"][0]["portfolio_rank"] == 1
    assert document["cases"][0]["scheduling_status"] == "awaiting_window"
    assert document["cases"][1]["portfolio_rank"] is None
    assert document["cases"][1]["scheduling_status"] == "awaiting_validation"
    assert document["shadow_policy"]["allow_execution"] is False
