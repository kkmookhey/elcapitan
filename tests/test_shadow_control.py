import json
import os
from pathlib import Path

import fake_az
import pytest

from elcapitan import shadow_control
from elcapitan.intake import IntakeContext
from elcapitan.shadow_control import ShadowControlError, ShadowFleetControlPlane

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"
ASFF_FIXTURE = Path(__file__).parent / "fixtures" / "securityhub-asff-real.json"


def findings():
    first = json.loads(FIXTURE.read_text())
    second = json.loads(json.dumps(first))
    second["finding_info"]["uid"] += "-SECOND"
    second["finding_info"]["title"] = "Storage blob public access is enabled"
    second["finding_info"]["analytic"]["uid"] = (
        "storage_blob_public_access_level_is_disabled")
    return [first, second]


def test_shadow_uses_postgresql_when_database_url_is_configured(
        tmp_path, monkeypatch):
    created = []

    class FakePostgresStore:
        def __init__(self, dsn):
            created.append(dsn)

        def list_cases(self, *, tenant_id=None):
            return ()

        def hydrate(self, root):
            return 0

        def count(self):
            return 0

    monkeypatch.setattr(shadow_control, "PostgresCaseStore", FakePostgresStore)
    monkeypatch.setattr(shadow_control, "PostgresFindingStore", FakePostgresStore)
    monkeypatch.setattr(
        shadow_control, "PostgresProductRecordStore", FakePostgresStore)
    monkeypatch.setattr(shadow_control, "PostgresArtifactStore", FakePostgresStore)

    dsn = "postgresql://shadow:secret@database/elcapitan?sslmode=require"
    control = ShadowFleetControlPlane(
        tmp_path, host_env={"ELCAPITAN_DATABASE_URL": dsn})

    assert created == [dsn, dsn, dsn, dsn]
    assert control.health()["state_store"] == "postgresql"


def test_shadow_intake_creates_tenant_fleet_and_is_idempotent(tmp_path):
    control = ShadowFleetControlPlane(tmp_path, host_env={})
    first = control.intake(
        tenant_id="TEN-CUSTOMER", documents=findings(),
        context=IntakeContext(asset_criticality=.8, reachable=True),
        identity="customer-upload",
    ).to_dict()
    assert first["received"] == 2
    assert first["created_cases"] == 1
    assert first["fleet"]["summary"]["total_cases"] == 1
    assert first["fleet"]["summary"]["total_findings"] == 2

    replay = control.intake(
        tenant_id="TEN-CUSTOMER", documents=findings(),
        identity="customer-upload",
    ).to_dict()
    assert replay["duplicates"] == 2
    assert replay["fleet"]["summary"]["total_findings"] == 2
    assert control.health()["state_store"] == "sqlite"


def test_shadow_case_detail_orders_findings_by_score_driver(tmp_path):
    documents = findings()
    documents[1]["severity"] = "Critical"
    control = ShadowFleetControlPlane(tmp_path, host_env={})
    outcome = control.intake(tenant_id="TEN-DRIVER", documents=documents)

    detail = control.case_detail(
        tenant_id="TEN-DRIVER", case_id=outcome.case_ids[0])

    assert detail["findings"][0]["record"]["severity"] == "Critical"
    assert detail["findings"][0]["priority"]["score"] == 50
    assert detail["findings"][1]["priority"]["score"] == 40
    assert detail["case"]["priority"]["score"] == 50


def test_shadow_intake_preview_is_fail_closed_and_persists_nothing(tmp_path):
    supported = findings()[0]
    unsupported = json.loads(json.dumps(supported))
    unsupported["finding_info"]["uid"] += "-UNSUPPORTED"
    unsupported["resources"][0]["uid"] += "-UNSUPPORTED"
    unsupported["finding_info"]["analytic"]["uid"] = "unknown_customer_control"
    passed = json.loads(json.dumps(supported))
    passed["finding_info"]["uid"] += "-PASS"
    passed["resources"][0]["uid"] += "-PASS"
    passed["status_code"] = "PASS"
    manual = json.loads(json.dumps(supported))
    manual["finding_info"]["uid"] += "-MANUAL"
    manual["resources"][0]["uid"] += "-MANUAL"
    manual["status_code"] = "MANUAL"
    control = ShadowFleetControlPlane(tmp_path, host_env={})

    result = control.preview_intake(
        documents=[supported, unsupported, passed, manual]).to_dict()

    assert result == {
        "submitted": 4,
        "accepted_failures": 2,
        "skipped": {"pass": 1, "manual": 1},
        "provider_counts": {"azure": 2},
        "format_counts": {"OCSF": 4},
        "resource_count": 2,
        "account_count": 1,
        "supported_findings": 1,
        "unsupported_findings": 1,
        "supported_controls": ["storage_account_public_network_access_disabled"],
        "unsupported_controls": ["unknown_customer_control"],
        "asset_context": {
            "rows": 0,
            "matched_rows": 0,
            "unmatched_rows": 0,
            "matched_resources": 0,
            "unmatched_resources": 2,
            "contextualized_findings": 0,
            "internet_exposed_resources": 0,
            "critical_resources": 0,
            "synthetic_context_resources": 0,
        },
        "safety_boundary": {
            "persistent_writes": False,
            "cloud_requests": False,
            "external_models": False,
            "execution": False,
        },
    }
    assert control.snapshot(tenant_id="TEN-PREVIEW")["summary"][
        "total_findings"] == 0
    assert list((tmp_path / "artifacts").iterdir()) == []


def test_shadow_asset_context_preview_and_intake_are_exact_and_evidence_bound(
        tmp_path):
    document = findings()[0]
    resource_uid = document["resources"][0]["uid"]
    asset = {
        "resource_uid": resource_uid.upper(),
        "environment": "production",
        "owner": "payments-platform",
        "asset_criticality": .9,
        "internet_exposed": True,
        "reachable": True,
        "runtime_dependency": True,
        "compensating_control_strength": .1,
        "service_ids": ["payments"],
        "context_source": "synthetic-trial-assignment",
        "observed_at": "2026-09-01T20:00:00Z",
        "evidence_references": ["azure-config:publicNetworkAccess=Enabled"],
        "synthetic_business_context": True,
    }
    unmatched = {**asset, "resource_uid": resource_uid + "/unmatched"}
    control = ShadowFleetControlPlane(tmp_path, host_env={})

    preview = control.preview_intake(
        documents=[document], asset_contexts=[asset, unmatched]).to_dict()

    assert preview["asset_context"] == {
        "rows": 2,
        "matched_rows": 1,
        "unmatched_rows": 1,
        "matched_resources": 1,
        "unmatched_resources": 0,
        "contextualized_findings": 1,
        "internet_exposed_resources": 1,
        "critical_resources": 1,
        "synthetic_context_resources": 1,
    }
    assert control.snapshot(tenant_id="TEN-ASSET")["summary"]["total_findings"] == 0

    outcome = control.intake(
        tenant_id="TEN-ASSET", documents=[document],
        asset_contexts=[asset]).to_dict()
    case = outcome["fleet"]["cases"][0]
    assert case["asset_context"]["owner"] == "payments-platform"
    assert case["asset_context"]["synthetic_business_context"] is True
    assert case["service_ids"] == ["payments"]
    assert case["risk_score"] > 30
    detail = control.case_detail(
        tenant_id="TEN-ASSET", case_id=case["case_id"])
    stored = detail["findings"][0]["record"]["vendor_extensions"][
        "elcapitan_asset_context"]
    assert stored["evidence_references"] == [
        "azure-config:publicNetworkAccess=Enabled"]


def test_shadow_intake_preview_identifies_security_hub_asff(tmp_path):
    result = ShadowFleetControlPlane(tmp_path, host_env={}).preview_intake(
        documents=[json.loads(ASFF_FIXTURE.read_text())]).to_dict()

    assert result["accepted_failures"] == 1
    assert result["provider_counts"] == {"aws": 1}
    assert result["format_counts"] == {"AWS Security Hub ASFF": 1}
    assert result["supported_findings"] == 0
    assert result["unsupported_findings"] == 1


def test_shadow_export_intake_accepts_only_explicit_prowler_failures(tmp_path):
    failed = findings()[0]
    passed = json.loads(json.dumps(failed))
    passed["finding_info"]["uid"] += "-PASS"
    passed["resources"][0]["uid"] += "-PASS"
    passed.update(status="New", status_code="PASS", severity="Critical")
    manual = json.loads(json.dumps(failed))
    manual["finding_info"]["uid"] += "-MANUAL"
    manual["resources"][0]["uid"] += "-MANUAL"
    manual["status_code"] = "MANUAL"

    result = ShadowFleetControlPlane(tmp_path, host_env={}).intake(
        tenant_id="TEN", documents=[failed, passed, manual]).to_dict()

    assert result["submitted"] == 3
    assert result["received"] == result["accepted_failures"] == 1
    assert result["skipped"] == {"pass": 1, "manual": 1}
    assert result["fleet"]["summary"]["total_findings"] == 1


def test_shadow_export_intake_rejects_unknown_prowler_outcome(tmp_path):
    document = findings()[0]
    document["status_code"] = "UNKNOWN"
    control = ShadowFleetControlPlane(tmp_path, host_env={})

    with pytest.raises(ShadowControlError, match="status_code"):
        control.intake(tenant_id="TEN", documents=[document])
    assert control.snapshot(tenant_id="TEN")["summary"]["total_findings"] == 0


def test_shadow_intake_rejects_entire_unsupported_provider_batch(tmp_path):
    valid = findings()[0]
    unsupported = json.loads(json.dumps(valid))
    unsupported["cloud"]["provider"] = "gcp"
    control = ShadowFleetControlPlane(tmp_path, host_env={})
    with pytest.raises(ShadowControlError, match="entire batch was rejected"):
        control.intake(tenant_id="TEN", documents=[valid, unsupported])
    assert control.snapshot(tenant_id="TEN")["summary"]["total_findings"] == 0


def test_shadow_intake_preflights_every_schema_before_durable_writes(tmp_path):
    valid = findings()[0]
    malformed = json.loads(json.dumps(valid))
    malformed["finding_info"]["uid"] += "-MALFORMED"
    malformed.pop("class_uid")
    control = ShadowFleetControlPlane(tmp_path, host_env={})

    with pytest.raises(ShadowControlError, match="finding 2 failed intake preflight"):
        control.intake(tenant_id="TEN", documents=[valid, malformed])

    assert control.snapshot(tenant_id="TEN")["summary"]["total_findings"] == 0


def test_shadow_case_detail_is_tenant_isolated_and_has_no_action_boundary(tmp_path):
    control = ShadowFleetControlPlane(tmp_path, host_env={})
    batch = control.intake(tenant_id="TEN-A", documents=[findings()[0]])
    case_id = batch.case_ids[0]
    detail = control.case_detail(tenant_id="TEN-A", case_id=case_id)
    assert detail["safety_boundary"] == {
        "mode": "shadow", "approval": False, "scheduling": False,
        "execution": False, "external_models": False,
    }
    with pytest.raises(ShadowControlError, match="does not belong"):
        control.case_detail(tenant_id="TEN-B", case_id=case_id)


def test_shadow_live_validation_uses_only_ready_read_only_connector(
        tmp_path, monkeypatch):
    bin_dir = fake_az.install(tmp_path / "bin")
    environment = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                   "HOME": str(tmp_path / "home"), **fake_az.scanner_credentials()}
    control = ShadowFleetControlPlane(tmp_path / "fleet", host_env=environment)
    batch = control.intake(tenant_id="TEN", documents=[findings()[0]])
    result = control.validate(tenant_id="TEN", case_id=batch.case_ids[0])
    assert result["case"]["state"] == "validated"
    assert result["findings"][0]["status"] == "confirmed"
    assert result["fleet"]["summary"]["case_state_counts"] == {"validated": 1}


def test_shadow_validation_refuses_an_unready_connector(tmp_path):
    control = ShadowFleetControlPlane(tmp_path, host_env={})
    batch = control.intake(tenant_id="TEN", documents=[findings()[0]])
    with pytest.raises(ShadowControlError, match="connector is not ready"):
        control.validate(tenant_id="TEN", case_id=batch.case_ids[0])


def test_shadow_batch_validation_preflights_then_processes_multiple_cases(tmp_path):
    bin_dir = fake_az.install(tmp_path / "bin")
    environment = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                   "HOME": str(tmp_path / "home"), **fake_az.scanner_credentials()}
    control = ShadowFleetControlPlane(tmp_path / "fleet", host_env=environment)
    documents = []
    for suffix in ("one", "two"):
        document = json.loads(FIXTURE.read_text())
        document["finding_info"]["uid"] += f"-{suffix}"
        document["resources"][0]["uid"] = (
            document["resources"][0]["uid"].rsplit("/", 1)[0] + f"/{suffix}")
        documents.append(document)
    batch = control.intake(tenant_id="TEN", documents=documents)

    result = control.validate_batch(tenant_id="TEN", case_ids=batch.case_ids)

    assert result["requested"] == result["processed"] == 2
    assert {item["state"] for item in result["outcomes"]} == {"validated"}
    assert result["fleet"]["summary"]["case_state_counts"] == {"validated": 2}


def test_shadow_validation_rejects_unsupported_control_before_cloud_access(tmp_path):
    bin_dir = fake_az.install(tmp_path / "bin")
    environment = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                   "HOME": str(tmp_path / "home"), **fake_az.scanner_credentials()}
    control = ShadowFleetControlPlane(tmp_path / "fleet", host_env=environment)
    document = findings()[0]
    document["finding_info"]["analytic"]["uid"] = "unknown_customer_control"
    case_id = control.intake(tenant_id="TEN", documents=[document]).case_ids[0]

    with pytest.raises(ShadowControlError, match="no controls with deterministic"):
        control.validate(tenant_id="TEN", case_id=case_id)
    assert fake_az.calls(bin_dir) == []


def test_shadow_validation_confirms_supported_control_in_mixed_case(
        tmp_path, monkeypatch):
    bin_dir = fake_az.install(tmp_path / "bin")
    environment = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                   "HOME": str(tmp_path / "home"), **fake_az.scanner_credentials()}
    control = ShadowFleetControlPlane(tmp_path / "fleet", host_env=environment)
    supported = findings()[0]
    unsupported = json.loads(json.dumps(supported))
    unsupported["finding_info"]["uid"] += "-UNKNOWN"
    unsupported["finding_info"]["analytic"]["uid"] = "unknown_customer_control"
    case_id = control.intake(
        tenant_id="TEN", documents=[supported, unsupported]).case_ids[0]

    result = control.validate(tenant_id="TEN", case_id=case_id)

    assert result["case"]["state"] == "validated"
    assert {item["status"] for item in result["findings"]} == {
        "confirmed", "unsupported"}
    fleet_case = result["fleet"]["cases"][0]
    assert fleet_case["validation_counts"] == {
        "confirmed": 1, "unsupported": 1}
