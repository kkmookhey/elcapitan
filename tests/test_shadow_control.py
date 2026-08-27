import json
import os
from pathlib import Path

import fake_az
import pytest

from elcapitan.intake import IntakeContext
from elcapitan import shadow_control
from elcapitan.shadow_control import ShadowControlError, ShadowFleetControlPlane


FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"


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

    with pytest.raises(ShadowControlError, match="without deterministic"):
        control.validate(tenant_id="TEN", case_id=case_id)
    assert fake_az.calls(bin_dir) == []
