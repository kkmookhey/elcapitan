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
NETWORK_SUBNET_UID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001/"
    "resourceGroups/fixture/providers/Microsoft.Network/virtualNetworks/"
    "fixture/subnets/application")
APP_SERVICE_UID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001/"
    "resourceGroups/fixture/providers/Microsoft.Web/sites/application")


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


def raw(rule_id="storage_account_public_network_access_disabled", *, resource_type=None):
    document = json.loads(FIXTURE.read_text())
    document["finding_info"]["analytic"]["uid"] = rule_id
    if resource_type is not None:
        document["resources"][0]["type"] = resource_type
    elif rule_id.startswith("sqlserver_"):
        document["resources"][0]["type"] = "microsoft.sql/servers"
    elif rule_id.startswith("keyvault_"):
        document["resources"][0]["type"] = "microsoft.keyvault/vaults"
    elif rule_id.startswith("network_subnet_"):
        document["resources"][0]["type"] = (
            "microsoft.network/virtualnetworks/subnets")
        document["resources"][0]["uid"] = NETWORK_SUBNET_UID
        document["resources"][0]["name"] = "application"
    elif rule_id.startswith("app_"):
        document["resources"][0]["type"] = (
            "microsoft.web/sites/config"
            if rule_id == "app_client_certificates_on"
            else "microsoft.web/sites")
        document["resources"][0]["uid"] = APP_SERVICE_UID
        document["resources"][0]["name"] = "application"
    return document


def state(public_network_access="Enabled"):
    return CloudState(
        provider="azure",
        resource_uid=("/subscriptions/8cd2b4cc-c789-466d-a8f7-8f51fb20985d/"
                      "resourceGroups/eiger-rg/providers/Microsoft.Storage/"
                      "storageAccounts/eigercorpus8dlub3zy"),
        config=(("public_network_access", json.dumps(public_network_access)),))


def storage_security_state(**overrides):
    values = {
        "encryption": {
            "keySource": "Microsoft.Storage",
            "requireInfrastructureEncryption": False,
        },
        "sku": {"name": "Standard_LRS", "tier": "Standard"},
        "network_rule_set": {"defaultAction": "Allow", "bypass": "None"},
        "private_endpoint_connections": [],
        "allow_shared_key_access": True,
        "default_to_oauth_authentication": False,
        "blob_container_delete_retention_policy": {"enabled": False},
        "key_policy": None,
    }
    values.update(overrides)
    return CloudState(
        provider="azure",
        resource_uid=("/subscriptions/8cd2b4cc-c789-466d-a8f7-8f51fb20985d/"
                      "resourceGroups/eiger-rg/providers/Microsoft.Storage/"
                      "storageAccounts/eigercorpus8dlub3zy"),
        config=tuple((key, json.dumps(value)) for key, value in values.items()),
    )


def sql_state(protector="AzureKeyVault", database_tde=None):
    tde = {"application": "Enabled"} if database_tde is None else database_tde
    return CloudState(
        provider="azure",
        resource_uid=("/subscriptions/8cd2b4cc-c789-466d-a8f7-8f51fb20985d/"
                      "resourceGroups/eiger-rg/providers/Microsoft.Storage/"
                      "storageAccounts/eigercorpus8dlub3zy"),
        config=(
            ("sql_tde_protector_type", json.dumps(protector)),
            ("sql_database_inventory", json.dumps(
                ["master", *tde.keys()])),
            ("sql_user_database_tde", json.dumps(tde)),
        ))


def key_vault_state(*, rbac=False, soft_delete=True,
                    purge_protection=False, private_endpoints=0):
    return CloudState(
        provider="azure",
        resource_uid=("/subscriptions/8cd2b4cc-c789-466d-a8f7-8f51fb20985d/"
                      "resourceGroups/eiger-rg/providers/Microsoft.Storage/"
                      "storageAccounts/eigercorpus8dlub3zy"),
        config=(
            ("keyvault_enable_rbac_authorization", json.dumps(rbac)),
            ("keyvault_enable_soft_delete", json.dumps(soft_delete)),
            ("keyvault_enable_purge_protection", json.dumps(purge_protection)),
            ("keyvault_private_endpoint_connection_count",
             json.dumps(private_endpoints)),
        ))


def network_subnet_state(nsg_id=None):
    return CloudState(
        provider="azure", resource_uid=NETWORK_SUBNET_UID,
        config=(
            ("network_subnet_name", '"application"'),
            ("network_subnet_nsg_id", json.dumps(nsg_id)),
        ))


def app_service_state(*, kind="app,linux", client_cert_enabled=False,
                      client_cert_mode="Required", auth_enabled=False,
                      http20_enabled=False, logs=None, ftps_state=None,
                      public_network_access=None, virtual_network_subnet_id=None):
    return CloudState(
        provider="azure", resource_uid=APP_SERVICE_UID,
        config=(
            ("app_kind", json.dumps(kind)),
            ("app_client_cert_enabled", json.dumps(client_cert_enabled)),
            ("app_client_cert_mode", json.dumps(client_cert_mode)),
            ("app_auth_platform_enabled", json.dumps(auth_enabled)),
            ("app_http20_enabled", json.dumps(http20_enabled)),
            ("app_diagnostic_log_settings", json.dumps(logs or [])),
            ("app_ftps_state", json.dumps(ftps_state)),
            ("app_public_network_access", json.dumps(public_network_access)),
            ("app_virtual_network_subnet_id", json.dumps(virtual_network_subnet_id)),
        ))


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


def test_registered_rule_on_wrong_resource_type_is_unsupported(product):
    *_, intake = product
    opened = intake.ingest(raw(
        "sqlserver_tde_encrypted_with_cmk",
        resource_type="microsoft.storage/storageaccounts"), tenant_id="TEN-001")
    outcome = validator(product, lambda finding, env: sql_state()).validate(
        opened.case.case_id, host_env={})
    assert outcome.case.state is CaseState.BLOCKED
    assert outcome.findings[0].status is FindingValidationStatus.UNSUPPORTED
    assert "resource type" in outcome.findings[0].reason


def test_sql_tde_cmk_finding_is_not_confirmed_when_every_user_database_is_encrypted(
        product):
    *_, intake = product
    opened = intake.ingest(raw("sqlserver_tde_encrypted_with_cmk"), tenant_id="TEN-001")
    outcome = validator(product, lambda finding, env: sql_state()).validate(
        opened.case.case_id, host_env={})
    assert outcome.case.state is CaseState.CLOSED_NO_ACTION
    assert outcome.findings[0].status is FindingValidationStatus.NOT_CONFIRMED
    assert "every user database" in outcome.findings[0].reason


@pytest.mark.parametrize(
    ("protector", "database_tde", "reason"),
    [
        ("ServiceManaged", {"application": "Enabled"}, "not 'AzureKeyVault'"),
        ("AzureKeyVault", {"application": "Disabled"}, "application"),
    ],
)
def test_sql_tde_cmk_finding_is_confirmed_for_each_exact_failure_mode(
        product, protector, database_tde, reason):
    *_, intake = product
    opened = intake.ingest(raw("sqlserver_tde_encrypted_with_cmk"), tenant_id="TEN-001")
    outcome = validator(
        product, lambda finding, env: sql_state(protector, database_tde)).validate(
            opened.case.case_id, host_env={})
    assert outcome.case.state is CaseState.VALIDATED
    assert outcome.findings[0].status is FindingValidationStatus.CONFIRMED
    assert reason in outcome.findings[0].reason


def test_sql_tde_cmk_stale_finding_closes_when_no_user_databases_remain(product):
    *_, intake = product
    opened = intake.ingest(raw("sqlserver_tde_encrypted_with_cmk"), tenant_id="TEN-001")
    outcome = validator(
        product, lambda finding, env: sql_state("AzureKeyVault", {})).validate(
            opened.case.case_id, host_env={})
    assert outcome.case.state is CaseState.CLOSED_NO_ACTION
    assert "no user databases" in outcome.findings[0].reason


@pytest.mark.parametrize(
    ("rule_id", "cloud_state", "expected"),
    [
        ("keyvault_rbac_enabled", key_vault_state(rbac=False),
         FindingValidationStatus.CONFIRMED),
        ("keyvault_rbac_enabled", key_vault_state(rbac=True),
         FindingValidationStatus.NOT_CONFIRMED),
        ("keyvault_recoverable", key_vault_state(purge_protection=False),
         FindingValidationStatus.CONFIRMED),
        ("keyvault_recoverable", key_vault_state(purge_protection=True),
         FindingValidationStatus.NOT_CONFIRMED),
        ("keyvault_private_endpoints", key_vault_state(private_endpoints=0),
         FindingValidationStatus.CONFIRMED),
        ("keyvault_private_endpoints", key_vault_state(private_endpoints=1),
         FindingValidationStatus.NOT_CONFIRMED),
    ],
)
def test_key_vault_findings_use_the_registered_exact_evaluator(
        product, rule_id, cloud_state, expected):
    *_, intake = product
    opened = intake.ingest(raw(rule_id), tenant_id="TEN-001")
    outcome = validator(product, lambda finding, env: cloud_state).validate(
        opened.case.case_id, host_env={})
    assert outcome.findings[0].status is expected


@pytest.mark.parametrize(
    ("nsg_id", "expected"),
    [
        (None, FindingValidationStatus.CONFIRMED),
        ("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/"
         "networkSecurityGroups/application",
         FindingValidationStatus.NOT_CONFIRMED),
    ],
)
def test_network_subnet_finding_is_bound_to_nested_resource_type(
        product, nsg_id, expected):
    *_, intake = product
    opened = intake.ingest(
        raw("network_subnet_nsg_associated"), tenant_id="TEN-001")
    outcome = validator(
        product, lambda finding, env: network_subnet_state(nsg_id)).validate(
            opened.case.case_id, host_env={})
    assert outcome.findings[0].status is expected


@pytest.mark.parametrize(
    ("rule_id", "cloud_state", "expected"),
    [
        ("app_client_certificates_on", app_service_state(),
         FindingValidationStatus.CONFIRMED),
        ("app_client_certificates_on", app_service_state(client_cert_enabled=True),
         FindingValidationStatus.NOT_CONFIRMED),
        ("app_ensure_auth_is_set_up", app_service_state(),
         FindingValidationStatus.CONFIRMED),
        ("app_ensure_auth_is_set_up", app_service_state(auth_enabled=True),
         FindingValidationStatus.NOT_CONFIRMED),
        ("app_ensure_using_http20", app_service_state(),
         FindingValidationStatus.CONFIRMED),
        ("app_ensure_using_http20", app_service_state(http20_enabled=True),
         FindingValidationStatus.NOT_CONFIRMED),
        ("app_http_logs_enabled", app_service_state(),
         FindingValidationStatus.CONFIRMED),
        ("app_http_logs_enabled", app_service_state(logs=[{
            "setting": "security", "category": "AppServiceHTTPLogs",
            "category_group": None, "enabled": True,
         }]), FindingValidationStatus.NOT_CONFIRMED),
        ("app_function_ftps_deployment_disabled", app_service_state(
            kind="functionapp,linux", ftps_state="AllAllowed"),
         FindingValidationStatus.CONFIRMED),
        ("app_function_ftps_deployment_disabled", app_service_state(
            kind="functionapp,linux", ftps_state="Disabled"),
         FindingValidationStatus.NOT_CONFIRMED),
        ("app_function_not_publicly_accessible", app_service_state(
            kind="functionapp,linux", public_network_access="Enabled"),
         FindingValidationStatus.CONFIRMED),
        ("app_function_not_publicly_accessible", app_service_state(
            kind="functionapp,linux", public_network_access="Disabled"),
         FindingValidationStatus.NOT_CONFIRMED),
        ("app_function_vnet_integration_enabled", app_service_state(
            kind="functionapp,linux", virtual_network_subnet_id=None),
         FindingValidationStatus.CONFIRMED),
        ("app_function_vnet_integration_enabled", app_service_state(
            kind="functionapp,linux", virtual_network_subnet_id="/subnets/apps"),
         FindingValidationStatus.NOT_CONFIRMED),
    ],
)
def test_app_service_findings_are_bound_to_exact_ocsf_resource_types(
        product, rule_id, cloud_state, expected):
    *_, intake = product
    opened = intake.ingest(raw(rule_id), tenant_id="TEN-001")
    outcome = validator(product, lambda finding, env: cloud_state).validate(
        opened.case.case_id, host_env={})
    assert outcome.findings[0].status is expected


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


@pytest.mark.parametrize(
    "rule_id",
    [
        "storage_ensure_encryption_with_customer_managed_keys",
        "storage_geo_redundant_enabled",
        "storage_infrastructure_encryption_is_enabled",
        "storage_default_network_access_rule_is_denied",
        "storage_ensure_private_endpoints_in_storage_accounts",
        "storage_account_key_access_disabled",
        "storage_default_to_entra_authorization_enabled",
        "storage_ensure_soft_delete_is_enabled",
        "storage_ensure_azure_services_are_trusted_to_access_is_enabled",
        "storage_key_rotation_90_days",
    ],
)
def test_expanded_storage_findings_use_registered_evaluators(
        product, rule_id):
    *_, intake = product
    opened = intake.ingest(raw(rule_id), tenant_id="TEN-001")
    outcome = validator(
        product, lambda finding, env: storage_security_state()).validate(
            opened.case.case_id, host_env={})
    assert outcome.findings[0].status is FindingValidationStatus.CONFIRMED


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
