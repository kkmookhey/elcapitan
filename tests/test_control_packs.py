import pytest

from elcapitan.control_packs import (
    BUILTIN_CONTROL_PACKS, ControlDefinition, ControlPack, ControlPackRegistry,
    builtin_registry,
)
from elcapitan.control_packs.models import ControlEvaluation


def _evaluation(values):
    return ControlEvaluation(False, "fixture")


def definition(*, pack_id="fixture", provider="azure", rule_id="fixture_rule"):
    return ControlDefinition(
        pack_id=pack_id, provider=provider, rule_id=rule_id,
        resource_family="fixture", resource_types=("fixture/type",),
        live_validation=True, remediation_planning=False, live_execution=False,
        evidence_aspects=("fixture",), evaluator=_evaluation)


def test_builtin_registry_is_composed_from_service_packs():
    assert {pack.pack_id for pack in BUILTIN_CONTROL_PACKS} == {
        "aws-s3", "azure-app-service", "azure-key-vault", "azure-network", "azure-sql",
        "azure-storage"}
    registry = builtin_registry()
    assert len(registry.list()) == 25
    assert registry.get("AZURE", "sqlserver_tde_encrypted_with_cmk").pack_id == (
        "azure-sql")
    assert registry.get(
        "azure", "sqlserver_tde_encrypted_with_cmk",
        "microsoft.storage/storageaccounts") is None
    assert registry.get(
        "azure", "app_client_certificates_on",
        "microsoft.web/sites/config") is not None
    assert registry.get(
        "azure", "app_client_certificates_on",
        "microsoft.web/sites") is None


def test_control_definition_serialization_never_exposes_executable_callable():
    value = definition().to_dict()
    assert "evaluator" not in value
    assert value["evidence_aspects"] == ["fixture"]


def test_duplicate_provider_rule_registration_fails_closed():
    first = ControlPack("one", (definition(pack_id="one"),))
    second = ControlPack("two", (definition(pack_id="two"),))
    with pytest.raises(ValueError, match="unique by provider and rule"):
        ControlPackRegistry((first, second))


def test_pack_rejects_a_definition_owned_by_another_pack():
    with pytest.raises(ValueError, match="containing pack"):
        ControlPack("expected", (definition(pack_id="different"),))


@pytest.mark.parametrize(
    ("rule_id", "values", "confirmed"),
    [
        ("storage_ensure_encryption_with_customer_managed_keys", {
            "encryption": {"keySource": "Microsoft.Storage"}}, True),
        ("storage_ensure_encryption_with_customer_managed_keys", {
            "encryption": {"keySource": "Microsoft.Keyvault"}}, False),
        ("storage_geo_redundant_enabled", {
            "sku": {"name": "Standard_LRS"}}, True),
        ("storage_geo_redundant_enabled", {
            "sku": {"name": "Standard_GZRS"}}, False),
        ("storage_infrastructure_encryption_is_enabled", {
            "encryption": {"requireInfrastructureEncryption": None}}, True),
        ("storage_infrastructure_encryption_is_enabled", {
            "encryption": {"requireInfrastructureEncryption": True}}, False),
        ("storage_default_network_access_rule_is_denied", {
            "network_rule_set": {"defaultAction": "Allow"}}, True),
        ("storage_default_network_access_rule_is_denied", {
            "network_rule_set": {"defaultAction": "Deny"}}, False),
        ("storage_ensure_private_endpoints_in_storage_accounts", {
            "private_endpoint_connections": []}, True),
        ("storage_ensure_private_endpoints_in_storage_accounts", {
            "private_endpoint_connections": [{"id": "/privateEndpoints/one"}]},
         False),
        ("storage_account_key_access_disabled", {
            "allow_shared_key_access": None}, True),
        ("storage_account_key_access_disabled", {
            "allow_shared_key_access": False}, False),
        ("storage_default_to_entra_authorization_enabled", {
            "default_to_oauth_authentication": False}, True),
        ("storage_default_to_entra_authorization_enabled", {
            "default_to_oauth_authentication": True}, False),
        ("storage_ensure_soft_delete_is_enabled", {
            "blob_container_delete_retention_policy": {"enabled": False}}, True),
        ("storage_ensure_soft_delete_is_enabled", {
            "blob_container_delete_retention_policy": {"enabled": True}}, False),
        ("storage_ensure_azure_services_are_trusted_to_access_is_enabled", {
            "network_rule_set": {"bypass": "None"}}, True),
        ("storage_ensure_azure_services_are_trusted_to_access_is_enabled", {
            "network_rule_set": {"bypass": "Logging,AzureServices"}}, False),
    ],
)
def test_storage_pack_matches_pinned_prowler_truth_conditions(
        rule_id, values, confirmed):
    assert builtin_registry().get("azure", rule_id).evaluator(values).confirmed is (
        confirmed)


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("storage_ensure_encryption_with_customer_managed_keys", {
            "encryption": []}),
        ("storage_geo_redundant_enabled", {"sku": {"name": None}}),
        ("storage_infrastructure_encryption_is_enabled", {
            "encryption": {"requireInfrastructureEncryption": "false"}}),
        ("storage_default_network_access_rule_is_denied", {
            "network_rule_set": {"defaultAction": "Unknown"}}),
        ("storage_ensure_private_endpoints_in_storage_accounts", {
            "private_endpoint_connections": ["bad"]}),
        ("storage_account_key_access_disabled", {"allow_shared_key_access": 0}),
        ("storage_default_to_entra_authorization_enabled", {
            "default_to_oauth_authentication": "true"}),
        ("storage_ensure_soft_delete_is_enabled", {
            "blob_container_delete_retention_policy": {"enabled": 1}}),
        ("storage_ensure_azure_services_are_trusted_to_access_is_enabled", {
            "network_rule_set": {"bypass": None}}),
    ],
)
def test_storage_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid|no keySource|no name|not an"):
        builtin_registry().get("azure", rule_id).evaluator(values)


def test_sql_pack_rejects_partial_database_evidence():
    control = builtin_registry().get("azure", "sqlserver_tde_encrypted_with_cmk")
    with pytest.raises(ValueError, match="does not match"):
        control.evaluator({
            "sql_tde_protector_type": "AzureKeyVault",
            "sql_database_inventory": ["master", "one", "two"],
            "sql_user_database_tde": {"one": "Enabled"},
        })


@pytest.mark.parametrize(
    ("rule_id", "values", "confirmed"),
    [
        ("keyvault_rbac_enabled",
         {"keyvault_enable_rbac_authorization": False}, True),
        ("keyvault_rbac_enabled",
         {"keyvault_enable_rbac_authorization": True}, False),
        ("keyvault_recoverable", {
            "keyvault_enable_soft_delete": True,
            "keyvault_enable_purge_protection": False,
         }, True),
        ("keyvault_recoverable", {
            "keyvault_enable_soft_delete": True,
            "keyvault_enable_purge_protection": True,
         }, False),
        ("keyvault_private_endpoints",
         {"keyvault_private_endpoint_connection_count": 0}, True),
        ("keyvault_private_endpoints",
         {"keyvault_private_endpoint_connection_count": 1}, False),
    ],
)
def test_key_vault_pack_matches_pinned_prowler_truth_conditions(
        rule_id, values, confirmed):
    control = builtin_registry().get("azure", rule_id)
    assert control.evaluator(values).confirmed is confirmed


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("keyvault_rbac_enabled",
         {"keyvault_enable_rbac_authorization": "false"}),
        ("keyvault_recoverable", {
            "keyvault_enable_soft_delete": True,
            "keyvault_enable_purge_protection": 1,
         }),
        ("keyvault_private_endpoints",
         {"keyvault_private_endpoint_connection_count": True}),
    ],
)
def test_key_vault_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid"):
        builtin_registry().get("azure", rule_id).evaluator(values)


@pytest.mark.parametrize(
    ("name", "nsg_id", "confirmed"),
    [
        ("application", None, True),
        ("application", "/subscriptions/sub/resourceGroups/rg/providers/"
         "Microsoft.Network/networkSecurityGroups/app", False),
        ("GatewaySubnet", None, False),
        ("AzureFirewallSubnet", None, False),
        ("AzureFirewallManagementSubnet", None, False),
        ("AzureBastionSubnet", None, False),
        ("RouteServerSubnet", None, False),
    ],
)
def test_network_subnet_pack_matches_pinned_prowler_semantics(
        name, nsg_id, confirmed):
    control = builtin_registry().get("azure", "network_subnet_nsg_associated")
    result = control.evaluator({
        "network_subnet_name": name,
        "network_subnet_nsg_id": nsg_id,
    })
    assert result.confirmed is confirmed


def test_network_subnet_pack_rejects_malformed_nsg_id():
    control = builtin_registry().get("azure", "network_subnet_nsg_associated")
    with pytest.raises(ValueError, match="invalid NSG id"):
        control.evaluator({
            "network_subnet_name": "application",
            "network_subnet_nsg_id": {},
        })


@pytest.mark.parametrize(
    ("rule_id", "values", "confirmed"),
    [
        ("app_client_certificates_on", {
            "app_kind": "app,linux",
            "app_client_cert_enabled": True,
            "app_client_cert_mode": "Required",
         }, False),
        ("app_client_certificates_on", {
            "app_kind": "app,linux",
            "app_client_cert_enabled": False,
            "app_client_cert_mode": "Required",
         }, True),
        ("app_ensure_auth_is_set_up", {
            "app_kind": "app,linux",
            "app_auth_platform_enabled": True,
         }, False),
        ("app_ensure_auth_is_set_up", {
            "app_kind": "app,linux",
            "app_auth_platform_enabled": None,
         }, True),
        ("app_ensure_auth_is_set_up", {
            "app_kind": "functionapp,linux",
            "app_auth_platform_enabled": False,
         }, False),
        ("app_ensure_using_http20", {
            "app_kind": "app,linux",
            "app_http20_enabled": True,
         }, False),
        ("app_ensure_using_http20", {
            "app_kind": "app,linux",
            "app_http20_enabled": False,
         }, True),
        ("app_http_logs_enabled", {
            "app_kind": "app,linux",
            "app_diagnostic_log_settings": [{
                "setting": "security",
                "category": "AppServiceHTTPLogs",
                "category_group": None,
                "enabled": True,
            }],
         }, False),
        ("app_function_ftps_deployment_disabled", {
            "app_kind": "functionapp,linux",
            "app_ftps_state": "AllAllowed",
         }, True),
        ("app_function_ftps_deployment_disabled", {
            "app_kind": "functionapp,linux",
            "app_ftps_state": "Disabled",
         }, False),
        ("app_function_not_publicly_accessible", {
            "app_kind": "functionapp,linux",
            "app_public_network_access": "Enabled",
         }, True),
        ("app_function_not_publicly_accessible", {
            "app_kind": "functionapp,linux",
            "app_public_network_access": "Disabled",
         }, False),
        ("app_function_vnet_integration_enabled", {
            "app_kind": "functionapp,linux",
            "app_virtual_network_subnet_id": None,
         }, True),
        ("app_function_vnet_integration_enabled", {
            "app_kind": "functionapp,linux",
            "app_virtual_network_subnet_id": "/subscriptions/sub/resourceGroups/rg/"
                                             "providers/Microsoft.Network/"
                                             "virtualNetworks/vnet/subnets/apps",
         }, False),
        ("app_function_ftps_deployment_disabled", {
            "app_kind": "app,linux",
            "app_ftps_state": "AllAllowed",
         }, False),
        ("app_http_logs_enabled", {
            "app_kind": "app,linux",
            "app_diagnostic_log_settings": [{
                "setting": "security",
                "category": None,
                "category_group": "allLogs",
                "enabled": True,
            }],
         }, False),
        ("app_http_logs_enabled", {
            "app_kind": "app,linux",
            "app_diagnostic_log_settings": [],
         }, True),
        ("app_http_logs_enabled", {
            "app_kind": "functionapp,linux",
            "app_diagnostic_log_settings": [],
         }, False),
    ],
)
def test_app_service_pack_matches_pinned_prowler_truth_conditions(
        rule_id, values, confirmed):
    control = builtin_registry().get("azure", rule_id)
    assert control.evaluator(values).confirmed is confirmed


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("app_client_certificates_on", {
            "app_kind": "app", "app_client_cert_enabled": "true",
            "app_client_cert_mode": "Required"}),
        ("app_ensure_auth_is_set_up", {
            "app_kind": "app", "app_auth_platform_enabled": 1}),
        ("app_ensure_using_http20", {
            "app_kind": "app", "app_http20_enabled": "false"}),
        ("app_http_logs_enabled", {
            "app_kind": "app", "app_diagnostic_log_settings": [{}]}),
        ("app_function_ftps_deployment_disabled", {
            "app_kind": "functionapp", "app_ftps_state": 1}),
        ("app_function_not_publicly_accessible", {
            "app_kind": "functionapp", "app_public_network_access": False}),
        ("app_function_vnet_integration_enabled", {
            "app_kind": "functionapp", "app_virtual_network_subnet_id": {}}),
    ],
)
def test_app_service_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid|not a"):
        builtin_registry().get("azure", rule_id).evaluator(values)
