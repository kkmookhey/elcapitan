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
        "aws-s3", "azure-key-vault", "azure-sql", "azure-storage"}
    registry = builtin_registry()
    assert len(registry.list()) == 8
    assert registry.get("AZURE", "sqlserver_tde_encrypted_with_cmk").pack_id == (
        "azure-sql")
    assert registry.get(
        "azure", "sqlserver_tde_encrypted_with_cmk",
        "microsoft.storage/storageaccounts") is None


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
