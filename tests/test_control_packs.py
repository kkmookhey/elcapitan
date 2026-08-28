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
        "aws-s3", "azure-sql", "azure-storage"}
    registry = builtin_registry()
    assert len(registry.list()) == 5
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
