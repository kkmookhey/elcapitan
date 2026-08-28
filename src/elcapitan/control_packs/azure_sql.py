"""Deterministic Azure SQL control definitions."""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _tde_encrypted_with_cmk(values) -> ControlEvaluation:
    protector_type = require(values, "sql_tde_protector_type")
    inventory = require(values, "sql_database_inventory")
    database_tde = require(values, "sql_user_database_tde")
    if protector_type not in {"AzureKeyVault", "ServiceManaged"}:
        raise ValueError(
            f"live SQL state has unknown TDE protector type {protector_type!r}")
    if (not isinstance(inventory, list)
            or any(not isinstance(name, str) or not name for name in inventory)):
        raise ValueError("live SQL state has no valid database inventory")
    if len({name.lower() for name in inventory}) != len(inventory):
        raise ValueError("live SQL state has duplicate database inventory entries")
    if not isinstance(database_tde, dict):
        raise ValueError("live SQL state has no user-database TDE map")
    invalid = {
        name: value for name, value in database_tde.items()
        if (not isinstance(name, str) or not name
            or value not in {"Enabled", "Disabled"})
    }
    if invalid:
        raise ValueError(
            f"live SQL state has invalid user-database TDE values: {invalid!r}")
    expected = {name for name in inventory if name.lower() != "master"}
    if set(database_tde) != expected:
        raise ValueError(
            "live SQL state user-database TDE map does not match its complete "
            f"inventory: expected {sorted(expected)!r}, got {sorted(database_tde)!r}")

    disabled = sorted(
        name for name, value in database_tde.items() if value != "Enabled")
    confirmed = protector_type != "AzureKeyVault" or bool(disabled)
    if protector_type != "AzureKeyVault":
        reason = f"TDE protector type is {protector_type!r}, not 'AzureKeyVault'"
    elif disabled:
        reason = "TDE is disabled for user database(s): " + ", ".join(disabled)
    elif database_tde:
        reason = (
            "TDE protector is 'AzureKeyVault' and TDE is enabled for every "
            "user database")
    else:
        reason = "SQL server has no user databases; only master is excluded"
    return ControlEvaluation(confirmed=confirmed, reason=reason)


AZURE_SQL_PACK = ControlPack(
    pack_id="azure-sql",
    controls=(
        ControlDefinition(
            pack_id="azure-sql", provider="azure",
            rule_id="sqlserver_tde_encrypted_with_cmk",
            resource_family="sql_server",
            resource_types=("microsoft.sql/servers",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=(
                "sql_tde_protector_type", "sql_database_inventory",
                "sql_user_database_tde"),
            evaluator=_tde_encrypted_with_cmk,
        ),
    ),
)
