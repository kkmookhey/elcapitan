"""Deterministic Azure Cosmos DB control definitions."""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _optional_boolean(values, aspect: str):
    value = require(values, aspect)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"live Cosmos DB state has invalid {aspect} {value!r}")
    return value


def _optional_enum(values, aspect: str, allowed: set[str]):
    value = require(values, aspect)
    if value is not None and (not isinstance(value, str) or value not in allowed):
        raise ValueError(f"live Cosmos DB state has invalid {aspect} {value!r}")
    return value


def _automatic_failover(values) -> ControlEvaluation:
    enabled = _optional_boolean(values, "cosmosdb_enable_automatic_failover")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("Cosmos DB automatic failover is enabled" if enabled is True
                else "Cosmos DB automatic failover is not enabled"),
    )


def _continuous_backup(values) -> ControlEvaluation:
    policy = _optional_enum(
        values, "cosmosdb_backup_policy_type", {"Continuous", "Periodic"})
    return ControlEvaluation(
        confirmed=policy != "Continuous",
        reason=f"Cosmos DB backup policy type is {policy!r}",
    )


def _minimum_tls(values) -> ControlEvaluation:
    version = _optional_enum(
        values, "cosmosdb_minimum_tls_version",
        {"Tls", "Tls11", "Tls12", "Tls13"})
    secure = version in {"Tls12", "Tls13"}
    return ControlEvaluation(
        confirmed=not secure,
        reason=(f"Cosmos DB minimum TLS version is {version!r}"
                if version is not None else
                "Cosmos DB minimum TLS version is absent"),
    )


def _public_network(values) -> ControlEvaluation:
    access = _optional_enum(
        values, "cosmosdb_public_network_access",
        {"Disabled", "Enabled", "SecuredByPerimeter"})
    private = access in {"Disabled", "SecuredByPerimeter"}
    return ControlEvaluation(
        confirmed=not private,
        reason=(f"Cosmos DB public network access is {access!r}"
                if access is not None else
                "Cosmos DB public network access is absent"),
    )


AZURE_COSMOS_DB_PACK = ControlPack(
    pack_id="azure-cosmos-db",
    evidence_grade="contract_tested_export_observed",
    controls=(
        ControlDefinition(
            pack_id="azure-cosmos-db", provider="azure",
            rule_id="cosmosdb_account_automatic_failover_enabled",
            resource_family="cosmos_db",
            resource_types=("microsoft.documentdb/databaseaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("cosmosdb_enable_automatic_failover",),
            evaluator=_automatic_failover,
        ),
        ControlDefinition(
            pack_id="azure-cosmos-db", provider="azure",
            rule_id="cosmosdb_account_backup_policy_continuous",
            resource_family="cosmos_db",
            resource_types=("microsoft.documentdb/databaseaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("cosmosdb_backup_policy_type",),
            evaluator=_continuous_backup,
        ),
        ControlDefinition(
            pack_id="azure-cosmos-db", provider="azure",
            rule_id="cosmosdb_account_minimum_tls_version",
            resource_family="cosmos_db",
            resource_types=("microsoft.documentdb/databaseaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("cosmosdb_minimum_tls_version",),
            evaluator=_minimum_tls,
        ),
        ControlDefinition(
            pack_id="azure-cosmos-db", provider="azure",
            rule_id="cosmosdb_account_public_network_access_disabled",
            resource_family="cosmos_db",
            resource_types=("microsoft.documentdb/databaseaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("cosmosdb_public_network_access",),
            evaluator=_public_network,
        ),
    ),
)
