"""Deterministic Azure Key Vault control definitions."""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _optional_boolean(values, aspect: str):
    value = require(values, aspect)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"live Key Vault state has invalid {aspect} {value!r}")
    return value


def _rbac_enabled(values) -> ControlEvaluation:
    enabled = _optional_boolean(values, "keyvault_enable_rbac_authorization")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("Key Vault data-plane RBAC is enabled" if enabled is True
                else "Key Vault data-plane RBAC is not enabled"),
    )


def _recoverable(values) -> ControlEvaluation:
    soft_delete = _optional_boolean(values, "keyvault_enable_soft_delete")
    purge_protection = _optional_boolean(
        values, "keyvault_enable_purge_protection")
    missing = []
    if soft_delete is not True:
        missing.append("soft delete")
    if purge_protection is not True:
        missing.append("purge protection")
    return ControlEvaluation(
        confirmed=bool(missing),
        reason=("Key Vault has soft delete and purge protection enabled"
                if not missing else
                "Key Vault is missing: " + ", ".join(missing)),
    )


def _private_endpoints(values) -> ControlEvaluation:
    count = require(values, "keyvault_private_endpoint_connection_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError(
            "live Key Vault state has invalid private-endpoint connection count "
            f"{count!r}")
    return ControlEvaluation(
        confirmed=count == 0,
        reason=("Key Vault has no private-endpoint connections" if count == 0
                else f"Key Vault has {count} private-endpoint connection(s)"),
    )


AZURE_KEY_VAULT_PACK = ControlPack(
    pack_id="azure-key-vault",
    controls=(
        ControlDefinition(
            pack_id="azure-key-vault", provider="azure",
            rule_id="keyvault_private_endpoints",
            resource_family="key_vault",
            resource_types=("microsoft.keyvault/vaults",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("keyvault_private_endpoint_connection_count",),
            evaluator=_private_endpoints,
        ),
        ControlDefinition(
            pack_id="azure-key-vault", provider="azure",
            rule_id="keyvault_rbac_enabled",
            resource_family="key_vault",
            resource_types=("microsoft.keyvault/vaults",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("keyvault_enable_rbac_authorization",),
            evaluator=_rbac_enabled,
        ),
        ControlDefinition(
            pack_id="azure-key-vault", provider="azure",
            rule_id="keyvault_recoverable",
            resource_family="key_vault",
            resource_types=("microsoft.keyvault/vaults",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=(
                "keyvault_enable_soft_delete",
                "keyvault_enable_purge_protection",
            ),
            evaluator=_recoverable,
        ),
    ),
)
