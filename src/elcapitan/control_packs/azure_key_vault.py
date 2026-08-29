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


def _diagnostic_logging(values) -> ControlEvaluation:
    status = require(values, "keyvault_diagnostic_settings_status")
    settings = require(values, "keyvault_diagnostic_log_settings")
    if (not isinstance(status, str)
            or status not in {"available", "unavailable"}):
        raise ValueError(
            f"live Key Vault diagnostic-settings status is invalid: {status!r}")
    if status == "unavailable":
        if settings is not None:
            raise ValueError(
                "live Key Vault diagnostic settings have an invalid unavailable/"
                "logs pairing")
        raise ValueError("live Key Vault diagnostic settings are unavailable")
    if not isinstance(settings, list):
        raise ValueError("live Key Vault diagnostic settings are not a list")

    by_setting: dict[str, dict[str, bool]] = {}
    for position, entry in enumerate(settings):
        if not isinstance(entry, dict):
            raise ValueError(
                f"live Key Vault diagnostic log entry {position} is not an object")
        if set(entry) != {"setting", "category", "category_group", "enabled"}:
            raise ValueError(
                f"live Key Vault diagnostic log entry {position} has an invalid shape")
        setting = entry["setting"]
        category = entry["category"]
        category_group = entry["category_group"]
        enabled = entry["enabled"]
        if not isinstance(setting, str) or not setting:
            raise ValueError(
                f"live Key Vault diagnostic log entry {position} has no setting name")
        if category is not None and not isinstance(category, str):
            raise ValueError(
                f"live Key Vault diagnostic log entry {position} has invalid category")
        if category_group is not None and not isinstance(category_group, str):
            raise ValueError(
                f"live Key Vault diagnostic log entry {position} has invalid category group")
        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError(
                f"live Key Vault diagnostic log entry {position} has invalid enabled state")
        flags = by_setting.setdefault(setting, {
            "audit_category": False,
            "audit_group": False,
            "all_logs_group": False,
        })
        if enabled is True and category == "AuditEvent":
            flags["audit_category"] = True
        if enabled is True and category_group == "audit":
            flags["audit_group"] = True
        if enabled is True and category_group == "allLogs":
            flags["all_logs_group"] = True

    enabled = any(
        flags["audit_category"]
        or (flags["audit_group"] and flags["all_logs_group"])
        for flags in by_setting.values())
    return ControlEvaluation(
        confirmed=not enabled,
        reason=("Key Vault diagnostic audit logging is enabled" if enabled else
                "Key Vault diagnostic audit logging is not enabled"),
    )


AZURE_KEY_VAULT_PACK = ControlPack(
    pack_id="azure-key-vault",
    evidence_grade="e2e_measured",
    controls=(
        ControlDefinition(
            pack_id="azure-key-vault", provider="azure",
            rule_id="keyvault_logging_enabled",
            resource_family="key_vault",
            resource_types=("microsoft.keyvault/vaults",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=(
                "keyvault_diagnostic_settings_status",
                "keyvault_diagnostic_log_settings",
            ),
            evaluator=_diagnostic_logging,
            evidence_grade="contract_tested",
        ),
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
