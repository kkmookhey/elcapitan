"""Deterministic Azure Storage control definitions."""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _public_network_access(values) -> ControlEvaluation:
    value = require(values, "public_network_access")
    return ControlEvaluation(
        confirmed=str(value).lower() != "disabled",
        reason=f"public network access is {value!r}")


def _blob_public_access(values) -> ControlEvaluation:
    value = require(values, "allow_blob_public_access")
    return ControlEvaluation(
        confirmed=value is not False,
        reason=f"allow blob public access is {value!r}")


def _blob_versioning(values) -> ControlEvaluation:
    value = require(values, "blob_versioning")
    return ControlEvaluation(
        confirmed=value is not True,
        reason=f"blob versioning is {value!r}")


def _object(values, aspect: str) -> dict:
    value = require(values, aspect)
    if not isinstance(value, dict):
        raise ValueError(f"live storage state has invalid {aspect} {value!r}")
    return value


def _optional_boolean(values, aspect: str):
    value = require(values, aspect)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"live storage state has invalid {aspect} {value!r}")
    return value


def _customer_managed_key(values) -> ControlEvaluation:
    encryption = _object(values, "encryption")
    key_source = encryption.get("keySource")
    if not isinstance(key_source, str) or not key_source:
        raise ValueError("live storage encryption has no keySource")
    uses_cmk = key_source == "Microsoft.Keyvault"
    return ControlEvaluation(
        confirmed=not uses_cmk,
        reason=("storage encryption uses a customer-managed key" if uses_cmk else
                f"storage encryption key source is {key_source!r}"),
    )


def _geo_redundant(values) -> ControlEvaluation:
    sku = _object(values, "sku")
    name = sku.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("live storage SKU has no name")
    enabled = name in {
        "Standard_GRS", "Standard_GZRS", "Standard_RAGRS", "Standard_RAGZRS",
    }
    return ControlEvaluation(
        confirmed=not enabled,
        reason=(f"storage replication SKU {name!r} is geo-redundant" if enabled else
                f"storage replication SKU {name!r} is not geo-redundant"),
    )


def _infrastructure_encryption(values) -> ControlEvaluation:
    encryption = _object(values, "encryption")
    enabled = encryption.get("requireInfrastructureEncryption")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError(
            "live storage encryption has invalid requireInfrastructureEncryption")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("storage infrastructure encryption is enabled" if enabled is True else
                "storage infrastructure encryption is not enabled"),
    )


def _default_network_deny(values) -> ControlEvaluation:
    network = _object(values, "network_rule_set")
    action = network.get("defaultAction")
    if action not in {"Allow", "Deny"}:
        raise ValueError(f"live storage network default action is invalid: {action!r}")
    return ControlEvaluation(
        confirmed=action == "Allow",
        reason=f"storage network default action is {action!r}",
    )


def _private_endpoints(values) -> ControlEvaluation:
    connections = require(values, "private_endpoint_connections")
    if (not isinstance(connections, list)
            or any(not isinstance(item, dict) for item in connections)):
        raise ValueError(
            "live storage private endpoint connections are not an object list")
    count = len(connections)
    return ControlEvaluation(
        confirmed=count == 0,
        reason=("storage account has no private endpoint connections" if count == 0
                else f"storage account has {count} private endpoint connection(s)"),
    )


def _shared_key_access(values) -> ControlEvaluation:
    enabled = _optional_boolean(values, "allow_shared_key_access")
    # Prowler maps an absent/null SDK value to True: Azure's compatibility
    # default permits Shared Key unless it is explicitly disabled.
    disabled = enabled is False
    return ControlEvaluation(
        confirmed=not disabled,
        reason=("storage Shared Key access is disabled" if disabled else
                "storage Shared Key access is not explicitly disabled"),
    )


def _default_entra_authorization(values) -> ControlEvaluation:
    enabled = _optional_boolean(values, "default_to_oauth_authentication")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("storage defaults to Microsoft Entra authorization"
                if enabled is True else
                "storage does not default to Microsoft Entra authorization"),
    )


def _container_soft_delete(values) -> ControlEvaluation:
    policy = _object(values, "blob_container_delete_retention_policy")
    enabled = policy.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("live storage container-delete policy has invalid enabled state")
    return ControlEvaluation(
        confirmed=enabled is not True,
        reason=("storage container soft delete is enabled" if enabled is True else
                "storage container soft delete is not enabled"),
    )


def _trusted_azure_services(values) -> ControlEvaluation:
    network = _object(values, "network_rule_set")
    bypass = network.get("bypass")
    if not isinstance(bypass, str):
        raise ValueError(f"live storage network bypass is invalid: {bypass!r}")
    trusted = "AzureServices" in bypass
    return ControlEvaluation(
        confirmed=not trusted,
        reason=("trusted Azure services network bypass is enabled" if trusted else
                "trusted Azure services network bypass is not enabled"),
    )


AZURE_STORAGE_PACK = ControlPack(
    pack_id="azure-storage",
    controls=(
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_account_public_network_access_disabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=True,
            live_execution=True,
            evidence_aspects=(
                "public_network_access", "network_rule_set",
                "private_endpoint_connections"),
            evaluator=_public_network_access,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_blob_public_access_level_is_disabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=True,
            live_execution=True,
            evidence_aspects=("allow_blob_public_access",),
            evaluator=_blob_public_access,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_blob_versioning_is_enabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=True,
            live_execution=False, evidence_aspects=("blob_versioning",),
            evaluator=_blob_versioning,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_ensure_encryption_with_customer_managed_keys",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False, evidence_aspects=("encryption",),
            evaluator=_customer_managed_key,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_geo_redundant_enabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False, evidence_aspects=("sku",),
            evaluator=_geo_redundant,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_infrastructure_encryption_is_enabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False, evidence_aspects=("encryption",),
            evaluator=_infrastructure_encryption,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_default_network_access_rule_is_denied",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False, evidence_aspects=("network_rule_set",),
            evaluator=_default_network_deny,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_ensure_private_endpoints_in_storage_accounts",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("private_endpoint_connections",),
            evaluator=_private_endpoints,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_account_key_access_disabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False, evidence_aspects=("allow_shared_key_access",),
            evaluator=_shared_key_access,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_default_to_entra_authorization_enabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("default_to_oauth_authentication",),
            evaluator=_default_entra_authorization,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_ensure_soft_delete_is_enabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("blob_container_delete_retention_policy",),
            evaluator=_container_soft_delete,
        ),
        ControlDefinition(
            pack_id="azure-storage", provider="azure",
            rule_id="storage_ensure_azure_services_are_trusted_to_access_is_enabled",
            resource_family="storage_account",
            resource_types=("microsoft.storage/storageaccounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False, evidence_aspects=("network_rule_set",),
            evaluator=_trusted_azure_services,
        ),
    ),
)
