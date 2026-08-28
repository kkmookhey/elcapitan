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
    ),
)
