"""Deterministic Azure Container Registry control definitions."""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _admin_user(values) -> ControlEvaluation:
    enabled = require(values, "acr_admin_user_enabled")
    if not isinstance(enabled, bool):
        raise ValueError(f"live ACR admin-user state is invalid: {enabled!r}")
    return ControlEvaluation(
        confirmed=enabled,
        reason=f"Container Registry admin user is {'enabled' if enabled else 'disabled'}",
    )


def _public_network(values) -> ControlEvaluation:
    access = require(values, "acr_public_network_access")
    if not isinstance(access, str) or access not in {"Enabled", "Disabled"}:
        raise ValueError(f"live ACR public-network state is invalid: {access!r}")
    return ControlEvaluation(
        confirmed=access != "Disabled",
        reason=f"Container Registry public network access is {access!r}",
    )


def _private_link(values) -> ControlEvaluation:
    count = require(values, "acr_private_endpoint_connection_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise ValueError(f"live ACR private endpoint count is invalid: {count!r}")
    return ControlEvaluation(
        confirmed=count == 0,
        reason=("Container Registry has no private endpoint connections"
                if count == 0 else
                f"Container Registry has {count} private endpoint connection(s)"),
    )


AZURE_CONTAINER_REGISTRY_PACK = ControlPack(
    pack_id="azure-container-registry",
    evidence_grade="e2e_measured",
    controls=(
        ControlDefinition(
            pack_id="azure-container-registry", provider="azure",
            rule_id="containerregistry_admin_user_disabled",
            resource_family="container_registry",
            resource_types=("microsoft.containerregistry/registries",),
            live_validation=True, remediation_planning=False,
            live_execution=False, evidence_aspects=("acr_admin_user_enabled",),
            evaluator=_admin_user,
        ),
        ControlDefinition(
            pack_id="azure-container-registry", provider="azure",
            rule_id="containerregistry_not_publicly_accessible",
            resource_family="container_registry",
            resource_types=("microsoft.containerregistry/registries",),
            live_validation=True, remediation_planning=False,
            live_execution=False, evidence_aspects=("acr_public_network_access",),
            evaluator=_public_network,
        ),
        ControlDefinition(
            pack_id="azure-container-registry", provider="azure",
            rule_id="containerregistry_uses_private_link",
            resource_family="container_registry",
            resource_types=("microsoft.containerregistry/registries",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("acr_private_endpoint_connection_count",),
            evaluator=_private_link,
        ),
    ),
)
