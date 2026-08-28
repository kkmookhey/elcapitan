"""Deterministic Azure Network control definitions."""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


_AZURE_MANAGED_SUBNETS = frozenset({
    "GatewaySubnet",
    "AzureFirewallSubnet",
    "AzureFirewallManagementSubnet",
    "AzureBastionSubnet",
    "RouteServerSubnet",
})


def _subnet_nsg_associated(values) -> ControlEvaluation:
    name = require(values, "network_subnet_name")
    nsg_id = require(values, "network_subnet_nsg_id")
    if not isinstance(name, str) or not name:
        raise ValueError(f"live subnet state has invalid name {name!r}")
    if nsg_id is not None and (not isinstance(nsg_id, str) or not nsg_id):
        raise ValueError(f"live subnet state has invalid NSG id {nsg_id!r}")
    if name in _AZURE_MANAGED_SUBNETS:
        return ControlEvaluation(
            confirmed=False,
            reason=f"Azure-managed subnet {name!r} is excluded by Prowler")
    return ControlEvaluation(
        confirmed=nsg_id is None,
        reason=(f"subnet {name!r} has no NSG associated" if nsg_id is None
                else f"subnet {name!r} has NSG {nsg_id!r} associated"),
    )


AZURE_NETWORK_PACK = ControlPack(
    pack_id="azure-network",
    controls=(
        ControlDefinition(
            pack_id="azure-network", provider="azure",
            rule_id="network_subnet_nsg_associated",
            resource_family="network_subnet",
            resource_types=("microsoft.network/virtualnetworks/subnets",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=("network_subnet_name", "network_subnet_nsg_id"),
            evaluator=_subnet_nsg_associated,
        ),
    ),
)
