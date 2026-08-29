"""Deterministic Azure OpenAI control definitions."""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


_AZURE_OPENAI_KINDS = {"AIServices", "OpenAI"}


def _public_network(values) -> ControlEvaluation:
    kind = require(values, "azureopenai_kind")
    access = require(values, "azureopenai_public_network_access")
    if not isinstance(kind, str) or kind not in _AZURE_OPENAI_KINDS:
        raise ValueError(
            f"live Cognitive Services kind is not an Azure OpenAI kind: {kind!r}")
    if not isinstance(access, str) or access not in {"Enabled", "Disabled"}:
        raise ValueError(
            f"live Azure OpenAI public-network state is invalid: {access!r}")
    return ControlEvaluation(
        confirmed=access != "Disabled",
        reason=(f"Azure OpenAI account kind {kind!r} has public network "
                f"access {access!r}"),
    )


AZURE_OPENAI_PACK = ControlPack(
    pack_id="azure-openai",
    controls=(
        ControlDefinition(
            pack_id="azure-openai", provider="azure",
            rule_id="azureopenai_account_public_network_access_disabled",
            resource_family="azure_openai",
            resource_types=("microsoft.cognitiveservices/accounts",),
            live_validation=True, remediation_planning=False,
            live_execution=False,
            evidence_aspects=(
                "azureopenai_kind", "azureopenai_public_network_access"),
            evaluator=_public_network,
        ),
    ),
)
