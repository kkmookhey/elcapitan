"""Provider-neutral contracts for deterministic service control packs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping


@dataclass(frozen=True)
class ControlEvaluation:
    """One deterministic decision from already-collected typed evidence."""
    confirmed: bool
    reason: str


ControlEvaluator = Callable[[Mapping[str, object]], ControlEvaluation]


@dataclass(frozen=True)
class ControlDefinition:
    """The complete registration contract for one scanner control.

    Collection remains a provider-adapter concern: a pack names the evidence
    aspects it is permitted to consume, while its evaluator receives only the
    immutable cloud-state record. Planning and execution are separate flags so
    validation coverage can never silently imply mutation authority.
    """
    pack_id: str
    provider: str
    rule_id: str
    resource_family: str
    resource_types: tuple[str, ...]
    live_validation: bool
    remediation_planning: bool
    live_execution: bool
    evidence_aspects: tuple[str, ...]
    evaluator: ControlEvaluator

    def __post_init__(self) -> None:
        if not self.pack_id or not self.provider or not self.rule_id:
            raise ValueError("control definitions require pack, provider, and rule ids")
        if self.provider != self.provider.lower():
            raise ValueError("control definition provider must be lower-case")
        if not self.resource_types or any(not item for item in self.resource_types):
            raise ValueError("control definitions require explicit resource types")
        if not self.evidence_aspects or any(not item for item in self.evidence_aspects):
            raise ValueError("control definitions require explicit evidence aspects")
        if len(set(self.evidence_aspects)) != len(self.evidence_aspects):
            raise ValueError("control evidence aspects must be unique")
        if not self.live_validation:
            raise ValueError("registered deterministic controls must support validation")

    def to_dict(self) -> dict:
        # Compatibility projection consumed by the fleet API. The callable is
        # intentionally not serialised; executable policy is never API data.
        return {
            "provider": self.provider,
            "rule_id": self.rule_id,
            "resource_family": self.resource_family,
            "live_validation": self.live_validation,
            "remediation_planning": self.remediation_planning,
            "live_execution": self.live_execution,
            "evidence_aspects": list(self.evidence_aspects),
        }


@dataclass(frozen=True)
class ControlPack:
    pack_id: str
    controls: tuple[ControlDefinition, ...]

    def __post_init__(self) -> None:
        if not self.pack_id or not self.controls:
            raise ValueError("control packs require an id and at least one control")
        if any(item.pack_id != self.pack_id for item in self.controls):
            raise ValueError("every control definition must belong to its containing pack")


def require(values: Mapping[str, object], aspect: str):
    if aspect not in values:
        raise ValueError(f"live cloud state did not capture {aspect}")
    return values[aspect]
