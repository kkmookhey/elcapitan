"""Deterministic first-pass prioritization for remediation cases.

Models may explain, challenge, or request evidence for a priority.  The base
queue order is a transparent policy calculation so that the same facts do not
produce a different emergency merely because a model sampled different text.
Customers can replace the weights without replacing the workflow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .cases import RiskAssessment


@dataclass(frozen=True)
class PrioritySignals:
    severity: str
    asset_criticality: float
    exploit_probability: float
    internet_exposed: bool
    reachable: bool
    known_exploited: bool
    active_exploitation: bool
    runtime_dependency: bool
    compensating_control_strength: float
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        for name in (
            "asset_criticality", "exploit_probability",
            "compensating_control_strength",
        ):
            value = getattr(self, name)
            if not 0 <= value <= 1:
                raise ValueError(f"{name} must be between 0 and 1")


@dataclass(frozen=True)
class PriorityPolicy:
    severity_weights: Mapping[str, float] = field(default_factory=lambda: {
        "critical": 40.0,
        "high": 30.0,
        "medium": 15.0,
        "low": 5.0,
        "informational": 0.0,
        "unknown": 10.0,
    })
    asset_criticality_weight: float = 20.0
    exploit_probability_weight: float = 20.0
    internet_exposed_weight: float = 10.0
    reachable_weight: float = 10.0
    known_exploited_weight: float = 20.0
    active_exploitation_weight: float = 25.0
    runtime_dependency_weight: float = 10.0
    compensating_control_weight: float = 20.0
    urgent_threshold: float = 80.0
    high_threshold: float = 60.0
    normal_threshold: float = 30.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "severity_weights",
            MappingProxyType({k.lower(): float(v) for k, v in self.severity_weights.items()}),
        )
        if not 0 <= self.normal_threshold <= self.high_threshold <= self.urgent_threshold <= 100:
            raise ValueError("priority thresholds must be ordered between 0 and 100")


DEFAULT_PRIORITY_POLICY = PriorityPolicy()


def signals_to_dict(signals: PrioritySignals) -> dict:
    return {
        "severity": signals.severity,
        "asset_criticality": signals.asset_criticality,
        "exploit_probability": signals.exploit_probability,
        "internet_exposed": signals.internet_exposed,
        "reachable": signals.reachable,
        "known_exploited": signals.known_exploited,
        "active_exploitation": signals.active_exploitation,
        "runtime_dependency": signals.runtime_dependency,
        "compensating_control_strength": signals.compensating_control_strength,
        "evidence_ids": list(signals.evidence_ids),
    }


def signals_from_dict(document: Mapping) -> PrioritySignals:
    return PrioritySignals(**document)


def assess_priority(assessment_id: str, signals: PrioritySignals, *,
                    policy: PriorityPolicy = DEFAULT_PRIORITY_POLICY) -> RiskAssessment:
    severity = signals.severity.lower()
    severity_score = policy.severity_weights.get(
        severity, policy.severity_weights.get("unknown", 0.0))
    contributions = [
        (severity_score, f"severity is {severity}"),
        (signals.asset_criticality * policy.asset_criticality_weight,
         f"asset criticality is {signals.asset_criticality:.2f}"),
        (signals.exploit_probability * policy.exploit_probability_weight,
         f"exploit probability is {signals.exploit_probability:.2f}"),
        (policy.internet_exposed_weight if signals.internet_exposed else 0,
         "asset is internet exposed"),
        (policy.reachable_weight if signals.reachable else 0,
         "vulnerable path is reachable"),
        (policy.known_exploited_weight if signals.known_exploited else 0,
         "vulnerability is known to be exploited"),
        (policy.active_exploitation_weight if signals.active_exploitation else 0,
         "active exploitation is observed"),
        (policy.runtime_dependency_weight if signals.runtime_dependency else 0,
         "asset has a supplied runtime dependency"),
        (-signals.compensating_control_strength * policy.compensating_control_weight,
         f"compensating-control strength is {signals.compensating_control_strength:.2f}"),
    ]
    score = max(0.0, min(100.0, round(sum(value for value, _ in contributions), 2)))
    if score >= policy.urgent_threshold:
        urgency = "urgent"
    elif score >= policy.high_threshold:
        urgency = "high"
    elif score >= policy.normal_threshold:
        urgency = "normal"
    else:
        urgency = "low"

    material = tuple(
        detail for value, detail in contributions
        if value != 0 or detail.startswith("compensating-control"))
    # Confidence is evidence completeness, not confidence in arbitrary weights.
    observable = (
        signals.severity.lower() != "unknown",
        bool(signals.evidence_ids),
        signals.exploit_probability > 0 or signals.known_exploited,
        signals.asset_criticality > 0,
    )
    confidence = round(sum(observable) / len(observable), 2)
    return RiskAssessment(
        assessment_id=assessment_id,
        score=score,
        urgency=urgency,
        factors=material,
        confidence=confidence,
        evidence_ids=signals.evidence_ids,
    )
