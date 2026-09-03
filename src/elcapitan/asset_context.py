"""Strict per-resource business context for deterministic shadow prioritization."""
from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence

from .intake import IntakeContext
from .hashing import canonical_json


MAX_ASSET_CONTEXT_ROWS = 5_000
ENVIRONMENTS = frozenset({
    "production", "staging", "test", "development", "shared", "unknown",
})
ASSET_CONTEXT_FIELDS = frozenset({
    "resource_uid", "environment", "owner", "asset_criticality",
    "internet_exposed", "reachable", "runtime_dependency",
    "compensating_control_strength", "service_ids", "context_source",
    "observed_at", "evidence_references", "synthetic_business_context",
})


def asset_key(resource_uid: str) -> str:
    """Return an exact comparison key, respecting Azure ARM case insensitivity."""
    value = resource_uid.strip()
    if value.lower().startswith("/subscriptions/"):
        return value.lower()
    return value


def _string(document: Mapping, name: str, *, required: bool = False,
            maximum: int = 500) -> str:
    value = document.get(name, "")
    if not isinstance(value, str):
        raise ValueError(f"asset context {name} must be a string")
    value = value.strip()
    if required and not value:
        raise ValueError(f"asset context {name} is required")
    if len(value) > maximum:
        raise ValueError(
            f"asset context {name} must be at most {maximum} characters")
    return value


def _number(document: Mapping, name: str, *, default: float = 0) -> float:
    value = document.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"asset context {name} must be a number")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 1:
        raise ValueError(f"asset context {name} must be between 0 and 1")
    return result


def _boolean(document: Mapping, name: str, *, default: bool = False) -> bool:
    value = document.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"asset context {name} must be a boolean")
    return value


def _optional_boolean(document: Mapping, name: str) -> bool | None:
    value = document.get(name)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"asset context {name} must be a boolean or null")
    return value


def _strings(document: Mapping, name: str, *, maximum_items: int = 100,
             maximum_length: int = 500) -> tuple[str, ...]:
    value = document.get(name, [])
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ValueError(
            f"asset context {name} must be an array of at most {maximum_items} strings")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"asset context {name} entries must be strings")
    result = tuple(item.strip() for item in value)
    if any(not item or len(item) > maximum_length for item in result):
        raise ValueError(
            f"asset context {name} entries must be 1 to {maximum_length} characters")
    return tuple(dict.fromkeys(result))


@dataclass(frozen=True)
class AssetContext:
    resource_uid: str
    environment: str
    owner: str
    asset_criticality: float
    internet_exposed: bool | None
    reachable: bool
    runtime_dependency: bool
    compensating_control_strength: float
    service_ids: tuple[str, ...]
    context_source: str
    observed_at: str
    evidence_references: tuple[str, ...]
    synthetic_business_context: bool
    context_digest: str

    def intake_context(self, fallback: IntakeContext) -> IntakeContext:
        """Combine asset facts with finding/threat signals supplied for the batch."""
        return IntakeContext(
            asset_criticality=self.asset_criticality,
            exploit_probability=fallback.exploit_probability,
            internet_exposed=self.internet_exposed,
            reachable=self.reachable,
            known_exploited=fallback.known_exploited,
            active_exploitation=fallback.active_exploitation,
            runtime_dependency=self.runtime_dependency,
            compensating_control_strength=self.compensating_control_strength,
            service_ids=self.service_ids,
        )

    def to_dict(self) -> dict:
        value = asdict(self)
        value["service_ids"] = list(self.service_ids)
        value["evidence_references"] = list(self.evidence_references)
        return value


def parse_asset_contexts(documents: Sequence[Mapping] | None
                         ) -> dict[str, AssetContext]:
    if documents is None:
        return {}
    if isinstance(documents, (str, bytes)) or not isinstance(documents, Sequence):
        raise ValueError("asset context must be an array")
    if len(documents) > MAX_ASSET_CONTEXT_ROWS:
        raise ValueError(
            f"asset context must contain at most {MAX_ASSET_CONTEXT_ROWS} rows")

    result: dict[str, AssetContext] = {}
    for index, raw in enumerate(documents):
        if not isinstance(raw, Mapping):
            raise ValueError(f"asset context row {index + 1} is not an object")
        try:
            unknown = sorted(set(raw) - ASSET_CONTEXT_FIELDS)
            if unknown:
                raise ValueError(
                    "asset context contains unknown field(s): " + ", ".join(unknown))
            if "asset_criticality" not in raw:
                raise ValueError("asset context asset_criticality is required")
            resource_uid = _string(raw, "resource_uid", required=True, maximum=2_000)
            environment = _string(raw, "environment", required=True, maximum=50).lower()
            if environment not in ENVIRONMENTS:
                raise ValueError(
                    "asset context environment must be one of "
                    + ", ".join(sorted(ENVIRONMENTS)))
            context = AssetContext(
                resource_uid=resource_uid,
                environment=environment,
                owner=_string(raw, "owner", required=True, maximum=200),
                asset_criticality=_number(raw, "asset_criticality"),
                internet_exposed=_optional_boolean(raw, "internet_exposed"),
                reachable=_boolean(raw, "reachable"),
                runtime_dependency=_boolean(raw, "runtime_dependency"),
                compensating_control_strength=_number(
                    raw, "compensating_control_strength"),
                service_ids=_strings(
                    raw, "service_ids", maximum_items=100, maximum_length=200),
                context_source=_string(
                    raw, "context_source", required=True, maximum=200),
                observed_at=_string(raw, "observed_at", maximum=100),
                evidence_references=_strings(
                    raw, "evidence_references", maximum_items=50,
                    maximum_length=1_000),
                synthetic_business_context=_boolean(
                    raw, "synthetic_business_context"),
                context_digest=hashlib.sha256(canonical_json(dict(raw))).hexdigest(),
            )
            if not context.evidence_references:
                raise ValueError("asset context evidence_references must not be empty")
            if context.internet_exposed is not None and not context.observed_at:
                raise ValueError(
                    "asset context observed_at is required when internet_exposed is known")
        except ValueError as exc:
            raise ValueError(f"asset context row {index + 1}: {exc}") from exc
        key = asset_key(resource_uid)
        if key in result:
            raise ValueError(
                f"asset context row {index + 1}: duplicate resource_uid after normalization")
        result[key] = context
    return result
