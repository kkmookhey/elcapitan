"""Minimize and redact payloads before they cross a model-provider boundary."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping

from .agents import AgentResult, AgentRuntime, AgentTask


_SECRET_KEYS = re.compile(
    r"(^|_)(api_?key|secret|password|passwd|token|credential|connection_?string)($|_)",
    re.IGNORECASE,
)
_IDENTIFIER_KEYS = re.compile(
    r"(^|_)(subscription|subscription_?id|tenant|tenant_?id|account_?id|"
    r"resource_?(id|uid)|client_?id|principal_?id|email)($|_)",
    re.IGNORECASE,
)
_ARM_ID = re.compile(r"/subscriptions/[0-9a-f-]+(?:/[^\s\"'<>]+)+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HOME_PATH = re.compile(r"/(?:Users|home)/[^/\s]+(?:/[^\s\"'<>]+)*")


def _marker(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"[{kind}_REDACTED:{digest}]"


@dataclass(frozen=True)
class EgressReceipt:
    redactions: int
    input_bytes: int
    output_bytes: int


def sanitize_for_model(value: Any) -> tuple[Any, EgressReceipt]:
    """Return a JSON-like copy with secrets and customer identifiers removed."""
    redactions = 0

    def scrub_string(text: str) -> str:
        nonlocal redactions
        patterns = (
            (_ARM_ID, "AZURE_RESOURCE"),
            (_EMAIL, "EMAIL"),
            (_IPV4, "IP_ADDRESS"),
            (_HOME_PATH, "LOCAL_PATH"),
        )
        result = text
        for pattern, kind in patterns:
            def replace_match(match):
                nonlocal redactions
                redactions += 1
                return _marker(kind, match.group(0))
            result = pattern.sub(replace_match, result)
        return result

    def scrub(item: Any, *, key: str = "") -> Any:
        nonlocal redactions
        if _SECRET_KEYS.search(key):
            redactions += 1
            return "[SECRET_REDACTED]"
        if _IDENTIFIER_KEYS.search(key) and isinstance(item, (str, int)):
            redactions += 1
            return _marker("IDENTIFIER", str(item))
        if isinstance(item, Mapping):
            return {str(name): scrub(child, key=str(name)) for name, child in item.items()}
        if isinstance(item, (tuple, list, set, frozenset)):
            return [scrub(child, key=key) for child in item]
        if isinstance(item, str):
            return scrub_string(item)
        return item

    raw = repr(value).encode("utf-8")
    sanitized = scrub(value)
    output = repr(sanitized).encode("utf-8")
    return sanitized, EgressReceipt(redactions, len(raw), len(output))


class ModelEgressRuntime:
    """Agent runtime decorator enforcing redaction at the provider boundary."""

    def __init__(self, runtime: AgentRuntime) -> None:
        self.runtime = runtime
        self.last_receipt: EgressReceipt | None = None

    @property
    def name(self) -> str:
        return f"model-egress-policy:{self.runtime.name}"

    def run(self, task: AgentTask) -> AgentResult:
        metadata, receipt = sanitize_for_model(task.metadata)
        self.last_receipt = receipt
        safe_task = replace(task, metadata=MappingProxyType(metadata))
        return self.runtime.run(safe_task)
