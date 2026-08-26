"""Provider-neutral contracts for specialized remediation agents.

An agent runtime may call a model API directly, launch a constrained local
worker, or adapt Hermes.  Product workflow code depends only on these records
and the ``AgentRuntime`` protocol.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping, Protocol


def _freeze(value: Any) -> Any:
    """Recursively detach and freeze JSON-like runtime output."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze(item) for item in value)
    return value


class AgentRole(StrEnum):
    PRIORITIZER = "prioritizer"
    VALIDATOR = "validator"
    REMEDIATION_ENGINEER = "remediation_engineer"
    SRE_REVIEWER = "sre_reviewer"
    WINDOW_PLANNER = "window_planner"
    ROLLBACK_VERIFIER = "rollback_verifier"


class AgentResultStatus(StrEnum):
    SUCCEEDED = "succeeded"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    NEEDS_HUMAN_CONTEXT = "needs_human_context"
    FAILED = "failed"


@dataclass(frozen=True)
class AgentTask:
    task_id: str
    case_id: str
    role: AgentRole
    objective: str
    output_contract: str
    input_record_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    constraints: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.task_id or not self.case_id or not self.objective:
            raise ValueError("agent task requires task id, case id, and objective")
        if not self.output_contract:
            raise ValueError("agent task requires a named output contract")
        for name in ("input_record_ids", "evidence_ids", "constraints"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "metadata", _freeze(self.metadata))


@dataclass(frozen=True)
class AgentResult:
    task_id: str
    case_id: str
    role: AgentRole
    status: AgentResultStatus
    output: Mapping[str, Any]
    evidence_cited: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    runtime: str
    model: str
    started_at: str
    completed_at: str
    usage: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.task_id or not self.case_id or not self.runtime:
            raise ValueError("agent result requires task id, case id, and runtime")
        for name in ("evidence_cited", "missing_evidence"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "output", _freeze(self.output))
        object.__setattr__(self, "usage", _freeze(self.usage))


class AgentRuntime(Protocol):
    """Replaceable execution boundary; Hermes is one possible adapter."""

    @property
    def name(self) -> str: ...

    def run(self, task: AgentTask) -> AgentResult: ...


def validate_result(task: AgentTask, result: AgentResult) -> list[str]:
    """Check facts a runtime must not be trusted to police about itself."""
    failures: list[str] = []
    if result.task_id != task.task_id:
        failures.append("agent result task_id does not match the dispatched task")
    if result.case_id != task.case_id:
        failures.append("agent result case_id does not match the dispatched task")
    if result.role != task.role:
        failures.append("agent result role does not match the dispatched task")

    supplied = set(task.evidence_ids)
    unknown = sorted(set(result.evidence_cited) - supplied)
    if unknown:
        failures.append(
            "agent result cites evidence it was not supplied: " + ", ".join(unknown))

    if result.status is AgentResultStatus.SUCCEEDED and result.missing_evidence:
        failures.append("a succeeded agent result cannot also report missing evidence")
    if result.status is AgentResultStatus.NEEDS_MORE_EVIDENCE and not result.missing_evidence:
        failures.append("needs_more_evidence must name the missing evidence")
    return failures
