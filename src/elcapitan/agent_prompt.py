"""Shared, provider-neutral construction of bounded agent requests."""
from __future__ import annotations

from typing import Mapping

from .agents import AgentTask


ROLE_INSTRUCTIONS = {
    "remediation_engineer": (
        "Act as a security remediation engineer. Produce the smallest reversible "
        "Terraform change supported by the supplied finding, live validation, and "
        "source. This is pre-change planning: do not require evidence that the proposed "
        "change has already been applied. Put post-change proof in verification steps. "
        "Never claim a command ran or a dependency is safe without evidence."
    ),
    "sre_reviewer": (
        "Act as an independent SRE reviewer. Evaluate availability, dependencies, "
        "blast radius, health signals, rollout controls, and verification. Reject or "
        "request context when the supplied evidence cannot establish safety."
    ),
    "window_planner": (
        "Act as a change-window reviewer. Select only one supplied candidate using "
        "the usage summary and policy. Do not invent a window or telemetry."
    ),
    "rollback_verifier": (
        "Act as an independent rollback reviewer. Verify that every material failure "
        "mode has an observable trigger and executable reversal. Do not approve vague "
        "or circular rollback instructions."
    ),
    "release_auditor": (
        "Act as an independent post-change release auditor. Use only the supplied "
        "deployment, health, and verification evidence. Accept only when every "
        "mandatory probe passed and the original vulnerability is no longer present; "
        "otherwise request rollback or explicitly name missing human context."
    ),
}


def _thaw(value):
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def instructions(task: AgentTask) -> str:
    try:
        role = ROLE_INSTRUCTIONS[task.role.value]
    except KeyError:
        raise ValueError(f"no prompt is registered for role {task.role.value}") from None
    return (
        role
        + " Return only the strict structured result. Cite only evidence IDs listed in "
        "available_evidence_ids. Status semantics are mandatory: succeeded requires an "
        "empty missing_evidence list; when evidence needed to complete the task is absent, "
        "use needs_more_evidence or needs_human_context and name it. Implementation "
        "prerequisites that can be verified before rollout belong in the output's "
        "prerequisites or controls and are not, by themselves, missing planning evidence."
    )


def task_document(task: AgentTask) -> dict:
    return {
        "task_id": task.task_id, "case_id": task.case_id, "role": task.role.value,
        "objective": task.objective, "input_record_ids": list(task.input_record_ids),
        "available_evidence_ids": list(task.evidence_ids),
        "constraints": list(task.constraints), "context": _thaw(task.metadata),
    }
