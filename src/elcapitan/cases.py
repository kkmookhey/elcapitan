"""Product-domain records for a durable remediation case.

The capability probe writes immutable files for one trial.  The product needs
the same auditability across a workflow that may run for days, pause for a
human approval, retry work, and roll back.  This module is deliberately free
of Hermes, model-provider, cloud, queue, and database dependencies.

State is changed only by applying a :class:`CaseTransition`.  Each transition
produces an immutable event and a new immutable projection.  A durable store
can persist those two values transactionally; tests and local development can
use the in-memory implementation in ``workflow.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


def _tuple(value) -> tuple:
    return value if isinstance(value, tuple) else tuple(value)


class CaseState(StrEnum):
    OPEN = "open"
    PRIORITIZED = "prioritized"
    VALIDATED = "validated"
    PLAN_READY = "plan_ready"
    SRE_APPROVED = "sre_approved"
    WINDOW_SELECTED = "window_selected"
    ROLLBACK_READY = "rollback_ready"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    REMEDIATED = "remediated"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    CLOSED_NO_ACTION = "closed_no_action"
    REJECTED = "rejected"
    BLOCKED = "blocked"


TERMINAL_CASE_STATES = frozenset({
    CaseState.REMEDIATED,
    CaseState.ROLLED_BACK,
    CaseState.CLOSED_NO_ACTION,
    CaseState.REJECTED,
})


class CaseTransition(StrEnum):
    ADD_FINDING = "add_finding"
    PRIORITIZE = "prioritize"
    REPRIORITIZE = "reprioritize"
    VALIDATE = "validate"
    PREPARE_PLAN = "prepare_plan"
    APPROVE_SRE = "approve_sre"
    SELECT_WINDOW = "select_window"
    REVIEW_ROLLBACK = "review_rollback"
    REQUEST_APPROVAL = "request_approval"
    APPROVE_CHANGE = "approve_change"
    START_EXECUTION = "start_execution"
    START_VERIFICATION = "start_verification"
    COMPLETE_REMEDIATION = "complete_remediation"
    START_ROLLBACK = "start_rollback"
    COMPLETE_ROLLBACK = "complete_rollback"
    CLOSE_NO_ACTION = "close_no_action"
    REJECT = "reject"
    BLOCK = "block"
    RESUME = "resume"


@dataclass(frozen=True)
class RiskAssessment:
    assessment_id: str
    score: float
    urgency: str
    factors: tuple[str, ...]
    confidence: float
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "factors", _tuple(self.factors))
        object.__setattr__(self, "evidence_ids", _tuple(self.evidence_ids))
        if not 0 <= self.score <= 100:
            raise ValueError("risk score must be between 0 and 100")
        if not 0 <= self.confidence <= 1:
            raise ValueError("risk confidence must be between 0 and 1")
        if not self.assessment_id or not self.urgency or not self.factors:
            raise ValueError("risk assessment requires an id, urgency, and factors")


@dataclass(frozen=True)
class ChangeWindow:
    window_id: str
    starts_at: str
    ends_at: str
    timezone: str
    rationale: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    confidence: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "rationale", _tuple(self.rationale))
        object.__setattr__(self, "evidence_ids", _tuple(self.evidence_ids))
        if not self.window_id or not self.starts_at or not self.ends_at or not self.timezone:
            raise ValueError("change window requires id, bounds, and timezone")
        if not 0 <= self.confidence <= 1:
            raise ValueError("change-window confidence must be between 0 and 1")


@dataclass(frozen=True)
class ChangePlan:
    plan_id: str
    objective: str
    change_ref: str
    prerequisites: tuple[str, ...]
    steps: tuple[str, ...]
    rollout_steps: tuple[str, ...]
    verification_steps: tuple[str, ...]
    rollback_steps: tuple[str, ...]
    rollback_triggers: tuple[str, ...]
    blast_radius: tuple[str, ...]
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in (
            "prerequisites", "steps", "rollout_steps", "verification_steps",
            "rollback_steps", "rollback_triggers", "blast_radius", "evidence_ids",
        ):
            object.__setattr__(self, name, _tuple(getattr(self, name)))
        required = {
            "plan_id": self.plan_id,
            "objective": self.objective,
            "change_ref": self.change_ref,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"change plan requires {', '.join(missing)}")
        for name in (
            "steps", "rollout_steps", "verification_steps", "rollback_steps",
            "rollback_triggers",
        ):
            if not getattr(self, name):
                raise ValueError(f"change plan requires at least one {name}")


@dataclass(frozen=True)
class CaseEvent:
    event_id: str
    case_id: str
    sequence: int
    transition: CaseTransition
    from_state: CaseState
    to_state: CaseState
    occurred_at: str
    actor: str
    record_ids: Mapping[str, str] = field(default_factory=dict)
    evidence_ids: tuple[str, ...] = ()
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.event_id or not self.case_id or not self.actor or not self.occurred_at:
            raise ValueError("case event requires ids, actor, and timestamp")
        if self.sequence < 1:
            raise ValueError("case event sequence must be positive")
        object.__setattr__(self, "record_ids", MappingProxyType(dict(self.record_ids)))
        object.__setattr__(self, "evidence_ids", _tuple(self.evidence_ids))


@dataclass(frozen=True)
class RemediationCase:
    case_id: str
    tenant_id: str
    finding_ids: tuple[str, ...]
    asset_ids: tuple[str, ...]
    service_ids: tuple[str, ...]
    state: CaseState
    version: int
    created_at: str
    updated_at: str
    priority: RiskAssessment | None = None
    change_plan: ChangePlan | None = None
    change_window: ChangeWindow | None = None
    record_ids: Mapping[str, str] = field(default_factory=dict)
    blocked_from: CaseState | None = None

    def __post_init__(self) -> None:
        for name in ("finding_ids", "asset_ids", "service_ids"):
            object.__setattr__(self, name, _tuple(getattr(self, name)))
        if not self.case_id or not self.tenant_id or not self.finding_ids:
            raise ValueError("remediation case requires case, tenant, and finding ids")
        if self.version < 0:
            raise ValueError("case version cannot be negative")
        object.__setattr__(self, "record_ids", MappingProxyType(dict(self.record_ids)))

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_CASE_STATES


_LINEAR_TRANSITIONS = {
    (CaseState.OPEN, CaseTransition.PRIORITIZE): CaseState.PRIORITIZED,
    (CaseState.PRIORITIZED, CaseTransition.VALIDATE): CaseState.VALIDATED,
    (CaseState.VALIDATED, CaseTransition.PREPARE_PLAN): CaseState.PLAN_READY,
    (CaseState.PLAN_READY, CaseTransition.APPROVE_SRE): CaseState.SRE_APPROVED,
    (CaseState.SRE_APPROVED, CaseTransition.SELECT_WINDOW): CaseState.WINDOW_SELECTED,
    (CaseState.WINDOW_SELECTED, CaseTransition.REVIEW_ROLLBACK): CaseState.ROLLBACK_READY,
    (CaseState.ROLLBACK_READY, CaseTransition.REQUEST_APPROVAL): CaseState.AWAITING_APPROVAL,
    (CaseState.AWAITING_APPROVAL, CaseTransition.APPROVE_CHANGE): CaseState.APPROVED,
    (CaseState.APPROVED, CaseTransition.START_EXECUTION): CaseState.EXECUTING,
    (CaseState.EXECUTING, CaseTransition.START_VERIFICATION): CaseState.VERIFYING,
    (CaseState.VERIFYING, CaseTransition.COMPLETE_REMEDIATION): CaseState.REMEDIATED,
    (CaseState.EXECUTING, CaseTransition.START_ROLLBACK): CaseState.ROLLING_BACK,
    (CaseState.VERIFYING, CaseTransition.START_ROLLBACK): CaseState.ROLLING_BACK,
    (CaseState.ROLLING_BACK, CaseTransition.COMPLETE_ROLLBACK): CaseState.ROLLED_BACK,
}

_REQUIRED_RECORDS = {
    CaseTransition.ADD_FINDING: "finding_id",
    CaseTransition.PRIORITIZE: "risk_assessment_id",
    CaseTransition.REPRIORITIZE: "risk_assessment_id",
    CaseTransition.VALIDATE: "validation_result_id",
    CaseTransition.PREPARE_PLAN: "change_plan_id",
    CaseTransition.APPROVE_SRE: "sre_review_id",
    CaseTransition.SELECT_WINDOW: "change_window_id",
    CaseTransition.REVIEW_ROLLBACK: "rollback_review_id",
    CaseTransition.REQUEST_APPROVAL: "policy_decision_id",
    CaseTransition.APPROVE_CHANGE: "approval_id",
    CaseTransition.START_EXECUTION: "execution_id",
    CaseTransition.START_VERIFICATION: "execution_result_id",
    CaseTransition.COMPLETE_REMEDIATION: "verification_result_id",
    CaseTransition.START_ROLLBACK: "rollback_execution_id",
    CaseTransition.COMPLETE_ROLLBACK: "verification_result_id",
}


def open_case(*, case_id: str, tenant_id: str, finding_ids: tuple[str, ...],
              asset_ids: tuple[str, ...] = (), service_ids: tuple[str, ...] = (),
              now: str) -> RemediationCase:
    return RemediationCase(
        case_id=case_id,
        tenant_id=tenant_id,
        finding_ids=tuple(finding_ids),
        asset_ids=tuple(asset_ids),
        service_ids=tuple(service_ids),
        state=CaseState.OPEN,
        version=0,
        created_at=now,
        updated_at=now,
    )


def transition_case(case: RemediationCase, transition: CaseTransition, *,
                    event_id: str, occurred_at: str, actor: str,
                    record_ids: Mapping[str, str] | None = None,
                    evidence_ids: tuple[str, ...] = (), detail: str = "",
                    priority: RiskAssessment | None = None,
                    change_plan: ChangePlan | None = None,
                    change_window: ChangeWindow | None = None,
                    new_finding_ids: tuple[str, ...] = (),
                    ) -> tuple[RemediationCase, CaseEvent]:
    """Apply one valid transition and return ``(new_projection, event)``.

    This function contains no I/O and mutates neither input.  The caller is
    responsible for atomically appending the event with an expected version.
    """
    if case.terminal:
        raise ValueError(f"case {case.case_id} is terminal in state {case.state}")

    records = dict(record_ids or {})
    required = _REQUIRED_RECORDS.get(transition)
    if required and not records.get(required):
        raise ValueError(f"{transition} requires record {required}")

    finding_ids = case.finding_ids
    if transition is CaseTransition.ADD_FINDING:
        additions = tuple(fid for fid in new_finding_ids if fid not in case.finding_ids)
        if not additions:
            raise ValueError("add_finding requires at least one new finding id")
        to_state = case.state
        blocked_from = case.blocked_from
        finding_ids = case.finding_ids + additions
    elif transition is CaseTransition.REPRIORITIZE:
        if priority is None:
            raise ValueError("reprioritize requires a RiskAssessment")
        to_state = case.state
        blocked_from = case.blocked_from
    elif transition is CaseTransition.BLOCK:
        if case.state is CaseState.BLOCKED:
            raise ValueError("an already blocked case cannot be blocked again")
        if not detail:
            raise ValueError("blocking a case requires a reason")
        to_state = CaseState.BLOCKED
        blocked_from = case.state
    elif transition is CaseTransition.RESUME:
        if case.state is not CaseState.BLOCKED or case.blocked_from is None:
            raise ValueError("only a blocked case can resume")
        to_state = case.blocked_from
        blocked_from = None
    elif transition is CaseTransition.CLOSE_NO_ACTION:
        if case.state not in {CaseState.PRIORITIZED, CaseState.VALIDATED}:
            raise ValueError("a case may close without action only after triage or validation")
        if not detail:
            raise ValueError("closing without action requires a reason")
        to_state = CaseState.CLOSED_NO_ACTION
        blocked_from = None
    elif transition is CaseTransition.REJECT:
        if case.state not in {
            CaseState.PLAN_READY, CaseState.SRE_APPROVED, CaseState.WINDOW_SELECTED,
            CaseState.ROLLBACK_READY, CaseState.AWAITING_APPROVAL,
        }:
            raise ValueError(f"a case cannot be rejected from {case.state}")
        if not detail:
            raise ValueError("rejecting a case requires a reason")
        to_state = CaseState.REJECTED
        blocked_from = None
    else:
        try:
            to_state = _LINEAR_TRANSITIONS[(case.state, transition)]
        except KeyError as exc:
            raise ValueError(
                f"transition {transition} is not allowed from {case.state}") from exc
        blocked_from = None

    if transition is CaseTransition.PRIORITIZE and priority is None:
        raise ValueError("prioritize requires a RiskAssessment")
    if transition is CaseTransition.PREPARE_PLAN and change_plan is None:
        raise ValueError("prepare_plan requires a ChangePlan")
    if transition is CaseTransition.SELECT_WINDOW and change_window is None:
        raise ValueError("select_window requires a ChangeWindow")
    supplied_records = {
        "priority": priority,
        "change_plan": change_plan,
        "change_window": change_window,
    }
    permitted_transition = {
        "priority": {CaseTransition.PRIORITIZE, CaseTransition.REPRIORITIZE},
        "change_plan": CaseTransition.PREPARE_PLAN,
        "change_window": CaseTransition.SELECT_WINDOW,
    }
    for name, value in supplied_records.items():
        permitted = permitted_transition[name]
        allowed = transition in permitted if isinstance(permitted, set) else transition is permitted
        if value is not None and not allowed:
            raise ValueError(
                f"{name} may be attached only during {permitted_transition[name]}")
    if transition is not CaseTransition.ADD_FINDING and new_finding_ids:
        raise ValueError("new_finding_ids may be attached only during add_finding")

    merged_records = dict(case.record_ids)
    merged_records.update(records)
    event = CaseEvent(
        event_id=event_id,
        case_id=case.case_id,
        sequence=case.version + 1,
        transition=transition,
        from_state=case.state,
        to_state=to_state,
        occurred_at=occurred_at,
        actor=actor,
        record_ids=records,
        evidence_ids=tuple(evidence_ids),
        detail=detail,
    )
    projection = replace(
        case,
        finding_ids=finding_ids,
        state=to_state,
        version=event.sequence,
        updated_at=occurred_at,
        priority=priority or case.priority,
        change_plan=change_plan or case.change_plan,
        change_window=change_window or case.change_window,
        record_ids=merged_records,
        blocked_from=blocked_from,
    )
    return projection, event


def _risk_to_dict(value: RiskAssessment | None) -> dict | None:
    if value is None:
        return None
    return {
        "assessment_id": value.assessment_id,
        "score": value.score,
        "urgency": value.urgency,
        "factors": list(value.factors),
        "confidence": value.confidence,
        "evidence_ids": list(value.evidence_ids),
    }


def _risk_from_dict(value: Mapping | None) -> RiskAssessment | None:
    return RiskAssessment(**value) if value is not None else None


def _plan_to_dict(value: ChangePlan | None) -> dict | None:
    if value is None:
        return None
    return {
        "plan_id": value.plan_id,
        "objective": value.objective,
        "change_ref": value.change_ref,
        "prerequisites": list(value.prerequisites),
        "steps": list(value.steps),
        "rollout_steps": list(value.rollout_steps),
        "verification_steps": list(value.verification_steps),
        "rollback_steps": list(value.rollback_steps),
        "rollback_triggers": list(value.rollback_triggers),
        "blast_radius": list(value.blast_radius),
        "evidence_ids": list(value.evidence_ids),
    }


def _plan_from_dict(value: Mapping | None) -> ChangePlan | None:
    return ChangePlan(**value) if value is not None else None


def _window_to_dict(value: ChangeWindow | None) -> dict | None:
    if value is None:
        return None
    return {
        "window_id": value.window_id,
        "starts_at": value.starts_at,
        "ends_at": value.ends_at,
        "timezone": value.timezone,
        "rationale": list(value.rationale),
        "evidence_ids": list(value.evidence_ids),
        "confidence": value.confidence,
    }


def _window_from_dict(value: Mapping | None) -> ChangeWindow | None:
    return ChangeWindow(**value) if value is not None else None


def case_to_dict(case: RemediationCase) -> dict:
    return {
        "case_id": case.case_id,
        "tenant_id": case.tenant_id,
        "finding_ids": list(case.finding_ids),
        "asset_ids": list(case.asset_ids),
        "service_ids": list(case.service_ids),
        "state": case.state.value,
        "version": case.version,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "priority": _risk_to_dict(case.priority),
        "change_plan": _plan_to_dict(case.change_plan),
        "change_window": _window_to_dict(case.change_window),
        "record_ids": dict(case.record_ids),
        "blocked_from": case.blocked_from.value if case.blocked_from else None,
    }


def case_from_dict(document: Mapping) -> RemediationCase:
    return RemediationCase(
        case_id=document["case_id"],
        tenant_id=document["tenant_id"],
        finding_ids=document["finding_ids"],
        asset_ids=document["asset_ids"],
        service_ids=document["service_ids"],
        state=CaseState(document["state"]),
        version=document["version"],
        created_at=document["created_at"],
        updated_at=document["updated_at"],
        priority=_risk_from_dict(document.get("priority")),
        change_plan=_plan_from_dict(document.get("change_plan")),
        change_window=_window_from_dict(document.get("change_window")),
        record_ids=document.get("record_ids", {}),
        blocked_from=(CaseState(document["blocked_from"])
                      if document.get("blocked_from") else None),
    )


def event_to_dict(event: CaseEvent) -> dict:
    return {
        "event_id": event.event_id,
        "case_id": event.case_id,
        "sequence": event.sequence,
        "transition": event.transition.value,
        "from_state": event.from_state.value,
        "to_state": event.to_state.value,
        "occurred_at": event.occurred_at,
        "actor": event.actor,
        "record_ids": dict(event.record_ids),
        "evidence_ids": list(event.evidence_ids),
        "detail": event.detail,
    }


def event_from_dict(document: Mapping) -> CaseEvent:
    return CaseEvent(
        event_id=document["event_id"],
        case_id=document["case_id"],
        sequence=document["sequence"],
        transition=CaseTransition(document["transition"]),
        from_state=CaseState(document["from_state"]),
        to_state=CaseState(document["to_state"]),
        occurred_at=document["occurred_at"],
        actor=document["actor"],
        record_ids=document.get("record_ids", {}),
        evidence_ids=document.get("evidence_ids", ()),
        detail=document.get("detail", ""),
    )
