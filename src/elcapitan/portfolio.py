"""Fleet-level ordering and collision detection across remediation cases."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping

from .cases import CaseState, RemediationCase
from .observability import parse_timestamp
from .workflow import CaseStore


ELIGIBLE_STATES = frozenset({
    CaseState.VALIDATED, CaseState.PLAN_READY, CaseState.SRE_APPROVED,
    CaseState.WINDOW_SELECTED, CaseState.ROLLBACK_READY,
    CaseState.AWAITING_APPROVAL, CaseState.APPROVED,
})


@dataclass(frozen=True)
class PortfolioPolicy:
    maximum_parallel_changes: int = 1
    critical_service_penalty: float = 10
    internet_exposure_bonus: float = 10

    def __post_init__(self) -> None:
        if self.maximum_parallel_changes < 1:
            raise ValueError("maximum_parallel_changes must be positive")


@dataclass(frozen=True)
class PortfolioItem:
    rank: int
    case_id: str
    state: str
    base_risk_score: float
    effective_priority: float
    service_ids: tuple[str, ...]
    window_start: str
    window_end: str
    scheduling_status: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        value = asdict(self)
        value["service_ids"] = list(self.service_ids)
        value["reasons"] = list(self.reasons)
        return value


def _overlap(left: RemediationCase, right: RemediationCase) -> bool:
    if not left.change_window or not right.change_window:
        return False
    return (parse_timestamp(left.change_window.starts_at)
            < parse_timestamp(right.change_window.ends_at)
            and parse_timestamp(right.change_window.starts_at)
            < parse_timestamp(left.change_window.ends_at))


class PortfolioService:
    def __init__(self, *, case_store: CaseStore,
                 policy: PortfolioPolicy = PortfolioPolicy()) -> None:
        self.case_store, self.policy = case_store, policy

    def queue(self, *, tenant_id: str,
              service_criticality: Mapping[str, float] | None = None
              ) -> tuple[PortfolioItem, ...]:
        criticality = dict(service_criticality or {})
        cases = [case for case in self.case_store.list_cases(tenant_id=tenant_id)
                 if case.state in ELIGIBLE_STATES and case.priority is not None]
        scored = []
        for case in cases:
            service_weight = max(
                (criticality.get(service_id, 0) for service_id in case.service_ids),
                default=0)
            exposure = any("internet" in factor.lower() for factor in case.priority.factors)
            effective = (case.priority.score
                         + (self.policy.internet_exposure_bonus if exposure else 0)
                         - self.policy.critical_service_penalty * service_weight)
            scored.append((effective, case))
        scored.sort(key=lambda item: (
            -item[0], -item[1].priority.score,
            parse_timestamp(item[1].created_at), item[1].case_id))

        items = []
        for index, (effective, case) in enumerate(scored):
            conflicts = []
            for _, higher in scored[:index]:
                same_service = bool(set(case.service_ids) & set(higher.service_ids))
                if _overlap(case, higher) and (same_service
                        or self.policy.maximum_parallel_changes == 1):
                    conflicts.append(higher.case_id)
            reasons = [f"risk score {case.priority.score:.1f}"]
            if conflicts and case.state is CaseState.APPROVED:
                status = "window_conflict"
                reasons.append("conflicts with higher-priority case(s): " + ", ".join(conflicts))
            elif conflicts and case.change_window:
                status = "candidate_window_conflict"
                reasons.append(
                    "candidate conflicts with higher-priority case(s): "
                    + ", ".join(conflicts))
            elif case.state is CaseState.APPROVED and case.change_window:
                status = "scheduled"
                reasons.append("approved window has no fleet collision")
            elif case.state is CaseState.VALIDATED:
                status = "awaiting_plan"
                reasons.append("validated case must complete operational planning")
            elif case.state is CaseState.PLAN_READY:
                status = "awaiting_sre_review"
                reasons.append("verified plan is awaiting independent SRE review")
            elif case.state is CaseState.SRE_APPROVED:
                status = "awaiting_window"
                reasons.append("SRE-approved plan is awaiting window selection")
            elif case.state is CaseState.WINDOW_SELECTED:
                status = "awaiting_rollback_review"
                reasons.append("candidate window is not approved or scheduled")
            elif case.state is CaseState.ROLLBACK_READY:
                status = "assembling_human_review"
                reasons.append("rollback-ready package is entering the policy gate")
            else:
                status = "awaiting_human_approval"
                reasons.append("candidate window remains unapproved and unscheduled")
            items.append(PortfolioItem(
                rank=index + 1, case_id=case.case_id, state=case.state.value,
                base_risk_score=case.priority.score,
                effective_priority=round(effective, 3), service_ids=case.service_ids,
                window_start=(case.change_window.starts_at if case.change_window else ""),
                window_end=(case.change_window.ends_at if case.change_window else ""),
                scheduling_status=status, reasons=tuple(reasons)))
        return tuple(items)
