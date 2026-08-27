"""One-way orchestration from a validated case to human review."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from .agents import AgentRuntime
from .cases import CaseState
from .finding_store import FindingStore
from .intake import numeric_id
from .observability import UsageSample, WindowPolicy
from .preapproval import (
    ChangeWindowService, HumanReviewGate, HumanReviewOutcome, PreApprovalError,
    ReviewOutcome, RollbackReviewService, SREReviewService, WindowOutcome,
)
from .product_records import ProductRecordStore
from .remediation_planning import (
    RemediationPlanOutcome, RemediationPlanningService, TerraformRunner,
)
from .workflow import CaseStore


@dataclass(frozen=True)
class PreApprovalOutcome:
    planning: RemediationPlanOutcome
    sre_review: ReviewOutcome
    change_window: WindowOutcome
    rollback_review: ReviewOutcome
    human_review: HumanReviewOutcome


class PreApprovalOrchestrator:
    def __init__(self, *, case_store: CaseStore, finding_store: FindingStore,
                 record_store: ProductRecordStore, artifact_root,
                 runtime: AgentRuntime, runner: TerraformRunner,
                 now: Callable[[], str],
                 minimum_distinct_agent_models: int = 1,
                 require_state_grounded_plan: bool = False,
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        common = dict(case_store=case_store, record_store=record_store,
                      artifact_root=artifact_root, runtime=runtime, now=now,
                      id_factory=id_factory)
        self.case_store = case_store
        self.planning = RemediationPlanningService(
            case_store=case_store, finding_store=finding_store,
            record_store=record_store, artifact_root=artifact_root,
            runtime=runtime, runner=runner, now=now, id_factory=id_factory)
        self.sre = SREReviewService(**common)
        self.window = ChangeWindowService(**common)
        self.rollback = RollbackReviewService(**common)
        self.gate = HumanReviewGate(
            case_store=case_store, record_store=record_store,
            now=now, id_factory=id_factory,
            minimum_distinct_agent_models=minimum_distinct_agent_models,
            require_state_grounded_plan=require_state_grounded_plan)

    def advance_to_human_review(self, case_id: str, *, repository,
                                state_document: Mapping | None,
                                service_context: Mapping,
                                usage_samples: tuple[UsageSample, ...],
                                window_policy: WindowPolicy) -> HumanReviewOutcome:
        """Resume the durable case from its last completed preapproval stage."""
        # Five stage advances reach the gate normally. One bounded checker-to-maker
        # rework adds four more; a second rejection is terminal.
        for _ in range(9):
            state = self.case_store.get(case_id).state
            if state is CaseState.VALIDATED:
                self.planning.prepare(
                    case_id, repository=repository, state_document=state_document)
            elif state is CaseState.PLAN_READY:
                outcome = self.sre.review(case_id, service_context=service_context)
                if outcome.case.state is not CaseState.SRE_APPROVED:
                    raise PreApprovalError(
                        f"SRE review stopped workflow in {outcome.case.state}")
            elif state is CaseState.SRE_APPROVED:
                self.window.select(
                    case_id, samples=usage_samples, policy=window_policy)
            elif state is CaseState.WINDOW_SELECTED:
                outcome = self.rollback.review(case_id)
                if outcome.case.state is CaseState.VALIDATED:
                    continue
                if outcome.case.state is not CaseState.ROLLBACK_READY:
                    raise PreApprovalError(
                        f"rollback review stopped workflow in {outcome.case.state}")
            elif state is CaseState.ROLLBACK_READY:
                return self.gate.prepare(case_id)
            else:
                raise PreApprovalError(
                    f"case {case_id} cannot enter preapproval from {state}")
        raise PreApprovalError(
            f"case {case_id} did not reach the human-review gate")

    def prepare(self, case_id: str, *, repository,
                state_document: Mapping | None, service_context: Mapping,
                usage_samples: tuple[UsageSample, ...],
                window_policy: WindowPolicy) -> PreApprovalOutcome:
        planning = self.planning.prepare(
            case_id, repository=repository, state_document=state_document)
        sre = self.sre.review(case_id, service_context=service_context)
        if sre.case.state is not CaseState.SRE_APPROVED:
            raise RuntimeError(f"SRE review stopped workflow in {sre.case.state}")
        window = self.window.select(
            case_id, samples=usage_samples, policy=window_policy)
        rollback = self.rollback.review(case_id)
        if rollback.case.state is not CaseState.ROLLBACK_READY:
            raise RuntimeError(
                f"rollback review stopped workflow in {rollback.case.state}")
        human = self.gate.prepare(case_id)
        return PreApprovalOutcome(
            planning=planning, sre_review=sre, change_window=window,
            rollback_review=rollback, human_review=human)
