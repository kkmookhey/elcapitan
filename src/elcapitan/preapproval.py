"""Independent operational reviews and the deterministic human-approval gate."""
from __future__ import annotations

import math
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Mapping

from .agent_contracts import validate_output
from .agents import (
    AgentResult, AgentResultStatus, AgentRole, AgentRuntime, AgentTask,
    validate_result,
)
from .cases import (
    CaseState, CaseTransition, ChangeWindow, RemediationCase, case_to_dict,
)
from .evidence import Collector, write_evidence
from .hashing import canonical_json
from .intake import numeric_id
from .observability import (
    UsageSample, WindowCandidate, WindowPolicy, candidate_windows, parse_timestamp,
)
from .product_records import (
    ProductRecord, ProductRecordStore, product_record_to_dict,
)
from .workflow import CaseStore, WorkflowCoordinator


class PreApprovalError(RuntimeError):
    pass


def _jsonable(value):
    if isinstance(value, Mapping):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _strings(document: Mapping, name: str, *, required: bool = False) -> tuple[str, ...]:
    value = document.get(name)
    if not isinstance(value, (list, tuple)) or any(
            not isinstance(item, str) or not item.strip() for item in value):
        raise PreApprovalError(f"agent output {name!r} must be a list of non-empty strings")
    if required and not value:
        raise PreApprovalError(f"agent output {name!r} cannot be empty")
    return tuple(value)


def _prechange_claim_failures(summary: str) -> tuple[str, ...]:
    """Catch explicit claims that future-state proof already exists pre-change."""
    lowered = " ".join(summary.lower().split())
    phrases = (
        "post-change health signals confirm",
        "post-implementation health signals confirm",
        "verification confirms success", "finding is no longer",
        "finding has been remediated",
    )
    return tuple(phrase for phrase in phrases if phrase in lowered)


def _required_array_failures(output: Mapping, names: tuple[str, ...]
                             ) -> tuple[str, ...]:
    placeholders = {"placeholder", "tbd", "todo", "n/a", "none", "unknown"}
    failures = []
    for name in names:
        value = output.get(name)
        if not isinstance(value, (list, tuple)) or not value:
            failures.append(f"{name} must be a non-empty array")
        elif any(
                not isinstance(item, str)
                or item.strip().lower() in placeholders for item in value):
            failures.append(f"{name} contains an empty or placeholder item")
    return tuple(failures)


def _sre_semantic_failures(output: Mapping) -> tuple[str, ...]:
    if output.get("decision") != "approve":
        return ()
    return _required_array_failures(
        output, ("failure_modes", "required_controls", "verification_requirements"))


def _rollback_semantic_failures(output: Mapping) -> tuple[str, ...]:
    decision = output.get("decision")
    if decision == "approve":
        failures = list(_required_array_failures(
            output, ("verified_steps", "trigger_coverage")))
        if output.get("required_changes"):
            failures.append("approved rollback review must have no required_changes")
        return tuple(failures)
    if decision == "reject":
        return _required_array_failures(output, ("required_changes",))
    return ()


@dataclass(frozen=True)
class ReviewOutcome:
    case: RemediationCase
    record: ProductRecord
    agent_result: AgentResult


@dataclass(frozen=True)
class WindowOutcome(ReviewOutcome):
    candidates: tuple[WindowCandidate, ...]


@dataclass(frozen=True)
class HumanReviewOutcome:
    case: RemediationCase
    policy_record: ProductRecord
    review_package: ProductRecord


class _AgentStage:
    def __init__(self, *, case_store: CaseStore, record_store: ProductRecordStore,
                 artifact_root, runtime: AgentRuntime, now: Callable[[], str],
                 id_factory: Callable[[str], str]) -> None:
        self.case_store = case_store
        self.record_store = record_store
        self.artifact_root = Path(artifact_root)
        self.runtime = runtime
        self.now = now
        self.id_factory = id_factory
        self.workflow = WorkflowCoordinator(case_store)
        self.collector = Collector(
            tool="elcapitan-operational-review", version="0.1.0",
            identity="preapproval-control-plane",
        )

    def _run(self, task: AgentTask, *, run_dir: Path,
             required_citations: tuple[str, ...] = (),
             semantic_validator: Callable[[Mapping], tuple[str, ...]] | None = None,
             ) -> tuple[AgentResult, str]:
        dispatched = task
        if required_citations:
            dispatched = replace(task, constraints=tuple((*task.constraints,
                "Cite every mandatory evidence ID exactly: "
                + ", ".join(required_citations),
            )))
        current_task = dispatched
        result = self.runtime.run(current_task)
        retry_count = 0
        failures = validate_result(current_task, result)
        failures.extend(validate_output(
            current_task.output_contract, _jsonable(result.output)))
        semantic_failures = (
            semantic_validator(result.output) if semantic_validator else ())
        while semantic_failures and not failures and retry_count < 2:
            current_task = replace(current_task, constraints=tuple((*current_task.constraints,
                "Correct these decision-specific semantic failures from the previous "
                "response: " + "; ".join(semantic_failures),
                "Preserve every already-valid required field. Every required string, "
                "especially output.summary, must remain concrete and non-empty. "
                "Replace each identified bad field with evidence-grounded content; "
                "never use placeholder, TBD, TODO, N/A, none, or unknown.",
                "Return a complete strict result without weakening the decision.",
            )))
            result = self.runtime.run(current_task)
            retry_count += 1
            failures = validate_result(current_task, result)
            failures.extend(validate_output(
                current_task.output_contract, _jsonable(result.output)))
            semantic_failures = semantic_validator(result.output)
        failures.extend(semantic_failures)
        uncited = sorted(set(required_citations) - set(result.evidence_cited))
        if uncited and not failures and retry_count < 2:
            current_task = replace(current_task, constraints=tuple((*current_task.constraints,
                "The previous response omitted mandatory citations. Return a corrected "
                "response citing all of these evidence IDs: " + ", ".join(uncited),
            )))
            result = self.runtime.run(current_task)
            retry_count += 1
            failures = validate_result(current_task, result)
            failures.extend(validate_output(
                current_task.output_contract, _jsonable(result.output)))
            if semantic_validator:
                failures.extend(semantic_validator(result.output))
            uncited = sorted(
                set(required_citations) - set(result.evidence_cited))
        if uncited:
            failures.append("agent did not cite required evidence: " + ", ".join(uncited))
        if failures:
            raise PreApprovalError("; ".join(failures))
        if result.status is not AgentResultStatus.SUCCEEDED:
            detail = ", ".join(result.missing_evidence) or result.status.value
            raise PreApprovalError(f"{task.role.value} did not succeed: {detail}")
        ref = write_evidence(
            run_dir, self.id_factory("EVD"), f"{task.role.value}_agent_result",
            canonical_json({
                "runtime": result.runtime, "model": result.model,
                "output": _jsonable(result.output),
                "evidence_cited": list(result.evidence_cited),
                "usage": _jsonable(result.usage),
            }), self.collector, now=self.now(),
        )
        return result, ref.evidence_id


class SREReviewService(_AgentStage):
    def __init__(self, *, case_store: CaseStore, record_store: ProductRecordStore,
                 artifact_root, runtime: AgentRuntime, now: Callable[[], str],
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        super().__init__(case_store=case_store, record_store=record_store,
                         artifact_root=artifact_root, runtime=runtime, now=now,
                         id_factory=id_factory)

    def review(self, case_id: str, *, service_context: Mapping) -> ReviewOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.PLAN_READY:
            raise PreApprovalError(f"case {case_id} must be plan_ready for SRE review")
        plan_id = case.record_ids.get("change_plan_id")
        plan = self.record_store.get(plan_id or "")
        if plan.case_id != case_id or plan.record_type != "RemediationPlan.v1":
            raise PreApprovalError("case remediation plan has the wrong owner or type")
        if plan.body.get("status") != "verified" or not all(
                check.get("passed") is True for check in plan.body.get("checks", ())):
            raise PreApprovalError("SRE review requires a verified Terraform plan")
        required_context = ("service", "environment", "health_signals", "dependencies", "owner")
        missing_context = [name for name in required_context if name not in service_context]
        if missing_context:
            raise PreApprovalError(
                "service context is missing: " + ", ".join(missing_context))
        if not isinstance(service_context["health_signals"], (list, tuple)) \
                or not service_context["health_signals"]:
            raise PreApprovalError("service context requires at least one health signal")
        if not isinstance(service_context["dependencies"], (list, tuple)):
            raise PreApprovalError("service context dependencies must be a list")

        review_id, task_id, now = self.id_factory("SRE"), self.id_factory("TASK"), self.now()
        run_dir = self.artifact_root / "cases" / case_id / "sre" / review_id
        context_ref = write_evidence(
            run_dir, self.id_factory("EVD"), "service_operating_context",
            canonical_json(service_context), self.collector, now=now,
        )
        evidence_ids = tuple(dict.fromkeys((*plan.evidence_ids, context_ref.evidence_id)))
        task = AgentTask(
            task_id=task_id, case_id=case_id, role=AgentRole.SRE_REVIEWER,
            objective="Independently review the verified remediation for operational safety",
            output_contract="SREReview.v1", input_record_ids=(plan.record_id,),
            evidence_ids=evidence_ids,
            constraints=(
                "do not change the remediation", "do not approve missing health signals",
                "evaluate availability, dependencies, rollout, and verification",
                "this is pre-change: observed_topology contains current facts; "
                "health_signals are post-change success criteria unless explicitly "
                "labelled as observed",
                "do not state or imply that the change, rollback, or post-change "
                "verification has already run",
            ),
            metadata={"plan": plan.body, "service_context": service_context,
                      "case": case_to_dict(case)},
        )
        result, result_evidence = self._run(
            task, run_dir=run_dir,
            required_citations=(plan.evidence_ids[0], context_ref.evidence_id),
            semantic_validator=_sre_semantic_failures)

        output = result.output
        if service_context.get("evidence_phase") == "pre_change":
            false_claims = _prechange_claim_failures(output["summary"])
            if false_claims:
                raise PreApprovalError(
                    "SRE review claimed future-state evidence during pre-change: "
                    + ", ".join(false_claims))
        decision = output["decision"]
        if decision == "approve":
            for name in ("failure_modes", "required_controls", "verification_requirements"):
                _strings(output, name, required=True)
        body = {
            "review_id": review_id, "decision": decision,
            "risk_level": output["risk_level"], "summary": output["summary"],
            "dependencies": list(_strings(output, "dependencies")),
            "failure_modes": list(_strings(output, "failure_modes")),
            "required_controls": list(_strings(output, "required_controls")),
            "verification_requirements": list(
                _strings(output, "verification_requirements")),
            "plan_id": plan.record_id,
            "task": {"task_id": task_id, "runtime": result.runtime,
                     "model": result.model, "evidence_cited": list(result.evidence_cited)},
            "artifact_namespace": f"cases/{case_id}/sre/{review_id}",
        }
        record_evidence = tuple(dict.fromkeys((*evidence_ids, result_evidence)))
        record = ProductRecord(
            record_id=review_id, case_id=case_id, record_type="SREReview.v1",
            schema_version=1, created_at=now, body=body, evidence_ids=record_evidence)
        self.record_store.put(record)
        common = dict(
            event_id=self.id_factory("EVT"), occurred_at=now, actor="sre-reviewer",
            record_ids={"sre_review_id": review_id}, evidence_ids=record_evidence)
        if decision == "approve":
            case = self.workflow.advance(case_id, CaseTransition.APPROVE_SRE, **common)
        elif decision == "reject":
            case = self.workflow.advance(
                case_id, CaseTransition.REJECT, detail=output["summary"], **common)
        else:
            case = self.workflow.advance(
                case_id, CaseTransition.BLOCK, detail=output["summary"], **common)
        return ReviewOutcome(case=case, record=record, agent_result=result)

    def retry_invalid_approval(self, case_id: str) -> bool:
        """Reopen a persisted legacy approval that fails current semantics."""
        case = self.case_store.get(case_id)
        if case.state not in {CaseState.SRE_APPROVED, CaseState.WINDOW_SELECTED}:
            return False
        review_id = case.record_ids.get("sre_review_id", "")
        review = self.record_store.get(review_id)
        if review.case_id != case_id or review.record_type != "SREReview.v1":
            raise PreApprovalError(
                "case SRE review has the wrong owner or record type")
        failures = _sre_semantic_failures(review.body)
        if not failures:
            return False
        self.workflow.advance(
            case_id, CaseTransition.RETRY_SRE,
            event_id=self.id_factory("EVT"), occurred_at=self.now(),
            actor="operational-review-policy",
            record_ids={"review_feedback_id": review.record_id},
            evidence_ids=review.evidence_ids,
            detail="; ".join(failures))
        return True


class ChangeWindowService(_AgentStage):
    def __init__(self, *, case_store: CaseStore, record_store: ProductRecordStore,
                 artifact_root, runtime: AgentRuntime, now: Callable[[], str],
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        super().__init__(case_store=case_store, record_store=record_store,
                         artifact_root=artifact_root, runtime=runtime, now=now,
                         id_factory=id_factory)

    def reselect_started(self, case_id: str) -> bool:
        """Invalidate a started window and its dependent rollback approval."""
        case = self.case_store.get(case_id)
        if case.state is not CaseState.ROLLBACK_READY:
            return False
        if case.change_window is None:
            raise PreApprovalError(
                f"case {case_id} has no change window to evaluate")
        now = self.now()
        if (parse_timestamp(case.change_window.starts_at)
                > parse_timestamp(now)):
            return False
        window_id = case.record_ids.get("change_window_id", "")
        rollback_id = case.record_ids.get("rollback_review_id", "")
        window = self.record_store.get(window_id)
        rollback = self.record_store.get(rollback_id)
        if (window.case_id != case_id
                or window.record_type != "ChangeWindowRecommendation.v1"):
            raise PreApprovalError(
                "case change window has the wrong owner or record type")
        if (rollback.case_id != case_id
                or rollback.record_type != "RollbackReview.v1"):
            raise PreApprovalError(
                "case rollback review has the wrong owner or record type")
        evidence_ids = tuple(dict.fromkeys(
            (*window.evidence_ids, *rollback.evidence_ids)))
        self.workflow.advance(
            case_id, CaseTransition.RESELECT_WINDOW,
            event_id=self.id_factory("EVT"), occurred_at=now,
            actor="change-window-policy", evidence_ids=evidence_ids,
            detail=(
                f"window {window_id} started at {case.change_window.starts_at} "
                f"before the human gate; rollback review {rollback_id} must be "
                "repeated for a newly selected window"),
        )
        return True

    def select(self, case_id: str, *, samples: tuple[UsageSample, ...],
               policy: WindowPolicy) -> WindowOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.SRE_APPROVED:
            raise PreApprovalError(f"case {case_id} must be sre_approved for window selection")
        sre = self.record_store.get(case.record_ids.get("sre_review_id") or "")
        plan = self.record_store.get(case.record_ids.get("change_plan_id") or "")
        if sre.case_id != case_id or sre.record_type != "SREReview.v1" \
                or sre.body.get("decision") != "approve":
            raise PreApprovalError("window selection requires an approved SRE review")
        now = self.now()
        candidates = candidate_windows(samples, policy=policy, now=now)
        window_id, task_id = self.id_factory("WIN"), self.id_factory("TASK")
        run_dir = self.artifact_root / "cases" / case_id / "window" / window_id
        telemetry_ref = write_evidence(
            run_dir, self.id_factory("EVD"), "service_usage_samples",
            canonical_json({"samples": [sample.to_dict() for sample in samples]}),
            self.collector, now=now,
        )
        candidates_ref = write_evidence(
            run_dir, self.id_factory("EVD"), "deterministic_window_candidates",
            canonical_json({"policy": policy.to_dict(),
                            "candidates": [item.to_dict() for item in candidates]}),
            self.collector, now=now,
        )
        evidence_ids = tuple(dict.fromkeys((
            *plan.evidence_ids, *sre.evidence_ids,
            telemetry_ref.evidence_id, candidates_ref.evidence_id,
        )))
        task = AgentTask(
            task_id=task_id, case_id=case_id, role=AgentRole.WINDOW_PLANNER,
            objective="Select the safest supplied change-window candidate",
            output_contract="ChangeWindowSelection.v1",
            input_record_ids=(plan.record_id, sre.record_id), evidence_ids=evidence_ids,
            constraints=("select exactly one supplied candidate", "do not invent telemetry",
                         "respect the deterministic window policy"),
            metadata={"policy": policy.to_dict(),
                      "candidates": [item.to_dict() for item in candidates],
                      "sre_review": sre.body},
        )
        result, result_evidence = self._run(
            task, run_dir=run_dir,
            required_citations=(sre.evidence_ids[-1], telemetry_ref.evidence_id,
                                candidates_ref.evidence_id))
        by_id = {candidate.candidate_id: candidate for candidate in candidates}
        selected_id = result.output["selected_candidate_id"]
        if selected_id not in by_id:
            raise PreApprovalError("window agent selected a candidate it was not supplied")
        selected = by_id[selected_id]
        if parse_timestamp(selected.starts_at) <= parse_timestamp(now):
            raise PreApprovalError("selected change window is not in the future")
        rationale = _strings(result.output, "rationale", required=True)
        confidence = result.output["confidence"]
        if (isinstance(confidence, bool) or not isinstance(confidence, (int, float))
                or not math.isfinite(confidence) or not 0 <= confidence <= 1):
            raise PreApprovalError("window confidence must be a finite number from 0 to 1")
        record_evidence = tuple(dict.fromkeys((*evidence_ids, result_evidence)))
        body = {
            "window_id": window_id, "selected_candidate_id": selected_id,
            "selected": selected.to_dict(),
            "rationale": list(rationale), "confidence": confidence,
            "risks": list(_strings(result.output, "risks")),
            "policy": policy.to_dict(),
            "candidates": [candidate.to_dict() for candidate in candidates],
            "task": {"task_id": task_id, "runtime": result.runtime,
                     "model": result.model, "evidence_cited": list(result.evidence_cited)},
            "artifact_namespace": f"cases/{case_id}/window/{window_id}",
        }
        record = ProductRecord(
            record_id=window_id, case_id=case_id,
            record_type="ChangeWindowRecommendation.v1", schema_version=1,
            created_at=now, body=body, evidence_ids=record_evidence)
        self.record_store.put(record)
        change_window = ChangeWindow(
            window_id=window_id, starts_at=selected.starts_at, ends_at=selected.ends_at,
            timezone=selected.timezone, rationale=rationale,
            evidence_ids=record_evidence, confidence=confidence,
        )
        case = self.workflow.advance(
            case_id, CaseTransition.SELECT_WINDOW,
            event_id=self.id_factory("EVT"), occurred_at=now, actor="window-planner",
            record_ids={"change_window_id": window_id}, evidence_ids=record_evidence,
            change_window=change_window,
        )
        return WindowOutcome(case=case, record=record, agent_result=result,
                             candidates=candidates)


class RollbackReviewService(_AgentStage):
    def __init__(self, *, case_store: CaseStore, record_store: ProductRecordStore,
                 artifact_root, runtime: AgentRuntime, now: Callable[[], str],
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        super().__init__(case_store=case_store, record_store=record_store,
                         artifact_root=artifact_root, runtime=runtime, now=now,
                         id_factory=id_factory)

    def review(self, case_id: str) -> ReviewOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.WINDOW_SELECTED:
            raise PreApprovalError(f"case {case_id} must be window_selected for rollback review")
        plan = self.record_store.get(case.record_ids.get("change_plan_id") or "")
        sre = self.record_store.get(case.record_ids.get("sre_review_id") or "")
        window = self.record_store.get(case.record_ids.get("change_window_id") or "")
        if not case.change_plan or not case.change_plan.rollback_steps \
                or not case.change_plan.rollback_triggers:
            raise PreApprovalError("change plan has no executable rollback contract")
        review_id, task_id, now = self.id_factory("RBK"), self.id_factory("TASK"), self.now()
        run_dir = self.artifact_root / "cases" / case_id / "rollback" / review_id
        evidence_ids = tuple(dict.fromkeys((
            *plan.evidence_ids, *sre.evidence_ids, *window.evidence_ids)))
        task = AgentTask(
            task_id=task_id, case_id=case_id, role=AgentRole.ROLLBACK_VERIFIER,
            objective="Independently verify rollback completeness before human review",
            output_contract="RollbackReview.v1",
            input_record_ids=(plan.record_id, sre.record_id, window.record_id),
            evidence_ids=evidence_ids,
            constraints=("do not approve vague rollback steps",
                         "map material failure modes to observable triggers",
                         "require a reversible path",
                         "treat failed pre-mutation scope, tag, state, or permission "
                         "guards as abort-without-change controls",
                         "require rollback triggers only for failure modes possible "
                         "after mutation; if rejecting, list concrete required_changes"),
            metadata={"plan": plan.body, "sre_review": sre.body,
                      "change_window": window.body},
        )
        result, result_evidence = self._run(
            task, run_dir=run_dir,
            required_citations=(plan.evidence_ids[0], sre.evidence_ids[-1],
                                window.evidence_ids[-1]),
            semantic_validator=_rollback_semantic_failures)
        output, decision = result.output, result.output["decision"]
        if decision == "approve":
            _strings(output, "verified_steps", required=True)
            _strings(output, "trigger_coverage", required=True)
            if _strings(output, "required_changes"):
                raise PreApprovalError(
                    "rollback reviewer cannot approve while required changes remain")
        body = {
            "review_id": review_id, "decision": decision,
            "summary": output["summary"],
            "verified_steps": list(_strings(output, "verified_steps")),
            "trigger_coverage": list(_strings(output, "trigger_coverage")),
            "failure_modes": list(_strings(output, "failure_modes")),
            "required_changes": list(_strings(output, "required_changes")),
            "plan_id": plan.record_id, "window_id": window.record_id,
            "task": {"task_id": task_id, "runtime": result.runtime,
                     "model": result.model, "evidence_cited": list(result.evidence_cited)},
            "artifact_namespace": f"cases/{case_id}/rollback/{review_id}",
        }
        record_evidence = tuple(dict.fromkeys((*evidence_ids, result_evidence)))
        record = ProductRecord(
            record_id=review_id, case_id=case_id, record_type="RollbackReview.v1",
            schema_version=1, created_at=now, body=body, evidence_ids=record_evidence)
        self.record_store.put(record)
        common = dict(
            event_id=self.id_factory("EVT"), occurred_at=now, actor="rollback-reviewer",
            record_ids={"rollback_review_id": review_id}, evidence_ids=record_evidence)
        if decision == "approve":
            case = self.workflow.advance(case_id, CaseTransition.REVIEW_ROLLBACK, **common)
        elif decision == "reject":
            required_changes = _strings(output, "required_changes")
            events = self.case_store.events(case_id)
            cycle_start = max((
                event.sequence for event in events
                if event.transition is CaseTransition.ADD_FINDING
                and event.to_state is CaseState.PRIORITIZED
            ), default=0)
            already_reworked = any(
                event.transition is CaseTransition.REQUEST_REWORK
                and event.sequence > cycle_start for event in events)
            if required_changes and not already_reworked:
                case = self.workflow.advance(
                    case_id, CaseTransition.REQUEST_REWORK,
                    event_id=common["event_id"], occurred_at=common["occurred_at"],
                    actor=common["actor"],
                    record_ids={"review_feedback_id": review_id},
                    evidence_ids=common["evidence_ids"],
                    detail=output["summary"])
            else:
                case = self.workflow.advance(
                    case_id, CaseTransition.REJECT,
                    detail=output["summary"], **common)
        else:
            case = self.workflow.advance(
                case_id, CaseTransition.BLOCK, detail=output["summary"], **common)
        return ReviewOutcome(case=case, record=record, agent_result=result)


class HumanReviewGate:
    """Mechanical policy checks only; this component is deliberately not an agent."""

    def __init__(self, *, case_store: CaseStore, record_store: ProductRecordStore,
                 now: Callable[[], str],
                 minimum_distinct_agent_models: int = 1,
                 require_state_grounded_plan: bool = False,
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        self.case_store = case_store
        self.record_store = record_store
        self.now = now
        self.id_factory = id_factory
        if not 1 <= minimum_distinct_agent_models <= 4:
            raise ValueError("minimum distinct agent models must be between 1 and 4")
        self.minimum_distinct_agent_models = minimum_distinct_agent_models
        self.require_state_grounded_plan = require_state_grounded_plan
        self.workflow = WorkflowCoordinator(case_store)

    def prepare(self, case_id: str) -> HumanReviewOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.ROLLBACK_READY:
            raise PreApprovalError(f"case {case_id} must be rollback_ready for human review")
        required = {
            "validation_result_id": "ValidationResult.v1",
            "iac_link_id": "IaCLink.v1",
            "change_plan_id": "RemediationPlan.v1",
            "sre_review_id": "SREReview.v1",
            "change_window_id": "ChangeWindowRecommendation.v1",
            "rollback_review_id": "RollbackReview.v1",
        }
        records = {}
        checks = []
        for key, expected_type in required.items():
            record_id = case.record_ids.get(key)
            if not record_id:
                checks.append({"check": key, "passed": False, "detail": "record missing"})
                continue
            record = self.record_store.get(record_id)
            passed = record.case_id == case_id and record.record_type == expected_type
            checks.append({"check": key, "passed": passed,
                           "detail": f"{record.record_id} ({record.record_type})"})
            records[key] = record
        plan = records.get("change_plan_id")
        plan_ok = bool(plan and plan.body.get("status") == "verified" and
                       plan.body.get("checks") and
                       all(item.get("passed") is True for item in plan.body["checks"]))
        checks.append({"check": "terraform_verification", "passed": plan_ok,
                       "detail": "fmt/init/validate/plan must all pass"})
        if self.require_state_grounded_plan:
            verification = (plan.body.get("verification") if plan else {}) or {}
            state_plan_ok = (
                verification.get("mode") == "targeted_state_plan"
                and verification.get("plan_artifact_persisted") is False
                and bool(verification.get("resource_address"))
                and bool(verification.get("state_sha256"))
                and any(item.get("name") == "plan_scope" and item.get("passed") is True
                        for item in (plan.body.get("checks", ()) if plan else ()))
            )
            checks.append({
                "check": "state_grounded_plan_scope", "passed": state_plan_ok,
                "detail": (
                    "ephemeral plan must contain only the allowed in-place attribute "
                    "update to the state-linked resource"),
            })
        sre_ok = bool(
            records.get("sre_review_id")
            and records["sre_review_id"].body.get("decision") == "approve"
            and not _sre_semantic_failures(records["sre_review_id"].body))
        checks.append({"check": "sre_approval", "passed": sre_ok,
                       "detail": "independent SRE decision must be approve"})
        rollback_ok = bool(
            records.get("rollback_review_id")
            and records["rollback_review_id"].body.get("decision") == "approve"
            and not _rollback_semantic_failures(
                records["rollback_review_id"].body))
        checks.append({"check": "rollback_approval", "passed": rollback_ok,
                       "detail": "independent rollback decision must be approve"})
        agent_records = [records.get(name) for name in (
            "change_plan_id", "sre_review_id", "change_window_id", "rollback_review_id")]
        model_identities = {
            (record.body.get("task") or {}).get("runtime", "") + ":" +
            (record.body.get("task") or {}).get("model", "")
            for record in agent_records if record is not None
        }
        model_identities.discard(":")
        diversity_ok = len(model_identities) >= self.minimum_distinct_agent_models
        checks.append({
            "check": "agent_model_diversity", "passed": diversity_ok,
            "detail": (f"{len(model_identities)} distinct runtime/model identities; "
                       f"policy requires {self.minimum_distinct_agent_models}"),
        })
        window_ok = bool(case.change_window and
                         parse_timestamp(case.change_window.starts_at) > parse_timestamp(self.now()))
        checks.append({"check": "future_change_window", "passed": window_ok,
                       "detail": case.change_window.starts_at if case.change_window else "missing"})
        all_evidence = tuple(dict.fromkeys(
            evidence for record in records.values() for evidence in record.evidence_ids))
        evidence_ok = bool(all_evidence) and all(record.evidence_ids for record in records.values())
        checks.append({"check": "evidence_chain", "passed": evidence_ok,
                       "detail": f"{len(all_evidence)} immutable evidence references"})

        failed = [item["check"] for item in checks if not item["passed"]]
        if failed:
            raise PreApprovalError("human review policy failed: " + ", ".join(failed))
        now, policy_id, package_id = (
            self.now(), self.id_factory("POL"), self.id_factory("REVIEW"))
        policy = ProductRecord(
            record_id=policy_id, case_id=case_id, record_type="PolicyDecision.v1",
            schema_version=1, created_at=now,
            body={"policy_id": policy_id, "decision": "allow_human_review",
                  "checks": checks, "prohibitions": [
                      "no infrastructure apply has been performed",
                      "approval does not itself authorize or execute a change",
                  ]},
            evidence_ids=all_evidence,
        )
        self.record_store.put(policy)
        package = ProductRecord(
            record_id=package_id, case_id=case_id,
            record_type="HumanReviewPackage.v1", schema_version=1, created_at=now,
            body={
                "review_package_id": package_id, "case": case_to_dict(case),
                "risk_assessment": case_to_dict(case).get("priority"),
                "validation": product_record_to_dict(records["validation_result_id"]),
                "iac_link": product_record_to_dict(records["iac_link_id"]),
                "remediation_plan": product_record_to_dict(records["change_plan_id"]),
                "sre_review": product_record_to_dict(records["sre_review_id"]),
                "change_window": product_record_to_dict(records["change_window_id"]),
                "rollback_review": product_record_to_dict(records["rollback_review_id"]),
                "policy_decision": product_record_to_dict(policy),
                "requested_human_decision": "approve_or_reject_change",
                "execution_status": "not_started",
            }, evidence_ids=all_evidence,
        )
        self.record_store.put(package)
        case = self.workflow.advance(
            case_id, CaseTransition.REQUEST_APPROVAL,
            event_id=self.id_factory("EVT"), occurred_at=now, actor="approval-policy",
            record_ids={"policy_decision_id": policy_id,
                        "human_review_package_id": package_id},
            evidence_ids=all_evidence,
        )
        return HumanReviewOutcome(case=case, policy_record=policy,
                                  review_package=package)
