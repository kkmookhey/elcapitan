"""Application service: normalized findings into prioritized remediation cases."""
from __future__ import annotations

import secrets
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .cases import (
    CaseState,
    CaseTransition,
    RemediationCase,
    RiskAssessment,
)
from .evidence import Collector
from .finding import (
    cloud_target,
    finding_rule_id,
    normalise_ocsf,
    prowler_outcome,
    source_identity,
)
from .finding_store import DuplicateFinding, FindingStore, StoredFinding
from .priority import PrioritySignals, assess_priority
from .schema import validate_doc
from .workflow import CaseStore, ConcurrentCaseUpdate, WorkflowCoordinator


def numeric_id(prefix: str) -> str:
    """Schema-compatible random id without a central sequence dependency."""
    return f"{prefix}-{secrets.randbelow(10**18):018d}"


@dataclass(frozen=True)
class IntakeContext:
    asset_criticality: float = 0.0
    exploit_probability: float = 0.0
    internet_exposed: bool | None = None
    reachable: bool = False
    known_exploited: bool = False
    active_exploitation: bool = False
    runtime_dependency: bool = False
    compensating_control_strength: float = 0.0
    service_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class IntakeOutcome:
    finding: StoredFinding
    case: RemediationCase
    duplicate: bool
    case_created: bool
    finding_attached: bool
    priority_changed: bool


def canonical_asset_id(provider: str, account: str, resource_uid: str) -> str:
    if not provider or not account or not resource_uid:
        raise ValueError("canonical asset id requires provider, account, and resource uid")
    return f"{provider}:{account}:{resource_uid}"


def priority_signals(record: dict, context: IntakeContext) -> PrioritySignals:
    extensions = record.get("vendor_extensions") or {}
    categories = extensions.get("categories") or []
    if isinstance(categories, str):
        categories = [categories]
    inferred_exposure = any(
        str(category).lower().replace("_", "-") == "internet-exposed"
        for category in categories)
    internet_exposed = (
        inferred_exposure if context.internet_exposed is None
        else context.internet_exposed)
    return PrioritySignals(
        severity=record.get("severity") or "unknown",
        asset_criticality=context.asset_criticality,
        exploit_probability=context.exploit_probability,
        internet_exposed=internet_exposed,
        reachable=context.reachable,
        known_exploited=context.known_exploited,
        active_exploitation=context.active_exploitation,
        runtime_dependency=context.runtime_dependency,
        compensating_control_strength=context.compensating_control_strength,
        evidence_ids=(record["raw_event"]["evidence_id"],),
    )


def _merge_priority(assessment_id: str, current: RiskAssessment,
                    incoming: RiskAssessment) -> RiskAssessment:
    winner = incoming if incoming.score > current.score else current
    return RiskAssessment(
        assessment_id=assessment_id,
        score=max(current.score, incoming.score),
        urgency=winner.urgency,
        factors=tuple(dict.fromkeys((*current.factors, *incoming.factors))),
        confidence=min(current.confidence, incoming.confidence),
        evidence_ids=tuple(dict.fromkeys((*current.evidence_ids, *incoming.evidence_ids))),
    )


class RemediationIntake:
    def __init__(self, *, case_store: CaseStore, finding_store: FindingStore,
                 artifact_root, collector: Collector,
                 now: Callable[[], str], id_factory: Callable[[str], str] = numeric_id,
                 ) -> None:
        self.case_store = case_store
        self.finding_store = finding_store
        self.artifact_root = Path(artifact_root)
        self.collector = collector
        self.now = now
        self.id_factory = id_factory
        self.workflow = WorkflowCoordinator(case_store)

    def ingest(self, raw: dict, *, tenant_id: str,
               context: IntakeContext = IntakeContext()) -> IntakeOutcome:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        outcome = prowler_outcome(raw)
        if outcome is not None and outcome != "FAIL":
            raise ValueError(
                f"Prowler {outcome} records are not actionable findings")
        provider, account, original_uid = source_identity(raw)
        existing = self.finding_store.get_by_source(
            tenant_id, provider, account, original_uid)
        # Deployments created before collision-safe Prowler keys used the raw
        # producer UID. Preserve replay idempotency for a matching legacy row,
        # but do not let a UID collision hide a different rule/resource.
        raw_uid = (raw.get("finding_info") or {}).get("uid", "")
        if existing is None and original_uid != raw_uid and raw_uid:
            legacy = self.finding_store.get_by_source(
                tenant_id, provider, account, raw_uid)
            if legacy is not None:
                same_resource = legacy.resource_uid == cloud_target(raw)[1]
                same_rule = (
                    str(legacy.record.get("ocsf", {}).get("rule_id", ""))
                    == finding_rule_id(raw))
                if same_resource and same_rule:
                    existing = legacy
        if existing and existing.case_id:
            return IntakeOutcome(
                finding=existing, case=self.case_store.get(existing.case_id),
                duplicate=True, case_created=False, finding_attached=False,
                priority_changed=False)

        if existing:
            finding = existing
            finding_created = False
        else:
            finding, finding_created = self._store_finding(
                raw, tenant_id=tenant_id, provider=provider, account=account,
                original_uid=original_uid, context=context)
        asset_id = canonical_asset_id(
            finding.provider, finding.account, finding.resource_uid)
        current = self.case_store.find_active_by_asset(tenant_id, asset_id)
        case_created = current is None
        finding_attached = False
        priority_changed = False
        now = self.now()

        incoming = assess_priority(
            self.id_factory("RISK"), finding.priority_signals)
        if current is None:
            try:
                current = self.workflow.open(
                    case_id=self.id_factory("CASE"), tenant_id=tenant_id,
                    finding_ids=(finding.finding_id,), asset_ids=(asset_id,),
                    service_ids=tuple(context.service_ids), now=now)
            except ConcurrentCaseUpdate:
                # Another intake worker won the exact find-then-create race.
                current = self.case_store.find_active_by_asset(tenant_id, asset_id)
                if current is None:
                    raise
                case_created = False
                if finding.finding_id not in current.finding_ids:
                    current = self.workflow.advance(
                        current.case_id, CaseTransition.ADD_FINDING,
                        event_id=self.id_factory("EVT"), occurred_at=now,
                        actor="intake", record_ids={"finding_id": finding.finding_id},
                        evidence_ids=finding.priority_signals.evidence_ids,
                        new_finding_ids=(finding.finding_id,))
                    finding_attached = True
        # Different intake workers may attach different findings to the same
        # case concurrently. Each append is optimistic; reload and finish any
        # still-missing event rather than failing the losing worker.
        for attempt in range(3):
            try:
                if finding.finding_id not in current.finding_ids:
                    current = self.workflow.advance(
                        current.case_id, CaseTransition.ADD_FINDING,
                        event_id=self.id_factory("EVT"), occurred_at=now, actor="intake",
                        record_ids={"finding_id": finding.finding_id},
                        evidence_ids=finding.priority_signals.evidence_ids,
                        new_finding_ids=(finding.finding_id,))
                    finding_attached = True

                if current.state is CaseState.OPEN:
                    current = self.workflow.advance(
                        current.case_id, CaseTransition.PRIORITIZE,
                        event_id=self.id_factory("EVT"), occurred_at=now,
                        actor="priority-policy", priority=incoming,
                        record_ids={"risk_assessment_id": incoming.assessment_id},
                        evidence_ids=incoming.evidence_ids)
                    priority_changed = True
                elif current.priority is None or incoming.score > current.priority.score:
                    merged = (incoming if current.priority is None else
                              _merge_priority(self.id_factory("RISK"),
                                              current.priority, incoming))
                    current = self.workflow.advance(
                        current.case_id, CaseTransition.REPRIORITIZE,
                        event_id=self.id_factory("EVT"), occurred_at=now,
                        actor="priority-policy", priority=merged,
                        record_ids={"risk_assessment_id": merged.assessment_id},
                        evidence_ids=merged.evidence_ids)
                    priority_changed = True
                break
            except ConcurrentCaseUpdate:
                if attempt == 2:
                    raise
                current = self.case_store.get(current.case_id)

        finding = self.finding_store.assign_case(finding.finding_id, current.case_id)
        return IntakeOutcome(
            finding=finding, case=current, duplicate=not finding_created,
            case_created=case_created, finding_attached=finding_attached,
            priority_changed=priority_changed)

    def _store_finding(self, raw: dict, *, tenant_id: str, provider: str,
                       account: str, original_uid: str,
                       context: IntakeContext) -> tuple[StoredFinding, bool]:
        finding_id = self.id_factory("FIND")
        namespace = f"findings/{finding_id}"
        run_dir = self.artifact_root / namespace
        run_dir.mkdir(parents=True, exist_ok=False)
        now = self.now()
        record = normalise_ocsf(
            raw, run_dir=run_dir, finding_id=finding_id,
            collector=self.collector, now=now)
        failures = validate_doc("finding-record", record)
        if failures:
            raise ValueError("normalized finding is invalid: " + "; ".join(failures))
        _, resource_uid, _ = cloud_target(raw)
        finding = StoredFinding(
            tenant_id=tenant_id, finding_id=finding_id, provider=provider,
            account=account, original_uid=original_uid, resource_uid=resource_uid,
            record=record, priority_signals=priority_signals(record, context),
            artifact_namespace=namespace)
        try:
            self.finding_store.put(finding)
            return finding, True
        except DuplicateFinding:
            # Another worker won the same source-identity race. This directory
            # was created by this call and is not referenced by the winning
            # record, so remove only this exact namespace and return the winner.
            shutil.rmtree(run_dir)
            winner = self.finding_store.get_by_source(
                tenant_id, provider, account, original_uid)
            if winner is None:
                raise
            return winner, False
