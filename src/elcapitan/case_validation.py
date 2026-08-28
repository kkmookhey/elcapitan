"""Read-only live validation of findings attached to a remediation case."""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Mapping

from .cases import CaseState, CaseTransition, RemediationCase
from .cloud import CloudState, capture_cloud_state, to_dict, verification_env
from .control_packs import ControlPackRegistry, builtin_registry
from .evidence import Collector, write_evidence
from .finding_store import FindingStore, StoredFinding
from .hashing import canonical_json
from .intake import numeric_id
from .product_records import ProductRecord, ProductRecordStore
from .workflow import CaseStore, WorkflowCoordinator


_CONTROL_REGISTRY = builtin_registry()


class FindingValidationStatus(StrEnum):
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not_confirmed"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class FindingValidation:
    finding_id: str
    rule_id: str
    status: FindingValidationStatus
    reason: str
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "status": self.status.value,
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class CaseValidationOutcome:
    case: RemediationCase
    record: ProductRecord
    findings: tuple[FindingValidation, ...]


def read_live_state(finding: StoredFinding, host_env: Mapping[str, str]) -> CloudState:
    provenance = finding.record["provenance"]
    provider = provenance["provider"]
    env = verification_env(dict(host_env), provider=provider)
    return capture_cloud_state(
        finding.resource_uid, provider=provider,
        region=provenance.get("region", ""), env=env)


def _value(state: CloudState, aspect: str):
    raw = dict(state.config).get(aspect)
    if raw is None:
        raise ValueError(f"live cloud state did not capture {aspect}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def evaluate_finding(finding: StoredFinding, state: CloudState,
                     *, evidence_ids: tuple[str, ...],
                     registry: ControlPackRegistry | None = None
                     ) -> FindingValidation:
    rule_id = finding.record["ocsf"].get("rule_id", "")
    resource_type = str(finding.record.get("resource", {}).get("type", ""))
    definition = (registry or _CONTROL_REGISTRY).get(
        finding.provider, rule_id, resource_type)
    if definition is None:
        return FindingValidation(
            finding_id=finding.finding_id, rule_id=rule_id,
            status=FindingValidationStatus.UNSUPPORTED,
            reason=(f"no deterministic live evaluator is registered for provider "
                    f"{finding.provider!r}, rule {rule_id!r}, and resource type "
                    f"{resource_type!r}"))
    values = {aspect: _value(state, aspect) for aspect, _ in state.config}
    evaluation = definition.evaluator(values)
    return FindingValidation(
        finding_id=finding.finding_id, rule_id=rule_id,
        status=(FindingValidationStatus.CONFIRMED if evaluation.confirmed
                else FindingValidationStatus.NOT_CONFIRMED),
        reason=evaluation.reason, evidence_ids=evidence_ids)


class CaseValidationService:
    def __init__(self, *, case_store: CaseStore, finding_store: FindingStore,
                 record_store: ProductRecordStore, artifact_root,
                 now: Callable[[], str], id_factory: Callable[[str], str] = numeric_id,
                 reader: Callable[[StoredFinding, Mapping[str, str]], CloudState]
                 = read_live_state) -> None:
        self.case_store = case_store
        self.finding_store = finding_store
        self.record_store = record_store
        self.artifact_root = Path(artifact_root)
        self.now = now
        self.id_factory = id_factory
        self.reader = reader
        self.workflow = WorkflowCoordinator(case_store)
        self.collector = Collector(
            tool="elcapitan-live-validator", version="0.1.0",
            identity="read-only-scanner")

    def validate(self, case_id: str, *, host_env: Mapping[str, str]
                 ) -> CaseValidationOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.PRIORITIZED:
            raise ValueError(
                f"case {case_id} must be prioritized before validation; "
                f"current state is {case.state}")
        findings = self.finding_store.list_for_case(case_id)
        if not findings:
            raise ValueError(f"case {case_id} has no persisted findings")

        validation_id = self.id_factory("VAL")
        now = self.now()
        run_dir = self.artifact_root / "cases" / case_id / "validation" / validation_id
        results: list[FindingValidation] = []
        evidence_refs: list[dict] = []
        captured: dict[tuple[str, str], tuple[CloudState | None, tuple[str, ...], str]] = {}
        for finding in findings:
            key = (finding.provider, finding.resource_uid)
            if key not in captured:
                evidence_id = self.id_factory("EVD")
                command_id = self.id_factory("CMD")
                try:
                    state = self.reader(finding, host_env)
                    if (state.provider != finding.provider
                            or state.resource_uid != finding.resource_uid):
                        raise ValueError(
                            "live reader returned state for a different resource: "
                            f"expected {finding.provider}:{finding.resource_uid}, got "
                            f"{state.provider}:{state.resource_uid}")
                    ref = write_evidence(
                        run_dir, evidence_id, "live_cloud_configuration",
                        canonical_json(to_dict(state)), self.collector,
                        command_id=command_id, now=now)
                    evidence_refs.append(ref.to_dict())
                    captured[key] = state, (ref.evidence_id,), ""
                except (OSError, ValueError) as exc:
                    ref = write_evidence(
                        run_dir, evidence_id, "live_validation_error",
                        str(exc).encode("utf-8"), self.collector,
                        sensitivity="restricted",
                        command_id=command_id, now=now)
                    evidence_refs.append(ref.to_dict())
                    captured[key] = None, (ref.evidence_id,), str(exc)

            state, evidence_ids, error = captured[key]
            if state is None:
                results.append(FindingValidation(
                    finding_id=finding.finding_id,
                    rule_id=finding.record["ocsf"].get("rule_id", ""),
                    status=FindingValidationStatus.UNAVAILABLE,
                    reason=error, evidence_ids=evidence_ids))
                continue
            try:
                results.append(evaluate_finding(
                    finding, state, evidence_ids=evidence_ids))
            except ValueError as exc:
                results.append(FindingValidation(
                    finding_id=finding.finding_id,
                    rule_id=finding.record["ocsf"].get("rule_id", ""),
                    status=FindingValidationStatus.UNAVAILABLE,
                    reason=str(exc), evidence_ids=evidence_ids))

        all_evidence = tuple(dict.fromkeys(
            evidence_id for result in results for evidence_id in result.evidence_ids))
        body = {
            "validation_id": validation_id,
            "case_id": case_id,
            "findings": [result.to_dict() for result in results],
            "artifact_namespace": f"cases/{case_id}/validation/{validation_id}",
            "evidence": evidence_refs,
        }
        record = ProductRecord(
            record_id=validation_id, case_id=case_id,
            record_type="ValidationResult.v1", schema_version=1,
            created_at=now, body=body, evidence_ids=all_evidence)
        self.record_store.put(record)

        incomplete = [result for result in results if result.status in {
            FindingValidationStatus.UNAVAILABLE, FindingValidationStatus.UNSUPPORTED}]
        confirmed = [result for result in results
                     if result.status is FindingValidationStatus.CONFIRMED]
        common = dict(
            event_id=self.id_factory("EVT"), occurred_at=now,
            actor="live-validator", record_ids={"validation_result_id": validation_id},
            evidence_ids=all_evidence)
        if confirmed:
            # A resource case may contain both supported and unsupported
            # scanner controls. Confirmed controls are independently useful
            # and remain promotion-bound by their exact finding/evidence set;
            # unsupported siblings stay explicit in the validation record.
            case = self.workflow.advance(
                case_id, CaseTransition.VALIDATE,
                detail=(f"{len(confirmed)} finding(s) confirmed; "
                        f"{len(incomplete)} finding(s) unavailable or unsupported"),
                **common)
        elif incomplete:
            detail = "; ".join(result.reason for result in incomplete)
            case = self.workflow.advance(
                case_id, CaseTransition.BLOCK, detail=detail, **common)
        else:
            case = self.workflow.advance(
                case_id, CaseTransition.CLOSE_NO_ACTION,
                detail="live state no longer confirms any finding", **common)
        return CaseValidationOutcome(case=case, record=record, findings=tuple(results))
