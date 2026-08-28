"""Evidence-minimized promotion contracts from shadow validation to planning."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, dataclass

from .cases import CaseState
from .finding_store import FindingStore
from .fleet import CapabilityRegistry
from .hashing import canonical_json
from .product_records import ProductRecordStore
from .workflow import CaseStore


@dataclass(frozen=True)
class PromotionReadiness:
    case_id: str
    tenant_id: str
    eligible: bool
    status: str
    blockers: tuple[str, ...]
    provider: str
    resource_uids: tuple[str, ...]
    confirmed_finding_ids: tuple[str, ...]
    confirmed_rule_ids: tuple[str, ...]
    validation_record_id: str
    validation_evidence_ids: tuple[str, ...]
    required_inputs: tuple[str, ...]
    target_state: str
    promotion_token: str

    def to_dict(self) -> dict:
        value = asdict(self)
        for name in (
            "blockers", "resource_uids", "confirmed_finding_ids",
            "confirmed_rule_ids", "validation_evidence_ids", "required_inputs",
        ):
            value[name] = list(value[name])
        value["safety_boundary"] = {
            "source": "shadow",
            "destination": "preapproval-control-plane",
            "raw_finding_payload_included": False,
            "approval": False,
            "scheduling": False,
            "execution": False,
        }
        return value


class PromotionReadinessService:
    PREAPPROVAL_STATES = frozenset({
        CaseState.VALIDATED,
        CaseState.PLAN_READY,
        CaseState.SRE_APPROVED,
        CaseState.WINDOW_SELECTED,
        CaseState.ROLLBACK_READY,
    })
    REQUIRED_INPUTS = (
        "read-only IaC repository snapshot",
        "Terraform state JSON when resource names are computed",
        "service owner, environment, dependencies, and health signals",
        "historical usage samples or a separately scoped observer identity",
        "explicit maker, SRE checker, window reviewer, and rollback reviewer routes",
    )

    def __init__(self, *, case_store: CaseStore, finding_store: FindingStore,
                 record_store: ProductRecordStore,
                 registry: CapabilityRegistry | None = None) -> None:
        self.case_store = case_store
        self.finding_store = finding_store
        self.record_store = record_store
        self.registry = registry or CapabilityRegistry()

    def inspect(self, *, tenant_id: str, case_id: str) -> PromotionReadiness:
        case = self.case_store.get(case_id)
        if case.tenant_id != tenant_id:
            raise ValueError("case does not belong to the requested tenant")
        findings = self.finding_store.list_for_case(case_id)
        blockers: list[str] = []
        if (case.state not in self.PREAPPROVAL_STATES
                and case.state is not CaseState.AWAITING_APPROVAL):
            blockers.append(
                f"case is outside the preapproval workflow; current state is "
                f"{case.state.value}")
        validation_id = case.record_ids.get("validation_result_id", "")
        validation = None
        if not validation_id:
            blockers.append("case has no bound validation result")
        else:
            try:
                validation = self.record_store.get(validation_id)
            except KeyError:
                blockers.append("bound validation result does not exist")
            else:
                if (validation.case_id != case_id
                        or validation.record_type != "ValidationResult.v1"):
                    blockers.append("bound validation result has the wrong owner or type")

        statuses = {
            str(item.get("finding_id", "")): str(item.get("status", ""))
            for item in (validation.body.get("findings", ()) if validation else ())
        }
        by_id = {item.finding_id: item for item in findings}
        unvalidated = sorted(set(by_id) - set(statuses))
        if validation and unvalidated:
            blockers.append(
                "validation does not cover finding(s): " + ", ".join(unvalidated))
        confirmed_ids = tuple(sorted(
            finding_id for finding_id, status in statuses.items()
            if status == "confirmed" and finding_id in by_id))
        if validation and not confirmed_ids:
            blockers.append("live validation confirms no finding in this case")
        incomplete = sorted(
            finding_id for finding_id, status in statuses.items()
            if status in {"unsupported", "unavailable"})
        if incomplete:
            blockers.append(
                "validation is incomplete for finding(s): " + ", ".join(incomplete))

        confirmed = [by_id[finding_id] for finding_id in confirmed_ids]
        providers = {item.provider for item in confirmed}
        resources = tuple(sorted({item.resource_uid for item in confirmed}))
        if len(providers) > 1:
            blockers.append("confirmed findings span multiple cloud providers")
        if len(resources) > 1:
            blockers.append("confirmed findings span multiple resources")
        rules = tuple(sorted({
            str(item.record["ocsf"].get("rule_id", "")) for item in confirmed
        }))
        unsupported = sorted({
            str(item.record["ocsf"].get("rule_id", ""))
            for item in confirmed
            if not (capability := self.registry.get(
                item.provider, str(item.record["ocsf"].get("rule_id", "")),
                str(item.record.get("resource", {}).get("type", ""))))
            or not capability.remediation_planning
        })
        if unsupported:
            blockers.append(
                "no deterministic planning capability for: " + ", ".join(unsupported))

        provider = next(iter(providers), "")
        evidence_ids = tuple(validation.evidence_ids) if validation else ()
        token_document = {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "validation_record_id": validation_id,
            "validation_evidence_ids": list(evidence_ids),
            "confirmed_finding_ids": list(confirmed_ids),
            "provider": provider,
            "resource_uids": list(resources),
            "rule_ids": list(rules),
        }
        token = hashlib.sha256(canonical_json(token_document)).hexdigest()
        eligible = not blockers and case.state in self.PREAPPROVAL_STATES
        if blockers:
            status = "blocked"
        elif case.state is CaseState.VALIDATED:
            status = "ready_for_preapproval"
        elif case.state is CaseState.AWAITING_APPROVAL:
            status = "awaiting_human_approval"
        else:
            status = "preapproval_in_progress"
        return PromotionReadiness(
            case_id=case_id,
            tenant_id=tenant_id,
            eligible=eligible,
            status=status,
            blockers=tuple(blockers),
            provider=provider,
            resource_uids=resources,
            confirmed_finding_ids=confirmed_ids,
            confirmed_rule_ids=rules,
            validation_record_id=validation_id,
            validation_evidence_ids=evidence_ids,
            required_inputs=self.REQUIRED_INPUTS,
            target_state="awaiting_approval",
            promotion_token=token,
        )

    def list(self, *, tenant_id: str) -> tuple[PromotionReadiness, ...]:
        return tuple(
            self.inspect(tenant_id=tenant_id, case_id=case.case_id)
            for case in self.case_store.list_cases(tenant_id=tenant_id)
        )

    def require(self, *, tenant_id: str, case_id: str,
                promotion_token: str) -> PromotionReadiness:
        readiness = self.inspect(tenant_id=tenant_id, case_id=case_id)
        if not readiness.eligible:
            raise ValueError(
                "case is not eligible for preapproval: "
                + "; ".join(readiness.blockers))
        if not isinstance(promotion_token, str) or not hmac.compare_digest(
                promotion_token, readiness.promotion_token):
            raise ValueError(
                "promotion token does not match the current validation boundary")
        return readiness
