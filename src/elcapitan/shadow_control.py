"""Read-only customer shadow-run control plane for AWS and Azure fleets."""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping, Sequence

from .asff import asff_to_ocsf
from .case_store import SqliteCaseStore
from .case_validation import CaseValidationService
from .cases import case_to_dict, event_to_dict
from .evidence import Collector
from .finding import cloud_target, normalise_ocsf, source_identity
from .finding_store import SqliteFindingStore
from .fleet import CapabilityRegistry, FleetSnapshotService, connector_readiness
from .intake import IntakeContext, RemediationIntake, priority_signals
from .product_records import SqliteProductRecordStore, product_record_to_dict
from .promotion import PromotionReadinessService
from .schema import validate_doc


MAX_FINDINGS_PER_BATCH = 1_000
MAX_CASES_PER_VALIDATION_BATCH = 100
SUPPORTED_SHADOW_PROVIDERS = frozenset({"aws", "azure"})


class ShadowControlError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class IntakeBatchOutcome:
    tenant_id: str
    received: int
    created_cases: int
    attached_findings: int
    duplicates: int
    case_ids: tuple[str, ...]
    fleet: Mapping

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "received": self.received,
            "created_cases": self.created_cases,
            "attached_findings": self.attached_findings,
            "duplicates": self.duplicates,
            "case_ids": list(self.case_ids),
            "fleet": dict(self.fleet),
        }


class ShadowFleetControlPlane:
    """No approval, scheduling, or execution endpoints exist on this boundary."""

    def __init__(self, root, *, host_env: Mapping[str, str] | None = None) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.database = self.root / "product.db"
        self.artifacts = self.root / "artifacts"
        self.host_env = dict(os.environ if host_env is None else host_env)
        self.registry = CapabilityRegistry()
        self.cases = SqliteCaseStore(self.database)
        self.findings = SqliteFindingStore(self.database)
        self.records = SqliteProductRecordStore(self.database)

    def _fleet(self) -> FleetSnapshotService:
        return FleetSnapshotService(
            case_store=self.cases,
            finding_store=self.findings,
            record_store=self.records,
        )

    def _promotions(self) -> PromotionReadinessService:
        return PromotionReadinessService(
            case_store=self.cases,
            finding_store=self.findings,
            record_store=self.records,
            registry=self.registry,
        )

    @staticmethod
    def _tenant(tenant_id: str) -> str:
        if not isinstance(tenant_id, str):
            raise ShadowControlError("tenant_id must be a string")
        value = tenant_id.strip()
        if not value or len(value) > 100:
            raise ShadowControlError("tenant_id must be 1 to 100 characters")
        return value

    @staticmethod
    def _validate_context(context: IntakeContext) -> None:
        for name in (
            "internet_exposed", "reachable", "known_exploited",
            "active_exploitation", "runtime_dependency",
        ):
            value = getattr(context, name)
            if name == "internet_exposed" and value is None:
                continue
            if not isinstance(value, bool):
                raise ShadowControlError(f"context.{name} must be a boolean")
        if len(context.service_ids) > 100 or any(
                not isinstance(item, str) or not item.strip() or len(item) > 200
                for item in context.service_ids):
            raise ShadowControlError(
                "context.service_ids must contain at most 100 non-empty strings")

    def intake(self, *, tenant_id: str, documents: Sequence[Mapping],
               context: IntakeContext = IntakeContext(),
               identity: str = "shadow-intake") -> IntakeBatchOutcome:
        tenant_id = self._tenant(tenant_id)
        if not isinstance(identity, str) or not identity.strip() or len(identity) > 200:
            raise ShadowControlError("intake identity must be 1 to 200 characters")
        self._validate_context(context)
        if not documents or len(documents) > MAX_FINDINGS_PER_BATCH:
            raise ShadowControlError(
                f"a batch must contain 1 to {MAX_FINDINGS_PER_BATCH} findings")

        normalized = []
        for index, raw in enumerate(documents):
            if not isinstance(raw, Mapping):
                raise ShadowControlError(f"finding {index + 1} is not a JSON object")
            document = dict(raw)
            if "SchemaVersion" in document:
                document = asff_to_ocsf(document)
            provider, resource_uid, _ = cloud_target(document)
            if provider not in SUPPORTED_SHADOW_PROVIDERS:
                raise ShadowControlError(
                    f"finding {index + 1} uses unsupported provider {provider!r}; "
                    "the entire batch was rejected before ingestion")
            if not resource_uid:
                raise ShadowControlError(
                    f"finding {index + 1} does not identify a cloud resource")
            try:
                source_identity(document)
            except ValueError as exc:
                raise ShadowControlError(f"finding {index + 1}: {exc}") from exc
            normalized.append(document)

        # Normalize and schema-check every finding in a disposable namespace
        # before durable intake begins. This preserves all-or-nothing behavior
        # for malformed batches without placing a broad transaction around
        # immutable evidence files and SQLite projections.
        collector = Collector("elcapitan-shadow-intake", "0.1.0", identity)
        with tempfile.TemporaryDirectory(
                prefix=".intake-preflight-", dir=self.root) as temporary:
            for index, document in enumerate(normalized):
                try:
                    record = normalise_ocsf(
                        document, run_dir=Path(temporary) / str(index),
                        finding_id=f"FIND-{index + 1000:04d}",
                        collector=collector, now=_now())
                    failures = validate_doc("finding-record", record)
                    if failures:
                        raise ValueError("; ".join(failures))
                    priority_signals(record, context)
                except (OSError, TypeError, ValueError) as exc:
                    raise ShadowControlError(
                        f"finding {index + 1} failed intake preflight: {exc}") from exc

        service = RemediationIntake(
            case_store=self.cases,
            finding_store=self.findings,
            artifact_root=self.artifacts,
            collector=collector,
            now=_now,
        )
        outcomes = [
            service.ingest(document, tenant_id=tenant_id, context=context)
            for document in normalized
        ]
        case_ids = tuple(dict.fromkeys(item.case.case_id for item in outcomes))
        return IntakeBatchOutcome(
            tenant_id=tenant_id,
            received=len(outcomes),
            created_cases=sum(item.case_created for item in outcomes),
            attached_findings=sum(item.finding_attached for item in outcomes),
            duplicates=sum(item.duplicate for item in outcomes),
            case_ids=case_ids,
            fleet=self.snapshot(tenant_id=tenant_id),
        )

    def snapshot(self, *, tenant_id: str) -> dict:
        tenant_id = self._tenant(tenant_id)
        document = self._fleet().snapshot(tenant_id=tenant_id).to_dict()
        promotions = {
            item.case_id: item for item in self._promotions().list(tenant_id=tenant_id)
        }
        document["summary"]["review_ready_cases"] = sum(
            item.eligible for item in promotions.values())
        for case in document["cases"]:
            readiness = promotions[case["case_id"]]
            case["promotion_status"] = readiness.status
            case["promotion_blockers"] = list(readiness.blockers)
        return document

    def promotion_manifest(self, *, tenant_id: str, case_id: str) -> dict:
        tenant_id = self._tenant(tenant_id)
        return self._promotions().inspect(
            tenant_id=tenant_id, case_id=case_id).to_dict()

    def connector_status(self) -> dict:
        return {
            provider: connector_readiness(provider, host_env=self.host_env).to_dict()
            for provider in sorted(SUPPORTED_SHADOW_PROVIDERS)
        }

    def _validation_provider(self, *, tenant_id: str, case_id: str) -> str:
        tenant_id = self._tenant(tenant_id)
        case = self.cases.get(case_id)
        if case.tenant_id != tenant_id:
            raise ShadowControlError("case does not belong to the requested tenant")
        if case.state.value != "prioritized":
            raise ShadowControlError(
                f"case {case_id} is {case.state.value}, not awaiting validation")
        findings = self.findings.list_for_case(case_id)
        providers = {item.provider for item in findings}
        if len(providers) != 1:
            raise ShadowControlError("a validation case must contain exactly one provider")
        provider = next(iter(providers))
        unsupported = sorted({
            str(item.record["ocsf"].get("rule_id", ""))
            for item in findings
            if not (capability := self.registry.get(
                item.provider, str(item.record["ocsf"].get("rule_id", ""))))
            or not capability.live_validation
        })
        if unsupported:
            raise ShadowControlError(
                "case contains controls without deterministic live validation: "
                + ", ".join(unsupported))
        readiness = connector_readiness(
            provider, host_env=self.host_env, registry=self.registry)
        if not readiness.ready_for_live_validation:
            missing = ", ".join(readiness.missing_environment) or readiness.executable
            raise ShadowControlError(
                f"{provider} connector is not ready for live validation: {missing}")
        return provider

    def validate(self, *, tenant_id: str, case_id: str) -> dict:
        self._validation_provider(tenant_id=tenant_id, case_id=case_id)
        outcome = CaseValidationService(
            case_store=self.cases,
            finding_store=self.findings,
            record_store=self.records,
            artifact_root=self.artifacts,
            now=_now,
        ).validate(case_id, host_env=self.host_env)
        return {
            "case": case_to_dict(outcome.case),
            "validation": product_record_to_dict(outcome.record),
            "findings": [item.to_dict() for item in outcome.findings],
            "fleet": self.snapshot(tenant_id=tenant_id),
        }

    def validate_batch(self, *, tenant_id: str,
                       case_ids: Sequence[str]) -> dict:
        tenant_id = self._tenant(tenant_id)
        if any(not isinstance(item, str) for item in case_ids):
            raise ShadowControlError("validation case ids must be strings")
        unique = tuple(dict.fromkeys(item.strip() for item in case_ids))
        if not unique or len(unique) > MAX_CASES_PER_VALIDATION_BATCH:
            raise ShadowControlError(
                f"a validation batch must contain 1 to "
                f"{MAX_CASES_PER_VALIDATION_BATCH} unique cases")
        if any(not case_id for case_id in unique):
            raise ShadowControlError("validation case ids must be non-empty strings")
        # Resolve ownership, state, capability, and connector prerequisites for
        # the whole batch before making the first customer cloud request.
        for case_id in unique:
            self._validation_provider(tenant_id=tenant_id, case_id=case_id)
        outcomes = []
        for case_id in unique:
            result = self.validate(tenant_id=tenant_id, case_id=case_id)
            outcomes.append({
                "case_id": case_id,
                "state": result["case"]["state"],
                "findings": result["findings"],
                "validation_record_id": result["validation"]["record_id"],
            })
        return {
            "tenant_id": tenant_id,
            "requested": len(unique),
            "processed": len(outcomes),
            "outcomes": outcomes,
            "fleet": self.snapshot(tenant_id=tenant_id),
        }

    def case_detail(self, *, tenant_id: str, case_id: str) -> dict:
        tenant_id = self._tenant(tenant_id)
        case = self.cases.get(case_id)
        if case.tenant_id != tenant_id:
            raise ShadowControlError("case does not belong to the requested tenant")
        findings = self.findings.list_for_case(case_id)
        return {
            "case": case_to_dict(case),
            "findings": [{
                "finding_id": item.finding_id,
                "provider": item.provider,
                "account": item.account,
                "resource_uid": item.resource_uid,
                "record": dict(item.record),
            } for item in findings],
            "events": [event_to_dict(item) for item in self.cases.events(case_id)],
            "records": [
                product_record_to_dict(item)
                for item in self.records.list_for_case(case_id)
            ],
            "promotion": self.promotion_manifest(
                tenant_id=tenant_id, case_id=case_id),
            "safety_boundary": {
                "mode": "shadow",
                "approval": False,
                "scheduling": False,
                "execution": False,
                "external_models": False,
            },
        }
