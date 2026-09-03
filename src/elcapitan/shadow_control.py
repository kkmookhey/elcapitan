"""Read-only customer shadow-run control plane for AWS and Azure fleets."""
from __future__ import annotations

import os
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .asset_context import AssetContext, asset_key, parse_asset_contexts
from .asff import asff_to_ocsf
from .case_store import SqliteCaseStore
from .case_validation import CaseValidationService
from .cases import case_to_dict, event_to_dict
from .evidence import Collector
from .finding import (
    cloud_target,
    finding_rule_id,
    normalise_ocsf,
    prowler_outcome,
    source_identity,
)
from .finding_store import SqliteFindingStore
from .fleet import CapabilityRegistry, FleetSnapshotService, connector_readiness
from .intake import IntakeContext, RemediationIntake, priority_signals
from .postgres_store import (
    PostgresArtifactStore,
    PostgresCaseStore,
    PostgresFindingStore,
    PostgresProductRecordStore,
)
from .priority import assess_priority
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
    submitted: int
    received: int
    skipped_pass: int
    skipped_manual: int
    created_cases: int
    attached_findings: int
    duplicates: int
    case_ids: tuple[str, ...]
    fleet: Mapping

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "submitted": self.submitted,
            "received": self.received,
            "accepted_failures": self.received,
            "skipped": {
                "pass": self.skipped_pass,
                "manual": self.skipped_manual,
            },
            "created_cases": self.created_cases,
            "attached_findings": self.attached_findings,
            "duplicates": self.duplicates,
            "case_ids": list(self.case_ids),
            "fleet": dict(self.fleet),
        }


@dataclass(frozen=True)
class IntakeBatchPreview:
    submitted: int
    accepted_failures: int
    skipped_pass: int
    skipped_manual: int
    provider_counts: Mapping[str, int]
    format_counts: Mapping[str, int]
    resource_count: int
    account_count: int
    supported_findings: int
    unsupported_findings: int
    supported_controls: tuple[str, ...]
    unsupported_controls: tuple[str, ...]
    asset_context_rows: int
    matched_asset_rows: int
    unmatched_asset_rows: int
    matched_resources: int
    unmatched_resources: int
    contextualized_findings: int
    internet_exposed_resources: int
    critical_resources: int
    synthetic_context_resources: int

    def to_dict(self) -> dict:
        return {
            "submitted": self.submitted,
            "accepted_failures": self.accepted_failures,
            "skipped": {
                "pass": self.skipped_pass,
                "manual": self.skipped_manual,
            },
            "provider_counts": dict(self.provider_counts),
            "format_counts": dict(self.format_counts),
            "resource_count": self.resource_count,
            "account_count": self.account_count,
            "supported_findings": self.supported_findings,
            "unsupported_findings": self.unsupported_findings,
            "supported_controls": list(self.supported_controls),
            "unsupported_controls": list(self.unsupported_controls),
            "asset_context": {
                "rows": self.asset_context_rows,
                "matched_rows": self.matched_asset_rows,
                "unmatched_rows": self.unmatched_asset_rows,
                "matched_resources": self.matched_resources,
                "unmatched_resources": self.unmatched_resources,
                "contextualized_findings": self.contextualized_findings,
                "internet_exposed_resources": self.internet_exposed_resources,
                "critical_resources": self.critical_resources,
                "synthetic_context_resources": self.synthetic_context_resources,
            },
            "safety_boundary": {
                "persistent_writes": False,
                "cloud_requests": False,
                "external_models": False,
                "execution": False,
            },
        }


@dataclass(frozen=True)
class _PreparedIntake:
    entries: tuple["_PreparedFinding", ...]
    preview: IntakeBatchPreview


@dataclass(frozen=True)
class _PreparedFinding:
    document: Mapping
    context: IntakeContext
    asset_context: AssetContext | None


class ShadowFleetControlPlane:
    """No approval, scheduling, or execution endpoints exist on this boundary."""

    def __init__(self, root, *, host_env: Mapping[str, str] | None = None,
                 database_url: str | None = None) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.host_env = dict(os.environ if host_env is None else host_env)
        self.registry = CapabilityRegistry()
        selected_database_url = (
            database_url if database_url is not None
            else self.host_env.get("ELCAPITAN_DATABASE_URL", ""))
        if selected_database_url:
            self.database = "postgresql"
            self.cases = PostgresCaseStore(selected_database_url)
            self.findings = PostgresFindingStore(selected_database_url)
            self.records = PostgresProductRecordStore(selected_database_url)
            self.artifact_store = PostgresArtifactStore(selected_database_url)
            self.artifact_store.hydrate(self.artifacts)
        else:
            self.database = self.root / "product.db"
            self.cases = SqliteCaseStore(self.database)
            self.findings = SqliteFindingStore(self.database)
            self.records = SqliteProductRecordStore(self.database)
            self.artifact_store = None

    def _sync_artifacts(self) -> None:
        if self.artifact_store is not None:
            self.artifact_store.sync(self.artifacts)

    def health(self) -> dict:
        # Executes an actual state-store query; a process-only health response
        # could otherwise route traffic while PostgreSQL is unavailable.
        self.cases.list_cases(tenant_id="__elcapitan_health__")
        return {
            "status": "ok",
            "state_store": "postgresql" if self.database == "postgresql" else "sqlite",
            "artifact_store": "postgresql" if self.artifact_store else "filesystem",
            "durable_artifacts": (
                self.artifact_store.count() if self.artifact_store else None),
            "artifact_root_writable": os.access(self.artifacts, os.W_OK),
        }

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

    def _prepare_intake(
            self, documents: Sequence[Mapping], *, context: IntakeContext,
            identity: str,
            asset_contexts: Sequence[Mapping] | None = None) -> _PreparedIntake:
        self._validate_context(context)
        try:
            assets = parse_asset_contexts(asset_contexts)
        except ValueError as exc:
            raise ShadowControlError(str(exc)) from exc
        if not documents or len(documents) > MAX_FINDINGS_PER_BATCH:
            raise ShadowControlError(
                f"a batch must contain 1 to {MAX_FINDINGS_PER_BATCH} findings")

        normalized: list[_PreparedFinding] = []
        skipped = Counter()
        format_counts = Counter()
        provider_counts = Counter()
        resources = set()
        accounts = set()
        supported_controls = set()
        unsupported_controls = set()
        supported_findings = 0
        for index, raw in enumerate(documents):
            if not isinstance(raw, Mapping):
                raise ShadowControlError(f"finding {index + 1} is not a JSON object")
            document = dict(raw)
            source_format = (
                "AWS Security Hub ASFF" if "SchemaVersion" in document else "OCSF")
            format_counts[source_format] += 1
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
                outcome = prowler_outcome(document)
                source_identity(document)
            except ValueError as exc:
                raise ShadowControlError(f"finding {index + 1}: {exc}") from exc
            if outcome in {"PASS", "MANUAL"}:
                skipped[outcome] += 1
                continue

            cloud = document.get("cloud") or {}
            account = (cloud.get("account") or {}).get("uid", "")
            primary = (document.get("resources") or [{}])[0]
            resource_type = (
                str(primary.get("type", ""))
                if isinstance(primary, Mapping) else "")
            rule_id = finding_rule_id(document)
            provider_counts[provider] += 1
            resources.add((provider, account, resource_uid))
            accounts.add((provider, account))
            asset = assets.get(asset_key(resource_uid))
            normalized.append(_PreparedFinding(
                document=document,
                context=(asset.intake_context(context) if asset else context),
                asset_context=asset,
            ))
            capability = self.registry.get(provider, rule_id, resource_type)
            if capability is not None and capability.live_validation:
                supported_findings += 1
                supported_controls.add(rule_id)
            else:
                unsupported_controls.add(rule_id or "Unidentified control")

        # Normalize and schema-check every finding in a disposable namespace
        # before either preview or durable intake. This gives preview and
        # import one fail-closed contract without retaining source evidence.
        collector = Collector("elcapitan-shadow-intake", "0.1.0", identity)
        with tempfile.TemporaryDirectory(
                prefix=".intake-preflight-", dir=self.root) as temporary:
            for index, entry in enumerate(normalized):
                try:
                    record = normalise_ocsf(
                        entry.document, run_dir=Path(temporary) / str(index),
                        finding_id=f"FIND-{index + 1000:04d}",
                        collector=collector, now=_now())
                    failures = validate_doc("finding-record", record)
                    if failures:
                        raise ValueError("; ".join(failures))
                    priority_signals(record, entry.context)
                except (OSError, TypeError, ValueError) as exc:
                    raise ShadowControlError(
                        f"finding {index + 1} failed intake preflight: {exc}") from exc

        resource_keys = {asset_key(resource_uid) for _, _, resource_uid in resources}
        matched_keys = resource_keys & set(assets)
        preview = IntakeBatchPreview(
            submitted=len(documents),
            accepted_failures=len(normalized),
            skipped_pass=skipped["PASS"],
            skipped_manual=skipped["MANUAL"],
            provider_counts=dict(sorted(provider_counts.items())),
            format_counts=dict(sorted(format_counts.items())),
            resource_count=len(resources),
            account_count=len(accounts),
            supported_findings=supported_findings,
            unsupported_findings=len(normalized) - supported_findings,
            supported_controls=tuple(sorted(supported_controls)),
            unsupported_controls=tuple(sorted(unsupported_controls)),
            asset_context_rows=len(assets),
            matched_asset_rows=len(matched_keys),
            unmatched_asset_rows=len(set(assets) - resource_keys),
            matched_resources=len(matched_keys),
            unmatched_resources=len(resource_keys - set(assets)),
            contextualized_findings=sum(
                entry.asset_context is not None for entry in normalized),
            internet_exposed_resources=sum(
                assets[key].internet_exposed is True for key in matched_keys),
            critical_resources=sum(
                assets[key].asset_criticality >= .8 for key in matched_keys),
            synthetic_context_resources=sum(
                assets[key].synthetic_business_context for key in matched_keys),
        )
        return _PreparedIntake(tuple(normalized), preview)

    def preview_intake(
            self, *, documents: Sequence[Mapping],
            context: IntakeContext | None = None,
            asset_contexts: Sequence[Mapping] | None = None) -> IntakeBatchPreview:
        """Validate and summarize an intake batch without retaining it."""
        return self._prepare_intake(
            documents, context=context or IntakeContext(),
            identity="shadow-intake-preview",
            asset_contexts=asset_contexts).preview

    def intake(self, *, tenant_id: str, documents: Sequence[Mapping],
               context: IntakeContext = IntakeContext(),
               identity: str = "shadow-intake",
               asset_contexts: Sequence[Mapping] | None = None) -> IntakeBatchOutcome:
        tenant_id = self._tenant(tenant_id)
        if not isinstance(identity, str) or not identity.strip() or len(identity) > 200:
            raise ShadowControlError("intake identity must be 1 to 200 characters")
        prepared = self._prepare_intake(
            documents, context=context, identity=identity,
            asset_contexts=asset_contexts)
        skipped = prepared.preview

        collector = Collector("elcapitan-shadow-intake", "0.1.0", identity)

        service = RemediationIntake(
            case_store=self.cases,
            finding_store=self.findings,
            artifact_root=self.artifacts,
            collector=collector,
            now=_now,
        )
        outcomes = [
            service.ingest(
                entry.document, tenant_id=tenant_id, context=entry.context,
                asset_context=(entry.asset_context.to_dict()
                               if entry.asset_context else None))
            for entry in prepared.entries
        ]
        self._sync_artifacts()
        case_ids = tuple(dict.fromkeys(item.case.case_id for item in outcomes))
        return IntakeBatchOutcome(
            tenant_id=tenant_id,
            submitted=len(documents),
            received=len(outcomes),
            skipped_pass=skipped.skipped_pass,
            skipped_manual=skipped.skipped_manual,
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
            item.status == "ready_for_preapproval" for item in promotions.values())
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
        supported = [
            item for item in findings
            if (capability := self.registry.get(
                item.provider, str(item.record["ocsf"].get("rule_id", "")),
                str(item.record.get("resource", {}).get("type", ""))))
            and capability.live_validation
        ]
        if not supported:
            unsupported = sorted({
                str(item.record["ocsf"].get("rule_id", ""))
                for item in findings
            })
            raise ShadowControlError(
                "case contains no controls with deterministic live validation: "
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
        self._sync_artifacts()
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
        findings = sorted(
            self.findings.list_for_case(case_id),
            key=lambda item: (
                -assess_priority("RISK-DETAIL", item.priority_signals).score,
                item.finding_id,
            ),
        )
        finding_documents = []
        for item in findings:
            assessment = assess_priority("RISK-DETAIL", item.priority_signals)
            finding_documents.append({
                "finding_id": item.finding_id,
                "provider": item.provider,
                "account": item.account,
                "resource_uid": item.resource_uid,
                "record": dict(item.record),
                "priority": {
                    "score": assessment.score,
                    "urgency": assessment.urgency,
                    "factors": list(assessment.factors),
                    "confidence": assessment.confidence,
                },
            })
        return {
            "case": case_to_dict(case),
            "findings": finding_documents,
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
