"""Tenant-aware fleet inventory and fail-closed provider capability contracts."""
from __future__ import annotations

import os
import shutil
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Mapping

from .cases import RemediationCase
from .constants import (
    AZURE_MANAGED_IDENTITY_AUTH_MODE,
    AZURE_SCANNER_MANAGED_IDENTITY_CLIENT_ID,
    scanner_env_map,
)
from .finding_store import FindingStore, StoredFinding
from .portfolio import PortfolioItem, PortfolioService
from .product_records import ProductRecordStore
from .workflow import CaseStore


@dataclass(frozen=True)
class ControlCapability:
    provider: str
    rule_id: str
    resource_family: str
    live_validation: bool
    remediation_planning: bool
    live_execution: bool
    evidence_aspects: tuple[str, ...]

    def to_dict(self) -> dict:
        value = asdict(self)
        value["evidence_aspects"] = list(self.evidence_aspects)
        return value


_CAPABILITIES = (
    ControlCapability(
        "aws", "s3_bucket_object_versioning", "s3_bucket",
        True, True, False, ("versioning",),
    ),
    ControlCapability(
        "azure", "storage_account_public_network_access_disabled", "storage_account",
        True, True, True,
        ("public_network_access", "network_rule_set", "private_endpoint_connections"),
    ),
    ControlCapability(
        "azure", "storage_blob_public_access_level_is_disabled", "storage_account",
        True, True, True, ("allow_blob_public_access",),
    ),
    ControlCapability(
        "azure", "storage_blob_versioning_is_enabled", "storage_account",
        True, True, False, ("blob_versioning",),
    ),
)


class CapabilityRegistry:
    def __init__(self, capabilities: tuple[ControlCapability, ...] = _CAPABILITIES) -> None:
        self._capabilities = tuple(capabilities)
        self._by_key = {
            (item.provider, item.rule_id): item for item in self._capabilities
        }
        if len(self._by_key) != len(self._capabilities):
            raise ValueError("provider capabilities must be unique by provider and rule")

    def get(self, provider: str, rule_id: str) -> ControlCapability | None:
        return self._by_key.get((provider.lower(), rule_id))

    def list(self, *, provider: str | None = None) -> tuple[ControlCapability, ...]:
        selected = (
            item for item in self._capabilities
            if provider is None or item.provider == provider.lower()
        )
        return tuple(sorted(selected, key=lambda item: (item.provider, item.rule_id)))


@dataclass(frozen=True)
class ConnectorReadiness:
    provider: str
    ready_for_live_validation: bool
    executable: str
    executable_available: bool
    required_environment: tuple[str, ...]
    missing_environment: tuple[str, ...]
    configuration_errors: tuple[str, ...]
    supported_rule_ids: tuple[str, ...]
    prohibitions: tuple[str, ...]

    def to_dict(self) -> dict:
        value = asdict(self)
        for name in (
            "required_environment", "missing_environment", "configuration_errors",
            "supported_rule_ids", "prohibitions",
        ):
            value[name] = list(value[name])
        return value


def connector_readiness(provider: str, *, host_env: Mapping[str, str] | None = None,
                        which=shutil.which,
                        registry: CapabilityRegistry | None = None
                        ) -> ConnectorReadiness:
    """Check local prerequisites without authenticating or querying customer cloud state."""
    provider = provider.lower()
    environment = dict(os.environ if host_env is None else host_env)
    managed_identity = (
        provider == "azure"
        and bool(environment.get(AZURE_SCANNER_MANAGED_IDENTITY_CLIENT_ID)))
    if managed_identity:
        executable = "azure-arm-rest"
        available = True
        required = (
            AZURE_SCANNER_MANAGED_IDENTITY_CLIENT_ID,
            "IDENTITY_ENDPOINT",
            "IDENTITY_HEADER",
        )
        missing = tuple(name for name in required if not environment.get(name))
        conflicting = tuple(sorted(
            name for name in scanner_env_map("azure") if environment.get(name)))
        configuration_errors = (() if not conflicting else (
            "managed identity cannot be combined with " + ", ".join(conflicting),))
    else:
        mapping = scanner_env_map(provider)
        executable = {"aws": "aws", "azure": "az"}.get(provider, "")
        try:
            resolved = (
                which(executable, path=environment.get("PATH")) if executable else None)
        except TypeError:
            # Small injected test resolvers may intentionally accept only the name.
            resolved = which(executable) if executable else None
        available = bool(resolved)
        required = tuple(sorted(mapping))
        missing = tuple(
            sorted(name for name in mapping if not environment.get(name)))
        configuration_errors = ()
    capabilities = (registry or CapabilityRegistry()).list(provider=provider)
    return ConnectorReadiness(
        provider=provider,
        ready_for_live_validation=(
            available and not missing and not configuration_errors
            and bool(capabilities)),
        executable=executable,
        executable_available=available,
        required_environment=required,
        missing_environment=missing,
        configuration_errors=configuration_errors,
        supported_rule_ids=tuple(item.rule_id for item in capabilities if item.live_validation),
        prohibitions=(
            "no mutation credentials are accepted by the scanner connector",
            (f"Azure managed identity mode is {AZURE_MANAGED_IDENTITY_AUTH_MODE}"
             if managed_identity else "ambient cloud sessions are ignored"),
            "unsupported controls remain unverified",
            "connector preflight performs no cloud API request",
        ),
    )


@dataclass(frozen=True)
class ShadowModePolicy:
    allow_live_validation: bool = True
    allow_external_models: bool = False
    allow_approval: bool = False
    allow_scheduling: bool = False
    allow_execution: bool = False

    def __post_init__(self) -> None:
        if self.allow_execution or self.allow_scheduling or self.allow_approval:
            raise ValueError(
                "shadow mode cannot approve, schedule, or execute infrastructure changes")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FleetCase:
    case_id: str
    state: str
    risk_score: float
    urgency: str
    provider: str
    account: str
    resource_uids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    finding_titles: tuple[str, ...]
    rule_ids: tuple[str, ...]
    supported_findings: int
    unsupported_findings: int
    validation_counts: Mapping[str, int]
    service_ids: tuple[str, ...]
    portfolio_rank: int | None
    effective_priority: float
    scheduling_status: str
    scheduling_reasons: tuple[str, ...]
    window_start: str
    window_end: str
    updated_at: str

    def to_dict(self) -> dict:
        value = asdict(self)
        for name in (
            "resource_uids", "finding_ids", "finding_titles", "rule_ids", "service_ids",
            "scheduling_reasons",
        ):
            value[name] = list(value[name])
        value["validation_counts"] = dict(self.validation_counts)
        return value


@dataclass(frozen=True)
class FleetSnapshot:
    tenant_id: str
    cases: tuple[FleetCase, ...]
    case_state_counts: Mapping[str, int]
    provider_counts: Mapping[str, int]
    total_findings: int
    supported_findings: int
    unsupported_findings: int
    shadow_policy: ShadowModePolicy

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "summary": {
                "total_cases": len(self.cases),
                "total_findings": self.total_findings,
                "supported_findings": self.supported_findings,
                "unsupported_findings": self.unsupported_findings,
                "case_state_counts": dict(self.case_state_counts),
                "provider_counts": dict(self.provider_counts),
            },
            "shadow_policy": self.shadow_policy.to_dict(),
            "cases": [case.to_dict() for case in self.cases],
        }


class FleetSnapshotService:
    def __init__(self, *, case_store: CaseStore, finding_store: FindingStore,
                 record_store: ProductRecordStore,
                 registry: CapabilityRegistry | None = None,
                 shadow_policy: ShadowModePolicy = ShadowModePolicy()) -> None:
        self.case_store = case_store
        self.finding_store = finding_store
        self.record_store = record_store
        self.registry = registry or CapabilityRegistry()
        self.shadow_policy = shadow_policy

    def _case(self, case: RemediationCase,
              portfolio: PortfolioItem | None) -> FleetCase:
        findings = self.finding_store.list_for_case(case.case_id)
        supported = sum(
            self.registry.get(finding.provider, self._rule(finding)) is not None
            for finding in findings
        )
        validation_counts: Counter[str] = Counter()
        validation_records = self.record_store.list_for_case(
            case.case_id, record_type="ValidationResult.v1")
        if validation_records:
            for item in validation_records[-1].body.get("findings", ()):
                validation_counts[str(item.get("status", "unknown"))] += 1
        provider = findings[0].provider if findings else ""
        account = findings[0].account if findings else ""
        priority = case.priority
        return FleetCase(
            case_id=case.case_id,
            state=case.state.value,
            risk_score=priority.score if priority else 0,
            urgency=priority.urgency if priority else "unassessed",
            provider=provider,
            account=account,
            resource_uids=tuple(dict.fromkeys(item.resource_uid for item in findings)),
            finding_ids=tuple(item.finding_id for item in findings),
            finding_titles=tuple(
                str(item.record["ocsf"].get("title", "")) for item in findings),
            rule_ids=tuple(dict.fromkeys(self._rule(item) for item in findings)),
            supported_findings=supported,
            unsupported_findings=len(findings) - supported,
            validation_counts=dict(sorted(validation_counts.items())),
            service_ids=case.service_ids,
            portfolio_rank=portfolio.rank if portfolio else None,
            effective_priority=(portfolio.effective_priority if portfolio
                                else (priority.score if priority else 0)),
            scheduling_status=(portfolio.scheduling_status if portfolio
                               else self._pre_portfolio_status(case)),
            scheduling_reasons=(portfolio.reasons if portfolio else
                                self._pre_portfolio_reasons(case)),
            window_start=portfolio.window_start if portfolio else "",
            window_end=portfolio.window_end if portfolio else "",
            updated_at=case.updated_at,
        )

    @staticmethod
    def _pre_portfolio_status(case: RemediationCase) -> str:
        return {
            "open": "awaiting_priority",
            "prioritized": "awaiting_validation",
            "blocked": "blocked",
            "closed_no_action": "no_action",
            "remediated": "completed",
            "rolled_back": "rolled_back",
        }.get(case.state.value, "not_schedulable")

    @classmethod
    def _pre_portfolio_reasons(cls, case: RemediationCase) -> tuple[str, ...]:
        status = cls._pre_portfolio_status(case)
        return ({
            "awaiting_priority": "finding has not completed deterministic prioritization",
            "awaiting_validation": "live cloud state has not yet validated this case",
            "blocked": "case is blocked by incomplete or unavailable evidence",
            "no_action": "live state did not confirm the reported vulnerability",
            "completed": "remediation has completed",
            "rolled_back": "change was rolled back",
        }.get(status, "case is outside the active scheduling portfolio"),)

    @staticmethod
    def _rule(finding: StoredFinding) -> str:
        return str(finding.record["ocsf"].get("rule_id", ""))

    def snapshot(self, *, tenant_id: str) -> FleetSnapshot:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        portfolio = {
            item.case_id: item for item in PortfolioService(
                case_store=self.case_store).queue(tenant_id=tenant_id)
        }
        cases = [
            self._case(case, portfolio.get(case.case_id))
            for case in self.case_store.list_cases(tenant_id=tenant_id)
        ]
        cases.sort(key=lambda item: (-item.risk_score, item.updated_at, item.case_id))
        return FleetSnapshot(
            tenant_id=tenant_id,
            cases=tuple(cases),
            case_state_counts=dict(sorted(Counter(item.state for item in cases).items())),
            provider_counts=dict(sorted(Counter(item.provider for item in cases).items())),
            total_findings=sum(len(item.finding_ids) for item in cases),
            supported_findings=sum(item.supported_findings for item in cases),
            unsupported_findings=sum(item.unsupported_findings for item in cases),
            shadow_policy=self.shadow_policy,
        )
