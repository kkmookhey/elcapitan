"""Human decision plane for exact, evidence-bound remediation packages."""
from __future__ import annotations

import difflib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping

from .action_plane import (
    ActionPlaneError, ApprovalService, RejectionService, VerifiedApproval,
    VerifiedRejection,
)
from .case_store import SqliteCaseStore
from .cases import CaseState, case_to_dict, event_to_dict
from .finding_store import SqliteFindingStore
from .hashing import canonical_json, sha256_bytes, sha256_file
from .intake import numeric_id
from .observability import parse_timestamp
from .paths import PathEscape, safe_resolve
from .postgres_store import (
    PostgresArtifactStore, PostgresCaseStore, PostgresExecutionJobStore,
    PostgresFindingStore, PostgresProductRecordStore,
)
from .product_records import (
    ProductRecord, SqliteProductRecordStore, product_record_to_dict,
)
from .scheduler import ExecutionScheduler, SqliteExecutionJobStore


CURRENT_PACKAGE_RECORDS = (
    ("validation_result_id", "ValidationResult.v1", "Live validation"),
    ("iac_link_id", "IaCLink.v1", "IaC target"),
    ("change_plan_id", "RemediationPlan.v1", "Remediation plan"),
    ("sre_review_id", "SREReview.v1", "SRE review"),
    ("change_window_id", "ChangeWindowRecommendation.v1", "Change window"),
    ("rollback_review_id", "RollbackReview.v1", "Rollback review"),
    ("policy_decision_id", "PolicyDecision.v1", "Policy gate"),
    ("human_review_package_id", "HumanReviewPackage.v1", "Human decision"),
)
DECISION_STATES = frozenset({
    CaseState.AWAITING_APPROVAL, CaseState.APPROVED, CaseState.REJECTED,
})


class ReviewControlError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ReviewControlPlane:
    """Expose review and decision operations without any execution capability."""

    def __init__(self, root, *, host_env: Mapping[str, str] | None = None,
                 database_url: str | None = None) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        environment = dict(os.environ if host_env is None else host_env)
        selected_database_url = (
            database_url if database_url is not None
            else environment.get("ELCAPITAN_DATABASE_URL", ""))
        if selected_database_url:
            self.database = "postgresql"
            self.cases = PostgresCaseStore(selected_database_url)
            self.findings = PostgresFindingStore(selected_database_url)
            self.records = PostgresProductRecordStore(selected_database_url)
            self.jobs = PostgresExecutionJobStore(selected_database_url)
            self.artifact_store = PostgresArtifactStore(selected_database_url)
            self.artifact_store.hydrate(self.artifacts)
        else:
            database = self.root / "product.db"
            self.database = database
            self.cases = SqliteCaseStore(database)
            self.findings = SqliteFindingStore(database)
            self.records = SqliteProductRecordStore(database)
            self.jobs = SqliteExecutionJobStore(database)
            self.artifact_store = None

    @staticmethod
    def _text(value, name: str, *, minimum: int = 1, maximum: int = 200) -> str:
        if not isinstance(value, str):
            raise ReviewControlError(f"{name} must be a string")
        result = value.strip()
        if not minimum <= len(result) <= maximum:
            raise ReviewControlError(
                f"{name} must be between {minimum} and {maximum} characters")
        return result

    def _tenant(self, tenant_id: str) -> str:
        return self._text(tenant_id, "tenant_id", maximum=100)

    def _case(self, *, tenant_id: str, case_id: str):
        tenant_id = self._tenant(tenant_id)
        case_id = self._text(case_id, "case_id", maximum=100)
        case = self.cases.get(case_id)
        if case.tenant_id != tenant_id:
            raise ReviewControlError("case does not belong to the requested tenant")
        if case.state not in DECISION_STATES:
            raise ReviewControlError(
                f"case {case_id} is {case.state.value}, not in the human decision plane")
        if not case.record_ids.get("human_review_package_id"):
            raise ReviewControlError(
                f"case {case_id} has no human-review package")
        return case

    def _record(self, case, key: str, expected_type: str) -> ProductRecord:
        record_id = case.record_ids.get(key)
        if not record_id:
            raise ReviewControlError(f"case is missing authoritative {key}")
        record = self.records.get(record_id)
        if record.case_id != case.case_id or record.record_type != expected_type:
            raise ReviewControlError(f"case {key} has the wrong owner or type")
        return record

    def _current_records(self, case) -> list[dict]:
        result = []
        for key, record_type, stage in CURRENT_PACKAGE_RECORDS:
            record = self._record(case, key, record_type)
            result.append({"stage": stage, **product_record_to_dict(record)})
        return result

    def _package_binding(self, case) -> tuple[ProductRecord, str]:
        package = self._record(
            case, "human_review_package_id", "HumanReviewPackage.v1")
        body = product_record_to_dict(package)["body"]
        return package, sha256_bytes(canonical_json(body))

    def _change_diff(self, case) -> dict:
        plan = self._record(case, "change_plan_id", "RemediationPlan.v1")
        link = self._record(case, "iac_link_id", "IaCLink.v1")
        change = plan.body.get("change", {})
        source_path = str(change.get("source_path", ""))
        namespace = str(plan.body.get("artifact_namespace", ""))
        result = {
            "source_path": source_path,
            "before_sha256": change.get("before_sha256", ""),
            "after_sha256": change.get("after_sha256", ""),
            "verified": False,
            "unified_diff": "",
        }
        if not source_path or not namespace or not link.evidence_ids:
            return result
        try:
            run_dir = safe_resolve(self.artifacts, namespace)
            original = safe_resolve(
                run_dir, f"evidence/{link.evidence_ids[0]}.bin")
            replacement = safe_resolve(run_dir, f"workspace/{source_path}")
            if not original.is_file() or not replacement.is_file():
                return result
            verified = (
                sha256_file(original) == change.get("before_sha256") and
                sha256_file(replacement) == change.get("after_sha256")
            )
            result["verified"] = verified
            if not verified:
                return result
            before = original.read_text(encoding="utf-8")
            after = replacement.read_text(encoding="utf-8")
            diff = "".join(difflib.unified_diff(
                before.splitlines(keepends=True), after.splitlines(keepends=True),
                fromfile=f"source/{source_path}",
                tofile=f"verified-workspace/{source_path}",
            ))
            result["unified_diff"] = diff[:262_144]
            return result
        except (OSError, UnicodeError, PathEscape, FileNotFoundError):
            return result

    def _sync_artifacts(self) -> None:
        if self.artifact_store is not None:
            self.artifact_store.sync(self.artifacts)

    def health(self) -> dict:
        self.cases.list_cases(tenant_id="__elcapitan_review_health__")
        return {
            "status": "ok",
            "mode": "human-decision-only",
            "state_store": "postgresql" if self.database == "postgresql" else "sqlite",
            "execution_route": False,
        }

    def queue(self, *, tenant_id: str) -> dict:
        tenant_id = self._tenant(tenant_id)
        cases = [
            case for case in self.cases.list_cases(tenant_id=tenant_id)
            if case.state in DECISION_STATES
            and case.record_ids.get("human_review_package_id")
        ]
        items = []
        for case in sorted(
                cases, key=lambda value: (value.priority.score if value.priority else 0),
                reverse=True):
            findings = self.findings.list_for_case(case.case_id)
            package_id = case.record_ids.get("human_review_package_id", "")
            items.append({
                "case_id": case.case_id,
                "state": case.state.value,
                "risk_score": case.priority.score if case.priority else 0,
                "urgency": case.priority.urgency if case.priority else "unassessed",
                "resource_uid": findings[0].resource_uid if findings else "",
                "provider": findings[0].provider if findings else "",
                "finding_count": len(case.finding_ids),
                "review_package_id": package_id,
                "window": ({
                    "starts_at": case.change_window.starts_at,
                    "ends_at": case.change_window.ends_at,
                    "timezone": case.change_window.timezone,
                } if case.change_window else None),
            })
        return {"tenant_id": tenant_id, "cases": items,
                "awaiting_decision": sum(item["state"] == "awaiting_approval"
                                         for item in items)}

    def detail(self, *, tenant_id: str, case_id: str) -> dict:
        case = self._case(tenant_id=tenant_id, case_id=case_id)
        package, binding = self._package_binding(case)
        findings = self.findings.list_for_case(case.case_id)
        all_records = self.records.list_for_case(case.case_id)
        current_ids = {record["record_id"] for record in self._current_records(case)}
        decision_records = [
            product_record_to_dict(record) for record in all_records
            if record.record_type in {"ChangeApproval.v1", "ChangeRejection.v1",
                                      "ExecutionSchedule.v1"}
        ]
        return {
            "case": case_to_dict(case),
            "findings": [{
                "finding_id": finding.finding_id,
                "provider": finding.provider,
                "resource_uid": finding.resource_uid,
                "account": finding.account,
                "rule_id": finding.record.get("ocsf", {}).get("rule_id", ""),
                "severity": finding.record.get("severity", ""),
            } for finding in findings],
            "review_package_id": package.record_id,
            "review_package_sha256": binding,
            "current_records": self._current_records(case),
            "superseded_record_count": sum(
                record.record_id not in current_ids for record in all_records),
            "decision_records": decision_records,
            "change": self._change_diff(case),
            "events": [event_to_dict(event) for event in self.cases.events(case.case_id)],
            "authentication": {
                "method": "demo-shared-token-explicit-attestation",
                "production_ready": False,
                "notice": "Replace the shared token with Entra ID before customer approval.",
            },
            "capabilities": {"approve": case.state is CaseState.AWAITING_APPROVAL,
                             "reject": case.state is CaseState.AWAITING_APPROVAL,
                             "execute": False},
        }

    def _decision_inputs(self, document: Mapping, *, verb: str):
        tenant_id = self._tenant(document.get("tenant_id"))
        case = self._case(
            tenant_id=tenant_id, case_id=document.get("case_id"))
        if case.state is not CaseState.AWAITING_APPROVAL:
            raise ReviewControlError("the case is no longer awaiting approval")
        package, binding = self._package_binding(case)
        supplied_package = self._text(
            document.get("review_package_id"), "review_package_id", maximum=100)
        supplied_binding = self._text(
            document.get("review_package_sha256"), "review_package_sha256",
            minimum=64, maximum=64)
        if supplied_package != package.record_id or supplied_binding != binding:
            raise ReviewControlError("the decision is stale or bound to another package")
        confirmation = self._text(
            document.get("confirmation"), "confirmation", maximum=200)
        expected = f"{verb} {package.record_id}"
        if confirmation != expected:
            raise ReviewControlError(f"confirmation must exactly match {expected}")
        approver = self._text(document.get("approver"), "approver", maximum=200)
        return tenant_id, case, package, approver

    def approve(self, document: Mapping) -> dict:
        _, case, package, approver = self._decision_inputs(document, verb="APPROVE")
        now = _now()
        if not case.change_window:
            raise ReviewControlError("the package has no selected change window")
        if parse_timestamp(case.change_window.ends_at) <= parse_timestamp(now):
            raise ReviewControlError("the selected change window has expired")
        assertion = VerifiedApproval(
            approval_id=numeric_id("APPROVAL"), case_id=case.case_id,
            review_package_id=package.record_id, approver=approver,
            authenticated_at=now, expires_at=case.change_window.ends_at,
            authentication_method="demo-shared-token-explicit-attestation",
            statement="I approve this exact review package for its selected window.",
        )
        try:
            approval = ApprovalService(
                case_store=self.cases, record_store=self.records,
                artifact_root=self.artifacts, now=lambda: now).approve(assertion)
            scheduled = ExecutionScheduler(
                case_store=self.cases, record_store=self.records,
                job_store=self.jobs, now=lambda: now).schedule(case.case_id)
        except (ActionPlaneError, ValueError) as exc:
            raise ReviewControlError(str(exc)) from exc
        self._sync_artifacts()
        return {
            "case": case_to_dict(scheduled.case),
            "approval": product_record_to_dict(approval.record),
            "schedule": product_record_to_dict(scheduled.record),
            "job": {
                "job_id": scheduled.job.job_id,
                "state": scheduled.job.state.value,
                "execute_at": scheduled.job.execute_at,
                "deadline": scheduled.job.deadline,
            },
            "execution_started": False,
        }

    def reject(self, document: Mapping) -> dict:
        _, case, package, approver = self._decision_inputs(document, verb="REJECT")
        reason = self._text(document.get("reason"), "reason", minimum=20, maximum=2_000)
        now = _now()
        assertion = VerifiedRejection(
            rejection_id=numeric_id("REJECTION"), case_id=case.case_id,
            review_package_id=package.record_id, approver=approver,
            authenticated_at=now,
            authentication_method="demo-shared-token-explicit-attestation",
            reason=reason,
            statement="I reject this exact review package and require no execution.",
        )
        try:
            outcome = RejectionService(
                case_store=self.cases, record_store=self.records,
                artifact_root=self.artifacts, now=lambda: now).reject(assertion)
        except (ActionPlaneError, ValueError) as exc:
            raise ReviewControlError(str(exc)) from exc
        self._sync_artifacts()
        return {"case": case_to_dict(outcome.case),
                "rejection": product_record_to_dict(outcome.record),
                "execution_started": False}
