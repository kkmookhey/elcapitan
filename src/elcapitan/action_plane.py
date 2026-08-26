"""Human-gated execution, monitoring, rollback, and originator handoff."""
from __future__ import annotations

import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .agent_contracts import validate_output
from .agents import (
    AgentResultStatus, AgentRole, AgentRuntime, AgentTask, validate_result,
)
from .cases import CaseState, CaseTransition, RemediationCase, case_to_dict
from .case_validation import FindingValidationStatus, evaluate_finding, read_live_state
from .evidence import Collector, write_evidence
from .hashing import canonical_json, sha256_bytes, sha256_file
from .intake import numeric_id
from .finding_store import FindingStore
from .observability import parse_timestamp
from .paths import PathEscape, safe_resolve
from .product_records import ProductRecord, ProductRecordStore
from .workflow import CaseStore, WorkflowCoordinator


class ActionPlaneError(RuntimeError):
    pass


def _jsonable(value):
    if isinstance(value, Mapping):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


@dataclass(frozen=True)
class VerifiedApproval:
    approval_id: str
    case_id: str
    review_package_id: str
    approver: str
    authenticated_at: str
    expires_at: str
    authentication_method: str
    statement: str

    def __post_init__(self) -> None:
        required = asdict(self)
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError("verified approval is missing: " + ", ".join(missing))
        if parse_timestamp(self.expires_at) <= parse_timestamp(self.authenticated_at):
            raise ValueError("approval expiry must follow authentication")


@dataclass(frozen=True)
class ApprovalOutcome:
    case: RemediationCase
    record: ProductRecord


class ApprovalService:
    """Consumes an assertion already verified by a trusted identity adapter."""

    def __init__(self, *, case_store: CaseStore, record_store: ProductRecordStore,
                 artifact_root, now: Callable[[], str],
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        self.case_store = case_store
        self.record_store = record_store
        self.artifact_root = Path(artifact_root)
        self.now = now
        self.id_factory = id_factory
        self.workflow = WorkflowCoordinator(case_store)
        self.collector = Collector(
            "elcapitan-approval-gate", "0.1.0", "trusted-approval-adapter")

    def approve(self, assertion: VerifiedApproval) -> ApprovalOutcome:
        case = self.case_store.get(assertion.case_id)
        if case.state is not CaseState.AWAITING_APPROVAL:
            raise ActionPlaneError(
                f"case {case.case_id} must be awaiting_approval, not {case.state}")
        expected_package = case.record_ids.get("human_review_package_id")
        if assertion.review_package_id != expected_package:
            raise ActionPlaneError("approval is not bound to this case's review package")
        package = self.record_store.get(assertion.review_package_id)
        if package.case_id != case.case_id or package.record_type != "HumanReviewPackage.v1":
            raise ActionPlaneError("approval package has the wrong owner or type")
        now = self.now()
        if parse_timestamp(assertion.authenticated_at) > parse_timestamp(now):
            raise ActionPlaneError("approval authentication timestamp is in the future")
        if parse_timestamp(assertion.expires_at) <= parse_timestamp(now):
            raise ActionPlaneError("approval has expired")
        binding = sha256_bytes(canonical_json(_jsonable(package.body)))
        run_dir = self.artifact_root / "cases" / case.case_id / "approval" / assertion.approval_id
        approval_ref = write_evidence(
            run_dir, self.id_factory("EVD"), "verified_human_approval",
            canonical_json({**asdict(assertion), "review_package_sha256": binding}),
            self.collector, sensitivity="restricted", now=now)
        record = ProductRecord(
            record_id=assertion.approval_id, case_id=case.case_id,
            record_type="ChangeApproval.v1", schema_version=1, created_at=now,
            body={**asdict(assertion), "review_package_sha256": binding,
                  "plan_id": case.record_ids["change_plan_id"],
                  "window_id": case.record_ids["change_window_id"]},
            evidence_ids=(approval_ref.evidence_id,))
        self.record_store.put(record)
        case = self.workflow.advance(
            case.case_id, CaseTransition.APPROVE_CHANGE,
            event_id=self.id_factory("EVT"), occurred_at=now,
            actor=f"approver:{assertion.approver}",
            record_ids={"approval_id": assertion.approval_id},
            evidence_ids=record.evidence_ids)
        return ApprovalOutcome(case=case, record=record)


@dataclass(frozen=True)
class ExecutionContext:
    case: RemediationCase
    plan: ProductRecord
    link: ProductRecord
    approval: ProductRecord
    window: ProductRecord
    artifact_root: Path


@dataclass(frozen=True)
class ActionStep:
    name: str
    passed: bool
    detail: str
    payload: Mapping = None

    def to_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "detail": self.detail,
                "payload": _jsonable(self.payload or {})}


@dataclass(frozen=True)
class DeploymentCheckpoint:
    checkpoint_id: str
    detail: str
    payload: Mapping

    def to_dict(self) -> dict:
        return {"checkpoint_id": self.checkpoint_id, "detail": self.detail,
                "payload": _jsonable(self.payload)}


@dataclass(frozen=True)
class HealthObservation:
    healthy: bool
    reasons: tuple[str, ...]
    metrics: Mapping

    def to_dict(self) -> dict:
        return {"healthy": self.healthy, "reasons": list(self.reasons),
                "metrics": _jsonable(self.metrics)}


@dataclass(frozen=True)
class ProbeResult:
    probe: str
    target: str
    passed: bool
    detail: str
    payload: Mapping

    def to_dict(self) -> dict:
        return asdict(self)


class ChangeDriver(Protocol):
    @property
    def name(self) -> str: ...
    def preflight(self, context: ExecutionContext) -> ActionStep: ...
    def checkpoint(self, context: ExecutionContext) -> DeploymentCheckpoint: ...
    def deploy(self, context: ExecutionContext,
               checkpoint: DeploymentCheckpoint) -> ActionStep: ...
    def rollback(self, context: ExecutionContext,
                 checkpoint: DeploymentCheckpoint) -> ActionStep: ...


class HealthMonitor(Protocol):
    @property
    def name(self) -> str: ...
    def observe(self, phase: str, context: ExecutionContext) -> HealthObservation: ...


class VerificationProbe(Protocol):
    @property
    def name(self) -> str: ...
    def run(self, context: ExecutionContext) -> ProbeResult: ...


class FilesystemChangeDriver:
    """Safe executable reference driver for tests and non-cloud demonstrations."""

    def __init__(self, target_root, *, fail_deploy: bool = False,
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        self.target_root = Path(target_root).resolve(strict=True)
        self.fail_deploy = fail_deploy
        self.id_factory = id_factory

    @property
    def name(self) -> str:
        return "filesystem-reference-driver"

    def _paths(self, context: ExecutionContext) -> tuple[Path, Path, str]:
        source_path = context.plan.body["change"]["source_path"]
        target = safe_resolve(self.target_root, source_path)
        replacement = safe_resolve(
            context.artifact_root,
            f"{context.plan.body['artifact_namespace']}/workspace/{source_path}")
        return target, replacement, source_path

    def preflight(self, context: ExecutionContext) -> ActionStep:
        try:
            target, replacement, _ = self._paths(context)
        except (PathEscape, FileNotFoundError) as exc:
            return ActionStep("preflight", False, str(exc))
        if not target.is_file() or not replacement.is_file():
            return ActionStep("preflight", False, "target or verified replacement is missing")
        expected_before = context.plan.body["change"]["before_sha256"]
        expected_after = context.plan.body["change"]["after_sha256"]
        passed = sha256_file(target) == expected_before and sha256_file(replacement) == expected_after
        return ActionStep(
            "preflight", passed,
            "target and verified replacement hashes match the approved package" if passed
            else "target drift or replacement tampering detected",
            {"target_sha256": sha256_file(target),
             "replacement_sha256": sha256_file(replacement)})

    def checkpoint(self, context: ExecutionContext) -> DeploymentCheckpoint:
        target, _, source_path = self._paths(context)
        return DeploymentCheckpoint(
            checkpoint_id=self.id_factory("CHK"),
            detail="captured exact pre-change file content",
            payload={"source_path": source_path, "content": target.read_text(encoding="utf-8"),
                     "sha256": sha256_file(target)})

    @staticmethod
    def _replace(path: Path, content: str) -> None:
        temporary = path.with_name(f".{path.name}.elcapitan.tmp")
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    def deploy(self, context: ExecutionContext,
               checkpoint: DeploymentCheckpoint) -> ActionStep:
        if self.fail_deploy:
            return ActionStep("deploy", False, "injected reference-driver deployment failure")
        target, replacement, _ = self._paths(context)
        self._replace(target, replacement.read_text(encoding="utf-8"))
        passed = sha256_file(target) == context.plan.body["change"]["after_sha256"]
        return ActionStep("deploy", passed,
                          "verified replacement installed" if passed else "post-write hash mismatch",
                          {"target_sha256": sha256_file(target)})

    def rollback(self, context: ExecutionContext,
                 checkpoint: DeploymentCheckpoint) -> ActionStep:
        target, _, _ = self._paths(context)
        content = checkpoint.payload.get("content")
        if not isinstance(content, str):
            return ActionStep("rollback", False, "checkpoint has no restorable content")
        self._replace(target, content)
        passed = sha256_file(target) == checkpoint.payload.get("sha256")
        return ActionStep("rollback", passed,
                          "checkpoint restored" if passed else "restored file hash mismatch",
                          {"target_sha256": sha256_file(target)})


class RecordedHealthMonitor:
    def __init__(self, observations: Mapping[str, HealthObservation]) -> None:
        self.observations = dict(observations)

    @property
    def name(self) -> str:
        return "recorded-health-monitor"

    def observe(self, phase: str, context: ExecutionContext) -> HealthObservation:
        try:
            return self.observations[phase]
        except KeyError:
            raise ActionPlaneError(f"no recorded health observation for {phase}") from None


class FileHashProbe:
    def __init__(self, target_root) -> None:
        self.target_root = Path(target_root).resolve(strict=True)

    @property
    def name(self) -> str:
        return "deployed-file-hash"

    def run(self, context: ExecutionContext) -> ProbeResult:
        relative = context.plan.body["change"]["source_path"]
        target = safe_resolve(self.target_root, relative)
        expected = context.plan.body["change"]["after_sha256"]
        actual = sha256_file(target) if target.is_file() else ""
        return ProbeResult(
            probe=self.name, target=relative, passed=actual == expected,
            detail="deployed artifact matches approved hash" if actual == expected
            else "deployed artifact does not match approved hash",
            payload={"expected_sha256": expected, "actual_sha256": actual})


class RecordedVerificationProbe:
    def __init__(self, *, name: str, target: str, passed: bool, detail: str,
                 payload: Mapping | None = None) -> None:
        self._name, self.target, self.passed, self.detail = name, target, passed, detail
        self.payload = dict(payload or {})

    @property
    def name(self) -> str:
        return self._name

    def run(self, context: ExecutionContext) -> ProbeResult:
        return ProbeResult(self.name, self.target, self.passed, self.detail, self.payload)


class LiveFindingProbe:
    """Re-run deterministic finding evaluators against current cloud configuration."""

    def __init__(self, *, finding_store: FindingStore, host_env: Mapping[str, str],
                 reader=read_live_state) -> None:
        self.finding_store, self.host_env, self.reader = finding_store, dict(host_env), reader

    @property
    def name(self) -> str:
        return "live-vulnerability-revalidation"

    def run(self, context: ExecutionContext) -> ProbeResult:
        results = []
        for finding in self.finding_store.list_for_case(context.case.case_id):
            try:
                state = self.reader(finding, self.host_env)
                result = evaluate_finding(finding, state, evidence_ids=())
                results.append(result.to_dict())
            except (OSError, ValueError) as exc:
                results.append({"finding_id": finding.finding_id,
                                "status": "unavailable", "reason": str(exc)})
        passed = bool(results) and all(
            result["status"] == FindingValidationStatus.NOT_CONFIRMED.value
            for result in results)
        return ProbeResult(
            probe=self.name, target=context.case.case_id, passed=passed,
            detail=("original findings are no longer confirmed" if passed else
                    "one or more original findings remain confirmed or unavailable"),
            payload={"findings": results})


class HttpVerificationProbe:
    """Bounded read-only UI/API probe with an explicit host allowlist."""

    def __init__(self, *, name: str, url: str, allowed_hosts: tuple[str, ...],
                 expected_status: int = 200, body_contains: str = "",
                 timeout_seconds: float = 15) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("HTTP verification URL must be absolute http(s)")
        if parsed.hostname not in allowed_hosts:
            raise ValueError("HTTP verification host is not explicitly allowed")
        if timeout_seconds <= 0:
            raise ValueError("HTTP verification timeout must be positive")
        self._name, self.url = name, url
        self.expected_status, self.body_contains = expected_status, body_contains
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return self._name

    def run(self, context: ExecutionContext) -> ProbeResult:
        try:
            request = urllib.request.Request(
                self.url, headers={"User-Agent": "elcapitan-verification/0.1"},
                method="GET")
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read(1024 * 1024 + 1)
                if len(body) > 1024 * 1024:
                    raise ValueError("response exceeded 1 MiB")
                status = response.status
            text = body.decode("utf-8", errors="replace")
            passed = status == self.expected_status and (
                not self.body_contains or self.body_contains in text)
            detail = "HTTP verification passed" if passed else "unexpected status or body"
            payload = {"status": status, "body_sha256": sha256_bytes(body),
                       "required_text_present": (
                           not self.body_contains or self.body_contains in text)}
        except (OSError, ValueError, urllib.error.URLError) as exc:
            passed, detail, payload = False, f"HTTP verification failed: {exc}", {}
        return ProbeResult(self.name, self.url, passed, detail, payload)


@dataclass(frozen=True)
class ExecutionOutcome:
    case: RemediationCase
    execution_record: ProductRecord
    verification_record: ProductRecord | None
    handoff_record: ProductRecord | None
    rolled_back: bool


class ExecutionService:
    def __init__(self, *, case_store: CaseStore, record_store: ProductRecordStore,
                 artifact_root, driver: ChangeDriver, monitor: HealthMonitor,
                 probes: tuple[VerificationProbe, ...], runtime: AgentRuntime,
                 now: Callable[[], str],
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        self.case_store, self.record_store = case_store, record_store
        self.artifact_root = Path(artifact_root).resolve(strict=False)
        self.driver, self.monitor, self.probes = driver, monitor, tuple(probes)
        self.runtime, self.now, self.id_factory = runtime, now, id_factory
        self.workflow = WorkflowCoordinator(case_store)
        self.collector = Collector(
            "elcapitan-execution-control-plane", "0.1.0", "change-orchestrator")

    def _context(self, case: RemediationCase) -> ExecutionContext:
        def record(name):
            value = case.record_ids.get(name)
            if not value:
                raise ActionPlaneError(f"approved case is missing {name}")
            found = self.record_store.get(value)
            if found.case_id != case.case_id:
                raise ActionPlaneError(f"{name} belongs to another case")
            return found
        return ExecutionContext(
            case=case, plan=record("change_plan_id"), link=record("iac_link_id"),
            approval=record("approval_id"), window=record("change_window_id"),
            artifact_root=self.artifact_root)

    def _evidence(self, run_dir: Path, kind: str, document, *, now: str) -> str:
        return write_evidence(
            run_dir, self.id_factory("EVD"), kind, canonical_json(document),
            self.collector, now=now).evidence_id

    def _rollback(self, case_id: str, context: ExecutionContext,
                  checkpoint: DeploymentCheckpoint, run_dir: Path,
                  evidence_ids: tuple[str, ...], reason: str) -> ExecutionOutcome:
        now, rollback_id = self.now(), self.id_factory("RBEXEC")
        try:
            rollback_step = self.driver.rollback(context, checkpoint)
        except Exception as exc:
            rollback_step = ActionStep("rollback", False, f"rollback driver raised: {exc}")
        try:
            rollback_health = self.monitor.observe("rollback", context)
        except Exception as exc:
            rollback_health = HealthObservation(
                False, (f"rollback health monitor raised: {exc}",), {})
        rollback_evidence = self._evidence(
            run_dir, "rollback_execution", {
                "reason": reason, "step": rollback_step.to_dict(),
                "health": rollback_health.to_dict(),
            }, now=now)
        all_evidence = tuple(dict.fromkeys((*evidence_ids, rollback_evidence)))
        rollback_record = ProductRecord(
            record_id=rollback_id, case_id=case_id, record_type="RollbackExecution.v1",
            schema_version=1, created_at=now,
            body={"rollback_execution_id": rollback_id, "reason": reason,
                  "driver": self.driver.name, "step": rollback_step.to_dict(),
                  "health": rollback_health.to_dict(),
                  "checkpoint_id": checkpoint.checkpoint_id},
            evidence_ids=all_evidence)
        self.record_store.put(rollback_record)
        case = self.workflow.advance(
            case_id, CaseTransition.START_ROLLBACK,
            event_id=self.id_factory("EVT"), occurred_at=now, actor="execution-policy",
            record_ids={"rollback_execution_id": rollback_id},
            evidence_ids=all_evidence, detail=reason)
        if not rollback_step.passed or not rollback_health.healthy:
            detail = "rollback did not restore both checkpoint and healthy service state"
            self.workflow.advance(
                case_id, CaseTransition.BLOCK, event_id=self.id_factory("EVT"),
                occurred_at=self.now(), actor="execution-policy", detail=detail,
                record_ids={"rollback_failure_id": rollback_id},
                evidence_ids=all_evidence)
            raise ActionPlaneError(detail)
        verification_id = self.id_factory("VERIFY")
        verification = ProductRecord(
            record_id=verification_id, case_id=case_id,
            record_type="RollbackVerification.v1", schema_version=1, created_at=self.now(),
            body={"verification_id": verification_id, "checkpoint_restored": True,
                  "service_recovered": True, "reason": reason},
            evidence_ids=all_evidence)
        self.record_store.put(verification)
        case = self.workflow.advance(
            case_id, CaseTransition.COMPLETE_ROLLBACK,
            event_id=self.id_factory("EVT"), occurred_at=self.now(),
            actor="execution-policy",
            record_ids={"verification_result_id": verification_id},
            evidence_ids=all_evidence)
        return ExecutionOutcome(case, rollback_record, verification, None, True)

    def execute(self, case_id: str, *, originator: str,
                execution_job_id: str) -> ExecutionOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.APPROVED:
            raise ActionPlaneError(f"case {case_id} must be approved, not {case.state}")
        if not case.record_ids.get("schedule_id") or not case.record_ids.get(
                "execution_job_id"):
            raise ActionPlaneError("approved case must be released by the durable scheduler")
        if execution_job_id != case.record_ids["execution_job_id"]:
            raise ActionPlaneError("execution job is not bound to this approved case")
        if not originator:
            raise ActionPlaneError("originator is required for completion handoff")
        now = self.now()
        if not case.change_window:
            raise ActionPlaneError("approved case has no selected change window")
        current_time = parse_timestamp(now)
        if not (parse_timestamp(case.change_window.starts_at) <= current_time
                < parse_timestamp(case.change_window.ends_at)):
            raise ActionPlaneError(
                f"execution is outside approved window {case.change_window.starts_at} "
                f"to {case.change_window.ends_at}")
        context = self._context(case)
        if parse_timestamp(context.approval.body["expires_at"]) <= current_time:
            raise ActionPlaneError("bound approval expired before execution")
        execution_id = self.id_factory("EXEC")
        run_dir = self.artifact_root / "cases" / case_id / "execution" / execution_id
        preflight = self.driver.preflight(context)
        if not preflight.passed:
            raise ActionPlaneError(f"execution preflight failed: {preflight.detail}")
        baseline = self.monitor.observe("baseline", context)
        if not baseline.healthy:
            raise ActionPlaneError("service baseline is unhealthy; change is not eligible")
        checkpoint = self.driver.checkpoint(context)
        start_evidence = self._evidence(
            run_dir, "execution_preflight", {
                "preflight": preflight.to_dict(), "baseline": baseline.to_dict(),
                "checkpoint": checkpoint.to_dict(),
            }, now=now)
        execution = ProductRecord(
            record_id=execution_id, case_id=case_id, record_type="ExecutionStart.v1",
            schema_version=1, created_at=now,
            body={"execution_id": execution_id, "driver": self.driver.name,
                  "monitor": self.monitor.name, "preflight": preflight.to_dict(),
                  "baseline": baseline.to_dict(), "checkpoint": checkpoint.to_dict(),
                  "window_id": context.window.record_id,
                  "approval_id": context.approval.record_id,
                  "artifact_namespace": f"cases/{case_id}/execution/{execution_id}"},
            evidence_ids=(start_evidence,))
        self.record_store.put(execution)
        case = self.workflow.advance(
            case_id, CaseTransition.START_EXECUTION,
            event_id=self.id_factory("EVT"), occurred_at=now,
            actor=f"driver:{self.driver.name}",
            record_ids={"execution_id": execution_id}, evidence_ids=(start_evidence,))

        try:
            deployment = self.driver.deploy(context, checkpoint)
        except Exception as exc:
            deployment = ActionStep("deploy", False, f"deployment driver raised: {exc}")
        try:
            after = self.monitor.observe("after_deploy", context)
        except Exception as exc:
            after = HealthObservation(False, (f"health monitor raised: {exc}",), {})
        deploy_evidence = self._evidence(
            run_dir, "deployment_result",
            {"deployment": deployment.to_dict(), "health": after.to_dict()}, now=self.now())
        accumulated = (start_evidence, deploy_evidence)
        if not deployment.passed:
            return self._rollback(
                case_id, context, checkpoint, run_dir, accumulated,
                f"deployment failed: {deployment.detail}")
        if not after.healthy:
            return self._rollback(
                case_id, context, checkpoint, run_dir, accumulated,
                "post-deployment health policy failed: " + "; ".join(after.reasons))

        result_id = self.id_factory("EXRES")
        result_record = ProductRecord(
            record_id=result_id, case_id=case_id, record_type="ExecutionResult.v1",
            schema_version=1, created_at=self.now(),
            body={"execution_result_id": result_id, "deployment": deployment.to_dict(),
                  "health": after.to_dict(), "checkpoint_id": checkpoint.checkpoint_id},
            evidence_ids=accumulated)
        self.record_store.put(result_record)
        case = self.workflow.advance(
            case_id, CaseTransition.START_VERIFICATION,
            event_id=self.id_factory("EVT"), occurred_at=self.now(),
            actor="execution-policy", record_ids={"execution_result_id": result_id},
            evidence_ids=accumulated)

        probe_results = []
        for probe in self.probes:
            try:
                probe_results.append(probe.run(context))
            except Exception as exc:
                probe_results.append(ProbeResult(
                    probe=probe.name, target=case_id, passed=False,
                    detail=f"verification probe raised: {exc}", payload={}))
        probes = tuple(probe_results)
        probe_evidence = self._evidence(
            run_dir, "post_change_probes", [probe.to_dict() for probe in probes],
            now=self.now())
        accumulated = tuple(dict.fromkeys((*accumulated, probe_evidence)))
        failed = [probe for probe in probes if not probe.passed]
        if not probes or failed:
            reason = ("no post-change verification probes were configured" if not probes else
                      "post-change probes failed: " + ", ".join(probe.probe for probe in failed))
            return self._rollback(
                case_id, context, checkpoint, run_dir, accumulated, reason)

        task = AgentTask(
            task_id=self.id_factory("TASK"), case_id=case_id,
            role=AgentRole.RELEASE_AUDITOR,
            objective="Independently audit the completed change and prepare originator handoff",
            output_contract="PostChangeReview.v1",
            input_record_ids=(execution.record_id, result_record.record_id),
            evidence_ids=accumulated,
            constraints=("accept only when every mandatory deterministic probe passed",
                         "do not claim the original vulnerability cleared without evidence",
                         "request rollback for a material unresolved risk"),
            metadata={"case": case_to_dict(case), "plan": context.plan.body,
                      "deployment": result_record.body,
                      "probes": [probe.to_dict() for probe in probes]},
        )
        try:
            audit = self.runtime.run(task)
        except Exception as exc:
            return self._rollback(
                case_id, context, checkpoint, run_dir, accumulated,
                f"release auditor runtime failed: {exc}")
        failures = validate_result(task, audit)
        failures.extend(validate_output(task.output_contract, _jsonable(audit.output)))
        if audit.status is not AgentResultStatus.SUCCEEDED:
            failures.append(f"release auditor status is {audit.status}")
        if not set(accumulated).issubset(set(audit.evidence_cited)):
            failures.append("release auditor did not cite the complete execution evidence set")
        if audit.output.get("decision") == "accept" and not audit.output.get(
                "validated_outcomes"):
            failures.append("release auditor accepted without naming validated outcomes")
        if failures:
            return self._rollback(
                case_id, context, checkpoint, run_dir, accumulated,
                "release audit contract failed: " + "; ".join(failures))
        audit_evidence = self._evidence(
            run_dir, "release_auditor_result", {
                "runtime": audit.runtime, "model": audit.model,
                "output": _jsonable(audit.output),
                "evidence_cited": list(audit.evidence_cited),
            }, now=self.now())
        accumulated = tuple(dict.fromkeys((*accumulated, audit_evidence)))
        if audit.output["decision"] == "rollback":
            return self._rollback(
                case_id, context, checkpoint, run_dir, accumulated,
                "release auditor requested rollback: " + audit.output["summary"])
        if audit.output["decision"] == "needs_human_context":
            return self._rollback(
                case_id, context, checkpoint, run_dir, accumulated,
                "release auditor requires human context: " + audit.output["summary"])

        verification_id = self.id_factory("VERIFY")
        verification = ProductRecord(
            record_id=verification_id, case_id=case_id,
            record_type="PostChangeVerification.v1", schema_version=1,
            created_at=self.now(),
            body={"verification_id": verification_id, "status": "passed",
                  "probes": [probe.to_dict() for probe in probes],
                  "release_audit": _jsonable(audit.output)},
            evidence_ids=accumulated)
        self.record_store.put(verification)
        certificate_id = self.id_factory("CERT")
        certificate = ProductRecord(
            record_id=certificate_id, case_id=case_id,
            record_type="RemediationCertificate.v1", schema_version=1,
            created_at=self.now(),
            body={"certificate_id": certificate_id, "case_id": case_id,
                  "finding_ids": list(case.finding_ids), "plan_id": context.plan.record_id,
                  "approval_id": context.approval.record_id,
                  "execution_id": execution_id, "verification_id": verification_id,
                  "completed_status": "remediated",
                  "evidence_ids": list(accumulated)}, evidence_ids=accumulated)
        self.record_store.put(certificate)
        handoff_id = self.id_factory("HANDOFF")
        handoff = ProductRecord(
            record_id=handoff_id, case_id=case_id,
            record_type="OriginatorHandoff.v1", schema_version=1,
            created_at=self.now(),
            body={"handoff_id": handoff_id, "recipient": originator,
                  "status": "done", "summary": audit.output["summary"],
                  "validated_outcomes": list(audit.output["validated_outcomes"]),
                  "residual_risks": list(audit.output["residual_risks"]),
                  "notes": list(audit.output["handoff_notes"]),
                  "certificate_id": certificate_id}, evidence_ids=accumulated)
        self.record_store.put(handoff)
        case = self.workflow.advance(
            case_id, CaseTransition.COMPLETE_REMEDIATION,
            event_id=self.id_factory("EVT"), occurred_at=self.now(),
            actor="release-auditor",
            record_ids={"verification_result_id": verification_id,
                        "remediation_certificate_id": certificate_id,
                        "originator_handoff_id": handoff_id},
            evidence_ids=accumulated)
        return ExecutionOutcome(case, execution, verification, handoff, False)
