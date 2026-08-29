"""Durable budgets, replay protection, and circuits for agent runtime work."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping

from .agents import (
    AgentResult, AgentResultStatus, AgentRuntime, AgentTask, validate_result,
)
from .evidence import Collector, write_evidence
from .hashing import canonical_json, sha256_file
from .paths import PathEscape, safe_resolve
from .product_records import (
    DuplicateProductRecord, ProductRecord, ProductRecordStore,
)


INVOCATION_RECORD = "AgentInvocation.v1"
OUTCOME_RECORD = "AgentInvocationOutcome.v1"
TERMINAL_RECORD = "AgentRunTerminal.v1"


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(document: Mapping) -> str:
    return sha256(canonical_json(document)).hexdigest()


def _record_id(prefix: str, *parts: str) -> str:
    return prefix + "-" + sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:32]


def _evidence_id(invocation_id: str) -> str:
    return "EVD-" + str(int(sha256(invocation_id.encode("utf-8")).hexdigest()[:24], 16))


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("agent-run timestamps must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class AgentRunPolicy:
    """Central per-case limits; narrower stage/provider caps still apply."""

    max_model_calls: int = 42
    max_attempts_per_role_package: int = 3
    max_elapsed_seconds: int = 3600
    equivalent_failure_threshold: int = 2
    override_terminal_record_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in (
            "max_model_calls", "max_attempts_per_role_package",
            "max_elapsed_seconds", "equivalent_failure_threshold",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        object.__setattr__(
            self, "override_terminal_record_ids",
            tuple(self.override_terminal_record_ids))
        if any(not item for item in self.override_terminal_record_ids):
            raise ValueError("terminal record overrides must be non-empty ids")

    def to_dict(self) -> dict:
        return {
            "max_model_calls": self.max_model_calls,
            "max_attempts_per_role_package": self.max_attempts_per_role_package,
            "max_elapsed_seconds": self.max_elapsed_seconds,
            "equivalent_failure_threshold": self.equivalent_failure_threshold,
            "override_terminal_record_ids": list(
                self.override_terminal_record_ids),
        }


class AgentRunStopped(RuntimeError):
    """Raised after a durable needs-human terminal outcome has been written."""

    def __init__(self, record: ProductRecord) -> None:
        self.record = record
        super().__init__(
            f"agent run stopped: {record.body.get('reason', 'needs_human')}; "
            f"terminal record {record.record_id}")


@dataclass(frozen=True)
class _Binding:
    package_hash: str
    task_contract_hash: str
    package_key: str
    replay_key: str


def _binding(task: AgentTask) -> _Binding:
    package_hash = _digest({
        "input_record_ids": list(task.input_record_ids),
        "evidence_ids": list(task.evidence_ids),
    })
    task_contract_hash = _digest({
        "objective": task.objective,
        "output_contract": task.output_contract,
        "constraints": list(task.constraints),
    })
    package_key = _digest({
        "case_id": task.case_id,
        "role": task.role.value,
        "output_contract": task.output_contract,
        "package_hash": package_hash,
    })
    replay_key = _digest({
        "package_key": package_key,
        "task_contract_hash": task_contract_hash,
    })
    return _Binding(package_hash, task_contract_hash, package_key, replay_key)


def _result_document(result: AgentResult) -> dict:
    return {
        "task_id": result.task_id,
        "case_id": result.case_id,
        "role": result.role.value,
        "status": result.status.value,
        "output": _jsonable(result.output),
        "evidence_cited": list(result.evidence_cited),
        "missing_evidence": list(result.missing_evidence),
        "runtime": result.runtime,
        "model": result.model,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "usage": _jsonable(result.usage),
    }


def _restore_result(task: AgentTask, document: Mapping) -> AgentResult:
    return AgentResult(
        task_id=task.task_id, case_id=task.case_id, role=task.role,
        status=AgentResultStatus(document["status"]), output=document["output"],
        evidence_cited=tuple(document["evidence_cited"]),
        missing_evidence=tuple(document["missing_evidence"]),
        runtime=str(document["runtime"]), model=str(document.get("model", "")),
        started_at=str(document["started_at"]),
        completed_at=str(document["completed_at"]), usage=document.get("usage", {}),
    )


class AgentRunRuntime:
    """Persist and bound every call through one ``AgentRuntime`` boundary."""

    agent_run_managed = True

    def __init__(self, runtime: AgentRuntime, *, record_store: ProductRecordStore,
                 artifact_root, now: Callable[[], str],
                 policy: AgentRunPolicy | None = None) -> None:
        self.runtime = runtime
        self.record_store = record_store
        self.artifact_root = Path(artifact_root)
        self.now = now
        self.policy = policy or AgentRunPolicy()
        self.collector = Collector(
            tool="elcapitan-agent-run", version="0.1.0",
            identity="agent-run-control-plane")

    @property
    def name(self) -> str:
        return f"agent-run:{self.runtime.name}"

    @staticmethod
    def _outcomes(records: tuple[ProductRecord, ...]) -> dict[str, ProductRecord]:
        return {
            str(record.body.get("invocation_id")): record
            for record in records if record.record_type == OUTCOME_RECORD
        }

    def _terminal(self, task: AgentTask, binding: _Binding, *, reason: str,
                  scope: str, counts: Mapping[str, int],
                  failure_signature: str = "") -> ProductRecord:
        terminal_id = _record_id(
            "ARUN", task.case_id, scope,
            binding.package_key if scope == "role_package" else "case", reason,
            failure_signature)
        body = {
            "status": "needs_human",
            "reason": reason,
            "scope": scope,
            "role": task.role.value,
            "output_contract": task.output_contract,
            "package_hash": binding.package_hash,
            "package_key": binding.package_key,
            "failure_signature": failure_signature,
            "counts": dict(counts),
            "policy": self.policy.to_dict(),
            "operator_action": (
                "inspect invocation records and evidence, then resume only with an "
                "explicit terminal-record override or a changed evidence package"),
        }
        record = ProductRecord(
            record_id=terminal_id, case_id=task.case_id,
            record_type=TERMINAL_RECORD, schema_version=1,
            created_at=self.now(), body=body)
        try:
            self.record_store.put(record)
        except DuplicateProductRecord:
            record = self.record_store.get(terminal_id)
        return record

    def _active_terminal(self, records: tuple[ProductRecord, ...],
                         binding: _Binding) -> ProductRecord | None:
        overrides = set(self.policy.override_terminal_record_ids)
        for record in reversed(records):
            if record.record_type != TERMINAL_RECORD or record.record_id in overrides:
                continue
            scope = record.body.get("scope")
            if scope == "case" or (
                    scope == "role_package"
                    and record.body.get("package_key") == binding.package_key):
                return record
        return None

    def _restore_outcome(self, task: AgentTask, outcome: ProductRecord) -> AgentResult:
        namespace = str(outcome.body["artifact_namespace"])
        relative = str(outcome.body["result_artifact_path"])
        path = safe_resolve(self.artifact_root / namespace, relative)
        if not path.is_file() or sha256_file(path) != outcome.body["result_sha256"]:
            raise OSError("recorded agent result evidence is absent or has changed")
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, Mapping):
            raise ValueError("recorded agent result evidence is not an object")
        return _restore_result(task, document)

    def run(self, task: AgentTask) -> AgentResult:
        binding = _binding(task)
        records = self.record_store.list_for_case(task.case_id)
        outcomes = self._outcomes(records)

        for record in records:
            if (record.record_type == OUTCOME_RECORD
                    and record.body.get("replay_key") == binding.replay_key
                    and record.body.get("status") == "succeeded"):
                try:
                    return self._restore_outcome(task, record)
                except (KeyError, OSError, TypeError, ValueError,
                        json.JSONDecodeError, PathEscape):
                    terminal = self._terminal(
                        task, binding, reason="replay_artifact_unavailable",
                        scope="role_package",
                        counts={"model_calls": sum(
                            item.record_type == INVOCATION_RECORD for item in records)})
                    raise AgentRunStopped(terminal) from None

        terminal = self._active_terminal(records, binding)
        if terminal is not None:
            raise AgentRunStopped(terminal)

        invocations = tuple(
            record for record in records if record.record_type == INVOCATION_RECORD)
        package_invocations = tuple(
            record for record in invocations
            if record.body.get("package_key") == binding.package_key)
        pending = tuple(
            record for record in invocations if record.record_id not in outcomes)
        overridden_incomplete = any(
            record.record_type == TERMINAL_RECORD
            and record.record_id in self.policy.override_terminal_record_ids
            and record.body.get("reason") == "incomplete_prior_invocation"
            for record in records)
        if overridden_incomplete:
            pending = ()
        counts = {
            "model_calls": len(invocations),
            "role_package_attempts": len(package_invocations),
        }
        if pending:
            terminal = self._terminal(
                task, binding, reason="incomplete_prior_invocation",
                scope="case", counts=counts)
            raise AgentRunStopped(terminal)
        if len(invocations) >= self.policy.max_model_calls:
            terminal = self._terminal(
                task, binding, reason="model_call_budget_exhausted",
                scope="case", counts=counts)
            raise AgentRunStopped(terminal)
        if len(package_invocations) >= self.policy.max_attempts_per_role_package:
            terminal = self._terminal(
                task, binding, reason="role_package_attempt_budget_exhausted",
                scope="role_package", counts=counts)
            raise AgentRunStopped(terminal)
        if invocations:
            elapsed = max(0, int((
                _timestamp(self.now()) - _timestamp(invocations[0].created_at)
            ).total_seconds()))
            counts["elapsed_seconds"] = elapsed
            if elapsed >= self.policy.max_elapsed_seconds:
                terminal = self._terminal(
                    task, binding, reason="elapsed_run_budget_exhausted",
                    scope="case", counts=counts)
                raise AgentRunStopped(terminal)

        attempt = len(package_invocations) + 1
        invocation_id = _record_id(
            "AINV", binding.package_key, binding.replay_key, str(attempt))
        invocation = ProductRecord(
            record_id=invocation_id, case_id=task.case_id,
            record_type=INVOCATION_RECORD, schema_version=1,
            created_at=self.now(), body={
                "invocation_id": invocation_id,
                "replay_key": binding.replay_key,
                "package_key": binding.package_key,
                "package_hash": binding.package_hash,
                "task_contract_hash": binding.task_contract_hash,
                "role": task.role.value,
                "output_contract": task.output_contract,
                "attempt": attempt,
                "runtime": self.runtime.name,
                "status": "started",
                "policy": self.policy.to_dict(),
            })
        try:
            self.record_store.put(invocation)
        except DuplicateProductRecord:
            records = self.record_store.list_for_case(task.case_id)
            outcome = self._outcomes(records).get(invocation_id)
            if outcome and outcome.body.get("status") == "succeeded":
                try:
                    return self._restore_outcome(task, outcome)
                except (KeyError, OSError, TypeError, ValueError,
                        json.JSONDecodeError, PathEscape):
                    pass
            terminal = self._terminal(
                task, binding, reason="incomplete_prior_invocation",
                scope="case", counts=counts)
            raise AgentRunStopped(terminal)

        outcome_id = _record_id("AOUT", invocation_id)
        try:
            result = self.runtime.run(task)
        except Exception as exc:
            failure_code = type(exc).__name__
            signature = _digest({
                "failure_code": failure_code,
                "detail": " ".join(str(exc).split()),
            })
            outcome = ProductRecord(
                record_id=outcome_id, case_id=task.case_id,
                record_type=OUTCOME_RECORD, schema_version=1,
                created_at=self.now(), body={
                    "invocation_id": invocation_id,
                    "replay_key": binding.replay_key,
                    "package_key": binding.package_key,
                    "status": "failed",
                    "failure_code": failure_code,
                    "failure_signature": signature,
                })
            self.record_store.put(outcome)
            failures = [
                record for record in self.record_store.list_for_case(task.case_id)
                if record.record_type == OUTCOME_RECORD
                and record.body.get("package_key") == binding.package_key
                and record.body.get("failure_signature") == signature
            ]
            if len(failures) >= self.policy.equivalent_failure_threshold:
                terminal = self._terminal(
                    task, binding, reason="equivalent_failure_circuit_open",
                    scope="role_package",
                    counts={**counts, "role_package_attempts": attempt},
                    failure_signature=signature)
                raise AgentRunStopped(terminal) from exc
            raise

        contract_failures = validate_result(task, result)
        status = ("succeeded" if (
            result.status is AgentResultStatus.SUCCEEDED and not contract_failures
        ) else "not_succeeded")
        signature = ""
        if status != "succeeded":
            signature = _digest({
                "status": result.status.value,
                "missing_evidence": list(result.missing_evidence),
                "contract_failures": contract_failures,
            })
        namespace = f"cases/{task.case_id}/agent-runs/{invocation_id}"
        result_ref = write_evidence(
            self.artifact_root / namespace, _evidence_id(invocation_id),
            "agent_invocation_result", canonical_json(_result_document(result)),
            self.collector, now=self.now())
        outcome = ProductRecord(
            record_id=outcome_id, case_id=task.case_id,
            record_type=OUTCOME_RECORD, schema_version=1,
            created_at=self.now(), body={
                "invocation_id": invocation_id,
                "replay_key": binding.replay_key,
                "package_key": binding.package_key,
                "status": status,
                "failure_code": (
                    "invalid_result_contract" if contract_failures
                    else result.status.value if signature else ""),
                "failure_signature": signature,
                "artifact_namespace": namespace,
                "result_artifact_path": result_ref.artifact_path,
                "result_sha256": result_ref.sha256,
            }, evidence_ids=(result_ref.evidence_id,))
        self.record_store.put(outcome)
        if signature:
            failures = [
                record for record in self.record_store.list_for_case(task.case_id)
                if record.record_type == OUTCOME_RECORD
                and record.body.get("package_key") == binding.package_key
                and record.body.get("failure_signature") == signature
            ]
            if len(failures) >= self.policy.equivalent_failure_threshold:
                terminal = self._terminal(
                    task, binding, reason="equivalent_failure_circuit_open",
                    scope="role_package",
                    counts={**counts, "role_package_attempts": attempt},
                    failure_signature=signature)
                raise AgentRunStopped(terminal)
        return result
