"""Evidence-backed Terraform remediation planning for validated cases."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .agents import (
    AgentResult, AgentResultStatus, AgentRole, AgentRuntime, AgentTask,
    validate_result,
)
from .cases import CaseState, CaseTransition, ChangePlan, RemediationCase
from .evidence import Collector, write_evidence
from .finding_store import FindingStore
from .hashing import canonical_json, sha256_file
from .intake import numeric_id
from .paths import PathEscape, safe_resolve
from .product_records import ProductRecord, ProductRecordStore
from .terraform_linker import TerraformLink, link_terraform_resource
from .workflow import CaseStore, WorkflowCoordinator


class RemediationPlanningError(RuntimeError):
    pass


def _jsonable(value):
    if isinstance(value, Mapping):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


class TerraformChecksFailed(RemediationPlanningError):
    def __init__(self, record: ProductRecord, checks: tuple["TerraformCheck", ...]):
        self.record = record
        self.checks = checks
        failed = ", ".join(check.name for check in checks if not check.passed)
        super().__init__(f"Terraform verification failed: {failed}")


@dataclass(frozen=True)
class TerraformCheck:
    name: str
    argv: tuple[str, ...]
    exit_code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def passed(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "passed": self.passed,
        }


class TerraformRunner(Protocol):
    def check(self, workspace: Path, link: TerraformLink) -> tuple[TerraformCheck, ...]: ...


class SubprocessTerraformRunner:
    """Run local, non-interactive checks without ambient cloud credentials.

    Provider installation is constrained by the repository lock file. This is
    a development runner; production will execute the same contract in an
    isolated worker rather than in the control-plane process.
    """

    def __init__(self, executable: str = "terraform", *,
                 timeout_seconds: float = 300) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Terraform timeout must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _output(value) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        limit = 1_000_000
        if len(value) <= limit:
            return value
        return value[:limit] + "\n[output truncated by El Capitan]"

    def _run(self, name: str, argv: tuple[str, ...], *, cwd: Path,
             environment: Mapping[str, str]) -> TerraformCheck:
        try:
            completed = subprocess.run(
                argv, cwd=cwd, env=dict(environment), text=True,
                capture_output=True, check=False, timeout=self.timeout_seconds,
            )
            return TerraformCheck(
                name=name, argv=argv, exit_code=completed.returncode,
                stdout=self._output(completed.stdout),
                stderr=self._output(completed.stderr),
            )
        except subprocess.TimeoutExpired as exc:
            return TerraformCheck(
                name=name, argv=argv, exit_code=124,
                stdout=self._output(exc.stdout),
                stderr=(self._output(exc.stderr) +
                        f"\nTerraform command timed out after {self.timeout_seconds}s").strip(),
            )
        except OSError as exc:
            return TerraformCheck(name=name, argv=argv, exit_code=127, stderr=str(exc))

    def check(self, workspace: Path, link: TerraformLink) -> tuple[TerraformCheck, ...]:
        module = safe_resolve(workspace, link.module_path)
        source = safe_resolve(workspace, link.source_path)
        relative_source = source.relative_to(module).as_posix()
        isolated_home = workspace / ".elcapitan-home"
        isolated_home.mkdir()
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(isolated_home),
            "AZURE_CONFIG_DIR": str(isolated_home / ".azure"),
            "AWS_CONFIG_FILE": str(isolated_home / "aws-config"),
            "AWS_SHARED_CREDENTIALS_FILE": str(isolated_home / "aws-credentials"),
            "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1",
            "TF_INPUT": "0",
        }
        commands = (
            ("fmt", (self.executable, "fmt", "-check", "-diff", relative_source)),
            (
                "init",
                (
                    self.executable, "init", "-backend=false", "-input=false",
                    "-lockfile=readonly", "-no-color",
                ),
            ),
            ("validate", (self.executable, "validate", "-no-color")),
            (
                "plan",
                (
                    self.executable, "plan", "-input=false", "-lock=false",
                    "-refresh=false", "-no-color", "-out=.elcapitan-plan.tfplan",
                ),
            ),
        )
        results: list[TerraformCheck] = []
        for name, argv in commands:
            result = self._run(name, argv, cwd=module, environment=environment)
            if (name == "plan" and result.passed
                    and not (module / ".elcapitan-plan.tfplan").is_file()):
                result = TerraformCheck(
                    name=name, argv=argv, exit_code=1,
                    stdout=result.stdout,
                    stderr=(result.stderr + "\nterraform exited successfully but did not "
                            "create the requested plan artifact").strip(),
                )
            results.append(result)
            if not result.passed:
                break
        return tuple(results)


class RecordedAgentRuntime:
    """Adapter for a previously produced agent result supplied as JSON.

    This makes the deterministic product path usable before a model-provider
    adapter is selected.  Task and case identity are supplied by the product,
    not trusted from the file.
    """

    def __init__(self, document: Mapping, *, now: Callable[[], str]) -> None:
        self.document = dict(document)
        self.now = now

    @property
    def name(self) -> str:
        return str(self.document.get("runtime") or "recorded-agent-result")

    def run(self, task: AgentTask) -> AgentResult:
        output = self.document.get("output", self.document)
        if not isinstance(output, Mapping):
            raise RemediationPlanningError("recorded agent output must be an object")
        status = AgentResultStatus(self.document.get("status", "succeeded"))
        cited = self.document.get("evidence_cited", task.evidence_ids)
        missing = self.document.get("missing_evidence", ())
        now = self.now()
        return AgentResult(
            task_id=task.task_id,
            case_id=task.case_id,
            role=task.role,
            status=status,
            output=output,
            evidence_cited=tuple(cited),
            missing_evidence=tuple(missing),
            runtime=self.name,
            model=str(self.document.get("model") or "unspecified"),
            started_at=str(self.document.get("started_at") or now),
            completed_at=str(self.document.get("completed_at") or now),
            usage=self.document.get("usage", {}),
        )


@dataclass(frozen=True)
class RemediationPlanOutcome:
    case: RemediationCase
    link: TerraformLink
    link_record: ProductRecord
    plan_record: ProductRecord
    checks: tuple[TerraformCheck, ...]


def _copy_repository(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git", ".terraform", ".venv", ".tox", ".pytest_cache", "__pycache__",
        ".env", ".env.*", "*.tfstate", "*.tfstate.*", "*.pem", "*.key",
        ".elcapitan*",
    )
    shutil.copytree(source, destination, symlinks=True, ignore=ignored)
    for current, directories, names in os.walk(destination, followlinks=False):
        current_path = Path(current)
        for name in (*directories, *names):
            candidate = current_path / name
            if candidate.is_symlink():
                raise RemediationPlanningError(
                    f"repository workspace contains unsupported symlink: "
                    f"{candidate.relative_to(destination)}"
                )


def _string_tuple(output: Mapping, name: str, *, required: bool = True) -> tuple[str, ...]:
    value = output.get(name)
    if value is None and not required:
        return ()
    if not isinstance(value, (list, tuple)) or any(
            not isinstance(item, str) or not item.strip() for item in value):
        raise RemediationPlanningError(
            f"agent output {name!r} must be a list of non-empty strings"
        )
    if required and not value:
        raise RemediationPlanningError(f"agent output {name!r} cannot be empty")
    return tuple(value)


def _agent_plan(output: Mapping, *, plan_id: str, change_ref: str,
                evidence_ids: tuple[str, ...]) -> ChangePlan:
    objective = output.get("objective")
    if not isinstance(objective, str) or not objective.strip():
        raise RemediationPlanningError("agent output 'objective' must be a non-empty string")
    return ChangePlan(
        plan_id=plan_id,
        objective=objective,
        change_ref=change_ref,
        prerequisites=_string_tuple(output, "prerequisites", required=False),
        steps=_string_tuple(output, "steps"),
        rollout_steps=_string_tuple(output, "rollout_steps"),
        verification_steps=_string_tuple(output, "verification_steps"),
        rollback_steps=_string_tuple(output, "rollback_steps"),
        rollback_triggers=_string_tuple(output, "rollback_triggers"),
        blast_radius=_string_tuple(output, "blast_radius", required=False),
        evidence_ids=evidence_ids,
    )


def _plan_to_dict(plan: ChangePlan) -> dict:
    return {
        "plan_id": plan.plan_id,
        "objective": plan.objective,
        "change_ref": plan.change_ref,
        "prerequisites": list(plan.prerequisites),
        "steps": list(plan.steps),
        "rollout_steps": list(plan.rollout_steps),
        "verification_steps": list(plan.verification_steps),
        "rollback_steps": list(plan.rollback_steps),
        "rollback_triggers": list(plan.rollback_triggers),
        "blast_radius": list(plan.blast_radius),
        "evidence_ids": list(plan.evidence_ids),
    }


class RemediationPlanningService:
    def __init__(self, *, case_store: CaseStore, finding_store: FindingStore,
                 record_store: ProductRecordStore, artifact_root,
                 runtime: AgentRuntime, runner: TerraformRunner,
                 now: Callable[[], str], id_factory: Callable[[str], str] = numeric_id,
                 linker: Callable[..., TerraformLink] = link_terraform_resource) -> None:
        self.case_store = case_store
        self.finding_store = finding_store
        self.record_store = record_store
        self.artifact_root = Path(artifact_root)
        self.runtime = runtime
        self.runner = runner
        self.now = now
        self.id_factory = id_factory
        self.linker = linker
        self.workflow = WorkflowCoordinator(case_store)
        self.collector = Collector(
            tool="elcapitan-remediation-planner", version="0.1.0",
            identity="planning-control-plane",
        )

    def prepare(self, case_id: str, *, repository,
                state_document: Mapping | None = None) -> RemediationPlanOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.VALIDATED:
            raise RemediationPlanningError(
                f"case {case_id} must be validated before planning; current state is {case.state}"
            )
        findings = self.finding_store.list_for_case(case_id)
        if not findings:
            raise RemediationPlanningError(f"case {case_id} has no persisted findings")
        identities = {(finding.provider, finding.resource_uid) for finding in findings}
        if len(identities) != 1:
            raise RemediationPlanningError(
                "the first planning slice requires all case findings to target one resource"
            )
        provider, resource_uid = next(iter(identities))
        repository_root = Path(repository).resolve(strict=True)
        artifact_root = self.artifact_root.resolve(strict=False)
        if artifact_root.is_relative_to(repository_root):
            raise RemediationPlanningError(
                "artifact_root cannot be inside the source repository"
            )
        link = self.linker(
            repository_root, provider=provider, resource_uid=resource_uid,
            state_document=state_document,
        )

        validation_id = case.record_ids.get("validation_result_id")
        if not validation_id:
            raise RemediationPlanningError("validated case has no validation result record")
        validation = self.record_store.get(validation_id)
        if validation.case_id != case_id or validation.record_type != "ValidationResult.v1":
            raise RemediationPlanningError("case validation record has the wrong owner or type")

        plan_id = self.id_factory("PLAN")
        link_id = self.id_factory("LINK")
        task_id = self.id_factory("TASK")
        now = self.now()
        namespace = f"cases/{case_id}/planning/{plan_id}"
        run_dir = self.artifact_root / namespace
        run_dir.mkdir(parents=True, exist_ok=False)

        source_path = safe_resolve(repository_root, link.source_path)
        source_ref = write_evidence(
            run_dir, self.id_factory("EVD"), "terraform_source_before",
            source_path.read_bytes(), self.collector, now=now,
        )
        link_ref = write_evidence(
            run_dir, self.id_factory("EVD"), "terraform_resource_link",
            canonical_json(link.to_dict()), self.collector, now=now,
        )
        link_record = ProductRecord(
            record_id=link_id, case_id=case_id, record_type="IaCLink.v1",
            schema_version=1, created_at=now,
            body={
                "link_id": link_id,
                "repository": repository_root.name,
                "link": link.to_dict(),
                "artifact_namespace": namespace,
            },
            evidence_ids=(source_ref.evidence_id, link_ref.evidence_id),
        )
        self.record_store.put(link_record)

        input_evidence = tuple(dict.fromkeys((
            *validation.evidence_ids, source_ref.evidence_id, link_ref.evidence_id,
        )))
        task = AgentTask(
            task_id=task_id,
            case_id=case_id,
            role=AgentRole.REMEDIATION_ENGINEER,
            objective="Prepare a minimal Terraform remediation and reversible rollout plan",
            output_contract="TerraformRemediationProposal.v1",
            input_record_ids=(validation_id, link_id),
            evidence_ids=input_evidence,
            constraints=(
                "modify only the linked Terraform source file",
                "do not apply infrastructure changes",
                "include verification, rollback steps, and rollback triggers",
            ),
            metadata={
                "provider": provider,
                "resource_uid": resource_uid,
                "link": link.to_dict(),
                "source": source_path.read_text(encoding="utf-8"),
                "findings": [finding.record for finding in findings],
                "validation": validation.body,
            },
        )
        result = self.runtime.run(task)
        failures = validate_result(task, result)
        if failures:
            raise RemediationPlanningError("; ".join(failures))
        if result.status is not AgentResultStatus.SUCCEEDED:
            detail = ", ".join(result.missing_evidence) or result.status.value
            raise RemediationPlanningError(f"remediation agent did not succeed: {detail}")
        if source_ref.evidence_id not in result.evidence_cited:
            raise RemediationPlanningError(
                "successful remediation agent did not cite the linked Terraform source"
            )

        files = result.output.get("files")
        if not isinstance(files, Mapping) or set(files) != {link.source_path}:
            raise RemediationPlanningError(
                f"agent must replace exactly the linked file {link.source_path!r}"
            )
        replacement = files[link.source_path]
        if not isinstance(replacement, str) or not replacement:
            raise RemediationPlanningError("replacement Terraform source must be non-empty text")
        if len(replacement.encode("utf-8")) > 2 * 1024 * 1024:
            raise RemediationPlanningError("replacement Terraform source exceeds 2 MiB")

        workspace = run_dir / "workspace"
        _copy_repository(repository_root, workspace)
        try:
            workspace_source = safe_resolve(workspace, link.source_path)
        except PathEscape as exc:
            raise RemediationPlanningError(str(exc)) from exc
        before_sha256 = sha256_file(workspace_source)
        if before_sha256 != link.source_sha256:
            raise RemediationPlanningError("linked source changed while the plan was prepared")
        workspace_source.write_text(replacement, encoding="utf-8")
        after_sha256 = sha256_file(workspace_source)
        if after_sha256 == before_sha256:
            raise RemediationPlanningError("agent replacement does not change the linked source")

        proposal_ref = write_evidence(
            run_dir, self.id_factory("EVD"), "remediation_agent_result",
            canonical_json({
                "runtime": result.runtime,
                "model": result.model,
                "output": _jsonable(result.output),
                "evidence_cited": list(result.evidence_cited),
                "usage": _jsonable(result.usage),
            }),
            self.collector, now=now,
        )
        change_ref = (
            f"{namespace}/workspace/{link.source_path}#sha256:{after_sha256}"
        )
        checks = self.runner.check(workspace, link)
        if not checks:
            raise RemediationPlanningError("Terraform runner returned no checks")
        check_evidence = []
        for check in checks:
            ref = write_evidence(
                run_dir, self.id_factory("EVD"), f"terraform_{check.name}",
                canonical_json(check.to_dict()), self.collector, now=now,
            )
            check_evidence.append(ref.evidence_id)

        plan_evidence = tuple(dict.fromkeys((
            *input_evidence, proposal_ref.evidence_id, *check_evidence,
        )))
        plan = _agent_plan(
            result.output, plan_id=plan_id, change_ref=change_ref,
            evidence_ids=plan_evidence,
        )
        body = {
            "status": "verified" if all(check.passed for check in checks) else "rejected",
            "plan": _plan_to_dict(plan),
            "link_record_id": link_id,
            "task": {
                "task_id": task_id,
                "runtime": result.runtime,
                "model": result.model,
                "evidence_cited": list(result.evidence_cited),
                "usage": dict(result.usage),
            },
            "change": {
                "source_path": link.source_path,
                "before_sha256": before_sha256,
                "after_sha256": after_sha256,
            },
            "checks": [check.to_dict() for check in checks],
            "artifact_namespace": namespace,
        }
        record = ProductRecord(
            record_id=plan_id, case_id=case_id,
            record_type=("RemediationPlan.v1" if all(check.passed for check in checks)
                         else "RemediationPlanAttempt.v1"),
            schema_version=1, created_at=now, body=body,
            evidence_ids=plan_evidence,
        )
        self.record_store.put(record)
        if not all(check.passed for check in checks):
            raise TerraformChecksFailed(record, checks)

        case = self.workflow.advance(
            case_id, CaseTransition.PREPARE_PLAN,
            event_id=self.id_factory("EVT"), occurred_at=now,
            actor="remediation-planner",
            record_ids={"change_plan_id": plan_id, "iac_link_id": link_id},
            evidence_ids=plan_evidence,
            change_plan=plan,
        )
        return RemediationPlanOutcome(
            case=case, link=link, link_record=link_record,
            plan_record=record, checks=checks,
        )
