"""Evidence-backed Terraform remediation planning for validated cases."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .agent_contracts import validate_output
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


_CONTROL_RESOURCE_TYPES = {
    ("aws", "s3_bucket_object_versioning"): ("aws_s3_bucket_versioning",),
}


def _planning_resource_types(provider: str, rule_ids: set[str]) -> tuple[str, ...]:
    selected = {
        resource_type
        for rule_id in rule_ids
        for resource_type in _CONTROL_RESOURCE_TYPES.get((provider, rule_id), ())
    }
    return tuple(sorted(selected))


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
    def check(self, workspace: Path, link: TerraformLink, *,
              state_document: Mapping | None = None
              ) -> tuple[TerraformCheck, ...]: ...


@contextmanager
def _container_apps_identity_proxy(endpoint: str, identity_header: str,
                                   client_id: str):
    """Bridge AzureRM's IMDS request to the ACA header-authenticated endpoint."""
    if not endpoint or not identity_header:
        yield ""
        return
    parsed_endpoint = urllib.parse.urlsplit(endpoint)
    if (parsed_endpoint.scheme not in {"http", "https"}
            or parsed_endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}):
        raise RemediationPlanningError(
            "Container Apps managed-identity endpoint must be loopback-only")
    if not client_id:
        raise RemediationPlanningError(
            "Container Apps managed-identity proxy requires the planner client ID")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            query = urllib.parse.parse_qs(
                urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
            resource = (query.get("resource") or [""])[0]
            requested_client = (query.get("client_id") or [client_id])[0]
            audience_allowed = resource.rstrip("/") in {
                "https://graph.microsoft.com",
                "https://management.azure.com",
                "https://management.core.windows.net",
            }
            client_allowed = requested_client == client_id
            if not audience_allowed or not client_allowed:
                reported_resource = (
                    resource if resource.startswith("https://")
                    and len(resource) <= 256
                    and not any(character in resource for character in "\r\n")
                    else "[invalid]"
                )
                body = json.dumps({"error": {
                    "code": "IdentityRequestDenied",
                    "audience_allowed": audience_allowed,
                    "client_allowed": client_allowed,
                    "query_keys": sorted(query),
                    "resource": reported_resource,
                }}, sort_keys=True, separators=(",", ":")).encode()
                self._send(403, body)
                return
            upstream_query = urllib.parse.urlencode({
                "resource": resource,
                "api-version": "2019-08-01",
                "client_id": client_id,
            })
            separator = "&" if parsed_endpoint.query else "?"
            request = urllib.request.Request(
                endpoint + separator + upstream_query,
                headers={"X-IDENTITY-HEADER": identity_header},
            )
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    body = response.read(1024 * 1024 + 1)
                    status = response.status
            except urllib.error.HTTPError as error:
                body = error.read(1024 * 1024 + 1)
                status = error.code
            except (OSError, urllib.error.URLError):
                self._send(
                    502, b'{"error":{"code":"IdentityProxyUnavailable"}}')
                return
            if len(body) > 1024 * 1024:
                self._send(502, b'{"error":{"code":"IdentityResponseTooLarge"}}')
                return
            self._send(status, body)

        def _send(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/msi/token"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class SubprocessTerraformRunner:
    """Run non-interactive checks with an explicit planning identity only.

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

    @staticmethod
    def _raw_state(document: Mapping | None) -> bool:
        return bool(
            isinstance(document, Mapping)
            and isinstance(document.get("version"), int)
            and isinstance(document.get("resources"), list)
        )

    @staticmethod
    def _redact_output(value: str) -> str:
        assigned_secret = re.compile(
            r'''(?ix)
            (
              ["']?(?:access[_. -]?key|connection[_. -]?string|
                client[_. -]?secret|password|access[_. -]?token|token)["']?
              \s*[:=]\s*
            )
            (?:["'][^"'\n]*["']|[^\s,;}]+)
            ''')
        jwt = re.compile(r"\beyJ[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]+){1,2}\b")
        redacted = assigned_secret.sub(r'\1"[redacted]"', value)
        return jwt.sub("[redacted JWT]", redacted)

    @classmethod
    def _changed_paths(cls, before, after, *, prefix: str = "") -> tuple[str, ...]:
        """Return stable leaf paths without serializing before/after values."""
        if isinstance(before, Mapping) and isinstance(after, Mapping):
            paths = []
            for key in sorted(set(before) | set(after)):
                child = f"{prefix}.{key}" if prefix else str(key)
                if key not in before or key not in after:
                    paths.append(child)
                else:
                    paths.extend(cls._changed_paths(
                        before[key], after[key], prefix=child))
            return tuple(paths)
        if isinstance(before, list) and isinstance(after, list):
            if len(before) != len(after):
                return (prefix,)
            paths = []
            for index, (before_item, after_item) in enumerate(zip(before, after)):
                child = f"{prefix}[{index}]"
                paths.extend(cls._changed_paths(
                    before_item, after_item, prefix=child))
            return tuple(paths)
        return () if before == after else (prefix,)

    @staticmethod
    def _allowed_target_change(target: str, change: Mapping,
                               changed_paths: tuple[str, ...]) -> bool:
        """Fail closed around exact, separately admitted control changes."""
        resource_type = target.split(".", 1)[0]
        before, after = change.get("before"), change.get("after")
        if not isinstance(before, Mapping) or not isinstance(after, Mapping):
            return False
        if resource_type == "azurerm_storage_account":
            return (
                changed_paths == ("public_network_access_enabled",)
                and before.get("public_network_access_enabled") is True
                and after.get("public_network_access_enabled") is False
            )
        if resource_type == "aws_s3_bucket_versioning":
            before_configuration = before.get("versioning_configuration")
            after_configuration = after.get("versioning_configuration")
            return (
                changed_paths == ("versioning_configuration[0].status",)
                and isinstance(before_configuration, list)
                and len(before_configuration) == 1
                and isinstance(before_configuration[0], Mapping)
                and before_configuration[0].get("status") in {
                    "Disabled", "Suspended"}
                and isinstance(after_configuration, list)
                and len(after_configuration) == 1
                and isinstance(after_configuration[0], Mapping)
                and after_configuration[0].get("status") == "Enabled"
            )
        return False

    @staticmethod
    def _scope_requirement(target: str) -> str:
        resource_type = target.split(".", 1)[0]
        if resource_type == "aws_s3_bucket_versioning":
            return (
                "plan must contain exactly one in-place S3 bucket-versioning "
                "status update from Disabled or Suspended to Enabled")
        return (
            "plan must contain exactly the allowed public-network-access "
            "update to the linked storage account")

    def _plan_scope(self, *, plan_path: Path, target: str, cwd: Path,
                    environment: Mapping[str, str]) -> TerraformCheck:
        argv = (self.executable, "show", "-json", str(plan_path))
        try:
            completed = subprocess.run(
                argv, cwd=cwd, env=dict(environment), text=True,
                capture_output=True, check=False, timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return TerraformCheck(
                "plan_scope", (self.executable, "show", "-json", "[EPHEMERAL_PLAN]"),
                124, stderr="Terraform plan inspection timed out")
        except OSError as exc:
            return TerraformCheck(
                "plan_scope", (self.executable, "show", "-json", "[EPHEMERAL_PLAN]"),
                127, stderr=str(exc))
        normalized_argv = (
            self.executable, "show", "-json", "[EPHEMERAL_PLAN]")
        if completed.returncode != 0:
            return TerraformCheck(
                "plan_scope", normalized_argv, completed.returncode,
                stderr=self._redact_output(self._output(completed.stderr)))
        try:
            document = json.loads(completed.stdout)
        except (json.JSONDecodeError, RecursionError) as exc:
            return TerraformCheck(
                "plan_scope", normalized_argv, 1,
                stderr=f"Terraform plan JSON was invalid: {exc}")
        changes = []
        target_change = None
        for item in document.get("resource_changes", ()):
            if not isinstance(item, Mapping):
                continue
            change = item.get("change") or {}
            actions = list(change.get("actions") or ())
            if actions != ["no-op"]:
                changed_paths = self._changed_paths(
                    change.get("before"), change.get("after"))
                changes.append({
                    "address": str(item.get("address", "")),
                    "actions": actions,
                    "changed_attribute_paths": list(changed_paths),
                })
                if item.get("address") == target:
                    target_change = (change, changed_paths)
        structural_scope = (
            len(changes) == 1
            and changes[0]["address"] == target
            and changes[0]["actions"] == ["update"]
        )
        attribute_scope = bool(
            structural_scope
            and target_change
            and self._allowed_target_change(target, *target_change)
        )
        passed = structural_scope and attribute_scope
        summary = {
            "required_target": target,
            "observed_changes": changes,
            "creates": sum("create" in item["actions"] for item in changes),
            "updates": sum("update" in item["actions"] for item in changes),
            "deletes": sum("delete" in item["actions"] for item in changes),
            "attribute_scope_passed": attribute_scope,
            "passed": passed,
        }
        return TerraformCheck(
            "plan_scope", normalized_argv, 0 if passed else 1,
            stdout=json.dumps(summary, sort_keys=True, separators=(",", ":")),
            stderr=(self._scope_requirement(target) if not passed else ""),
        )

    def check(self, workspace: Path, link: TerraformLink, *,
              state_document: Mapping | None = None
              ) -> tuple[TerraformCheck, ...]:
        module = safe_resolve(workspace, link.module_path)
        source = safe_resolve(workspace, link.source_path)
        relative_source = source.relative_to(module).as_posix()
        identity_endpoint = os.environ.get("IDENTITY_ENDPOINT", "")
        identity_header = os.environ.get("IDENTITY_HEADER", "")
        planner_client_id = os.environ.get(
            "ELCAP_PLANNER_AZURE_MANAGED_IDENTITY_CLIENT_ID", "")
        with (tempfile.TemporaryDirectory(prefix="elcapitan-terraform-") as temporary,
              _container_apps_identity_proxy(
                  identity_endpoint, identity_header, planner_client_id) as proxy_endpoint):
            isolated = Path(temporary)
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(isolated / "home"),
                "AZURE_CONFIG_DIR": str(isolated / "azure"),
                "AWS_CONFIG_FILE": str(isolated / "aws-config"),
                "AWS_SHARED_CREDENTIALS_FILE": str(isolated / "aws-credentials"),
                "TF_DATA_DIR": str(isolated / "terraform-data"),
                "TF_IN_AUTOMATION": "1",
                "CHECKPOINT_DISABLE": "1",
                "TF_INPUT": "0",
            }
            # Only the explicitly configured identity for this provider may cross
            # into Terraform. Ambient scanner, observer, and user credentials stay out.
            planning_environment = {}
            if link.resource_type.startswith("aws_"):
                aws_mapping = {
                    "AWS_ACCESS_KEY_ID": "ELCAP_PLANNER_AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY": "ELCAP_PLANNER_AWS_SECRET_ACCESS_KEY",
                    "AWS_SESSION_TOKEN": "ELCAP_PLANNER_AWS_SESSION_TOKEN",
                }
                missing = sorted(
                    source for source in aws_mapping.values()
                    if not os.environ.get(source))
                if missing:
                    return (TerraformCheck(
                        "plan", (self.executable, "plan"), 1,
                        stderr=("AWS planning credentials are not set: "
                                + ", ".join(missing))),)
                planning_environment.update({
                    target: os.environ[source]
                    for target, source in aws_mapping.items()
                })
            else:
                planning_environment = {
                    "ARM_USE_MSI": os.environ.get(
                        "ELCAP_PLANNER_AZURE_USE_MSI", ""),
                    "ARM_CLIENT_ID": planner_client_id,
                    "ARM_SUBSCRIPTION_ID": os.environ.get(
                        "ELCAP_PLANNER_AZURE_SUBSCRIPTION_ID", ""),
                    "ARM_TENANT_ID": os.environ.get(
                        "ELCAP_PLANNER_AZURE_TENANT_ID", ""),
                    # Container Apps exposes an App Service-style identity endpoint,
                    # while AzureRM otherwise falls back to the VM IMDS address.
                    "ARM_MSI_ENDPOINT": os.environ.get(
                        "ELCAP_PLANNER_AZURE_MSI_ENDPOINT", "") or proxy_endpoint,
                    "ARM_MSI_API_VERSION": os.environ.get(
                        "ELCAP_PLANNER_AZURE_MSI_API_VERSION", "") or (
                            "2019-08-01" if identity_endpoint else ""),
                    "IDENTITY_ENDPOINT": os.environ.get("IDENTITY_ENDPOINT", ""),
                    "IDENTITY_HEADER": os.environ.get("IDENTITY_HEADER", ""),
                }
            environment.update({
                key: value for key, value in planning_environment.items() if value
            })
            plan_path = isolated / "target.tfplan"
            raw_state = self._raw_state(state_document)
            if raw_state and not link.resource_address:
                return (TerraformCheck(
                    "plan", (self.executable, "plan"), 1,
                    stderr="state-grounded planning requires an exact resource address"),)
            plan_args = [
                self.executable, "plan", "-input=false", "-lock=false",
                "-refresh=false", "-no-color",
            ]
            if raw_state:
                state_path = isolated / "input.tfstate"
                state_path.write_bytes(canonical_json(state_document))
                plan_args.extend((f"-state={state_path}",
                                  f"-target={link.resource_address}"))
            plan_args.append(f"-out={plan_path}")
            commands = (
                ("fmt", (self.executable, "fmt", "-check", "-diff", relative_source)),
                ("init", (self.executable, "init", "-backend=false", "-input=false",
                          "-lockfile=readonly", "-no-color")),
                ("validate", (self.executable, "validate", "-no-color")),
                ("plan", tuple(plan_args)),
            )
            results: list[TerraformCheck] = []
            for name, argv in commands:
                result = self._run(name, argv, cwd=module, environment=environment)
                if name == "plan":
                    normalized = tuple(
                        "-state=[EPHEMERAL_STATE]" if item.startswith("-state=")
                        else "-out=[EPHEMERAL_PLAN]" if item.startswith("-out=")
                        else item for item in argv)
                    if result.passed:
                        result = TerraformCheck(
                            name, normalized, result.exit_code,
                            stdout="Terraform created an ephemeral plan for policy inspection.",
                            stderr=self._redact_output(result.stderr))
                    else:
                        result = TerraformCheck(
                            name, normalized, result.exit_code,
                            stdout=self._redact_output(result.stdout),
                            stderr=self._redact_output(result.stderr))
                    if result.passed and not plan_path.is_file():
                        result = TerraformCheck(
                            name, normalized, 1, stdout=result.stdout,
                            stderr="Terraform exited successfully without a plan artifact")
                results.append(result)
                if not result.passed:
                    break
            if results and results[-1].name == "plan" and results[-1].passed and raw_state:
                results.append(self._plan_scope(
                    plan_path=plan_path, target=link.resource_address,
                    cwd=module, environment=environment))
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


def _materialize_control_patch(*, original: str, proposed: str,
                               link: TerraformLink,
                               rule_ids: set[str]) -> tuple[str, str]:
    """Materialize supported edits deterministically instead of trusting model text."""
    if (link.resource_type == "azurerm_storage_account"
            and rule_ids == {"storage_account_public_network_access_disabled"}):
        proposed_assignment = re.compile(
            r"(?m)^\s*public_network_access_enabled\s*=\s*false\s*(?:#.*)?$")
        if not proposed_assignment.search(proposed):
            raise RemediationPlanningError(
                "agent proposal did not request public_network_access_enabled = false")
        current_assignment = re.compile(
            r"(?m)^(?P<prefix>\s*public_network_access_enabled\s*=\s*)"
            r"true(?P<suffix>\s*(?:#.*)?)$")
        replacement, count = current_assignment.subn(
            r"\g<prefix>false\g<suffix>", original)
        if count != 1:
            raise RemediationPlanningError(
                "linked source must contain exactly one literal "
                "public_network_access_enabled = true assignment")
        return replacement, "deterministic_control_patch"
    if (link.resource_type == "aws_s3_bucket_versioning"
            and rule_ids == {"s3_bucket_object_versioning"}):
        proposed_assignment = re.compile(
            r'(?m)^\s*status\s*=\s*"Enabled"\s*(?:#.*)?$')
        if not proposed_assignment.search(proposed):
            raise RemediationPlanningError(
                'agent proposal did not request versioning status = "Enabled"')
        lines = original.splitlines(keepends=True)
        start, end = link.start_line - 1, link.end_line
        linked_block = "".join(lines[start:end])
        current_assignment = re.compile(
            r'(?m)^(?P<prefix>\s*status\s*=\s*)'
            r'"(?:Disabled|Suspended)"(?P<suffix>\s*(?:#.*)?)$')
        replacement_block, count = current_assignment.subn(
            r'\g<prefix>"Enabled"\g<suffix>', linked_block)
        if count != 1:
            raise RemediationPlanningError(
                "linked S3 versioning resource must contain exactly one literal "
                'status = "Disabled" or status = "Suspended" assignment')
        return (
            "".join((*lines[:start], replacement_block, *lines[end:])),
            "deterministic_control_patch",
        )
    return proposed, "agent_source_replacement"


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
                state_document: Mapping | None = None,
                finding_ids: tuple[str, ...] | None = None,
                ) -> RemediationPlanOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.VALIDATED:
            raise RemediationPlanningError(
                f"case {case_id} must be validated before planning; current state is {case.state}"
            )
        all_findings = self.finding_store.list_for_case(case_id)
        if not all_findings:
            raise RemediationPlanningError(f"case {case_id} has no persisted findings")
        by_id = {finding.finding_id: finding for finding in all_findings}
        if finding_ids is None:
            findings = all_findings
        else:
            requested_ids = tuple(dict.fromkeys(finding_ids))
            if not requested_ids:
                raise RemediationPlanningError(
                    "planning scope must contain at least one finding")
            missing = sorted(set(requested_ids) - set(by_id))
            if missing:
                raise RemediationPlanningError(
                    "planning scope contains finding(s) outside the case: "
                    + ", ".join(missing))
            findings = tuple(by_id[finding_id] for finding_id in requested_ids)
        identities = {(finding.provider, finding.resource_uid) for finding in findings}
        if len(identities) != 1:
            raise RemediationPlanningError(
                "the first planning slice requires all case findings to target one resource"
            )
        provider, resource_uid = next(iter(identities))

        validation_id = case.record_ids.get("validation_result_id")
        if not validation_id:
            raise RemediationPlanningError("validated case has no validation result record")
        validation = self.record_store.get(validation_id)
        if validation.case_id != case_id or validation.record_type != "ValidationResult.v1":
            raise RemediationPlanningError("case validation record has the wrong owner or type")
        validation_findings = {
            str(item.get("finding_id", "")): item
            for item in validation.body.get("findings", ())
            if isinstance(item, Mapping)
        }
        not_confirmed = sorted(
            finding.finding_id for finding in findings
            if str(validation_findings.get(finding.finding_id, {}).get(
                "status", "")) != "confirmed")
        if not_confirmed:
            raise RemediationPlanningError(
                "planning scope contains finding(s) not confirmed by live validation: "
                + ", ".join(not_confirmed))

        repository_root = Path(repository).resolve(strict=True)
        artifact_root = self.artifact_root.resolve(strict=False)
        if artifact_root.is_relative_to(repository_root):
            raise RemediationPlanningError(
                "artifact_root cannot be inside the source repository"
            )
        rule_ids = {
            str(item.record["ocsf"].get("rule_id", "")) for item in findings
        }
        link = self.linker(
            repository_root, provider=provider, resource_uid=resource_uid,
            state_document=state_document,
            resource_types=_planning_resource_types(provider, rule_ids),
        )

        feedback = None
        feedback_id = case.record_ids.get("review_feedback_id")
        if feedback_id:
            feedback = self.record_store.get(feedback_id)
            if (feedback.case_id != case_id
                    or feedback.record_type != "RollbackReview.v1"):
                raise RemediationPlanningError(
                    "review feedback record has the wrong owner or type")
            required_changes = feedback.body.get("required_changes")
            if (not isinstance(required_changes, (list, tuple))
                    or not required_changes
                    or any(not isinstance(item, str) or not item.strip()
                           for item in required_changes)):
                raise RemediationPlanningError(
                    "review feedback has no concrete required changes")

        plan_id = self.id_factory("PLAN")
        link_id = self.id_factory("LINK")
        task_id = self.id_factory("TASK")
        now = self.now()
        namespace = f"cases/{case_id}/planning/{plan_id}"
        run_dir = self.artifact_root / namespace
        run_dir.mkdir(parents=True, exist_ok=False)

        source_path = safe_resolve(repository_root, link.source_path)
        original_source = source_path.read_text(encoding="utf-8")
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

        scoped_validation_evidence = (
            tuple(validation.evidence_ids) if finding_ids is None else
            tuple(dict.fromkeys(
                str(evidence_id)
                for finding in findings
                for evidence_id in validation_findings[
                    finding.finding_id].get("evidence_ids", ())
                if isinstance(evidence_id, str) and evidence_id
            ))
        )
        input_evidence = tuple(dict.fromkeys((
            *scoped_validation_evidence,
            source_ref.evidence_id, link_ref.evidence_id,
            *(feedback.evidence_ids if feedback else ()),
        )))
        input_records = tuple(filter(None, (
            validation_id, link_id, feedback.record_id if feedback else None)))
        feedback_constraints = (() if feedback is None else (
            "This is a bounded checker rework. Address every item in "
            "review_feedback.required_changes explicitly in prerequisites, rollout, "
            "verification, rollback steps, or rollback triggers as appropriate.",
            "Classify pre-mutation guard failures as abort-without-change. Map only "
            "operational harm caused by the applied change to executable rollback. "
            "Map failed apply, failed security validation, recurrence of the original "
            "finding, policy drift, and rollback failure to retry, containment, or "
            "owned escalation without restoring the vulnerable pre-change state.",
        ))
        scoped_validation = dict(validation.body)
        scoped_validation["findings"] = [
            validation_findings[finding.finding_id] for finding in findings]
        task = AgentTask(
            task_id=task_id,
            case_id=case_id,
            role=AgentRole.REMEDIATION_ENGINEER,
            objective="Prepare a minimal Terraform remediation and reversible rollout plan",
            output_contract="TerraformRemediationProposal.v1",
            input_record_ids=input_records,
            evidence_ids=input_evidence,
            constraints=(
                "modify only the linked Terraform source file",
                "do not apply infrastructure changes",
                "include verification, rollback steps, and rollback triggers",
                "return the complete linked file and preserve all unrelated content",
                "do not request post-change state as planning input; express it as a "
                "verification step",
                *feedback_constraints,
            ),
            metadata={
                "provider": provider,
                "resource_uid": resource_uid,
                "link": link.to_dict(),
                "source": original_source,
                "source_evidence_id": source_ref.evidence_id,
                "link_evidence_id": link_ref.evidence_id,
                "findings": [finding.record for finding in findings],
                "validation": scoped_validation,
                "review_feedback": feedback.body if feedback else None,
            },
        )
        result = self.runtime.run(task)
        failures = validate_result(task, result)
        contract_output = _jsonable(result.output)
        if isinstance(contract_output, dict) and isinstance(
                contract_output.get("files"), dict):
            contract_output["files"] = [
                {"path": path, "content": content}
                for path, content in contract_output["files"].items()
            ]
        failures.extend(validate_output(task.output_contract, contract_output))
        if failures:
            raise RemediationPlanningError("; ".join(failures))
        if result.status is not AgentResultStatus.SUCCEEDED:
            detail = ", ".join(result.missing_evidence) or result.status.value
            raise RemediationPlanningError(f"remediation agent did not succeed: {detail}")
        if source_ref.evidence_id not in result.evidence_cited:
            raise RemediationPlanningError(
                "successful remediation agent did not cite the linked Terraform source"
            )

        supplied_files = result.output.get("files")
        if isinstance(supplied_files, Mapping):
            files = dict(supplied_files)
        elif isinstance(supplied_files, (list, tuple)):
            files = {}
            for item in supplied_files:
                if not isinstance(item, Mapping):
                    raise RemediationPlanningError(
                        "agent output files must contain path/content objects"
                    )
                path, content = item.get("path"), item.get("content")
                if not isinstance(path, str) or path in files:
                    raise RemediationPlanningError(
                        "agent output files contain an invalid or duplicate path"
                    )
                files[path] = content
        else:
            files = {}
        if set(files) != {link.source_path}:
            raise RemediationPlanningError(
                f"agent must replace exactly the linked file {link.source_path!r}"
            )
        proposed_replacement = files[link.source_path]
        if not isinstance(proposed_replacement, str) or not proposed_replacement:
            raise RemediationPlanningError("replacement Terraform source must be non-empty text")
        if len(proposed_replacement.encode("utf-8")) > 2 * 1024 * 1024:
            raise RemediationPlanningError("replacement Terraform source exceeds 2 MiB")
        replacement, source_materialization = _materialize_control_patch(
            original=original_source, proposed=proposed_replacement,
            link=link, rule_ids=rule_ids)

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
        checks = self.runner.check(
            workspace, link, state_document=state_document)
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
            "verification": {
                "mode": ("targeted_state_plan"
                         if SubprocessTerraformRunner._raw_state(state_document)
                         else "offline_plan_without_state"),
                "resource_address": link.resource_address,
                "state_sha256": link.state_sha256,
                "plan_artifact_persisted": False,
            },
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
                "materialization": source_materialization,
            },
            "scope": {
                "finding_ids": [finding.finding_id for finding in findings],
                "rule_ids": sorted(rule_ids),
                "resource_uid": resource_uid,
                "validation_record_id": validation_id,
            },
            "checks": [check.to_dict() for check in checks],
            "artifact_namespace": namespace,
            "review_feedback_record_id": feedback.record_id if feedback else None,
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
