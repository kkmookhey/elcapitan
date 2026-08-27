"""Narrow, fail-closed Azure execution adapters.

The first production-shaped connector changes one security property on one
explicitly approved, tagged Azure Storage account.  It intentionally does not
offer a generic ``az`` escape hatch: broad command execution would make the
human-reviewed package meaningless.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol

from .action_plane import (
    ActionStep, DeploymentCheckpoint, ExecutionContext, HealthObservation,
    ProbeResult,
)
from .hashing import canonical_json, sha256_bytes, sha256_file
from .intake import numeric_id
from .paths import PathEscape, safe_resolve
from .terraform_linker import TerraformLinkError, terraform_resource_block


class AzureActionError(RuntimeError):
    pass


@dataclass(frozen=True)
class AzureCommandResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


class AzureCommandRunner(Protocol):
    def run(self, argv: tuple[str, ...]) -> AzureCommandResult: ...


class SubprocessAzureCommandRunner:
    """Execute a bounded Azure CLI command using an already scoped identity."""

    def __init__(self, executable: str = "az", *, timeout_seconds: float = 120,
                 environment: Mapping[str, str] | None = None) -> None:
        if not executable or timeout_seconds <= 0:
            raise ValueError("Azure CLI executable and positive timeout are required")
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.environment = dict(environment) if environment is not None else dict(os.environ)
        # Provider-model and unrelated cloud credentials have no reason to be
        # visible to the Azure deployment process.  Snapshot before a release
        # model key can be loaded later in the workflow, and remove any that
        # were already ambient.
        for name in (
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AZURE_STORAGE_KEY", "AZURE_STORAGE_CONNECTION_STRING",
        ):
            self.environment.pop(name, None)

    @staticmethod
    def _bounded(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return value[:1_000_000]

    def run(self, argv: tuple[str, ...]) -> AzureCommandResult:
        try:
            completed = subprocess.run(
                (self.executable, *argv), capture_output=True, text=True,
                check=False, timeout=self.timeout_seconds,
                env=dict(self.environment),
            )
        except subprocess.TimeoutExpired as exc:
            return AzureCommandResult(
                124, self._bounded(exc.stdout),
                self._bounded(exc.stderr) +
                f"\nAzure CLI timed out after {self.timeout_seconds}s",
            )
        except OSError as exc:
            return AzureCommandResult(127, stderr=str(exc))
        return AzureCommandResult(
            completed.returncode, self._bounded(completed.stdout),
            self._bounded(completed.stderr),
        )


_STORAGE_ID = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)/resourceGroups/(?P<group>[^/]+)/"
    r"providers/Microsoft\.Storage/storageAccounts/(?P<name>[^/]+)$",
    re.IGNORECASE,
)
_PUBLIC_ACCESS = frozenset({"Enabled", "Disabled", "SecuredByPerimeter"})
_CHECKPOINT_FIELDS = (
    "id", "publicNetworkAccess", "allowBlobPublicAccess", "networkRuleSet",
    "minimumTlsVersion", "enableHttpsTrafficOnly", "tags",
)


def _configuration_sha256(document: Mapping) -> str:
    return sha256_bytes(canonical_json({
        key: document.get(key) for key in _CHECKPOINT_FIELDS
    }))


@dataclass(frozen=True)
class AzureStorageIdentity:
    resource_id: str
    subscription_id: str
    resource_group: str
    account_name: str


def parse_storage_account_id(resource_id: str, *,
                             expected_subscription: str) -> AzureStorageIdentity:
    match = _STORAGE_ID.fullmatch(resource_id)
    if not match:
        raise ValueError("resource id is not an Azure Storage account ARM id")
    subscription = match.group("subscription")
    if subscription.lower() != expected_subscription.lower():
        raise ValueError(
            f"Azure target subscription {subscription} is outside the pinned "
            f"subscription {expected_subscription}"
        )
    return AzureStorageIdentity(
        resource_id=resource_id, subscription_id=subscription,
        resource_group=match.group("group"), account_name=match.group("name"),
    )


class AzureStorageAccountClient:
    """Read and narrowly update one pinned, tagged storage account."""

    def __init__(self, resource_id: str, *, expected_subscription: str,
                 required_tags: Mapping[str, str], runner: AzureCommandRunner) -> None:
        if not required_tags:
            raise ValueError("Azure mutation requires at least one scope tag")
        self.identity = parse_storage_account_id(
            resource_id, expected_subscription=expected_subscription)
        self.required_tags = dict(required_tags)
        if any(not key or not value for key, value in self.required_tags.items()):
            raise ValueError("Azure mutation scope tags cannot be empty")
        self.runner = runner

    @property
    def resource_id(self) -> str:
        return self.identity.resource_id

    def _document(self, result: AzureCommandResult, *, operation: str) -> dict:
        if result.exit_code != 0:
            detail = (result.stderr or result.stdout).strip()
            raise AzureActionError(
                f"Azure CLI could not {operation} (exit {result.exit_code}): "
                f"{detail or 'no diagnostic output'}"
            )
        try:
            document = json.loads(result.stdout)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise AzureActionError(
                f"Azure CLI returned invalid JSON while trying to {operation}: {exc}"
            ) from exc
        if not isinstance(document, dict):
            raise AzureActionError(f"Azure CLI returned a non-object while trying to {operation}")
        actual_id = document.get("id")
        if not isinstance(actual_id, str) or actual_id.lower() != self.resource_id.lower():
            raise AzureActionError("Azure CLI response identity does not match the pinned target")
        tags = document.get("tags")
        if not isinstance(tags, Mapping):
            raise AzureActionError("Azure target has no mutation-scope tags")
        missing = [
            f"{key}={value}" for key, value in self.required_tags.items()
            if str(tags.get(key, "")) != value
        ]
        if missing:
            raise AzureActionError(
                "Azure target is outside the permitted mutation scope; missing tags: "
                + ", ".join(missing)
            )
        return document

    def read(self) -> dict:
        result = self.runner.run((
            "storage", "account", "show", "--ids", self.resource_id,
            "--subscription", self.identity.subscription_id,
            "--output", "json", "--only-show-errors",
        ))
        return self._document(result, operation="read the storage account")

    def set_public_network_access(self, value: str) -> dict:
        if value not in _PUBLIC_ACCESS:
            raise AzureActionError(f"unsupported Azure public network access value: {value}")
        result = self.runner.run((
            "storage", "account", "update", "--ids", self.resource_id,
            "--subscription", self.identity.subscription_id,
            "--public-network-access", value,
            "--output", "json", "--only-show-errors",
        ))
        return self._document(result, operation="update public network access")


class AzureStoragePublicNetworkDriver:
    """Disable public network access when the verified Terraform block says so."""

    def __init__(self, client: AzureStorageAccountClient, *,
                 id_factory=numeric_id) -> None:
        self.client = client
        self.id_factory = id_factory

    @property
    def name(self) -> str:
        return "azure-storage-public-network-driver"

    def _replacement_block(self, context: ExecutionContext) -> str:
        link = context.link.body.get("link")
        if not isinstance(link, Mapping):
            raise AzureActionError("IaC link record has no structured link")
        if str(link.get("resource_uid", "")).lower() != self.client.resource_id.lower():
            raise AzureActionError("approved IaC link does not target the pinned Azure resource")
        if link.get("resource_type") != "azurerm_storage_account":
            raise AzureActionError("approved IaC link is not an Azure storage account")
        if context.plan.body.get("status") != "verified":
            raise AzureActionError("Azure execution requires a verified remediation plan")
        namespace = context.plan.body.get("artifact_namespace")
        source_path = context.plan.body.get("change", {}).get("source_path")
        if not isinstance(namespace, str) or not isinstance(source_path, str):
            raise AzureActionError("verified plan has no deployment artifact path")
        try:
            replacement = safe_resolve(
                context.artifact_root, f"{namespace}/workspace/{source_path}")
        except (PathEscape, FileNotFoundError) as exc:
            raise AzureActionError(str(exc)) from exc
        expected = context.plan.body.get("change", {}).get("after_sha256")
        if not replacement.is_file() or not isinstance(expected, str):
            raise AzureActionError("verified replacement or approved hash is missing")
        if sha256_file(replacement) != expected:
            raise AzureActionError("verified Azure replacement hash no longer matches approval")
        try:
            return terraform_resource_block(
                replacement, resource_type=str(link["resource_type"]),
                resource_name=str(link["resource_name"]),
            )
        except (KeyError, TerraformLinkError) as exc:
            raise AzureActionError(str(exc)) from exc

    def preflight(self, context: ExecutionContext) -> ActionStep:
        try:
            block = self._replacement_block(context)
            values = re.findall(
                r"(?m)^\s*public_network_access_enabled\s*=\s*(true|false)\s*(?:#.*)?$",
                block,
            )
            if values != ["false"]:
                raise AzureActionError(
                    "approved Terraform block must set exactly one literal "
                    "public_network_access_enabled = false"
                )
            account = self.client.read()
            current = account.get("publicNetworkAccess")
            if current != "Enabled":
                raise AzureActionError(
                    f"expected vulnerable pre-change value Enabled; observed {current!r}"
                )
        except (AzureActionError, OSError, ValueError) as exc:
            return ActionStep("preflight", False, str(exc))
        return ActionStep(
            "preflight", True,
            "approved Terraform intent, pinned Azure identity, scope tags, and live value match",
            {"resource_id": self.client.resource_id,
             "public_network_access": current,
             "configuration_sha256": _configuration_sha256(account)},
        )

    def checkpoint(self, context: ExecutionContext) -> DeploymentCheckpoint:
        account = self.client.read()
        current = account.get("publicNetworkAccess")
        if current not in _PUBLIC_ACCESS:
            raise AzureActionError("Azure checkpoint has an unsupported public access value")
        return DeploymentCheckpoint(
            checkpoint_id=self.id_factory("AZCHK"),
            detail="captured exact Azure Storage public network access state",
            payload={
                "resource_id": self.client.resource_id,
                "public_network_access": current,
                "configuration_sha256": _configuration_sha256(account),
            },
        )

    def deploy(self, context: ExecutionContext,
               checkpoint: DeploymentCheckpoint) -> ActionStep:
        current = self.client.read()
        if (_configuration_sha256(current) !=
                checkpoint.payload.get("configuration_sha256")
                or current.get("publicNetworkAccess") !=
                checkpoint.payload.get("public_network_access")):
            return ActionStep(
                "deploy", False,
                "Azure resource drifted after checkpoint; refusing mutation",
                {"resource_id": self.client.resource_id},
            )
        updated = self.client.set_public_network_access("Disabled")
        passed = updated.get("publicNetworkAccess") == "Disabled"
        return ActionStep(
            "deploy", passed,
            "Azure Storage public network access disabled" if passed
            else "Azure update returned without the approved state",
            {"resource_id": self.client.resource_id,
             "public_network_access": updated.get("publicNetworkAccess"),
             "configuration_sha256": _configuration_sha256(updated)},
        )

    def rollback(self, context: ExecutionContext,
                 checkpoint: DeploymentCheckpoint) -> ActionStep:
        if str(checkpoint.payload.get("resource_id", "")).lower() != \
                self.client.resource_id.lower():
            return ActionStep("rollback", False, "checkpoint belongs to another resource")
        prior = checkpoint.payload.get("public_network_access")
        if prior not in _PUBLIC_ACCESS:
            return ActionStep("rollback", False, "checkpoint has no restorable Azure value")
        restored = self.client.set_public_network_access(str(prior))
        passed = restored.get("publicNetworkAccess") == prior
        return ActionStep(
            "rollback", passed,
            "Azure Storage checkpoint restored" if passed
            else "Azure Storage rollback verification failed",
            {"resource_id": self.client.resource_id,
             "public_network_access": restored.get("publicNetworkAccess"),
             "configuration_sha256": _configuration_sha256(restored)},
        )


class AzureStorageHealthMonitor:
    def __init__(self, client: AzureStorageAccountClient) -> None:
        self.client = client

    @property
    def name(self) -> str:
        return "azure-storage-control-plane-health"

    def observe(self, phase: str, context: ExecutionContext) -> HealthObservation:
        try:
            account = self.client.read()
        except (AzureActionError, OSError, ValueError) as exc:
            return HealthObservation(False, (f"Azure health read failed: {exc}",), {})
        provisioning = str(account.get("provisioningState") or "")
        primary = str(account.get("statusOfPrimary") or "")
        reasons = []
        if provisioning.lower() != "succeeded":
            reasons.append(f"provisioningState is {provisioning or 'missing'}")
        if primary.lower() != "available":
            reasons.append(f"statusOfPrimary is {primary or 'missing'}")
        return HealthObservation(
            not reasons, tuple(reasons) or (f"Azure storage is healthy during {phase}",),
            {"provisioning_state": provisioning, "status_of_primary": primary,
             "public_network_access": account.get("publicNetworkAccess")},
        )


class AzureStoragePublicNetworkProbe:
    def __init__(self, client: AzureStorageAccountClient) -> None:
        self.client = client

    @property
    def name(self) -> str:
        return "azure-storage-public-network-disabled"

    def run(self, context: ExecutionContext) -> ProbeResult:
        account = self.client.read()
        actual = account.get("publicNetworkAccess")
        passed = actual == "Disabled"
        return ProbeResult(
            probe=self.name, target=self.client.resource_id, passed=passed,
            detail=("public network access is disabled" if passed else
                    "public network access is not disabled"),
            payload={"expected": "Disabled", "actual": actual,
                     "configuration_sha256": _configuration_sha256(account)},
        )
