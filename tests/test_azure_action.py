import json
from pathlib import Path

import pytest

from elcapitan.action_plane import ExecutionContext
from elcapitan.azure_action import (
    AzureActionError, AzureCommandResult, AzureStorageAccountClient,
    AzureStorageBlobPublicAccessDriver, AzureStorageBlobPublicAccessProbe,
    AzureStorageHealthMonitor, AzureStoragePublicNetworkDriver,
    AzureStoragePublicNetworkProbe,
    ManagedIdentityAzureCommandRunner, SubprocessAzureCommandRunner,
    parse_storage_account_id,
)
from elcapitan.cases import CaseState, RemediationCase
from elcapitan.hashing import sha256_file
from elcapitan.product_records import ProductRecord


SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/elcapitan-lab-rg/"
    "providers/Microsoft.Storage/storageAccounts/elcapitanlab"
)


class FakeAzureRunner:
    def __init__(self, *, tags=None):
        self.document = {
            "id": RESOURCE_ID,
            "etag": "etag-1",
            "publicNetworkAccess": "Enabled",
            "allowBlobPublicAccess": True,
            "provisioningState": "Succeeded",
            "statusOfPrimary": "available",
            "tags": tags or {"elcapitan_scope": "lab", "environment": "nonproduction"},
        }
        self.commands = []

    def run(self, argv):
        self.commands.append(argv)
        if argv[:3] == ("storage", "account", "show"):
            return AzureCommandResult(0, json.dumps(self.document))
        if argv[:3] == ("storage", "account", "update"):
            if "--public-network-access" in argv:
                value = argv[argv.index("--public-network-access") + 1]
                self.document["publicNetworkAccess"] = value
            elif "--allow-blob-public-access" in argv:
                value = argv[argv.index("--allow-blob-public-access") + 1]
                self.document["allowBlobPublicAccess"] = value == "true"
            self.document["etag"] = f"etag-{len(self.commands)}"
            return AzureCommandResult(0, json.dumps(self.document))
        return AzureCommandResult(2, stderr="unexpected fake command")


def context(tmp_path: Path, runner: FakeAzureRunner):
    namespace = "cases/CASE-1/planning/PLAN-1"
    replacement = tmp_path / namespace / "workspace" / "main.tf"
    replacement.parent.mkdir(parents=True)
    replacement.write_text(
        'resource "azurerm_storage_account" "lab" {\n'
        '  name                          = "elcapitanlab"\n'
        '  resource_group_name           = "elcapitan-lab-rg"\n'
        '  public_network_access_enabled = false\n'
        '}\n', encoding="utf-8")
    case = RemediationCase(
        case_id="CASE-1", tenant_id="TEN-1", finding_ids=("FIND-1",),
        asset_ids=(RESOURCE_ID,), service_ids=("azure-lab",),
        state=CaseState.APPROVED, version=1,
        created_at="2026-08-26T00:00:00Z", updated_at="2026-08-26T00:00:00Z")
    plan = ProductRecord(
        "PLAN-1", "CASE-1", "RemediationPlan.v1", 1, "2026-08-26T00:00:00Z",
        {"status": "verified", "artifact_namespace": namespace,
         "change": {"source_path": "main.tf", "before_sha256": "before",
                    "after_sha256": sha256_file(replacement)}})
    link = ProductRecord(
        "LINK-1", "CASE-1", "IaCLink.v1", 1, "2026-08-26T00:00:00Z",
        {"link": {"resource_uid": RESOURCE_ID,
                  "resource_type": "azurerm_storage_account",
                  "resource_name": "lab"}})
    placeholder = ProductRecord(
        "RECORD-1", "CASE-1", "Placeholder.v1", 1, "2026-08-26T00:00:00Z", {})
    client = AzureStorageAccountClient(
        RESOURCE_ID, expected_subscription=SUBSCRIPTION,
        required_tags={"elcapitan_scope": "lab", "environment": "nonproduction"},
        runner=runner)
    return ExecutionContext(case, plan, link, placeholder, placeholder, tmp_path), client


def test_azure_driver_deploys_verifies_and_restores_checkpoint(tmp_path):
    runner = FakeAzureRunner()
    ctx, client = context(tmp_path, runner)
    driver = AzureStoragePublicNetworkDriver(client, id_factory=lambda prefix: prefix + "-1")
    assert driver.preflight(ctx).passed
    checkpoint = driver.checkpoint(ctx)
    assert checkpoint.payload["public_network_access"] == "Enabled"
    assert driver.deploy(ctx, checkpoint).passed
    assert AzureStoragePublicNetworkProbe(client).run(ctx).passed
    assert AzureStorageHealthMonitor(client).observe("after_deploy", ctx).healthy
    assert driver.rollback(ctx, checkpoint).passed
    assert runner.document["publicNetworkAccess"] == "Enabled"
    updates = [command for command in runner.commands if command[:3] ==
               ("storage", "account", "update")]
    assert [command[command.index("--public-network-access") + 1]
            for command in updates] == ["Disabled", "Enabled"]


def test_azure_driver_refuses_resource_drift_after_checkpoint(tmp_path):
    runner = FakeAzureRunner()
    ctx, client = context(tmp_path, runner)
    driver = AzureStoragePublicNetworkDriver(client)
    assert driver.preflight(ctx).passed
    checkpoint = driver.checkpoint(ctx)
    runner.document["minimumTlsVersion"] = "TLS1_3"
    result = driver.deploy(ctx, checkpoint)
    assert not result.passed
    assert "drifted" in result.detail
    assert not any(command[:3] == ("storage", "account", "update")
                   for command in runner.commands)


def test_blob_public_access_driver_deploys_probes_and_rolls_back(tmp_path):
    runner = FakeAzureRunner()
    ctx, client = context(tmp_path, runner)
    replacement = tmp_path / ctx.plan.body["artifact_namespace"] / "workspace" / "main.tf"
    replacement.write_text(replacement.read_text().replace(
        "public_network_access_enabled = false",
        "allow_nested_items_to_be_public = false"))
    plan = ProductRecord(
        "PLAN-1", "CASE-1", "RemediationPlan.v1", 1, "2026-08-26T00:00:00Z",
        {"status": "verified", "artifact_namespace": ctx.plan.body["artifact_namespace"],
         "change": {"source_path": "main.tf", "before_sha256": "before",
                    "after_sha256": sha256_file(replacement)}})
    changed = ExecutionContext(ctx.case, plan, ctx.link, ctx.approval, ctx.window,
                               ctx.artifact_root)
    driver = AzureStorageBlobPublicAccessDriver(client)
    assert driver.preflight(changed).passed
    checkpoint = driver.checkpoint(changed)
    assert driver.deploy(changed, checkpoint).passed
    assert AzureStorageBlobPublicAccessProbe(client).run(changed).passed
    assert driver.rollback(changed, checkpoint).passed
    assert runner.document["allowBlobPublicAccess"] is True


def test_azure_driver_refuses_untagged_target(tmp_path):
    runner = FakeAzureRunner(tags={"project": "some-production-service"})
    ctx, client = context(tmp_path, runner)
    result = AzureStoragePublicNetworkDriver(client).preflight(ctx)
    assert not result.passed
    assert "outside the permitted mutation scope" in result.detail


def test_azure_driver_refuses_unapproved_terraform_intent(tmp_path):
    runner = FakeAzureRunner()
    ctx, client = context(tmp_path, runner)
    replacement = tmp_path / ctx.plan.body["artifact_namespace"] / "workspace" / "main.tf"
    replacement.write_text(replacement.read_text().replace("= false", "= true"))
    plan = ProductRecord(
        "PLAN-1", "CASE-1", "RemediationPlan.v1", 1, "2026-08-26T00:00:00Z",
        {"status": "verified", "artifact_namespace": ctx.plan.body["artifact_namespace"],
         "change": {"source_path": "main.tf", "before_sha256": "before",
                    "after_sha256": sha256_file(replacement)}})
    changed = ExecutionContext(ctx.case, plan, ctx.link, ctx.approval, ctx.window,
                               ctx.artifact_root)
    result = AzureStoragePublicNetworkDriver(client).preflight(changed)
    assert not result.passed
    assert "must set exactly one literal" in result.detail


def test_storage_id_is_pinned_to_expected_subscription():
    with pytest.raises(ValueError, match="outside the pinned subscription"):
        parse_storage_account_id(RESOURCE_ID, expected_subscription="another-subscription")


def test_azure_runner_strips_model_and_unrelated_cloud_credentials(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-reach-azure")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-reach-azure")
    runner = SubprocessAzureCommandRunner()
    assert "OPENAI_API_KEY" not in runner.environment
    assert "AWS_SECRET_ACCESS_KEY" not in runner.environment


class FakeManagedIdentityRunner:
    def __init__(self, subscription=SUBSCRIPTION):
        self.subscription = subscription
        self.commands = []

    def run(self, argv):
        self.commands.append(argv)
        if argv[0] == "login":
            return AzureCommandResult(0)
        if argv[:2] == ("account", "show"):
            return AzureCommandResult(0, json.dumps({
                "id": self.subscription, "user": {"type": "servicePrincipal"}}))
        return AzureCommandResult(0, "{}")


def test_managed_identity_runner_authenticates_once_and_pins_subscription():
    backend = FakeManagedIdentityRunner()
    runner = ManagedIdentityAzureCommandRunner(
        identity_client_id="client-id", expected_subscription=SUBSCRIPTION,
        runner=backend)
    runner.run(("storage", "account", "show"))
    runner.run(("storage", "account", "show"))
    assert [command[0] for command in backend.commands].count("login") == 1
    assert backend.commands[0] == (
        "login", "--identity", "--client-id", "client-id",
        "--output", "none", "--only-show-errors")


def test_managed_identity_runner_refuses_wrong_subscription():
    runner = ManagedIdentityAzureCommandRunner(
        identity_client_id="client-id", expected_subscription=SUBSCRIPTION,
        runner=FakeManagedIdentityRunner(subscription="wrong"))
    with pytest.raises(AzureActionError, match="pinned subscription"):
        runner.run(("storage", "account", "show"))
