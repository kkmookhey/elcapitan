import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from elcapitan.agents import AgentResult, AgentResultStatus
from elcapitan.case_store import SqliteCaseStore
from elcapitan.case_validation import CaseValidationService
from elcapitan.cases import CaseState
from elcapitan.cloud import CloudState
from elcapitan.evidence import Collector
from elcapitan.finding_store import SqliteFindingStore
from elcapitan.intake import RemediationIntake
from elcapitan.product_records import SqliteProductRecordStore
from elcapitan.remediation_planning import (
    RemediationPlanningError, RemediationPlanningService,
    SubprocessTerraformRunner, TerraformCheck, TerraformChecksFailed,
    _container_apps_identity_proxy,
)
from elcapitan.terraform_linker import TerraformLink


FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"
NOW = "2026-08-26T12:00:00Z"


class Ids:
    def __init__(self):
        self.counts = {}

    def __call__(self, prefix):
        self.counts[prefix] = self.counts.get(prefix, 0) + 1
        return f"{prefix}-{self.counts[prefix]:03d}"


class Runtime:
    name = "test-runtime"

    def __init__(self, replacement, *, citations=None, files=None):
        self.replacement = replacement
        self.citations = citations
        self.files = files
        self.tasks = []

    def run(self, task):
        self.tasks.append(task)
        return AgentResult(
            task_id=task.task_id,
            case_id=task.case_id,
            role=task.role,
            status=AgentResultStatus.SUCCEEDED,
            output={
                "objective": "disable public network access",
                "files": self.files or {"infra/storage.tf": self.replacement},
                "prerequisites": ["confirm private endpoint connectivity"],
                "steps": ["set public_network_access_enabled to false"],
                "rollout_steps": ["apply to a canary environment first"],
                "verification_steps": ["verify the scanner check clears"],
                "rollback_steps": ["restore public_network_access_enabled to true"],
                "rollback_triggers": ["private endpoint requests fail"],
                "blast_radius": ["storage clients"],
            },
            evidence_cited=(tuple(task.evidence_ids) if self.citations is None
                            else tuple(self.citations)),
            missing_evidence=(),
            runtime=self.name,
            model="test-model",
            started_at=NOW,
            completed_at=NOW,
            usage={"input": 100, "output": 50},
        )


class Runner:
    def __init__(self, exit_codes=(0, 0, 0)):
        self.exit_codes = exit_codes
        self.calls = []

    def check(self, workspace, link, *, state_document=None):
        self.calls.append((workspace, link, state_document))
        names = ("fmt", "validate", "plan")
        return tuple(
            TerraformCheck(name, ("terraform", name), code, stdout=f"{name} output")
            for name, code in zip(names, self.exit_codes)
        )


@pytest.fixture
def prepared(tmp_path):
    db = tmp_path / "product.db"
    cases = SqliteCaseStore(db)
    findings = SqliteFindingStore(db)
    records = SqliteProductRecordStore(db)
    ids = Ids()
    intake = RemediationIntake(
        case_store=cases,
        finding_store=findings,
        artifact_root=tmp_path / "artifacts",
        collector=Collector("prowler", "5.37.1", "scanner"),
        now=lambda: NOW,
        id_factory=ids,
    )
    raw = json.loads(FIXTURE.read_text())
    opened = intake.ingest(raw, tenant_id="TEN-001")
    state = CloudState(
        provider="azure",
        resource_uid=findings.get(opened.finding.finding_id).resource_uid,
        config=(("public_network_access", '"Enabled"'),),
    )
    validated = CaseValidationService(
        case_store=cases,
        finding_store=findings,
        record_store=records,
        artifact_root=tmp_path / "artifacts",
        now=lambda: NOW,
        id_factory=ids,
        reader=lambda finding, env: state,
    ).validate(opened.case.case_id, host_env={}).case
    repository = tmp_path / "customer-repo"
    source = repository / "infra" / "storage.tf"
    source.parent.mkdir(parents=True)
    source.write_text('''
resource "azurerm_storage_account" "corpus" {
  name                          = "eigercorpus8dlub3zy"
  resource_group_name           = "eiger-rg"
  location                      = "centralindia"
  public_network_access_enabled = true
}
''')
    replacement = source.read_text().replace("= true", "= false")
    return tmp_path, cases, findings, records, ids, validated, repository, source, replacement


def service(prepared, runtime, runner):
    tmp_path, cases, findings, records, ids, *_ = prepared
    return RemediationPlanningService(
        case_store=cases,
        finding_store=findings,
        record_store=records,
        artifact_root=tmp_path / "artifacts",
        runtime=runtime,
        runner=runner,
        now=lambda: NOW,
        id_factory=ids,
    )


def test_verified_agent_change_advances_case_without_mutating_source(prepared):
    _, cases, _, records, _, validated, repository, source, replacement = prepared
    (repository / ".env").write_text("ARM_CLIENT_SECRET=do-not-copy\n")
    (repository / "terraform.tfstate").write_text('{"sensitive": true}\n')
    original = source.read_text()
    runtime = Runtime(replacement)
    runner = Runner()
    outcome = service(prepared, runtime, runner).prepare(
        validated.case_id, repository=source.parents[1]
    )

    assert outcome.case.state is CaseState.PLAN_READY
    assert outcome.case.change_plan.plan_id == outcome.plan_record.record_id
    assert outcome.plan_record.record_type == "RemediationPlan.v1"
    assert outcome.plan_record.body["status"] == "verified"
    assert records.get(outcome.link_record.record_id).record_type == "IaCLink.v1"
    assert source.read_text() == original
    workspace = runner.calls[0][0]
    assert (workspace / "infra" / "storage.tf").read_text() == replacement
    assert not (workspace / ".env").exists()
    assert not (workspace / "terraform.tfstate").exists()
    assert cases.events(validated.case_id)[-1].transition.value == "prepare_plan"

    task = runtime.tasks[0]
    assert task.output_contract == "TerraformRemediationProposal.v1"
    assert task.metadata["link"]["source_path"] == "infra/storage.tf"
    assert task.metadata["source_evidence_id"] in task.evidence_ids
    assert task.metadata["link_evidence_id"] in task.evidence_ids
    assert validated.record_ids["validation_result_id"] in task.input_record_ids


def test_failed_terraform_check_is_persisted_but_does_not_advance(prepared):
    _, cases, _, records, _, validated, repository, _, replacement = prepared
    runner = Runner((0, 1, 0))
    with pytest.raises(TerraformChecksFailed) as failure:
        service(prepared, Runtime(replacement), runner).prepare(
            validated.case_id, repository=repository
        )
    assert failure.value.record.record_type == "RemediationPlanAttempt.v1"
    assert failure.value.record.body["status"] == "rejected"
    assert records.get(failure.value.record.record_id) == failure.value.record
    assert cases.get(validated.case_id).state is CaseState.VALIDATED


def test_agent_cannot_modify_a_file_other_than_the_linked_source(prepared):
    *_, validated, repository, _, replacement = prepared
    runtime = Runtime(replacement, files={"../escape.tf": replacement})
    with pytest.raises(RemediationPlanningError, match="replace exactly"):
        service(prepared, runtime, Runner()).prepare(
            validated.case_id, repository=repository
        )


def test_supported_control_is_materialized_without_model_side_edits(prepared):
    _, _, _, _, _, validated, repository, _, replacement = prepared
    proposed = replacement + '\nresource "null_resource" "unrelated" {}\n'
    runner = Runner()

    outcome = service(prepared, Runtime(proposed), runner).prepare(
        validated.case_id, repository=repository)

    workspace = runner.calls[0][0]
    assert (workspace / "infra" / "storage.tf").read_text() == replacement
    assert outcome.plan_record.body["change"]["materialization"] == (
        "deterministic_control_patch")


def test_agent_must_cite_the_linked_source(prepared):
    *_, validated, repository, _, replacement = prepared
    runtime = Runtime(replacement, citations=())
    with pytest.raises(RemediationPlanningError, match="did not cite"):
        service(prepared, runtime, Runner()).prepare(
            validated.case_id, repository=repository
        )


def test_repository_symlinks_are_rejected_before_terraform_runs(prepared):
    *_, validated, repository, _, replacement = prepared
    (repository / "untrusted.tf").symlink_to(repository / "infra" / "storage.tf")
    runner = Runner()
    with pytest.raises(RemediationPlanningError, match="unsupported symlink"):
        service(prepared, Runtime(replacement), runner).prepare(
            validated.case_id, repository=repository
        )
    assert runner.calls == []


def test_state_grounded_runner_accepts_only_one_targeted_update(tmp_path, monkeypatch):
    monkeypatch.setenv("IDENTITY_ENDPOINT", "http://localhost:42356/msi/token")
    monkeypatch.setenv("IDENTITY_HEADER", "rotating-platform-header")
    monkeypatch.setenv(
        "ELCAP_PLANNER_AZURE_MANAGED_IDENTITY_CLIENT_ID", "planner-client")
    terraform = tmp_path / "terraform"
    terraform.write_text(
        "#!/bin/sh\n"
        "case \"$ARM_MSI_ENDPOINT\" in http://127.0.0.1:*/msi/token) :;; *) exit 41;; esac\n"
        "[ \"$ARM_MSI_API_VERSION\" = \"2019-08-01\" ] || exit 42\n"
        "[ \"$IDENTITY_HEADER\" = \"rotating-platform-header\" ] || exit 43\n"
        "if [ \"$1\" = \"plan\" ]; then for arg in \"$@\"; do "
        "case \"$arg\" in -out=*) touch \"${arg#-out=}\";; esac; done; fi\n"
        "if [ \"$1\" = \"show\" ]; then "
        "printf '%s' '{\"resource_changes\":[{\"address\":\"azurerm_storage_account.corpus\",\"change\":{\"actions\":[\"update\"],\"before\":{\"public_network_access_enabled\":true},\"after\":{\"public_network_access_enabled\":false}}}]}'; fi\n"
        "exit 0\n"
    )
    terraform.chmod(0o755)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "storage.tf").write_text(
        'resource "azurerm_storage_account" "corpus" {}\n')
    link = TerraformLink(
        resource_uid="/subscriptions/sub/resourceGroups/rg/providers/"
                     "Microsoft.Storage/storageAccounts/account",
        source_path="storage.tf", module_path=".",
        resource_type="azurerm_storage_account", resource_name="corpus",
        start_line=1, end_line=1, match_strategy="state_resource_id",
        confidence=1, source_sha256="a", resource_address=(
            "azurerm_storage_account.corpus"), state_sha256="b",
    )
    state = {
        "version": 4, "serial": 1, "lineage": "lineage", "outputs": {},
        "resources": [],
    }

    checks = SubprocessTerraformRunner(str(terraform)).check(
        workspace, link, state_document=state)

    assert [item.name for item in checks] == [
        "fmt", "init", "validate", "plan", "plan_scope"]
    assert all(item.passed for item in checks)
    assert json.loads(checks[-1].stdout) == {
        "creates": 0, "deletes": 0,
        "attribute_scope_passed": True,
        "observed_changes": [{
            "actions": ["update"],
            "address": "azurerm_storage_account.corpus",
            "changed_attribute_paths": ["public_network_access_enabled"],
        }],
        "passed": True,
        "required_target": "azurerm_storage_account.corpus",
        "updates": 1,
    }
    assert "-state=[EPHEMERAL_STATE]" in checks[-2].argv
    assert "-out=[EPHEMERAL_PLAN]" in checks[-2].argv


def test_container_apps_identity_proxy_injects_header_and_bounds_request():
    observed = {}

    class PlatformIdentityHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            observed["header"] = self.headers.get("X-IDENTITY-HEADER")
            observed["query"] = urllib.parse.parse_qs(
                urllib.parse.urlsplit(self.path).query)
            body = b'{"access_token":"opaque","expires_on":"1"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002
            return

    platform = ThreadingHTTPServer(("127.0.0.1", 0), PlatformIdentityHandler)
    thread = threading.Thread(target=platform.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{platform.server_port}/msi/token"
    try:
        with _container_apps_identity_proxy(
                endpoint, "rotating-header", "planner-client") as proxy:
            query = urllib.parse.urlencode({
                "resource": "https://management.azure.com/",
                "api-version": "2018-02-01",
                "client_id": "planner-client",
            })
            with urllib.request.urlopen(f"{proxy}?{query}") as response:
                assert json.load(response)["access_token"] == "opaque"
            denied = urllib.parse.urlencode({
                "resource": "https://vault.azure.net/",
                "client_id": "planner-client",
            })
            with pytest.raises(urllib.error.HTTPError) as failure:
                urllib.request.urlopen(f"{proxy}?{denied}")
            assert failure.value.code == 403
            assert json.load(failure.value)["error"] == {
                "audience_allowed": False,
                "client_allowed": True,
                "code": "IdentityRequestDenied",
                "query_keys": ["client_id", "resource"],
                "resource": "https://vault.azure.net/",
            }
    finally:
        platform.shutdown()
        platform.server_close()
        thread.join(timeout=5)

    assert observed == {
        "header": "rotating-header",
        "query": {
            "api-version": ["2019-08-01"],
            "client_id": ["planner-client"],
            "resource": ["https://management.azure.com/"],
        },
    }


def test_terraform_output_redaction_preserves_diagnostic_text_only():
    raw = (
        "could not acquire access token to parse claims\n"
        'access_token="credential-value" client_secret: hidden-value\n'
        "eyJabcdefghijklmnop.qrstuvwxyz012345.signature\n"
    )

    redacted = SubprocessTerraformRunner._redact_output(raw)

    assert "could not acquire access token to parse claims" in redacted
    assert "credential-value" not in redacted
    assert "hidden-value" not in redacted
    assert "eyJabcdefghijklmnop" not in redacted
    assert redacted.count("[redacted]") == 2
    assert "[redacted JWT]" in redacted


def test_plan_scope_rejects_create_or_destroy(tmp_path):
    terraform = tmp_path / "terraform"
    terraform.write_text(
        "#!/bin/sh\n"
        "printf '%s' '{\"resource_changes\":["
        "{\"address\":\"azurerm_storage_account.corpus\",\"change\":{\"actions\":[\"delete\",\"create\"]}}]}'\n"
    )
    terraform.chmod(0o755)
    plan = tmp_path / "plan"
    plan.write_bytes(b"opaque")

    check = SubprocessTerraformRunner(str(terraform))._plan_scope(
        plan_path=plan, target="azurerm_storage_account.corpus",
        cwd=tmp_path, environment={"PATH": ""})

    assert check.passed is False
    summary = json.loads(check.stdout)
    assert summary["creates"] == 1
    assert summary["deletes"] == 1


def test_plan_scope_rejects_extra_attribute_change(tmp_path):
    terraform = tmp_path / "terraform"
    terraform.write_text(
        "#!/bin/sh\n"
        "printf '%s' '{\"resource_changes\":[{"
        "\"address\":\"azurerm_storage_account.corpus\","
        "\"change\":{\"actions\":[\"update\"],"
        "\"before\":{\"public_network_access_enabled\":true,\"min_tls_version\":\"TLS1_2\"},"
        "\"after\":{\"public_network_access_enabled\":false,\"min_tls_version\":\"TLS1_0\"}}}]}'\n"
    )
    terraform.chmod(0o755)
    plan = tmp_path / "plan"
    plan.write_bytes(b"opaque")

    check = SubprocessTerraformRunner(str(terraform))._plan_scope(
        plan_path=plan, target="azurerm_storage_account.corpus",
        cwd=tmp_path, environment={"PATH": ""})

    assert check.passed is False
    summary = json.loads(check.stdout)
    assert summary["attribute_scope_passed"] is False
    assert summary["observed_changes"][0]["changed_attribute_paths"] == [
        "min_tls_version", "public_network_access_enabled"]
