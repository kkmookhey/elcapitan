import json
import os
from pathlib import Path

import fake_az
import pytest

from elcapitan.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"


def test_cli_ingests_a_finding_and_prints_the_prioritized_case(tmp_path, capsys):
    args = [
        "intake", str(FIXTURE), "--tenant", "TEN-001",
        "--db", str(tmp_path / "product.db"),
        "--artifacts", str(tmp_path / "artifacts"),
        "--asset-criticality", "0.8", "--reachable",
    ]
    assert main(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output) == 1
    assert output[0]["case"]["state"] == "prioritized"
    assert output[0]["case_created"] is True
    assert output[0]["case"]["priority"]["score"] == 66

    assert main(args) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay[0]["duplicate"] is True
    assert replay[0]["case_id"] == output[0]["case_id"]


def test_cli_validates_case_with_scoped_read_only_cloud_identity(
        tmp_path, capsys, monkeypatch):
    db = tmp_path / "product.db"
    artifacts = tmp_path / "artifacts"
    assert main([
        "intake", str(FIXTURE), "--tenant", "TEN-001",
        "--db", str(db), "--artifacts", str(artifacts),
    ]) == 0
    ingested = json.loads(capsys.readouterr().out)[0]

    bin_dir = fake_az.install(tmp_path / "bin")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    for name, value in fake_az.scanner_credentials().items():
        monkeypatch.setenv(name, value)
    assert main([
        "validate", "--case", ingested["case_id"],
        "--db", str(db), "--artifacts", str(artifacts),
    ]) == 0
    validated = json.loads(capsys.readouterr().out)
    assert validated["case"]["state"] == "validated"
    assert validated["findings"][0]["status"] == "confirmed"
    assert validated["record"]["body"]["evidence"][0]["collector"]["identity"] == (
        "read-only-scanner")


def test_cli_prepares_a_verified_terraform_plan(tmp_path, capsys, monkeypatch):
    db = tmp_path / "product.db"
    artifacts = tmp_path / "artifacts"
    assert main([
        "intake", str(FIXTURE), "--tenant", "TEN-001",
        "--db", str(db), "--artifacts", str(artifacts),
    ]) == 0
    case_id = json.loads(capsys.readouterr().out)[0]["case_id"]

    az_bin = fake_az.install(tmp_path / "az-bin")
    monkeypatch.setenv("PATH", f"{az_bin}{os.pathsep}{os.environ['PATH']}")
    for name, value in fake_az.scanner_credentials().items():
        monkeypatch.setenv(name, value)
    assert main([
        "validate", "--case", case_id, "--db", str(db),
        "--artifacts", str(artifacts),
    ]) == 0
    capsys.readouterr()

    repository = tmp_path / "customer-repo"
    source = repository / "infra" / "storage.tf"
    source.parent.mkdir(parents=True)
    source.write_text('''
resource "azurerm_storage_account" "corpus" {
  name                          = "eigercorpus8dlub3zy"
  resource_group_name           = "eiger-rg"
  public_network_access_enabled = true
}
''')
    replacement = source.read_text().replace("= true", "= false")
    result_file = tmp_path / "agent-result.json"
    result_file.write_text(json.dumps({
        "runtime": "test-recording",
        "model": "test-model",
        "output": {
            "objective": "disable public network access",
            "files": {"infra/storage.tf": replacement},
            "prerequisites": ["confirm private connectivity"],
            "steps": ["change the Terraform argument"],
            "rollout_steps": ["deploy to canary"],
            "verification_steps": ["rerun the scanner"],
            "rollback_steps": ["restore the previous value"],
            "rollback_triggers": ["private requests fail"],
            "blast_radius": ["storage clients"],
        },
    }))
    terraform = tmp_path / "terraform"
    terraform.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"plan\" ]; then for arg in \"$@\"; do "
        "case \"$arg\" in -out=*) touch \"${arg#-out=}\";; esac; done; fi\n"
        "exit 0\n"
    )
    terraform.chmod(0o755)

    assert main([
        "plan", "--case", case_id, "--db", str(db),
        "--artifacts", str(artifacts), "--repo", str(repository),
        "--agent-result", str(result_file), "--terraform-bin", str(terraform),
    ]) == 0
    planned = json.loads(capsys.readouterr().out)
    assert planned["status"] == "plan_ready"
    assert planned["case"]["state"] == "plan_ready"
    assert [check["name"] for check in planned["checks"]] == [
        "fmt", "init", "validate", "plan",
    ]
    assert source.read_text().endswith("public_network_access_enabled = true\n}\n")


def test_cli_demo_stops_at_human_review_without_changing_source(
        tmp_path, capsys):
    terraform = tmp_path / "terraform"
    terraform.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"plan\" ]; then for arg in \"$@\"; do "
        "case \"$arg\" in -out=*) touch \"${arg#-out=}\";; esac; done; fi\n"
        "exit 0\n"
    )
    terraform.chmod(0o755)
    workdir = tmp_path / "demo"
    assert main([
        "demo-review", "--workdir", str(workdir),
        "--terraform-bin", str(terraform),
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "awaiting_approval"
    assert result["execution_status"] == "not_started"
    assert result["source_repository_unchanged"] is True
    assert len(result["promotion_token"]) == 64
    assert [check["passed"] for check in result["terraform_checks"]] == [
        True, True, True, True,
    ]
    assert "public_network_access = true" in (
        workdir / "customer-repo" / "infra" / "main.tf").read_text()

    assert main([
        "show-review", "--case", result["case_id"],
        "--db", result["database"],
    ]) == 0
    package = json.loads(capsys.readouterr().out)
    assert package["record_type"] == "HumanReviewPackage.v1"
    assert package["body"]["policy_decision"]["body"]["decision"] == (
        "allow_human_review")
    assert package["body"]["execution_status"] == "not_started"


@pytest.mark.parametrize("requested, expected_state, rolled_back", [
    ("success", "remediated", False),
    ("rollback", "rolled_back", True),
])
def test_cli_complete_lifecycle_success_and_automatic_rollback(
        tmp_path, capsys, requested, expected_state, rolled_back):
    terraform = tmp_path / "terraform"
    terraform.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"plan\" ]; then for arg in \"$@\"; do "
        "case \"$arg\" in -out=*) touch \"${arg#-out=}\";; esac; done; fi\n"
        "exit 0\n"
    )
    terraform.chmod(0o755)
    workdir = tmp_path / requested
    assert main([
        "demo-lifecycle", "--workdir", str(workdir),
        "--outcome", requested, "--terraform-bin", str(terraform),
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == expected_state
    assert result["rolled_back"] is rolled_back
    assert result["source_repository_unchanged"] is True
    if rolled_back:
        assert result["deployment_target_restored"] is True
        assert result["handoff"] is None
        assert result["workflow_transitions"][-2:] == [
            "start_rollback", "complete_rollback",
        ]
    else:
        assert result["deployment_target_changed"] is True
        assert result["handoff"]["body"]["status"] == "done"
        assert result["workflow_transitions"][-2:] == [
            "start_verification", "complete_remediation",
        ]


def test_azure_lab_lifecycle_requires_exact_double_confirmation(tmp_path):
    resource_id = (
        "/subscriptions/sub/resourceGroups/lab/providers/"
        "Microsoft.Storage/storageAccounts/account")
    with pytest.raises(ValueError, match="confirm-resource-id"):
        main([
            "azure-storage-lifecycle", "--resource-id", resource_id,
            "--subscription", "sub", "--confirm-resource-id", resource_id + "-wrong",
            "--confirm-subscription", "sub", "--workdir", str(tmp_path / "lab"),
        ])


def test_cli_reports_capabilities_connector_preflight_and_full_fleet(
        tmp_path, capsys, monkeypatch):
    db = tmp_path / "product.db"
    artifacts = tmp_path / "artifacts"
    assert main([
        "intake", str(FIXTURE), "--tenant", "TEN-FLEET",
        "--db", str(db), "--artifacts", str(artifacts),
    ]) == 0
    case_id = json.loads(capsys.readouterr().out)[0]["case_id"]

    assert main(["capabilities", "--provider", "azure"]) == 0
    capabilities = json.loads(capsys.readouterr().out)
    assert len(capabilities["capabilities"]) == 3
    assert all(item["provider"] == "azure" for item in capabilities["capabilities"])

    monkeypatch.setenv("PATH", "")
    for name in fake_az.scanner_credentials():
        monkeypatch.delenv(name, raising=False)
    assert main(["connector-preflight", "--provider", "azure"]) == 0
    preflight = json.loads(capsys.readouterr().out)
    assert preflight["ready_for_live_validation"] is False
    assert preflight["executable_available"] is False
    assert len(preflight["missing_environment"]) == 3

    assert main([
        "fleet-snapshot", "--tenant", "TEN-FLEET", "--db", str(db),
    ]) == 0
    fleet = json.loads(capsys.readouterr().out)
    assert fleet["summary"]["total_cases"] == 1
    assert fleet["summary"]["total_findings"] == 1
    assert fleet["summary"]["supported_findings"] == 1
    assert fleet["shadow_policy"]["allow_execution"] is False

    assert main([
        "promotion-manifest", "--tenant", "TEN-FLEET", "--case", case_id,
        "--db", str(db),
    ]) == 0
    promotion = json.loads(capsys.readouterr().out)
    assert promotion["status"] == "blocked"
    assert promotion["safety_boundary"]["execution"] is False
