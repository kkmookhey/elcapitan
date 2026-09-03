import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from scripts.check_release_tree import check_release_approval, is_forbidden_tracked_path


ROOT = Path(__file__).resolve().parents[1]


def run_release_check(*args):
    return subprocess.run(
        [sys.executable, "scripts/check_release_tree.py", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def test_repository_readiness_check_passes_before_release():
    result = run_release_check()

    assert result.returncode == 0, result.stderr
    assert result.stdout == "release-tree checks passed\n"


def test_repository_declares_the_approved_apache_license():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    license_text = (ROOT / "LICENSE").read_text()
    notice = (ROOT / "NOTICE").read_text()

    assert project["license"] == {"text": "Apache-2.0"}
    assert "License :: OSI Approved :: Apache Software License" in project[
        "classifiers"
    ]
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
    assert "Copyright 2026 Transilience, Inc." in notice


def test_gitleaks_allowlists_are_limited_to_adjudicated_false_positives():
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    anna_rule = "".join(
        (
            r"^API ",
            r"calls, `finish_",
            r"reason=stop`$",
        )
    )

    assert config["extend"] == {"useDefault": True}
    assert config["allowlists"] == [
        {
            "description": (
                "Terraform Container App password_secret_name is a reference "
                "identifier"
            ),
            "condition": "AND",
            "paths": [r"^environments/eiger/infra/app\.tf$"],
            "regexTarget": "line",
            "regexes": [
                r'^\s*password_secret_name\s*=\s*"[A-Za-z0-9._-]+"\s*$'
            ],
        },
        {
            "description": (
                "Dated El Capitan lab ACR demo image references are not credentials"
            ),
            "condition": "AND",
            "paths": [r"^deploy/azure/shadow-app\.yaml$"],
            "regexTarget": "line",
            "regexes": [
                r"^\s*image:\s+[a-z0-9]+\.azurecr\.io/elcapitan-demo:"
                r"20260827-shadow\.(?:[56]|[89]|1[0-5])\s*$"
            ],
        },
        {
            "description": (
                "Anna observation records model termination metadata, not an API key"
            ),
            "condition": "AND",
            "paths": [r"^environments/anna/OBSERVATIONS\.md$"],
            "regexTarget": "match",
            "regexes": [anna_rule],
        },
    ]

    image_reference = re.compile(config["allowlists"][1]["regexes"][0])
    image_field = "image: "
    image_repository = "example.azurecr.io/" + "elcapitan-demo:"
    reviewed_build = "20260827-" + "shadow."
    assert image_reference.fullmatch("  " + image_field + image_repository + reviewed_build + "5")
    assert image_reference.fullmatch("  " + image_field + image_repository + reviewed_build + "15")
    for rejected in (
        image_field + image_repository + reviewed_build + "7",
        image_field + image_repository + reviewed_build + "16",
        image_field + image_repository + "20260828-" + "shadow.1",
        image_field + "example.azurecr.io/another-repository:" + reviewed_build + "1",
        image_field + "user:" + "password@" + image_repository + reviewed_build + "1",
        "password: " + image_repository + reviewed_build + "1",
    ):
        assert image_reference.fullmatch(rejected) is None

    anna_metadata = re.compile(config["allowlists"][2]["regexes"][0])
    anna_prefix = "API " + "calls, `"
    anna_stop = "finish_" + "reason=stop`"
    assert anna_metadata.fullmatch(anna_prefix + anna_stop)
    for rejected in (
        anna_prefix + "api_" + "key=value`",
        anna_prefix + "finish_" + "reason=length`",
        "65 " + anna_prefix + anna_stop,
        anna_stop.removesuffix("`"),
    ):
        assert anna_metadata.fullmatch(rejected) is None


def test_release_tree_rejects_terraform_state_and_variable_artifacts():
    for name in (
        "infra/terraform.tfstate",
        "infra/prod.tfstate.backup",
        "infra/prod.tfstate.1700000000",
        "infra/private.tfvars",
        "infra/private.tfvars.json",
        "infra/deploy.tfplan",
    ):
        assert is_forbidden_tracked_path(name)

    assert not is_forbidden_tracked_path("infra/main.tf")


def test_final_release_check_fails_closed_without_approvals_and_dated_changelog():
    result = run_release_check("--release", "--tag", "v0.1.0")

    assert result.returncode == 1
    assert "CHANGELOG 0.1.0 release date is still Unreleased" in result.stderr
    assert "--approval-sha256 is required" in result.stderr
    assert "RELEASE_APPROVAL.json is missing" in result.stderr
    assert "RELEASE_APPROVAL.json must be committed" in result.stderr


def test_final_release_check_rejects_version_mismatched_tag():
    result = run_release_check("--release", "--tag", "v0.2.0")

    assert result.returncode == 1
    assert "release tag must be v0.1.0" in result.stderr


def test_generated_capability_matrix_is_current():
    result = subprocess.run(
        [sys.executable, "scripts/generate_capability_matrix.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "generated capability matrix is current\n"


def test_customer_shadow_deployment_requires_immutable_image_and_scanner_identity():
    template = (ROOT / "deploy/azure/customer-shadow-app.template.yaml").read_text()
    create_script = (ROOT / "deploy/azure/create-customer-shadow-app.sh").read_text()
    bootstrap_script = (ROOT / "deploy/azure/bootstrap-shadow-database.sh").read_text()
    repair_script = (
        ROOT / "deploy/azure/repair-customer-shadow-database.sh"
    ).read_text()

    assert "__SCANNER_ID__: {}" in template
    assert "ELCAP_SCANNER_AZURE_MANAGED_IDENTITY_CLIENT_ID" in template
    assert "value: __SCANNER_CLIENT_ID__" in template
    assert "ELCAPITAN_LAB_SCANNER_ID" in create_script
    assert "ELCAPITAN_LAB_SCANNER_CLIENT_ID" in create_script
    assert "userAssignedIdentities/elcapitan-${SLUG}-scanner" in create_script
    for script in (create_script, bootstrap_script, repair_script):
        assert "ELCAPITAN_LAB_IMAGE" in script
        assert "@sha256:[0-9a-f]{64}" in script


def test_azure_worker_image_is_pinned_and_non_root():
    dockerfile = (ROOT / "Dockerfile.azure-worker").read_text()

    assert "mcr.microsoft.com/azure-cli:2.86.0@sha256:" in dockerfile
    assert "hashicorp/terraform:1.15.8@sha256:" in dockerfile
    assert "--require-hashes -r requirements-runtime.txt" in dockerfile
    assert "USER 10001" in dockerfile
    assert 'ENTRYPOINT ["elcapitan"]' in dockerfile


def test_public_runtime_rebuilds_pinned_terraform_with_patched_go():
    dockerfile = (ROOT / "Dockerfile").read_text()

    assert "golang:1.26.6-alpine@sha256:" in dockerfile
    assert "terraform/archive/58e916f6706597d9d87898f9ecedf811b68c6f29" in dockerfile
    assert (
        "ADD --checksum=sha256:"
        "091ca86edd29d325d5400c80c110cb51847a092c37c16d101607fc3321ae183b"
        in dockerfile
    )
    assert "GOTOOLCHAIN=local go build" in dockerfile
    assert "python:3.12-slim-bookworm@sha256:" in dockerfile
    assert "USER 10001" in dockerfile

    for workflow_name in ("ci.yml", "release.yml"):
        workflow = (ROOT / ".github" / "workflows" / workflow_name).read_text()
        assert 'terraform_version: "1.16.1"' in workflow


def test_workflow_actions_are_commit_pinned():
    uses = []
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        uses.extend(re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow.read_text()))

    assert uses
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in uses)


def test_release_workflow_hash_binds_approval_without_shell_interpolation():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()

    assert "approval_record_sha256:" in workflow
    assert "APPROVAL_RECORD_SHA256: ${{ inputs.approval_record_sha256 }}" in workflow
    assert '--approval-sha256 "${APPROVAL_RECORD_SHA256}"' in workflow
    assert '--approval-sha256 "${{ inputs.approval_record_sha256 }}"' not in workflow


def test_exact_owner_approval_record_is_required_and_hash_bound(tmp_path):
    record = {
        "schema_version": 1,
        "release_tag": "v0.1.0",
        "license": {
            "spdx_id": "Apache-2.0",
            "decision": "approved",
            "approved_by": "Legal Owner",
            "approved_at": "2026-08-29",
            "evidence_ref": "approval:license:001",
        },
        "project_name": {
            "value": "El Capitan",
            "decision": "approved",
            "approved_by": "Business Owner",
            "approved_at": "2026-08-29",
            "evidence_ref": "approval:name:001",
        },
        "historical_secret_response": {
            "decision": "complete",
            "legacy_fingerprints_reviewed": 22,
            "remaining_baseline_fingerprints": 0,
            "potential_credentials_dispositioned": True,
            "history_rewrite": "not_required",
            "zero_finding_history_scan": True,
            "approved_by": "Security Owner",
            "approved_at": "2026-08-29",
            "evidence_ref": "approval:secrets:001",
        },
        "release_environment": {
            "name": "release",
            "decision": "configured",
            "required_reviewers_configured": True,
            "approved_by": "Repository Owner",
            "approved_at": "2026-08-29",
            "evidence_ref": "approval:environment:001",
        },
    }
    path = tmp_path / "RELEASE_APPROVAL.json"
    path.write_text(json.dumps(record, sort_keys=True))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    assert (
        check_release_approval(
            path,
            expected_tag="v0.1.0",
            supplied_sha256=digest,
            project_license="Apache-2.0",
            baseline_fingerprints=0,
        )
        == []
    )
    errors = check_release_approval(
        path,
        expected_tag="v0.1.0",
        supplied_sha256="0" * 64,
        project_license="Apache-2.0",
        baseline_fingerprints=0,
    )
    assert "does not match --approval-sha256" in "\n".join(errors)


def test_owner_approval_record_cannot_waive_unresolved_secret_baseline(tmp_path):
    example = json.loads(
        (ROOT / "docs/release-approval-record.example.json").read_text()
    )
    path = tmp_path / "RELEASE_APPROVAL.json"
    path.write_text(json.dumps(example))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    errors = check_release_approval(
        path,
        expected_tag="v0.1.0",
        supplied_sha256=digest,
        project_license=None,
        baseline_fingerprints=22,
    )

    assert ".gitleaksignore must contain zero unresolved fingerprints" in errors
    assert (
        "historical secret response must disposition every potential credential"
        in errors
    )
    assert "release environment must have required reviewers configured" in errors
