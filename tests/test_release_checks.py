import re
import subprocess
import sys
from pathlib import Path


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


def test_final_release_check_fails_closed_without_license_and_dated_changelog():
    result = run_release_check("--release", "--tag", "v0.1.0")

    assert result.returncode == 1
    assert "LICENSE is missing" in result.stderr
    assert "CHANGELOG 0.1.0 release date is still Unreleased" in result.stderr


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
    repair_script = (ROOT / "deploy/azure/repair-customer-shadow-database.sh").read_text()

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
    assert "terraform/archive/bfe8a941dc45f9f39227b2cd0adc21069ba99319" in dockerfile
    assert "ADD --checksum=sha256:" in dockerfile
    assert "GOTOOLCHAIN=local go build" in dockerfile
    assert "python:3.12-slim-bookworm@sha256:" in dockerfile
    assert "USER 10001" in dockerfile


def test_workflow_actions_are_commit_pinned():
    uses = []
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        uses.extend(re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow.read_text()))

    assert uses
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in uses)
