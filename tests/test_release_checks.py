from pathlib import Path
import subprocess
import sys


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
