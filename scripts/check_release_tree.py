#!/usr/bin/env python3
"""Fail closed when repository or release metadata violates declared gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Mapping
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "compose.yaml",
    "SECURITY.md",
    "SUPPORT.md",
    "VERSIONING.md",
    "docs/public-release-v0.1.md",
    "docs/quickstart.md",
    "docs/release-approval-record.example.json",
    "docs/generated/capability-matrix.json",
    "docs/generated/capability-matrix.md",
    "examples/synthetic-shadow-intake.json",
    "requirements-runtime.txt",
    "scripts/rehearse_release_candidate.sh",
)
FORBIDDEN_TRACKED_PARTS = {
    ".env",
    ".DS_Store",
    ".terraform",
    "terraform.tfstate",
    "terraform.tfstate.backup",
}


def _baseline_fingerprint_count() -> int:
    path = ROOT / ".gitleaksignore"
    if not path.is_file():
        return 0
    return sum(
        1
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _approval_metadata_errors(section: object, name: str) -> list[str]:
    if not isinstance(section, Mapping):
        return [f"release approval {name} section must be an object"]
    errors = []
    for field in ("approved_by", "approved_at", "evidence_ref"):
        value = section.get(field)
        if not isinstance(value, str) or not value.strip() or "<" in value:
            errors.append(f"release approval {name}.{field} must be recorded")
    approved_at = section.get("approved_at")
    if isinstance(approved_at, str) and approved_at.strip() and "<" not in approved_at:
        try:
            date.fromisoformat(approved_at)
        except ValueError:
            errors.append(f"release approval {name}.approved_at must be YYYY-MM-DD")
        else:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", approved_at):
                errors.append(f"release approval {name}.approved_at must be YYYY-MM-DD")
    return errors


def check_release_approval(
    path: Path,
    *,
    expected_tag: str,
    supplied_sha256: str | None,
    project_license: object,
    baseline_fingerprints: int,
) -> list[str]:
    """Validate and hash-bind the exact owner decisions authorizing publication."""
    errors = []
    if not supplied_sha256:
        errors.append("--approval-sha256 is required for a release")
    elif (
        not isinstance(supplied_sha256, str)
        or len(supplied_sha256) != 64
        or any(character not in "0123456789abcdef" for character in supplied_sha256)
    ):
        errors.append("--approval-sha256 must be 64 lowercase hexadecimal characters")
    if not path.is_file():
        return [*errors, "RELEASE_APPROVAL.json is missing"]

    actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if supplied_sha256 and supplied_sha256 != actual_sha256:
        errors.append("RELEASE_APPROVAL.json does not match --approval-sha256")
    try:
        document = json.loads(path.read_text())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [*errors, f"RELEASE_APPROVAL.json is invalid JSON: {exc}"]
    if not isinstance(document, Mapping):
        return [*errors, "RELEASE_APPROVAL.json must contain an object"]
    if document.get("schema_version") != 1:
        errors.append("release approval schema_version must be 1")
    if document.get("release_tag") != expected_tag:
        errors.append(f"release approval release_tag must be {expected_tag}")

    license_record = document.get("license")
    errors.extend(_approval_metadata_errors(license_record, "license"))
    if isinstance(license_record, Mapping):
        spdx_id = license_record.get("spdx_id")
        if license_record.get("decision") != "approved":
            errors.append("release approval license.decision must be approved")
        if not isinstance(spdx_id, str) or not spdx_id.strip() or "<" in spdx_id:
            errors.append("release approval license.spdx_id must be recorded")
        if project_license != spdx_id:
            errors.append("project.license must match release approval license.spdx_id")

    name_record = document.get("project_name")
    errors.extend(_approval_metadata_errors(name_record, "project_name"))
    if isinstance(name_record, Mapping):
        if name_record.get("value") != "El Capitan":
            errors.append("release approval project_name.value must be El Capitan")
        if name_record.get("decision") != "approved":
            errors.append("release approval project_name.decision must be approved")

    secret_record = document.get("historical_secret_response")
    errors.extend(
        _approval_metadata_errors(secret_record, "historical_secret_response")
    )
    if isinstance(secret_record, Mapping):
        if secret_record.get("decision") != "complete":
            errors.append("historical secret response decision must be complete")
        reviewed = secret_record.get("legacy_fingerprints_reviewed")
        if not isinstance(reviewed, int) or isinstance(reviewed, bool) or reviewed < 22:
            errors.append(
                "historical secret response must review all 22 legacy fingerprints"
            )
        if (
            secret_record.get("remaining_baseline_fingerprints")
            != baseline_fingerprints
        ):
            errors.append(
                "historical secret response baseline count does not match .gitleaksignore"
            )
        if baseline_fingerprints != 0:
            errors.append(".gitleaksignore must contain zero unresolved fingerprints")
        if secret_record.get("potential_credentials_dispositioned") is not True:
            errors.append(
                "historical secret response must disposition every potential credential"
            )
        if secret_record.get("zero_finding_history_scan") is not True:
            errors.append(
                "historical secret response must record a zero-finding history scan"
            )
        if secret_record.get("history_rewrite") not in {"completed", "not_required"}:
            errors.append(
                "historical secret response history_rewrite must be completed or not_required"
            )

    environment_record = document.get("release_environment")
    errors.extend(_approval_metadata_errors(environment_record, "release_environment"))
    if isinstance(environment_record, Mapping):
        if environment_record.get("name") != "release":
            errors.append("release environment name must be release")
        if environment_record.get("decision") != "configured":
            errors.append("release environment decision must be configured")
        if environment_record.get("required_reviewers_configured") is not True:
            errors.append("release environment must have required reviewers configured")
    return errors


def tracked_files() -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    return tuple(item.decode() for item in result.stdout.split(b"\0") if item)


def check(
    release: bool,
    tag: str | None,
    approval_sha256: str | None = None,
) -> list[str]:
    errors = [
        name + " is missing" for name in REQUIRED_FILES if not (ROOT / name).is_file()
    ]
    document = tomllib.loads((ROOT / "pyproject.toml").read_text())
    version = document["project"]["version"]
    tracked = tracked_files()
    if document["project"].get("requires-python") != "==3.12.*":
        errors.append("project.requires-python must remain pinned to Python 3.12")
    for name in tracked:
        parts = set(Path(name).parts)
        if parts & FORBIDDEN_TRACKED_PARTS:
            errors.append(f"forbidden generated or sensitive path is tracked: {name}")
    if release:
        if not (ROOT / "LICENSE").is_file():
            errors.append("LICENSE is missing; legal/business approval is required")
        if "RELEASE_APPROVAL.json" not in tracked:
            errors.append("RELEASE_APPROVAL.json must be committed before release")
        expected_tag = f"v{version}"
        if tag != expected_tag:
            errors.append(f"release tag must be {expected_tag}, got {tag!r}")
        release_heading = next(
            (
                line
                for line in (ROOT / "CHANGELOG.md").read_text().splitlines()
                if line.startswith(f"## [{version}]")
            ),
            "",
        )
        if "Unreleased" in release_heading:
            errors.append(f"CHANGELOG {version} release date is still Unreleased")
        errors.extend(
            check_release_approval(
                ROOT / "RELEASE_APPROVAL.json",
                expected_tag=expected_tag,
                supplied_sha256=approval_sha256,
                project_license=document["project"].get("license"),
                baseline_fingerprints=_baseline_fingerprint_count(),
            )
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--tag")
    parser.add_argument("--approval-sha256")
    args = parser.parse_args()
    errors = check(args.release, args.tag, args.approval_sha256)
    if errors:
        for error in errors:
            print(f"release-tree error: {error}", file=sys.stderr)
        return 1
    print("release-tree checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
