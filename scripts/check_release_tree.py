#!/usr/bin/env python3
"""Fail closed when repository or release metadata violates declared gates."""
from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "VERSIONING.md",
    "docs/public-release-v0.1.md",
    "docs/generated/capability-matrix.json",
    "docs/generated/capability-matrix.md",
)
FORBIDDEN_TRACKED_PARTS = {
    ".env",
    ".DS_Store",
    ".terraform",
    "terraform.tfstate",
    "terraform.tfstate.backup",
}


def tracked_files() -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    return tuple(item.decode() for item in result.stdout.split(b"\0") if item)


def check(release: bool, tag: str | None) -> list[str]:
    errors = [name + " is missing" for name in REQUIRED_FILES if not (ROOT / name).is_file()]
    document = tomllib.loads((ROOT / "pyproject.toml").read_text())
    version = document["project"]["version"]
    if document["project"].get("requires-python") != "==3.12.*":
        errors.append("project.requires-python must remain pinned to Python 3.12")
    for name in tracked_files():
        parts = set(Path(name).parts)
        if parts & FORBIDDEN_TRACKED_PARTS:
            errors.append(f"forbidden generated or sensitive path is tracked: {name}")
    if release:
        if not (ROOT / "LICENSE").is_file():
            errors.append("LICENSE is missing; legal/business approval is required")
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
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--tag")
    args = parser.parse_args()
    errors = check(args.release, args.tag)
    if errors:
        for error in errors:
            print(f"release-tree error: {error}", file=sys.stderr)
        return 1
    print("release-tree checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
