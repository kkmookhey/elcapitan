#!/usr/bin/env python3
"""Render the public capability/evidence matrix from the installed registry."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import tomllib

from elcapitan.fleet import CapabilityRegistry


ROOT = Path(__file__).resolve().parents[1]
JSON_PATH = ROOT / "docs/generated/capability-matrix.json"
MARKDOWN_PATH = ROOT / "docs/generated/capability-matrix.md"
GRADE_LABELS = {
    "contract_tested": "Contract tested",
    "contract_tested_export_observed": "Contract tested + export observed",
    "e2e_measured": "E2E measured",
    "export_observed": "Export observed",
    "unverified": "Unverified",
}


def matrix() -> dict:
    capabilities = [item.to_dict() for item in CapabilityRegistry().list()]
    providers = Counter(item["provider"] for item in capabilities)
    grades = Counter(item["evidence_grade"] for item in capabilities)
    return {
        "schema_version": 1,
        "project_version": tomllib.loads((ROOT / "pyproject.toml").read_text())[
            "project"
        ]["version"],
        "authority": "elcapitan capabilities / installed control-pack registry",
        "summary": {
            "controls": len(capabilities),
            "live_validation": sum(item["live_validation"] for item in capabilities),
            "remediation_planning": sum(
                item["remediation_planning"] for item in capabilities
            ),
            "live_execution": sum(item["live_execution"] for item in capabilities),
            "providers": dict(sorted(providers.items())),
            "evidence_grades": dict(sorted(grades.items())),
        },
        "capabilities": capabilities,
    }


def render_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def render_markdown(document: dict) -> str:
    summary = document["summary"]
    lines = [
        "# Generated capability and evidence matrix",
        "",
        "This file is generated from the installed control-pack registry. Do not edit it by hand.",
        "`elcapitan capabilities` is the machine-readable authority.",
        "",
        f"Version: `{document['project_version']}` · validation: {summary['live_validation']} · planning: {summary['remediation_planning']} · execution: {summary['live_execution']}",
        "",
        "Validation, planning, and execution are independent columns. Evidence grade describes the strongest completed proof; it does not grant mutation authority.",
        "",
        "| Provider | Control | Family | Validation | Planning | Execution | Evidence grade |",
        "|---|---|---|:---:|:---:|:---:|---|",
    ]
    for item in document["capabilities"]:
        lines.append(
            "| {provider} | `{rule_id}` | {resource_family} | {validation} | {planning} | {execution} | {grade} |".format(
                provider=item["provider"].upper(),
                rule_id=item["rule_id"],
                resource_family=item["resource_family"].replace("_", " "),
                validation="yes" if item["live_validation"] else "no",
                planning="yes" if item["remediation_planning"] else "no",
                execution="yes" if item["live_execution"] else "no",
                grade=GRADE_LABELS[item["evidence_grade"]],
            )
        )
    lines.extend(
        [
            "",
            "Evidence grades:",
            "",
            "- **E2E measured:** collector and evaluator ran with a least-privilege identity against an authorized disposable or non-production resource.",
            "- **Contract tested + export observed:** official response contracts and sanitized fixtures are tested, and an authorized scanner export established the rule/resource shape; no live resource measurement is claimed.",
            "- **Contract tested:** official response contracts and sanitized fixtures cover success, failure, malformed, denied, and absent-property behavior; no live resource measurement is claimed.",
            "- **Export observed:** an authorized scanner export established the offline rule/resource shape; no live resource measurement is claimed.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    document = matrix()
    outputs = {
        JSON_PATH: render_json(document),
        MARKDOWN_PATH: render_markdown(document),
    }
    if args.check:
        stale = [
            str(path.relative_to(ROOT))
            for path, expected in outputs.items()
            if not path.is_file() or path.read_text() != expected
        ]
        if stale:
            print("generated capability matrix is stale: " + ", ".join(stale), file=sys.stderr)
            return 1
        print("generated capability matrix is current")
        return 0
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
