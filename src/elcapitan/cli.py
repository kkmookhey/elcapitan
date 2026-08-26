"""Local product CLI. No agent runtime or Hermes process is required."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from .asff import asff_to_ocsf
from .case_store import SqliteCaseStore
from .case_validation import CaseValidationService
from .cases import case_to_dict
from .evidence import Collector
from .finding_store import SqliteFindingStore
from .intake import IntakeContext, RemediationIntake
from .product_records import SqliteProductRecordStore, product_record_to_dict
from .remediation_planning import (
    RecordedAgentRuntime, RemediationPlanningService, SubprocessTerraformRunner,
    TerraformChecksFailed,
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="elcapitan")
    sub = parser.add_subparsers(dest="command", required=True)
    intake = sub.add_parser("intake", help="ingest OCSF or ASFF findings")
    intake.add_argument("input", type=Path)
    intake.add_argument("--tenant", required=True)
    intake.add_argument("--db", type=Path, required=True)
    intake.add_argument("--artifacts", type=Path, required=True)
    intake.add_argument("--identity", default="local-intake")
    intake.add_argument("--asset-criticality", type=float, default=0.0)
    intake.add_argument("--exploit-probability", type=float, default=0.0)
    intake.add_argument("--internet-exposed", action="store_true", default=None)
    intake.add_argument("--reachable", action="store_true")
    intake.add_argument("--known-exploited", action="store_true")
    intake.add_argument("--active-exploitation", action="store_true")
    intake.add_argument("--runtime-dependency", action="store_true")
    intake.add_argument("--compensating-control-strength", type=float, default=0.0)
    intake.add_argument("--service-id", action="append", default=[])
    validate = sub.add_parser("validate", help="validate a prioritized case live")
    validate.add_argument("--case", required=True)
    validate.add_argument("--db", type=Path, required=True)
    validate.add_argument("--artifacts", type=Path, required=True)
    plan = sub.add_parser("plan", help="prepare and verify a Terraform remediation")
    plan.add_argument("--case", required=True)
    plan.add_argument("--db", type=Path, required=True)
    plan.add_argument("--artifacts", type=Path, required=True)
    plan.add_argument("--repo", type=Path, required=True)
    plan.add_argument(
        "--agent-result", type=Path, required=True,
        help="recorded TerraformRemediationProposal.v1 agent result",
    )
    plan.add_argument(
        "--state-json", type=Path,
        help="optional terraform show -json output for computed resource names",
    )
    plan.add_argument("--terraform-bin", default="terraform")
    plan.add_argument("--terraform-timeout", type=float, default=300)
    return parser


def _intake(args) -> int:
    document = json.loads(args.input.read_text())
    documents = document if isinstance(document, list) else [document]
    case_store = SqliteCaseStore(args.db)
    finding_store = SqliteFindingStore(args.db)
    service = RemediationIntake(
        case_store=case_store, finding_store=finding_store,
        artifact_root=args.artifacts,
        collector=Collector(tool="elcapitan-intake", version="0.1.0",
                            identity=args.identity), now=_now)
    context = IntakeContext(
        asset_criticality=args.asset_criticality,
        exploit_probability=args.exploit_probability,
        internet_exposed=args.internet_exposed,
        reachable=args.reachable,
        known_exploited=args.known_exploited,
        active_exploitation=args.active_exploitation,
        runtime_dependency=args.runtime_dependency,
        compensating_control_strength=args.compensating_control_strength,
        service_ids=tuple(args.service_id))
    outcomes = []
    for raw in documents:
        if isinstance(raw, dict) and "SchemaVersion" in raw:
            raw = asff_to_ocsf(raw)
        outcome = service.ingest(raw, tenant_id=args.tenant, context=context)
        outcomes.append({
            "finding_id": outcome.finding.finding_id,
            "case_id": outcome.case.case_id,
            "duplicate": outcome.duplicate,
            "case_created": outcome.case_created,
            "finding_attached": outcome.finding_attached,
            "priority_changed": outcome.priority_changed,
            "case": case_to_dict(outcome.case),
        })
    json.dump(outcomes, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "intake":
        return _intake(args)
    if args.command == "validate":
        case_store = SqliteCaseStore(args.db)
        service = CaseValidationService(
            case_store=case_store,
            finding_store=SqliteFindingStore(args.db),
            record_store=SqliteProductRecordStore(args.db),
            artifact_root=args.artifacts, now=_now)
        outcome = service.validate(args.case, host_env=os.environ)
        json.dump({
            "case": case_to_dict(outcome.case),
            "record": product_record_to_dict(outcome.record),
            "findings": [finding.to_dict() for finding in outcome.findings],
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.command == "plan":
        document = json.loads(args.agent_result.read_text())
        now = _now
        service = RemediationPlanningService(
            case_store=SqliteCaseStore(args.db),
            finding_store=SqliteFindingStore(args.db),
            record_store=SqliteProductRecordStore(args.db),
            artifact_root=args.artifacts,
            runtime=RecordedAgentRuntime(document, now=now),
            runner=SubprocessTerraformRunner(
                args.terraform_bin, timeout_seconds=args.terraform_timeout,
            ),
            now=now,
        )
        try:
            state_document = (
                json.loads(args.state_json.read_text()) if args.state_json else None
            )
            outcome = service.prepare(
                args.case, repository=args.repo, state_document=state_document,
            )
        except TerraformChecksFailed as exc:
            json.dump({
                "status": "rejected",
                "record": product_record_to_dict(exc.record),
                "checks": [check.to_dict() for check in exc.checks],
            }, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 2
        json.dump({
            "status": "plan_ready",
            "case": case_to_dict(outcome.case),
            "link": outcome.link.to_dict(),
            "link_record": product_record_to_dict(outcome.link_record),
            "plan_record": product_record_to_dict(outcome.plan_record),
            "checks": [check.to_dict() for check in outcome.checks],
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
