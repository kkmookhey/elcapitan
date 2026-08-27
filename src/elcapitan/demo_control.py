"""Stateful control plane for the browser demonstration.

The demo uses the same durable case, approval, scheduler, execution, rollback,
and certificate services as the product.  Its only synthetic inputs are the
scanner finding, usage history, and service-health observations.
"""
from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import io
import json
import shutil
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Mapping

from .action_plane import (
    ApprovalService,
    ExecutionService,
    FileHashProbe,
    FilesystemChangeDriver,
    HealthObservation,
    RecordedHealthMonitor,
    RecordedVerificationProbe,
    VerifiedApproval,
)
from .agents import RecordedContractRuntime
from .case_store import SqliteCaseStore
from .cases import case_to_dict, event_to_dict
from .cli import _demo_review
from .product_records import SqliteProductRecordStore, product_record_to_dict
from .scheduler import ExecutionScheduler, ScheduledExecutionWorker, SqliteExecutionJobStore


class DemoControlError(RuntimeError):
    """A safe, user-visible demo transition failure."""


_STAGE_ORDER = (
    "open",
    "prioritized",
    "validated",
    "plan_ready",
    "sre_approved",
    "window_selected",
    "rollback_ready",
    "awaiting_approval",
    "approved",
    "executing",
    "verifying",
    "remediated",
)


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, document: Mapping) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


class DemoControlPlane:
    """Drive a resettable, single-node demonstration through real services."""

    def __init__(self, root, *, terraform_bin: str = "terraform",
                 terraform_timeout: float = 120) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.terraform_bin = terraform_bin
        self.terraform_timeout = terraform_timeout
        self._lock = threading.RLock()
        self._session_path = self.root / "active-session.json"
        if not self._session_path.exists():
            self.reset()

    def reset(self) -> dict:
        """Start a new session without deleting evidence from earlier runs."""
        with self._lock:
            session_id = f"DEMO-{datetime.now(UTC):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
            session = {
                "session_id": session_id,
                "phase": "ready",
                "created_at": _utc_text(datetime.now(UTC)),
                "message": "Demo workspace is ready. No case has been prepared.",
                "requested_outcome": None,
            }
            _write_json(self._session_path, session)
            return self.state()

    def _session(self) -> dict:
        return _read_json(self._session_path)

    def _save(self, session: Mapping) -> None:
        _write_json(self._session_path, session)

    def prepare(self) -> dict:
        with self._lock:
            session = self._session()
            if session["phase"] != "ready":
                raise DemoControlError("Reset the demo before preparing another case.")
            run = self.root / "runs" / session["session_id"]
            args = argparse.Namespace(
                workdir=run,
                terraform_bin=self.terraform_bin,
                terraform_timeout=self.terraform_timeout,
            )
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                _demo_review(args)
            prepared = json.loads(capture.getvalue())
            session.update({
                "phase": "awaiting_approval",
                "message": "Fleet review complete. Human approval is required.",
                "run_dir": str(run),
                "case_id": prepared["case_id"],
                "database": prepared["database"],
                "artifacts": prepared["artifacts"],
                "review_package_id": prepared["review_package_id"],
                "terraform_checks": prepared["terraform_checks"],
                "source_repository_unchanged": prepared["source_repository_unchanged"],
            })
            self._save(session)
            return self.state()

    def approve(self, *, approver: str) -> dict:
        with self._lock:
            session = self._session()
            if session["phase"] != "awaiting_approval":
                raise DemoControlError("The case is not waiting for approval.")
            approver = approver.strip()
            if not approver:
                raise DemoControlError("An approver name is required.")
            run, db, artifacts = self._paths(session)
            cases, records = SqliteCaseStore(db), SqliteProductRecordStore(db)
            case = cases.get(session["case_id"])
            target = run / "deployment-target"
            shutil.copytree(run / "customer-repo", target)
            target_source = target / "infra" / "main.tf"
            original_sha256 = hashlib.sha256(target_source.read_bytes()).hexdigest()
            window_start = datetime.fromisoformat(
                case.change_window.starts_at.replace("Z", "+00:00"))
            approval_time = window_start - timedelta(minutes=1)
            execution_time = window_start + timedelta(minutes=1)
            approval_now = lambda: _utc_text(approval_time)
            approval = VerifiedApproval(
                approval_id=f"APPROVAL-{case.case_id.split('-', 1)[-1]}",
                case_id=case.case_id,
                review_package_id=case.record_ids["human_review_package_id"],
                approver=approver,
                authenticated_at=approval_now(),
                expires_at=case.change_window.ends_at,
                authentication_method="demo-browser-explicit-approval",
                statement="I approve this exact review package for its selected window.",
            )
            ApprovalService(
                case_store=cases,
                record_store=records,
                artifact_root=artifacts,
                now=approval_now,
            ).approve(approval)
            scheduled = ExecutionScheduler(
                case_store=cases,
                record_store=records,
                job_store=SqliteExecutionJobStore(db),
                now=approval_now,
            ).schedule(case.case_id)
            session.update({
                "phase": "approved",
                "message": "Package approved and durably scheduled for the selected window.",
                "approver": approver,
                "approval_id": approval.approval_id,
                "execution_job_id": scheduled.job.job_id,
                "execution_time": _utc_text(execution_time),
                "deployment_target": str(target),
                "original_sha256": original_sha256,
            })
            self._save(session)
            return self.state()

    def execute(self, *, outcome: str) -> dict:
        with self._lock:
            if outcome not in {"success", "rollback"}:
                raise DemoControlError("Outcome must be success or rollback.")
            session = self._session()
            if session["phase"] != "approved":
                raise DemoControlError("The case must be approved and scheduled first.")
            run, db, artifacts = self._paths(session)
            cases, records = SqliteCaseStore(db), SqliteProductRecordStore(db)
            target = Path(session["deployment_target"])
            target_source = target / "infra" / "main.tf"
            execution_time = datetime.fromisoformat(
                session["execution_time"].replace("Z", "+00:00"))
            now = lambda: _utc_text(execution_time)
            healthy = HealthObservation(
                True,
                ("all required health signals pass",),
                {"success_rate": 1.0, "p95_latency_ms": 50},
            )
            unhealthy = HealthObservation(
                False,
                ("injected post-deploy SLO breach",),
                {"success_rate": 0.7, "p95_latency_ms": 900},
            )
            monitor = RecordedHealthMonitor({
                "baseline": healthy,
                "after_deploy": healthy if outcome == "success" else unhealthy,
                "rollback": healthy,
            })
            runtime = RecordedContractRuntime({
                "PostChangeReview.v1": {"output": {
                    "decision": "accept",
                    "summary": (
                        "The approved change is deployed, healthy, and independently verified."
                    ),
                    "validated_outcomes": [
                        "approved file hash deployed",
                        "original vulnerability no longer confirmed",
                    ],
                    "residual_risks": [],
                    "handoff_notes": ["continue normal service monitoring"],
                }}
            }, now=now)
            service = ExecutionService(
                case_store=cases,
                record_store=records,
                artifact_root=artifacts,
                driver=FilesystemChangeDriver(target),
                monitor=monitor,
                probes=(
                    FileHashProbe(target),
                    RecordedVerificationProbe(
                        name="live-vulnerability-revalidation",
                        target="demo-storage",
                        passed=True,
                        detail="public network finding is no longer confirmed",
                        payload={"status": "not_confirmed"},
                    ),
                    RecordedVerificationProbe(
                        name="ui-and-api-smoke",
                        target="demo-service",
                        passed=True,
                        detail="UI and API smoke checks pass",
                    ),
                ),
                runtime=runtime,
                now=now,
            )
            jobs = SqliteExecutionJobStore(db)
            dispatched = ScheduledExecutionWorker(
                job_store=jobs,
                worker_id="demo-browser-worker",
                execute=lambda job: service.execute(
                    job.case_id,
                    originator="demo-scanner-originator",
                    execution_job_id=job.job_id,
                ),
            ).run_once(now=session["execution_time"])
            if dispatched is None:
                raise DemoControlError("The scheduler did not release the approved job.")
            result = dispatched.result
            final_sha256 = hashlib.sha256(target_source.read_bytes()).hexdigest()
            session.update({
                "phase": result.case.state.value,
                "message": (
                    "Remediation verified and handed back to the originator."
                    if not result.rolled_back
                    else "Health policy triggered automatic rollback; service was restored."
                ),
                "requested_outcome": outcome,
                "rolled_back": result.rolled_back,
                "final_sha256": final_sha256,
                "deployment_target_changed": final_sha256 != session["original_sha256"],
                "deployment_target_restored": final_sha256 == session["original_sha256"],
            })
            self._save(session)
            return self.state()

    @staticmethod
    def _paths(session: Mapping) -> tuple[Path, Path, Path]:
        return Path(session["run_dir"]), Path(session["database"]), Path(session["artifacts"])

    def state(self) -> dict:
        with self._lock:
            session = self._session()
            result = {
                "demo": {
                    key: value for key, value in session.items()
                    if key not in {"database", "artifacts", "deployment_target", "run_dir"}
                },
                "case": None,
                "events": [],
                "records": [],
                "review_package": None,
                "change_diff": "",
                "stages": self._stages(session.get("phase", "ready")),
                "safety": {
                    "target": "isolated local reference deployment",
                    "source_repository_mutated": False,
                    "human_gate_bypassed": False,
                    "demo_clock": "The approved future window is simulated deterministically.",
                },
            }
            if not session.get("case_id"):
                return result
            run, db, _ = self._paths(session)
            cases, records = SqliteCaseStore(db), SqliteProductRecordStore(db)
            case = cases.get(session["case_id"])
            serialized_records = [
                product_record_to_dict(record)
                for record in records.list_for_case(case.case_id)
            ]
            result.update({
                "case": case_to_dict(case),
                "events": [event_to_dict(event) for event in cases.events(case.case_id)],
                "records": serialized_records,
                "review_package": next((
                    record for record in serialized_records
                    if record["record_type"] == "HumanReviewPackage.v1"
                ), None),
                "change_diff": self._change_diff(run),
                "stages": self._stages(case.state.value),
            })
            return result

    @staticmethod
    def _change_diff(run: Path) -> str:
        original = run / "customer-repo" / "infra" / "main.tf"
        workspace = next(
            (path for path in (run / "artifacts" / "cases").glob(
                "*/planning/*/workspace/infra/main.tf")),
            None,
        )
        if not original.is_file() or workspace is None or not workspace.is_file():
            return ""
        return "".join(difflib.unified_diff(
            original.read_text(encoding="utf-8").splitlines(keepends=True),
            workspace.read_text(encoding="utf-8").splitlines(keepends=True),
            fromfile="customer-repo/infra/main.tf",
            tofile="verified-workspace/infra/main.tf",
        ))

    @staticmethod
    def _stages(state: str) -> list[dict]:
        aliases = {
            "rolled_back": "executing",
            "rolling_back": "executing",
            "awaiting_approval": "awaiting_approval",
            "approved": "approved",
        }
        current = aliases.get(state, state)
        try:
            current_index = _STAGE_ORDER.index(current)
        except ValueError:
            current_index = -1
        labels = {
            "open": "Finding intake",
            "prioritized": "Risk prioritized",
            "validated": "Live validation",
            "plan_ready": "Remediation plan",
            "sre_approved": "SRE review",
            "window_selected": "Change window",
            "rollback_ready": "Rollback checked",
            "awaiting_approval": "Human approval",
            "approved": "Scheduled",
            "executing": "Deploy & monitor",
            "verifying": "Post-change verify",
            "remediated": "Signed handoff",
        }
        return [
            {
                "state": item,
                "label": labels[item],
                "status": (
                    "complete" if index < current_index else
                    "current" if index == current_index else "pending"
                ),
            }
            for index, item in enumerate(_STAGE_ORDER)
        ]
