"""Durable execution scheduling with leases and missed-window protection."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Callable, Protocol

from .cases import CaseState, CaseTransition, RemediationCase
from .intake import numeric_id
from .observability import parse_timestamp, utc_text
from .product_records import ProductRecord, ProductRecordStore
from .workflow import CaseStore, WorkflowCoordinator


class JobState(StrEnum):
    SCHEDULED = "scheduled"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    MISSED = "missed"


@dataclass(frozen=True)
class ExecutionJob:
    job_id: str
    case_id: str
    execute_at: str
    deadline: str
    state: JobState
    attempts: int
    lease_owner: str = ""
    lease_until: str = ""
    detail: str = ""


class ExecutionJobStore(Protocol):
    def put(self, job: ExecutionJob) -> None: ...
    def get(self, job_id: str) -> ExecutionJob: ...
    def claim_due(self, *, now: str, worker_id: str,
                  lease_seconds: int = 300) -> ExecutionJob | None: ...
    def complete(self, job_id: str, *, worker_id: str, state: JobState,
                 detail: str = "") -> ExecutionJob: ...


class SqliteExecutionJobStore:
    def __init__(self, path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS execution_jobs (
                        job_id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL UNIQUE,
                        execute_at TEXT NOT NULL,
                        deadline TEXT NOT NULL,
                        state TEXT NOT NULL,
                        attempts INTEGER NOT NULL,
                        lease_owner TEXT NOT NULL,
                        lease_until TEXT NOT NULL,
                        detail TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS execution_jobs_due
                        ON execution_jobs(state, execute_at, deadline);
                """)

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @staticmethod
    def _job(row) -> ExecutionJob:
        return ExecutionJob(row[0], row[1], row[2], row[3], JobState(row[4]),
                            row[5], row[6], row[7], row[8])

    def put(self, job: ExecutionJob) -> None:
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        "INSERT INTO execution_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (job.job_id, job.case_id, job.execute_at, job.deadline,
                         job.state.value, job.attempts, job.lease_owner,
                         job.lease_until, job.detail))
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"case {job.case_id} already has a scheduled job") from exc

    def get(self, job_id: str) -> ExecutionJob:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM execution_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        return self._job(row)

    def claim_due(self, *, now: str, worker_id: str,
                  lease_seconds: int = 300) -> ExecutionJob | None:
        if not worker_id or lease_seconds <= 0:
            raise ValueError("worker id and positive lease are required")
        current = parse_timestamp(now)
        lease_until = utc_text(current + timedelta(seconds=lease_seconds))
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE execution_jobs SET state = ?, detail = ? "
                "WHERE state = ? AND deadline <= ?",
                (JobState.MISSED.value, "approved window elapsed before execution",
                 JobState.SCHEDULED.value, now))
            row = connection.execute(
                "SELECT * FROM execution_jobs WHERE execute_at <= ? AND deadline > ? "
                "AND (state = ? OR (state = ? AND lease_until <= ?)) "
                "ORDER BY execute_at, job_id LIMIT 1",
                (now, now, JobState.SCHEDULED.value, JobState.RUNNING.value, now),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            job = self._job(row)
            connection.execute(
                "UPDATE execution_jobs SET state = ?, attempts = attempts + 1, "
                "lease_owner = ?, lease_until = ? WHERE job_id = ?",
                (JobState.RUNNING.value, worker_id, lease_until, job.job_id))
            connection.commit()
            return self.get(job.job_id)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete(self, job_id: str, *, worker_id: str, state: JobState,
                 detail: str = "") -> ExecutionJob:
        if state not in {JobState.SUCCEEDED, JobState.ROLLED_BACK, JobState.FAILED}:
            raise ValueError("job completion state must be terminal")
        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    "UPDATE execution_jobs SET state = ?, detail = ?, lease_owner = '', "
                    "lease_until = '' WHERE job_id = ? AND state = ? AND lease_owner = ?",
                    (state.value, detail, job_id, JobState.RUNNING.value, worker_id))
                if cursor.rowcount != 1:
                    raise ValueError("job is not leased by this worker")
        return self.get(job_id)


@dataclass(frozen=True)
class SchedulingOutcome:
    case: RemediationCase
    record: ProductRecord
    job: ExecutionJob


class ExecutionScheduler:
    def __init__(self, *, case_store: CaseStore, record_store: ProductRecordStore,
                 job_store: ExecutionJobStore, now: Callable[[], str],
                 id_factory: Callable[[str], str] = numeric_id) -> None:
        self.case_store, self.record_store, self.job_store = case_store, record_store, job_store
        self.now, self.id_factory = now, id_factory
        self.workflow = WorkflowCoordinator(case_store)

    def schedule(self, case_id: str) -> SchedulingOutcome:
        case = self.case_store.get(case_id)
        if case.state is not CaseState.APPROVED or not case.change_window:
            raise ValueError("only an approved case with a change window can be scheduled")
        if parse_timestamp(case.change_window.ends_at) <= parse_timestamp(self.now()):
            raise ValueError("approved change window has already elapsed")
        job_id, schedule_id, now = (
            self.id_factory("JOB"), self.id_factory("SCHEDULE"), self.now())
        job = ExecutionJob(
            job_id, case_id, case.change_window.starts_at, case.change_window.ends_at,
            JobState.SCHEDULED, 0)
        self.job_store.put(job)
        record = ProductRecord(
            record_id=schedule_id, case_id=case_id, record_type="ExecutionSchedule.v1",
            schema_version=1, created_at=now,
            body={"schedule_id": schedule_id, "job_id": job_id,
                  "execute_at": job.execute_at, "deadline": job.deadline,
                  "window_id": case.change_window.window_id},
            evidence_ids=case.change_window.evidence_ids)
        self.record_store.put(record)
        case = self.workflow.advance(
            case_id, CaseTransition.SCHEDULE_EXECUTION,
            event_id=self.id_factory("EVT"), occurred_at=now, actor="execution-scheduler",
            record_ids={"schedule_id": schedule_id, "execution_job_id": job_id},
            evidence_ids=record.evidence_ids)
        return SchedulingOutcome(case, record, job)


@dataclass(frozen=True)
class DispatchOutcome:
    job: ExecutionJob
    result: object


class ScheduledExecutionWorker:
    """Claim exactly one due job and always release its durable lease."""

    def __init__(self, *, job_store: ExecutionJobStore, worker_id: str,
                 execute: Callable[[ExecutionJob], object]) -> None:
        if not worker_id:
            raise ValueError("worker_id is required")
        self.job_store, self.worker_id, self.execute = job_store, worker_id, execute

    def run_once(self, *, now: str) -> DispatchOutcome | None:
        job = self.job_store.claim_due(now=now, worker_id=self.worker_id)
        if job is None:
            return None
        try:
            result = self.execute(job)
            rolled_back = bool(getattr(result, "rolled_back", False))
            state = JobState.ROLLED_BACK if rolled_back else JobState.SUCCEEDED
            completed = self.job_store.complete(
                job.job_id, worker_id=self.worker_id, state=state,
                detail=str(getattr(getattr(result, "case", None), "state", state.value)))
            return DispatchOutcome(completed, result)
        except Exception as exc:
            self.job_store.complete(
                job.job_id, worker_id=self.worker_id, state=JobState.FAILED,
                detail=f"execution worker failed: {exc}")
            raise
