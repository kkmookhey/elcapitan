import pytest

from elcapitan.cases import CaseState, ChangeWindow, RemediationCase
from elcapitan.product_records import SqliteProductRecordStore
from elcapitan.scheduler import (
    ExecutionScheduler, JobState, ScheduledExecutionWorker,
    SqliteExecutionJobStore,
)
from elcapitan.workflow import InMemoryCaseStore


def approved_case():
    return RemediationCase(
        case_id="CASE-001", tenant_id="TEN-001", finding_ids=("FIND-001",),
        asset_ids=("asset",), service_ids=("service",), state=CaseState.APPROVED,
        version=0, created_at="2026-08-26T00:00:00Z",
        updated_at="2026-08-26T00:00:00Z",
        change_window=ChangeWindow(
            "WIN-001", "2026-08-27T02:00:00Z", "2026-08-27T03:00:00Z",
            "UTC", ("low usage",), ("EVD-001",), .9),
        record_ids={"approval_id": "APP-001"})


def test_scheduler_persists_claims_and_enforces_worker_lease(tmp_path):
    cases = InMemoryCaseStore()
    cases.create(approved_case())
    jobs = SqliteExecutionJobStore(tmp_path / "product.db")
    outcome = ExecutionScheduler(
        case_store=cases, record_store=SqliteProductRecordStore(tmp_path / "product.db"),
        job_store=jobs, now=lambda: "2026-08-26T12:00:00Z",
        id_factory=lambda prefix: f"{prefix}-001",
    ).schedule("CASE-001")
    assert outcome.case.state is CaseState.APPROVED
    assert outcome.case.record_ids["execution_job_id"] == "JOB-001"
    assert jobs.claim_due(now="2026-08-27T01:59:00Z", worker_id="worker") is None
    claimed = jobs.claim_due(now="2026-08-27T02:00:00Z", worker_id="worker")
    assert claimed.state is JobState.RUNNING
    assert claimed.attempts == 1
    completed = jobs.complete(
        claimed.job_id, worker_id="worker", state=JobState.SUCCEEDED,
        detail="case remediated")
    assert completed.state is JobState.SUCCEEDED


def test_scheduler_marks_unclaimed_elapsed_window_missed(tmp_path):
    cases = InMemoryCaseStore()
    cases.create(approved_case())
    jobs = SqliteExecutionJobStore(tmp_path / "product.db")
    ExecutionScheduler(
        case_store=cases, record_store=SqliteProductRecordStore(tmp_path / "product.db"),
        job_store=jobs, now=lambda: "2026-08-26T12:00:00Z",
        id_factory=lambda prefix: f"{prefix}-001",
    ).schedule("CASE-001")
    assert jobs.claim_due(now="2026-08-27T03:01:00Z", worker_id="worker") is None
    assert jobs.get("JOB-001").state is JobState.MISSED


def test_worker_releases_failed_job_lease(tmp_path):
    cases = InMemoryCaseStore()
    cases.create(approved_case())
    jobs = SqliteExecutionJobStore(tmp_path / "product.db")
    ExecutionScheduler(
        case_store=cases, record_store=SqliteProductRecordStore(tmp_path / "product.db"),
        job_store=jobs, now=lambda: "2026-08-26T12:00:00Z",
        id_factory=lambda prefix: f"{prefix}-001",
    ).schedule("CASE-001")

    def fail(job):
        raise RuntimeError("worker crashed")

    with pytest.raises(RuntimeError, match="worker crashed"):
        ScheduledExecutionWorker(
            job_store=jobs, worker_id="worker", execute=fail,
        ).run_once(now="2026-08-27T02:00:00Z")
    failed = jobs.get("JOB-001")
    assert failed.state is JobState.FAILED
    assert failed.lease_owner == ""
