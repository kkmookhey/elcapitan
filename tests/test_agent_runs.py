from dataclasses import replace

import pytest

from elcapitan.agent_runs import (
    AgentRunPolicy, AgentRunRuntime, AgentRunStopped, INVOCATION_RECORD,
    OUTCOME_RECORD, TERMINAL_RECORD,
)
from elcapitan.agents import AgentResult, AgentResultStatus, AgentRole, AgentTask
from elcapitan.cases import CaseState, RemediationCase
from elcapitan.orchestration import PreApprovalOrchestrator
from elcapitan.preapproval import PreApprovalError
from elcapitan.product_records import ProductRecord, SqliteProductRecordStore
from elcapitan.workflow import InMemoryCaseStore


NOW = "2026-08-28T18:00:00Z"


def task(case_id="CASE-1", task_id="TASK-1", constraints=()) -> AgentTask:
    return AgentTask(
        task_id=task_id, case_id=case_id, role=AgentRole.SRE_REVIEWER,
        objective="Review the bounded package", output_contract="SREReview.v1",
        input_record_ids=("PLAN-1",), evidence_ids=("EVD-1",),
        constraints=constraints)


def result(dispatched, *, status=AgentResultStatus.SUCCEEDED) -> AgentResult:
    return AgentResult(
        task_id=dispatched.task_id, case_id=dispatched.case_id,
        role=dispatched.role, status=status,
        output={"summary": "bounded result"}, evidence_cited=("EVD-1",),
        missing_evidence=("owner context",) if status is not AgentResultStatus.SUCCEEDED else (),
        runtime="fake-runtime", model="fake-model", started_at=NOW,
        completed_at=NOW, usage={"total_tokens": 17})


class SuccessRuntime:
    name = "fake-runtime"

    def __init__(self):
        self.calls = []

    def run(self, dispatched):
        self.calls.append(dispatched)
        return result(dispatched)


def test_success_is_recorded_and_replayed_after_durable_restart(tmp_path):
    path = tmp_path / "product.db"
    provider = SuccessRuntime()
    runtime = AgentRunRuntime(
        provider, record_store=SqliteProductRecordStore(path),
        artifact_root=tmp_path / "artifacts", now=lambda: NOW)

    first = runtime.run(task())
    restarted = AgentRunRuntime(
        provider, record_store=SqliteProductRecordStore(path),
        artifact_root=tmp_path / "artifacts", now=lambda: NOW)
    replayed = restarted.run(task(task_id="TASK-NEW"))

    assert first.status is AgentResultStatus.SUCCEEDED
    assert replayed.task_id == "TASK-NEW"
    assert replayed.output == first.output
    assert len(provider.calls) == 1
    records = SqliteProductRecordStore(path).list_for_case("CASE-1")
    assert [record.record_type for record in records] == [
        INVOCATION_RECORD, OUTCOME_RECORD]
    assert records[0].body["status"] == "started"
    assert records[1].body["status"] == "succeeded"
    assert "result" not in records[1].body
    assert records[1].body["result_sha256"]
    assert records[1].evidence_ids


def test_role_package_attempt_exhaustion_is_durable_and_stops_dispatch(tmp_path):
    class NeedsContextRuntime(SuccessRuntime):
        def run(self, dispatched):
            self.calls.append(dispatched)
            return result(dispatched, status=AgentResultStatus.NEEDS_HUMAN_CONTEXT)

    provider = NeedsContextRuntime()
    store = SqliteProductRecordStore(tmp_path / "product.db")
    runtime = AgentRunRuntime(
        provider, record_store=store, artifact_root=tmp_path / "artifacts",
        now=lambda: NOW,
        policy=AgentRunPolicy(
            max_attempts_per_role_package=2,
            equivalent_failure_threshold=3))

    assert runtime.run(task()).status is AgentResultStatus.NEEDS_HUMAN_CONTEXT
    assert runtime.run(task()).status is AgentResultStatus.NEEDS_HUMAN_CONTEXT
    with pytest.raises(AgentRunStopped) as stopped:
        runtime.run(task())

    assert len(provider.calls) == 2
    assert stopped.value.record.body["status"] == "needs_human"
    assert stopped.value.record.body["reason"] == "role_package_attempt_budget_exhausted"
    assert store.get(stopped.value.record.record_id).record_type == TERMINAL_RECORD


def test_repeated_equivalent_failures_open_circuit_before_another_dispatch(tmp_path):
    class FailingRuntime:
        name = "failing-runtime"

        def __init__(self):
            self.calls = 0

        def run(self, dispatched):
            self.calls += 1
            raise RuntimeError("same bounded provider failure")

    provider = FailingRuntime()
    store = SqliteProductRecordStore(tmp_path / "product.db")
    runtime = AgentRunRuntime(
        provider, record_store=store, artifact_root=tmp_path / "artifacts",
        now=lambda: NOW)

    with pytest.raises(RuntimeError, match="same bounded"):
        runtime.run(task())
    with pytest.raises(AgentRunStopped) as stopped:
        runtime.run(task())
    with pytest.raises(AgentRunStopped):
        AgentRunRuntime(
            provider, record_store=store, artifact_root=tmp_path / "artifacts",
            now=lambda: NOW).run(task())

    assert provider.calls == 2
    assert stopped.value.record.body["reason"] == "equivalent_failure_circuit_open"
    outcomes = store.list_for_case("CASE-1", record_type=OUTCOME_RECORD)
    assert len(outcomes) == 2
    assert len({item.body["failure_signature"] for item in outcomes}) == 1


def test_invalid_runtime_identity_is_never_cached_as_success(tmp_path):
    class MismatchedRuntime:
        name = "mismatched-runtime"

        def __init__(self):
            self.calls = 0

        def run(self, dispatched):
            self.calls += 1
            return replace(result(dispatched), case_id="OTHER-CASE")

    provider = MismatchedRuntime()
    store = SqliteProductRecordStore(tmp_path / "product.db")
    runtime = AgentRunRuntime(
        provider, record_store=store, artifact_root=tmp_path / "artifacts",
        now=lambda: NOW)

    assert runtime.run(task()).case_id == "OTHER-CASE"
    with pytest.raises(AgentRunStopped) as stopped:
        runtime.run(task())

    assert provider.calls == 2
    assert stopped.value.record.body["reason"] == "equivalent_failure_circuit_open"
    outcomes = store.list_for_case("CASE-1", record_type=OUTCOME_RECORD)
    assert all(item.body["status"] == "not_succeeded" for item in outcomes)
    assert all(item.body["failure_code"] == "invalid_result_contract"
               for item in outcomes)


def test_elapsed_limit_and_independent_case_budgets(tmp_path):
    current = [NOW]

    class NeedsContextRuntime(SuccessRuntime):
        def run(self, dispatched):
            self.calls.append(dispatched)
            return result(dispatched, status=AgentResultStatus.NEEDS_HUMAN_CONTEXT)

    provider = NeedsContextRuntime()
    store = SqliteProductRecordStore(tmp_path / "product.db")
    policy = AgentRunPolicy(
        max_model_calls=3, max_elapsed_seconds=10,
        equivalent_failure_threshold=3)
    runtime = AgentRunRuntime(
        provider, record_store=store, artifact_root=tmp_path / "artifacts",
        now=lambda: current[0], policy=policy)
    runtime.run(task(case_id="CASE-1"))
    runtime.run(task(case_id="CASE-2"))
    current[0] = "2026-08-28T18:00:11Z"

    with pytest.raises(AgentRunStopped) as stopped:
        runtime.run(replace(task(case_id="CASE-1"), constraints=("correct",)))

    assert len(provider.calls) == 2
    assert stopped.value.record.body["reason"] == "elapsed_run_budget_exhausted"
    assert len(store.list_for_case("CASE-2", record_type=INVOCATION_RECORD)) == 1


def test_model_call_budget_is_per_case_across_distinct_packages(tmp_path):
    provider = SuccessRuntime()
    store = SqliteProductRecordStore(tmp_path / "product.db")
    runtime = AgentRunRuntime(
        provider, record_store=store, artifact_root=tmp_path / "artifacts",
        now=lambda: NOW,
        policy=AgentRunPolicy(max_model_calls=1))
    runtime.run(task(case_id="CASE-1"))
    runtime.run(task(case_id="CASE-2"))
    changed_package = replace(task(case_id="CASE-1"), evidence_ids=("EVD-2",))

    with pytest.raises(AgentRunStopped) as stopped:
        runtime.run(changed_package)

    assert stopped.value.record.body["reason"] == "model_call_budget_exhausted"
    assert len(provider.calls) == 2


def test_incomplete_invocation_blocks_reload_without_redispatch(tmp_path):
    store = SqliteProductRecordStore(tmp_path / "product.db")
    store.put(ProductRecord(
        record_id="AINV-PENDING", case_id="CASE-1",
        record_type=INVOCATION_RECORD, schema_version=1, created_at=NOW,
        body={"package_key": "different-package", "status": "started"}))
    provider = SuccessRuntime()

    with pytest.raises(AgentRunStopped) as stopped:
        AgentRunRuntime(
            provider, record_store=store, artifact_root=tmp_path / "artifacts",
            now=lambda: NOW).run(task())

    assert provider.calls == []
    assert stopped.value.record.body["reason"] == "incomplete_prior_invocation"


def test_orchestrator_binds_terminal_record_to_blocked_case():
    cases = InMemoryCaseStore()
    cases.create(RemediationCase(
        case_id="CASE-1", tenant_id="TENANT-1", finding_ids=("FIND-1",),
        asset_ids=(), service_ids=(), state=CaseState.VALIDATED, version=0,
        created_at=NOW, updated_at=NOW))
    terminal = ProductRecord(
        record_id="ARUN-1", case_id="CASE-1", record_type=TERMINAL_RECORD,
        schema_version=1, created_at=NOW,
        body={"status": "needs_human", "reason": "model_call_budget_exhausted"})
    orchestrator = object.__new__(PreApprovalOrchestrator)
    orchestrator.case_store = cases
    orchestrator.now = lambda: NOW
    orchestrator.id_factory = lambda prefix: f"{prefix}-1"

    with pytest.raises(PreApprovalError, match="agent run stopped"):
        orchestrator._guard_agent_run(
            "CASE-1", lambda: (_ for _ in ()).throw(AgentRunStopped(terminal)))

    blocked = cases.get("CASE-1")
    assert blocked.state is CaseState.BLOCKED
    assert blocked.record_ids["agent_run_terminal_id"] == "ARUN-1"
