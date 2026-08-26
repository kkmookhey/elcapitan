"""Persistence and coordination boundaries for remediation workflows."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Protocol

from .cases import (CaseEvent, CaseTransition, RemediationCase,
                    open_case, transition_case)


class CaseNotFound(KeyError):
    pass


class ConcurrentCaseUpdate(RuntimeError):
    pass


class CaseStore(Protocol):
    def create(self, case: RemediationCase) -> None: ...
    def get(self, case_id: str) -> RemediationCase: ...
    def append(self, case: RemediationCase, event: CaseEvent,
               *, expected_version: int) -> None: ...
    def events(self, case_id: str) -> tuple[CaseEvent, ...]: ...
    def find_active_by_asset(self, tenant_id: str, asset_id: str
                             ) -> RemediationCase | None: ...


class InMemoryCaseStore:
    """Contract implementation for tests; production will use a durable store."""

    def __init__(self) -> None:
        self._cases: dict[str, RemediationCase] = {}
        self._events: dict[str, list[CaseEvent]] = {}
        self._lock = RLock()

    def create(self, case: RemediationCase) -> None:
        with self._lock:
            if case.case_id in self._cases:
                raise ConcurrentCaseUpdate(f"case {case.case_id} already exists")
            conflicts = [
                existing.case_id for existing in self._cases.values()
                if existing.tenant_id == case.tenant_id and not existing.terminal
                and set(existing.asset_ids) & set(case.asset_ids)
            ]
            if conflicts:
                raise ConcurrentCaseUpdate(
                    f"tenant {case.tenant_id} already has an active case for this asset: "
                    + ", ".join(sorted(conflicts)))
            self._cases[case.case_id] = case
            self._events[case.case_id] = []

    def get(self, case_id: str) -> RemediationCase:
        try:
            return self._cases[case_id]
        except KeyError as exc:
            raise CaseNotFound(case_id) from exc

    def append(self, case: RemediationCase, event: CaseEvent,
               *, expected_version: int) -> None:
        with self._lock:
            current = self.get(case.case_id)
            if current.version != expected_version:
                raise ConcurrentCaseUpdate(
                    f"case {case.case_id} is version {current.version}, "
                    f"expected {expected_version}")
            if event.sequence != expected_version + 1 or case.version != event.sequence:
                raise ValueError("event and projection versions are not contiguous")
            self._events[case.case_id].append(event)
            self._cases[case.case_id] = case

    def events(self, case_id: str) -> tuple[CaseEvent, ...]:
        self.get(case_id)
        return tuple(self._events[case_id])

    def find_active_by_asset(self, tenant_id: str, asset_id: str
                             ) -> RemediationCase | None:
        matches = [
            case for case in self._cases.values()
            if case.tenant_id == tenant_id and asset_id in case.asset_ids
            and not case.terminal
        ]
        if not matches:
            return None
        return max(matches, key=lambda case: (case.updated_at, case.case_id))


@dataclass(frozen=True)
class WorkflowCoordinator:
    store: CaseStore

    def open(self, **kwargs) -> RemediationCase:
        case = open_case(**kwargs)
        self.store.create(case)
        return case

    def advance(self, case_id: str, transition: CaseTransition, **kwargs) -> RemediationCase:
        current = self.store.get(case_id)
        projection, event = transition_case(current, transition, **kwargs)
        self.store.append(projection, event, expected_version=current.version)
        return projection
