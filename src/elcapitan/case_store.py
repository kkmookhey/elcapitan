"""Durable local case store with append-only events and optimistic locking.

SQLite is the development and single-node implementation of the ``CaseStore``
contract.  The product can move this contract to PostgreSQL without changing
domain transitions or agent runtimes.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .cases import (
    CaseEvent, RemediationCase, case_from_dict, case_to_dict,
    event_from_dict, event_to_dict,
)
from .hashing import canonical_json
from .workflow import CaseNotFound, ConcurrentCaseUpdate


class SqliteCaseStore:
    def __init__(self, path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @staticmethod
    def _json(document: dict) -> str:
        return canonical_json(document).decode("utf-8")

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS remediation_cases (
                        case_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        projection TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS remediation_cases_tenant_state
                        ON remediation_cases(tenant_id, state);
                    CREATE TABLE IF NOT EXISTS case_assets (
                        case_id TEXT NOT NULL REFERENCES remediation_cases(case_id),
                        tenant_id TEXT NOT NULL,
                        asset_id TEXT NOT NULL,
                        PRIMARY KEY (case_id, asset_id)
                    );
                    CREATE INDEX IF NOT EXISTS case_assets_lookup
                        ON case_assets(tenant_id, asset_id);
                    CREATE TABLE IF NOT EXISTS active_case_assets (
                        tenant_id TEXT NOT NULL,
                        asset_id TEXT NOT NULL,
                        case_id TEXT NOT NULL REFERENCES remediation_cases(case_id),
                        PRIMARY KEY (tenant_id, asset_id)
                    );
                    CREATE TABLE IF NOT EXISTS case_events (
                        case_id TEXT NOT NULL REFERENCES remediation_cases(case_id),
                        sequence INTEGER NOT NULL,
                        event_id TEXT NOT NULL UNIQUE,
                        event TEXT NOT NULL,
                        PRIMARY KEY (case_id, sequence)
                    );
                """)

    def create(self, case: RemediationCase) -> None:
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        "INSERT INTO remediation_cases"
                        "(case_id, tenant_id, state, version, projection) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (case.case_id, case.tenant_id, case.state.value, case.version,
                         self._json(case_to_dict(case))),
                    )
                    connection.executemany(
                        "INSERT INTO case_assets(case_id, tenant_id, asset_id) "
                        "VALUES (?, ?, ?)",
                        [(case.case_id, case.tenant_id, asset_id)
                         for asset_id in case.asset_ids],
                    )
                    if not case.terminal:
                        connection.executemany(
                            "INSERT INTO active_case_assets(tenant_id, asset_id, case_id) "
                            "VALUES (?, ?, ?)",
                            [(case.tenant_id, asset_id, case.case_id)
                             for asset_id in case.asset_ids],
                        )
        except sqlite3.IntegrityError as exc:
            active = None
            for asset_id in case.asset_ids:
                active = self.find_active_by_asset(case.tenant_id, asset_id)
                if active is not None:
                    break
            if active:
                raise ConcurrentCaseUpdate(
                    f"tenant {case.tenant_id} already has active case "
                    f"{active.case_id} for this asset") from exc
            raise ConcurrentCaseUpdate(f"case {case.case_id} already exists") from exc

    def get(self, case_id: str) -> RemediationCase:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT projection FROM remediation_cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            raise CaseNotFound(case_id)
        return case_from_dict(json.loads(row[0]))

    def append(self, case: RemediationCase, event: CaseEvent,
               *, expected_version: int) -> None:
        if event.case_id != case.case_id:
            raise ValueError("event and projection belong to different cases")
        if event.sequence != expected_version + 1 or case.version != event.sequence:
            raise ValueError("event and projection versions are not contiguous")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE remediation_cases SET state = ?, version = ?, projection = ? "
                "WHERE case_id = ? AND version = ?",
                (case.state.value, case.version, self._json(case_to_dict(case)),
                 case.case_id, expected_version),
            )
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT version FROM remediation_cases WHERE case_id = ?",
                    (case.case_id,),
                ).fetchone()
                if row is None:
                    raise CaseNotFound(case.case_id)
                raise ConcurrentCaseUpdate(
                    f"case {case.case_id} is version {row[0]}, expected {expected_version}")
            connection.execute(
                "INSERT INTO case_events(case_id, sequence, event_id, event) "
                "VALUES (?, ?, ?, ?)",
                (event.case_id, event.sequence, event.event_id,
                 self._json(event_to_dict(event))),
            )
            if case.terminal:
                connection.execute(
                    "DELETE FROM active_case_assets WHERE case_id = ?", (case.case_id,))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def events(self, case_id: str) -> tuple[CaseEvent, ...]:
        # Distinguish an existing case with no events from an unknown case.
        self.get(case_id)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT event FROM case_events WHERE case_id = ? ORDER BY sequence",
                (case_id,),
            ).fetchall()
        return tuple(event_from_dict(json.loads(row[0])) for row in rows)

    def find_active_by_asset(self, tenant_id: str, asset_id: str
                             ) -> RemediationCase | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT c.projection FROM remediation_cases c "
                "JOIN active_case_assets a ON a.case_id = c.case_id "
                "WHERE a.tenant_id = ? AND a.asset_id = ?",
                (tenant_id, asset_id),
            ).fetchone()
        return case_from_dict(json.loads(row[0])) if row else None
