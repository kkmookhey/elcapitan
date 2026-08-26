"""Durable normalized-finding store and idempotent source index."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol

from .hashing import canonical_json
from .priority import PrioritySignals, signals_from_dict, signals_to_dict


class FindingNotFound(KeyError):
    pass


class DuplicateFinding(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredFinding:
    tenant_id: str
    finding_id: str
    provider: str
    account: str
    original_uid: str
    resource_uid: str
    record: Mapping
    priority_signals: PrioritySignals
    artifact_namespace: str
    case_id: str | None = None


class FindingStore(Protocol):
    def put(self, finding: StoredFinding) -> None: ...
    def get(self, finding_id: str) -> StoredFinding: ...
    def get_by_source(self, tenant_id: str, provider: str, account: str,
                      original_uid: str) -> StoredFinding | None: ...
    def assign_case(self, finding_id: str, case_id: str) -> StoredFinding: ...
    def list_for_case(self, case_id: str) -> tuple[StoredFinding, ...]: ...


class SqliteFindingStore:
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
    def _json(document) -> str:
        return canonical_json(document).decode("utf-8")

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS finding_records (
                        finding_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        account TEXT NOT NULL,
                        original_uid TEXT NOT NULL,
                        resource_uid TEXT NOT NULL,
                        record TEXT NOT NULL,
                        priority_signals TEXT NOT NULL,
                        artifact_namespace TEXT NOT NULL,
                        case_id TEXT,
                        UNIQUE (tenant_id, provider, account, original_uid)
                    );
                    CREATE INDEX IF NOT EXISTS finding_records_resource
                        ON finding_records(tenant_id, provider, account, resource_uid);
                    CREATE INDEX IF NOT EXISTS finding_records_case
                        ON finding_records(case_id);
                """)

    @staticmethod
    def _from_row(row) -> StoredFinding:
        if row is None:
            raise FindingNotFound
        return StoredFinding(
            finding_id=row[0], tenant_id=row[1], provider=row[2], account=row[3],
            original_uid=row[4], resource_uid=row[5], record=json.loads(row[6]),
            priority_signals=signals_from_dict(json.loads(row[7])),
            artifact_namespace=row[8], case_id=row[9],
        )

    def put(self, finding: StoredFinding) -> None:
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        "INSERT INTO finding_records"
                        "(finding_id, tenant_id, provider, account, original_uid, "
                        "resource_uid, record, priority_signals, artifact_namespace, case_id) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (finding.finding_id, finding.tenant_id, finding.provider,
                         finding.account, finding.original_uid, finding.resource_uid,
                         self._json(finding.record),
                         self._json(signals_to_dict(finding.priority_signals)),
                         finding.artifact_namespace, finding.case_id),
                    )
        except sqlite3.IntegrityError as exc:
            raise DuplicateFinding(
                f"finding {finding.original_uid} was already ingested") from exc

    def get(self, finding_id: str) -> StoredFinding:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT finding_id, tenant_id, provider, account, original_uid, "
                "resource_uid, record, priority_signals, artifact_namespace, case_id "
                "FROM finding_records WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            raise FindingNotFound(finding_id)
        return self._from_row(row)

    def get_by_source(self, tenant_id: str, provider: str, account: str,
                      original_uid: str) -> StoredFinding | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT finding_id, tenant_id, provider, account, original_uid, "
                "resource_uid, record, priority_signals, artifact_namespace, case_id "
                "FROM finding_records WHERE tenant_id = ? AND provider = ? "
                "AND account = ? AND original_uid = ?",
                (tenant_id, provider, account, original_uid),
            ).fetchone()
        return self._from_row(row) if row else None

    def assign_case(self, finding_id: str, case_id: str) -> StoredFinding:
        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    "UPDATE finding_records SET case_id = ? "
                    "WHERE finding_id = ? AND (case_id IS NULL OR case_id = ?)",
                    (case_id, finding_id, case_id),
                )
                if cursor.rowcount != 1:
                    row = connection.execute(
                        "SELECT case_id FROM finding_records WHERE finding_id = ?",
                        (finding_id,),
                    ).fetchone()
                    if row is None:
                        raise FindingNotFound(finding_id)
                    raise DuplicateFinding(
                        f"finding {finding_id} is already assigned to case {row[0]}")
        return self.get(finding_id)

    def list_for_case(self, case_id: str) -> tuple[StoredFinding, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT finding_id, tenant_id, provider, account, original_uid, "
                "resource_uid, record, priority_signals, artifact_namespace, case_id "
                "FROM finding_records WHERE case_id = ? ORDER BY finding_id",
                (case_id,),
            ).fetchall()
        return tuple(self._from_row(row) for row in rows)
