"""Immutable typed records emitted by product workflow stages."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol

from .hashing import canonical_json


class ProductRecordNotFound(KeyError):
    pass


class DuplicateProductRecord(RuntimeError):
    pass


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class ProductRecord:
    record_id: str
    case_id: str
    record_type: str
    schema_version: int
    created_at: str
    body: Mapping
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.record_id or not self.case_id or not self.record_type:
            raise ValueError("product record requires record, case, and type ids")
        if self.schema_version < 1:
            raise ValueError("product record schema version must be positive")
        object.__setattr__(self, "body", _freeze(self.body))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))


class ProductRecordStore(Protocol):
    def put(self, record: ProductRecord) -> None: ...
    def get(self, record_id: str) -> ProductRecord: ...
    def list_for_case(self, case_id: str, *, record_type: str | None = None
                      ) -> tuple[ProductRecord, ...]: ...


def product_record_to_dict(record: ProductRecord) -> dict:
    return {
        "record_id": record.record_id,
        "case_id": record.case_id,
        "record_type": record.record_type,
        "schema_version": record.schema_version,
        "created_at": record.created_at,
        "body": _thaw(record.body),
        "evidence_ids": list(record.evidence_ids),
    }


class SqliteProductRecordStore:
    def __init__(self, path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS product_records (
                        record_id TEXT PRIMARY KEY,
                        case_id TEXT NOT NULL,
                        record_type TEXT NOT NULL,
                        schema_version INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        body TEXT NOT NULL,
                        evidence_ids TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS product_records_case_type
                        ON product_records(case_id, record_type, created_at);
                """)

    @staticmethod
    def _from_row(row) -> ProductRecord:
        return ProductRecord(
            record_id=row[0], case_id=row[1], record_type=row[2],
            schema_version=row[3], created_at=row[4], body=json.loads(row[5]),
            evidence_ids=json.loads(row[6]))

    def put(self, record: ProductRecord) -> None:
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        "INSERT INTO product_records"
                        "(record_id, case_id, record_type, schema_version, created_at, "
                        "body, evidence_ids) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (record.record_id, record.case_id, record.record_type,
                         record.schema_version, record.created_at,
                         canonical_json(_thaw(record.body)).decode("utf-8"),
                         canonical_json(list(record.evidence_ids)).decode("utf-8")),
                    )
        except sqlite3.IntegrityError as exc:
            raise DuplicateProductRecord(record.record_id) from exc

    def get(self, record_id: str) -> ProductRecord:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT record_id, case_id, record_type, schema_version, created_at, "
                "body, evidence_ids FROM product_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
        if row is None:
            raise ProductRecordNotFound(record_id)
        return self._from_row(row)

    def list_for_case(self, case_id: str, *, record_type: str | None = None
                      ) -> tuple[ProductRecord, ...]:
        query = (
            "SELECT record_id, case_id, record_type, schema_version, created_at, "
            "body, evidence_ids FROM product_records WHERE case_id = ?")
        params: tuple = (case_id,)
        if record_type is not None:
            query += " AND record_type = ?"
            params += (record_type,)
        query += " ORDER BY created_at, record_id"
        with closing(self._connect()) as connection:
            rows = connection.execute(query, params).fetchall()
        return tuple(self._from_row(row) for row in rows)
