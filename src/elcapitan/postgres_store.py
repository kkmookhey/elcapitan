"""PostgreSQL implementations of the shadow control-plane store contracts."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import psycopg

from .cases import (
    CaseEvent, RemediationCase, case_from_dict, case_to_dict,
    event_from_dict, event_to_dict,
)
from .finding_store import (
    DuplicateFinding, FindingNotFound, StoredFinding,
)
from .hashing import canonical_json, sha256_bytes
from .paths import safe_resolve
from .priority import signals_from_dict, signals_to_dict
from .observability import parse_timestamp, utc_text
from .scheduler import ExecutionJob, JobState
from .product_records import (
    DuplicateProductRecord, ProductRecord, ProductRecordNotFound, _thaw,
)
from .workflow import CaseNotFound, ConcurrentCaseUpdate


class _PostgresStore:
    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL connection string is required")
        self.dsn = dsn

    def _connect(self):
        return psycopg.connect(
            self.dsn, connect_timeout=10,
            application_name="elcapitan-shadow-control-plane")

    @staticmethod
    def _json(document) -> str:
        return canonical_json(document).decode("utf-8")


class PostgresCaseStore(_PostgresStore):
    def __init__(self, dsn: str) -> None:
        super().__init__(dsn)
        self._initialize()

    def _initialize(self) -> None:
        statements = (
            """CREATE TABLE IF NOT EXISTS remediation_cases (
                case_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                state TEXT NOT NULL,
                version INTEGER NOT NULL,
                projection TEXT NOT NULL
            )""",
            """CREATE INDEX IF NOT EXISTS remediation_cases_tenant_state
                ON remediation_cases(tenant_id, state)""",
            """CREATE TABLE IF NOT EXISTS case_assets (
                case_id TEXT NOT NULL REFERENCES remediation_cases(case_id),
                tenant_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                PRIMARY KEY (case_id, asset_id)
            )""",
            """CREATE INDEX IF NOT EXISTS case_assets_lookup
                ON case_assets(tenant_id, asset_id)""",
            """CREATE TABLE IF NOT EXISTS active_case_assets (
                tenant_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                case_id TEXT NOT NULL REFERENCES remediation_cases(case_id),
                PRIMARY KEY (tenant_id, asset_id)
            )""",
            """CREATE TABLE IF NOT EXISTS case_events (
                case_id TEXT NOT NULL REFERENCES remediation_cases(case_id),
                sequence INTEGER NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                event TEXT NOT NULL,
                PRIMARY KEY (case_id, sequence)
            )""",
        )
        with self._connect() as connection:
            for statement in statements:
                connection.execute(statement)

    def create(self, case: RemediationCase) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO remediation_cases"
                    "(case_id, tenant_id, state, version, projection) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (case.case_id, case.tenant_id, case.state.value, case.version,
                     self._json(case_to_dict(case))),
                )
                for asset_id in case.asset_ids:
                    connection.execute(
                        "INSERT INTO case_assets(case_id, tenant_id, asset_id) "
                        "VALUES (%s, %s, %s)",
                        (case.case_id, case.tenant_id, asset_id),
                    )
                    if not case.terminal:
                        connection.execute(
                            "INSERT INTO active_case_assets"
                            "(tenant_id, asset_id, case_id) VALUES (%s, %s, %s)",
                            (case.tenant_id, asset_id, case.case_id),
                        )
        except psycopg.IntegrityError as exc:
            active = next((
                found for asset_id in case.asset_ids
                if (found := self.find_active_by_asset(case.tenant_id, asset_id))
                is not None
            ), None)
            if active:
                raise ConcurrentCaseUpdate(
                    f"tenant {case.tenant_id} already has active case "
                    f"{active.case_id} for this asset") from exc
            raise ConcurrentCaseUpdate(f"case {case.case_id} already exists") from exc

    def get(self, case_id: str) -> RemediationCase:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT projection FROM remediation_cases WHERE case_id = %s",
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
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE remediation_cases SET state = %s, version = %s, projection = %s "
                "WHERE case_id = %s AND version = %s",
                (case.state.value, case.version, self._json(case_to_dict(case)),
                 case.case_id, expected_version),
            )
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT version FROM remediation_cases WHERE case_id = %s",
                    (case.case_id,),
                ).fetchone()
                if row is None:
                    raise CaseNotFound(case.case_id)
                raise ConcurrentCaseUpdate(
                    f"case {case.case_id} is version {row[0]}, "
                    f"expected {expected_version}")
            connection.execute(
                "INSERT INTO case_events(case_id, sequence, event_id, event) "
                "VALUES (%s, %s, %s, %s)",
                (event.case_id, event.sequence, event.event_id,
                 self._json(event_to_dict(event))),
            )
            if case.terminal:
                connection.execute(
                    "DELETE FROM active_case_assets WHERE case_id = %s",
                    (case.case_id,))

    def events(self, case_id: str) -> tuple[CaseEvent, ...]:
        self.get(case_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event FROM case_events WHERE case_id = %s ORDER BY sequence",
                (case_id,),
            ).fetchall()
        return tuple(event_from_dict(json.loads(row[0])) for row in rows)

    def find_active_by_asset(self, tenant_id: str, asset_id: str
                             ) -> RemediationCase | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT c.projection FROM remediation_cases c "
                "JOIN active_case_assets a ON a.case_id = c.case_id "
                "WHERE a.tenant_id = %s AND a.asset_id = %s",
                (tenant_id, asset_id),
            ).fetchone()
        return case_from_dict(json.loads(row[0])) if row else None

    def list_cases(self, *, tenant_id: str | None = None
                   ) -> tuple[RemediationCase, ...]:
        query = "SELECT projection FROM remediation_cases"
        params: tuple = ()
        if tenant_id is not None:
            query += " WHERE tenant_id = %s"
            params = (tenant_id,)
        query += " ORDER BY tenant_id, case_id"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return tuple(case_from_dict(json.loads(row[0])) for row in rows)


class PostgresFindingStore(_PostgresStore):
    _SELECT = (
        "SELECT finding_id, tenant_id, provider, account, original_uid, "
        "resource_uid, record, priority_signals, artifact_namespace, case_id "
        "FROM finding_records")

    def __init__(self, dsn: str) -> None:
        super().__init__(dsn)
        self._initialize()

    def _initialize(self) -> None:
        statements = (
            """CREATE TABLE IF NOT EXISTS finding_records (
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
            )""",
            """CREATE INDEX IF NOT EXISTS finding_records_resource
                ON finding_records(tenant_id, provider, account, resource_uid)""",
            """CREATE INDEX IF NOT EXISTS finding_records_case
                ON finding_records(case_id)""",
        )
        with self._connect() as connection:
            for statement in statements:
                connection.execute(statement)

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
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO finding_records"
                    "(finding_id, tenant_id, provider, account, original_uid, "
                    "resource_uid, record, priority_signals, artifact_namespace, case_id) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (finding.finding_id, finding.tenant_id, finding.provider,
                     finding.account, finding.original_uid, finding.resource_uid,
                     self._json(finding.record),
                     self._json(signals_to_dict(finding.priority_signals)),
                     finding.artifact_namespace, finding.case_id),
                )
        except psycopg.IntegrityError as exc:
            raise DuplicateFinding(
                f"finding {finding.original_uid} was already ingested") from exc

    def get(self, finding_id: str) -> StoredFinding:
        with self._connect() as connection:
            row = connection.execute(
                self._SELECT + " WHERE finding_id = %s", (finding_id,)
            ).fetchone()
        if row is None:
            raise FindingNotFound(finding_id)
        return self._from_row(row)

    def get_by_source(self, tenant_id: str, provider: str, account: str,
                      original_uid: str) -> StoredFinding | None:
        with self._connect() as connection:
            row = connection.execute(
                self._SELECT + " WHERE tenant_id = %s AND provider = %s "
                "AND account = %s AND original_uid = %s",
                (tenant_id, provider, account, original_uid),
            ).fetchone()
        return self._from_row(row) if row else None

    def assign_case(self, finding_id: str, case_id: str) -> StoredFinding:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE finding_records SET case_id = %s "
                "WHERE finding_id = %s AND (case_id IS NULL OR case_id = %s)",
                (case_id, finding_id, case_id),
            )
            if cursor.rowcount != 1:
                row = connection.execute(
                    "SELECT case_id FROM finding_records WHERE finding_id = %s",
                    (finding_id,),
                ).fetchone()
                if row is None:
                    raise FindingNotFound(finding_id)
                raise DuplicateFinding(
                    f"finding {finding_id} is already assigned to case {row[0]}")
        return self.get(finding_id)

    def list_for_case(self, case_id: str) -> tuple[StoredFinding, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                self._SELECT + " WHERE case_id = %s ORDER BY finding_id",
                (case_id,),
            ).fetchall()
        return tuple(self._from_row(row) for row in rows)


class PostgresProductRecordStore(_PostgresStore):
    _SELECT = (
        "SELECT record_id, case_id, record_type, schema_version, created_at, "
        "body, evidence_ids FROM product_records")

    def __init__(self, dsn: str) -> None:
        super().__init__(dsn)
        self._initialize()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS product_records (
                record_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                record_type TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                body TEXT NOT NULL,
                evidence_ids TEXT NOT NULL
            )""")
            connection.execute("""CREATE INDEX IF NOT EXISTS product_records_case_type
                ON product_records(case_id, record_type, created_at)""")

    @staticmethod
    def _from_row(row) -> ProductRecord:
        return ProductRecord(
            record_id=row[0], case_id=row[1], record_type=row[2],
            schema_version=row[3], created_at=row[4], body=json.loads(row[5]),
            evidence_ids=json.loads(row[6]))

    def put(self, record: ProductRecord) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO product_records"
                    "(record_id, case_id, record_type, schema_version, created_at, "
                    "body, evidence_ids) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (record.record_id, record.case_id, record.record_type,
                     record.schema_version, record.created_at,
                     self._json(_thaw(record.body)),
                     self._json(list(record.evidence_ids))),
                )
        except psycopg.IntegrityError as exc:
            raise DuplicateProductRecord(record.record_id) from exc

    def get(self, record_id: str) -> ProductRecord:
        with self._connect() as connection:
            row = connection.execute(
                self._SELECT + " WHERE record_id = %s", (record_id,)
            ).fetchone()
        if row is None:
            raise ProductRecordNotFound(record_id)
        return self._from_row(row)

    def list_for_case(self, case_id: str, *, record_type: str | None = None
                      ) -> tuple[ProductRecord, ...]:
        query = self._SELECT + " WHERE case_id = %s"
        params: tuple = (case_id,)
        if record_type is not None:
            query += " AND record_type = %s"
            params += (record_type,)
        query += " ORDER BY created_at, record_id"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return tuple(self._from_row(row) for row in rows)


class PostgresExecutionJobStore(_PostgresStore):
    """Concurrent durable execution queue with PostgreSQL row leases."""

    _SELECT = (
        "SELECT job_id, case_id, execute_at, deadline, state, attempts, "
        "lease_owner, lease_until, detail FROM execution_jobs")

    def __init__(self, dsn: str) -> None:
        super().__init__(dsn)
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS execution_jobs (
                job_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL UNIQUE,
                execute_at TEXT NOT NULL,
                deadline TEXT NOT NULL,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                lease_owner TEXT NOT NULL,
                lease_until TEXT NOT NULL,
                detail TEXT NOT NULL
            )""")
            connection.execute("""CREATE INDEX IF NOT EXISTS execution_jobs_due
                ON execution_jobs(state, execute_at, deadline)""")

    @staticmethod
    def _job(row) -> ExecutionJob:
        if row is None:
            raise KeyError
        return ExecutionJob(
            row[0], row[1], row[2], row[3], JobState(row[4]),
            row[5], row[6], row[7], row[8])

    def put(self, job: ExecutionJob) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO execution_jobs"
                    "(job_id, case_id, execute_at, deadline, state, attempts, "
                    "lease_owner, lease_until, detail) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (job.job_id, job.case_id, job.execute_at, job.deadline,
                     job.state.value, job.attempts, job.lease_owner,
                     job.lease_until, job.detail))
        except psycopg.IntegrityError as exc:
            raise ValueError(
                f"case {job.case_id} already has a scheduled job") from exc

    def get(self, job_id: str) -> ExecutionJob:
        with self._connect() as connection:
            row = connection.execute(
                self._SELECT + " WHERE job_id = %s", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        return self._job(row)

    def claim_due(self, *, now: str, worker_id: str,
                  lease_seconds: int = 300) -> ExecutionJob | None:
        if not worker_id or lease_seconds <= 0:
            raise ValueError("worker id and positive lease are required")
        lease_until = utc_text(
            parse_timestamp(now) + timedelta(seconds=lease_seconds))
        with self._connect() as connection:
            connection.execute(
                "UPDATE execution_jobs SET state = %s, detail = %s "
                "WHERE state = %s AND deadline <= %s",
                (JobState.MISSED.value,
                 "approved window elapsed before execution",
                 JobState.SCHEDULED.value, now))
            row = connection.execute(
                self._SELECT +
                " WHERE execute_at <= %s AND deadline > %s "
                "AND (state = %s OR (state = %s AND lease_until <= %s)) "
                "ORDER BY execute_at, job_id LIMIT 1 FOR UPDATE SKIP LOCKED",
                (now, now, JobState.SCHEDULED.value,
                 JobState.RUNNING.value, now)).fetchone()
            if row is None:
                return None
            job = self._job(row)
            updated = connection.execute(
                "UPDATE execution_jobs SET state = %s, attempts = attempts + 1, "
                "lease_owner = %s, lease_until = %s WHERE job_id = %s "
                "RETURNING job_id, case_id, execute_at, deadline, state, attempts, "
                "lease_owner, lease_until, detail",
                (JobState.RUNNING.value, worker_id, lease_until,
                 job.job_id)).fetchone()
            return self._job(updated)

    def complete(self, job_id: str, *, worker_id: str, state: JobState,
                 detail: str = "") -> ExecutionJob:
        if state not in {
                JobState.SUCCEEDED, JobState.ROLLED_BACK, JobState.FAILED}:
            raise ValueError("job completion state must be terminal")
        with self._connect() as connection:
            row = connection.execute(
                "UPDATE execution_jobs SET state = %s, detail = %s, "
                "lease_owner = '', lease_until = '' "
                "WHERE job_id = %s AND state = %s AND lease_owner = %s "
                "RETURNING job_id, case_id, execute_at, deadline, state, attempts, "
                "lease_owner, lease_until, detail",
                (state.value, detail, job_id, JobState.RUNNING.value,
                 worker_id)).fetchone()
        if row is None:
            raise ValueError("job is not leased by this worker")
        return self._job(row)


class PostgresArtifactStore(_PostgresStore):
    """Immutable evidence blobs mirrored into PostgreSQL for durable recovery."""

    def __init__(self, dsn: str) -> None:
        super().__init__(dsn)
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS artifact_blobs (
                artifact_path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                payload BYTEA NOT NULL
            )""")

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM artifact_blobs").fetchone()
        return int(row[0])

    def hydrate(self, root) -> int:
        root = Path(root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT artifact_path, sha256, payload "
                "FROM artifact_blobs ORDER BY artifact_path").fetchall()
        hydrated = 0
        for relative, expected_sha256, raw_payload in rows:
            target = safe_resolve(root, relative)
            payload = bytes(raw_payload)
            if sha256_bytes(payload) != expected_sha256:
                raise RuntimeError(
                    f"durable artifact {relative} failed its stored hash check")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if (target.is_symlink()
                        or sha256_bytes(target.read_bytes()) != expected_sha256):
                    raise RuntimeError(
                        f"local artifact {relative} conflicts with durable evidence")
                continue
            with target.open("xb") as handle:
                handle.write(payload)
            hydrated += 1
        return hydrated

    def sync(self, root) -> int:
        root = Path(root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        stored = 0
        with self._connect() as connection:
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                if path.is_symlink():
                    raise RuntimeError(
                        f"refusing to persist symlinked artifact {path}")
                relative = path.relative_to(root).as_posix()
                payload = path.read_bytes()
                digest = sha256_bytes(payload)
                cursor = connection.execute(
                    "INSERT INTO artifact_blobs(artifact_path, sha256, payload) "
                    "VALUES (%s, %s, %s) ON CONFLICT (artifact_path) DO NOTHING",
                    (relative, digest, payload),
                )
                if cursor.rowcount == 1:
                    stored += 1
                    continue
                row = connection.execute(
                    "SELECT sha256 FROM artifact_blobs WHERE artifact_path = %s",
                    (relative,),
                ).fetchone()
                if row is None or row[0] != digest:
                    raise RuntimeError(
                        f"immutable artifact {relative} already has different content")
        return stored
