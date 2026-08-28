"""One-time, fail-closed bootstrap for an isolated PostgreSQL application role."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{2,62}$")
_CONFIRMATION = "CREATE-ISOLATED-DATABASE"


@dataclass(frozen=True)
class BootstrapTarget:
    host: str
    role: str
    database: str
    admin_dsn: str = field(repr=False)
    app_password: str = field(repr=False)

    @classmethod
    def from_environment(
        cls, *, expected_host: str, role: str, database: str, confirmation: str,
        environment: dict[str, str] | None = None,
    ) -> "BootstrapTarget":
        env = os.environ if environment is None else environment
        if confirmation != _CONFIRMATION:
            raise ValueError("bootstrap confirmation phrase is incorrect")
        if not expected_host.endswith(".postgres.database.azure.com"):
            raise ValueError("bootstrap host must be an Azure PostgreSQL hostname")
        for label, value in (("role", role), ("database", database)):
            if not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"bootstrap {label} is not a safe PostgreSQL identifier")
        admin_dsn = env.get("ELCAPITAN_BOOTSTRAP_ADMIN_URL", "")
        app_password = env.get("ELCAPITAN_BOOTSTRAP_APP_PASSWORD", "")
        if not admin_dsn:
            raise ValueError("ELCAPITAN_BOOTSTRAP_ADMIN_URL is required")
        if len(app_password) < 32:
            raise ValueError("bootstrap application password must be at least 32 characters")
        parameters = conninfo_to_dict(admin_dsn)
        if parameters.get("host", "").lower() != expected_host.lower():
            raise ValueError("bootstrap administrator URL is outside the confirmed host")
        if parameters.get("sslmode") != "require":
            raise ValueError("bootstrap administrator URL must require TLS")
        if parameters.get("dbname", "postgres") != "postgres":
            raise ValueError("bootstrap administrator URL must target the postgres database")
        return cls(
            host=expected_host, role=role, database=database,
            admin_dsn=admin_dsn, app_password=app_password,
        )

    @property
    def app_dsn(self) -> str:
        return make_conninfo(
            host=self.host, dbname=self.database, user=self.role,
            password=self.app_password, sslmode="require",
        )

    @property
    def admin_database_dsn(self) -> str:
        parameters = conninfo_to_dict(self.admin_dsn)
        parameters["dbname"] = self.database
        return make_conninfo(**parameters)


def bootstrap(target: BootstrapTarget) -> dict[str, str]:
    """Create or tighten the one database owner, then prove its connection."""
    with psycopg.connect(target.admin_dsn, autocommit=True) as connection:
        existing = connection.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (target.role,),
        ).fetchone()
        if existing:
            connection.execute(
                sql.SQL(
                    "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION PASSWORD {}"
                ).format(sql.Identifier(target.role), sql.Literal(target.app_password))
            )
        else:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION PASSWORD {}"
                ).format(sql.Identifier(target.role), sql.Literal(target.app_password))
            )
        owner = connection.execute(
            "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database "
            "WHERE datname = %s", (target.database,),
        ).fetchone()
        if owner and owner[0] != target.role:
            raise RuntimeError("existing application database has an unexpected owner")
        if not owner:
            connection.execute(
                sql.SQL("CREATE DATABASE {} OWNER {}").format(
                    sql.Identifier(target.database), sql.Identifier(target.role)))

    # Azure PostgreSQL doesn't guarantee that a newly created database gives
    # its owner CREATE on the pre-existing public schema. Give the application
    # a private schema instead of broadening public-schema privileges.
    with psycopg.connect(target.admin_database_dsn, autocommit=True) as connection:
        connection.execute(
            sql.SQL("CREATE SCHEMA IF NOT EXISTS {} AUTHORIZATION {}").format(
                sql.Identifier(target.role), sql.Identifier(target.role)))
        schema_owner = connection.execute(
            "SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_namespace "
            "WHERE nspname = %s", (target.role,),
        ).fetchone()
        if not schema_owner or schema_owner[0] != target.role:
            raise RuntimeError("application schema has an unexpected owner")
        connection.execute(
            sql.SQL("GRANT USAGE, CREATE ON SCHEMA {} TO {}").format(
                sql.Identifier(target.role), sql.Identifier(target.role)))
        connection.execute(
            sql.SQL("ALTER ROLE {} IN DATABASE {} SET search_path TO {}").format(
                sql.Identifier(target.role), sql.Identifier(target.database),
                sql.Identifier(target.role)))

    with psycopg.connect(target.app_dsn, connect_timeout=10) as connection:
        identity = connection.execute(
            "SELECT current_user, current_database(), current_schema()"
        ).fetchone()
    if identity != (target.role, target.database, target.role):
        raise RuntimeError("application database identity verification failed")
    return {
        "status": "ready", "host": target.host,
        "role": target.role, "database": target.database,
    }
