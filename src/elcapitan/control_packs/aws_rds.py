"""Deterministic AWS RDS DB instance control definitions.

The collector reduces one resource-scoped ``DescribeDBInstances`` response to
the fields used by these pinned Prowler truth conditions.  Planning and
execution remain deliberately out of scope for this validation-only pack.
"""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


_AURORA_ENGINES = frozenset({"aurora", "aurora-mysql", "aurora-postgresql"})
_IAM_ENGINE_TOKENS = (
    "postgres", "aurora-postgresql", "mysql", "mariadb", "aurora-mysql",
    "aurora",
)


def _bool(values, aspect: str) -> bool:
    value = require(values, aspect)
    if not isinstance(value, bool):
        raise ValueError(f"live RDS state has invalid {aspect} {value!r}")
    return value


def _engine(values) -> str:
    value = require(values, "rds_engine")
    if not isinstance(value, str) or not value:
        raise ValueError(f"live RDS state has invalid engine {value!r}")
    return value


def _backup(values) -> ControlEvaluation:
    replica = _bool(values, "rds_read_replica_source_present")
    retention = require(values, "rds_backup_retention_period")
    if isinstance(retention, bool) or not isinstance(retention, int) or retention < 0:
        raise ValueError(
            f"live RDS state has invalid backup retention period {retention!r}")
    if replica:
        return ControlEvaluation(
            confirmed=False,
            reason="read replica is excluded by Prowler's default RDS audit scope",
        )
    return ControlEvaluation(
        confirmed=retention <= 0,
        reason=f"RDS automated backup retention is {retention} day(s)",
    )


def _copy_tags(values) -> ControlEvaluation:
    engine = _engine(values)
    enabled = _bool(values, "rds_copy_tags_to_snapshot")
    if engine in _AURORA_ENGINES:
        return ControlEvaluation(
            confirmed=False,
            reason=f"copy-tags control is not emitted for Aurora engine {engine!r}",
        )
    return ControlEvaluation(
        confirmed=not enabled,
        reason=f"copy tags to DB snapshots is {'enabled' if enabled else 'disabled'}",
    )


def _enhanced_monitoring(values) -> ControlEvaluation:
    enabled = _bool(values, "rds_enhanced_monitoring_enabled")
    return ControlEvaluation(
        confirmed=not enabled,
        reason=f"RDS enhanced monitoring is {'enabled' if enabled else 'disabled'}",
    )


def _iam_authentication(values) -> ControlEvaluation:
    engine = _engine(values)
    enabled = _bool(values, "rds_iam_database_authentication_enabled")
    if not any(token in engine for token in _IAM_ENGINE_TOKENS):
        return ControlEvaluation(
            confirmed=False,
            reason=f"IAM database authentication control is not emitted for {engine!r}",
        )
    return ControlEvaluation(
        confirmed=not enabled,
        reason=("RDS IAM database authentication is enabled" if enabled else
                "RDS IAM database authentication is disabled"),
    )


def _inside_vpc(values) -> ControlEvaluation:
    enabled = _bool(values, "rds_in_vpc")
    return ControlEvaluation(
        confirmed=not enabled,
        reason=f"RDS instance is {'inside a VPC' if enabled else 'not inside a VPC'}",
    )


def _cloudwatch_logs(values) -> ControlEvaluation:
    exports = require(values, "rds_enabled_cloudwatch_logs_exports")
    if (not isinstance(exports, list)
            or any(not isinstance(item, str) or not item for item in exports)
            or len(exports) != len(set(exports))):
        raise ValueError(
            f"live RDS state has invalid CloudWatch log exports {exports!r}")
    return ControlEvaluation(
        confirmed=not exports,
        reason=(f"RDS exports {', '.join(exports)} to CloudWatch Logs" if exports else
                "RDS exports no database logs to CloudWatch Logs"),
    )


def _minor_version_upgrade(values) -> ControlEvaluation:
    enabled = _bool(values, "rds_auto_minor_version_upgrade")
    return ControlEvaluation(
        confirmed=not enabled,
        reason=f"automatic minor version upgrades are {'enabled' if enabled else 'disabled'}",
    )


def _storage_encrypted(values) -> ControlEvaluation:
    enabled = _bool(values, "rds_storage_encrypted")
    return ControlEvaluation(
        confirmed=not enabled,
        reason=f"RDS storage encryption is {'enabled' if enabled else 'disabled'}",
    )


def _control(rule_id: str, aspects: tuple[str, ...], evaluator) -> ControlDefinition:
    return ControlDefinition(
        pack_id="aws-rds", provider="aws", rule_id=rule_id,
        resource_family="rds_db_instance",
        resource_types=("awsrdsdbinstance",),
        live_validation=True, remediation_planning=False, live_execution=False,
        evidence_aspects=aspects, evaluator=evaluator,
        evidence_grade="contract_tested",
    )


AWS_RDS_PACK = ControlPack(
    pack_id="aws-rds",
    evidence_grade="contract_tested",
    controls=(
        _control(
            "rds_instance_backup_enabled",
            ("rds_backup_retention_period", "rds_read_replica_source_present"),
            _backup,
        ),
        _control(
            "rds_instance_copy_tags_to_snapshots",
            ("rds_engine", "rds_copy_tags_to_snapshot"),
            _copy_tags,
        ),
        _control(
            "rds_instance_enhanced_monitoring_enabled",
            ("rds_enhanced_monitoring_enabled",),
            _enhanced_monitoring,
        ),
        _control(
            "rds_instance_iam_authentication_enabled",
            ("rds_engine", "rds_iam_database_authentication_enabled"),
            _iam_authentication,
        ),
        _control("rds_instance_inside_vpc", ("rds_in_vpc",), _inside_vpc),
        _control(
            "rds_instance_integration_cloudwatch_logs",
            ("rds_enabled_cloudwatch_logs_exports",),
            _cloudwatch_logs,
        ),
        _control(
            "rds_instance_minor_version_upgrade_enabled",
            ("rds_auto_minor_version_upgrade",),
            _minor_version_upgrade,
        ),
        _control(
            "rds_instance_storage_encrypted",
            ("rds_storage_encrypted",),
            _storage_encrypted,
        ),
    ),
)
