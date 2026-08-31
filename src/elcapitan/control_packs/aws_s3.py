"""Deterministic AWS S3 control definitions.

The collector records the direct S3 API documents rather than Prowler's
derived booleans.  These evaluators deliberately reconstruct only the pinned
Prowler truth conditions and reject malformed or unknown response shapes.
"""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


_ABSENT = {
    "encryption": "<absent: ServerSideEncryptionConfigurationNotFoundError>",
    "lifecycle": "<absent: NoSuchLifecycleConfiguration>",
    "object_lock": "<absent: ObjectLockConfigurationNotFoundError>",
}


def _document(values, aspect: str, *, absent: bool = False) -> dict | None:
    value = require(values, aspect)
    if absent and value == _ABSENT[aspect]:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"live S3 state has invalid {aspect} response {value!r}")
    return value


def _enum(document: dict, name: str, allowed: frozenset[str], *, optional=False):
    if name not in document and optional:
        return None
    value = document.get(name)
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"live S3 response has invalid {name} {value!r}")
    return value


def _object_versioning(values) -> ControlEvaluation:
    value = _document(values, "versioning")
    status = _enum(value, "Status", frozenset({"Enabled", "Suspended"}), optional=True)
    enabled = status == "Enabled"
    reason = f"bucket versioning status is {status!r}"
    return ControlEvaluation(confirmed=not enabled, reason=reason)


def _kms_encryption(values) -> ControlEvaluation:
    value = _document(values, "encryption", absent=True)
    if value is None:
        return ControlEvaluation(
            confirmed=True, reason="bucket has no encryption configuration")
    configuration = value.get("ServerSideEncryptionConfiguration")
    if not isinstance(configuration, dict):
        raise ValueError("live S3 encryption response has invalid configuration")
    rules = configuration.get("Rules")
    if (not isinstance(rules, list) or not rules
            or any(not isinstance(rule, dict) for rule in rules)):
        raise ValueError("live S3 encryption response has invalid Rules")
    default = rules[0].get("ApplyServerSideEncryptionByDefault")
    if not isinstance(default, dict):
        raise ValueError("live S3 encryption response has invalid default rule")
    algorithm = _enum(
        default, "SSEAlgorithm", frozenset({"AES256", "aws:kms", "aws:kms:dsse"}))
    enabled = algorithm in {"aws:kms", "aws:kms:dsse"}
    return ControlEvaluation(
        confirmed=not enabled,
        reason=f"bucket default encryption algorithm is {algorithm!r}",
    )


def _server_access_logging(values) -> ControlEvaluation:
    value = _document(values, "logging")
    logging = value.get("LoggingEnabled")
    if logging is not None and not isinstance(logging, dict):
        raise ValueError("live S3 logging response has invalid LoggingEnabled")
    if isinstance(logging, dict):
        target = logging.get("TargetBucket")
        prefix = logging.get("TargetPrefix")
        if (not isinstance(target, str) or not target
                or not isinstance(prefix, str)):
            raise ValueError(
                "live S3 logging response has invalid target bucket or prefix")
    enabled = logging is not None
    return ControlEvaluation(
        confirmed=not enabled,
        reason=("bucket server access logging is enabled" if enabled else
                "bucket server access logging is disabled"),
    )


def _event_notifications(values) -> ControlEvaluation:
    value = _document(values, "notification")
    keys = (
        "TopicConfigurations", "QueueConfigurations",
        "LambdaFunctionConfigurations", "EventBridgeConfiguration",
    )
    for key in keys[:3]:
        if key in value and (
                not isinstance(value[key], list)
                or any(not isinstance(item, dict) for item in value[key])):
            raise ValueError(f"live S3 notification response has invalid {key}")
    if ("EventBridgeConfiguration" in value
            and not isinstance(value["EventBridgeConfiguration"], dict)):
        raise ValueError(
            "live S3 notification response has invalid EventBridgeConfiguration")
    enabled = any(key in value for key in keys)
    return ControlEvaluation(
        confirmed=not enabled,
        reason=("bucket event notifications are enabled" if enabled else
                "bucket event notifications are disabled"),
    )


def _lifecycle_enabled(values) -> ControlEvaluation:
    value = _document(values, "lifecycle", absent=True)
    if value is None:
        return ControlEvaluation(
            confirmed=True, reason="bucket has no lifecycle configuration")
    rules = value.get("Rules")
    if (not isinstance(rules, list) or not rules
            or any(not isinstance(rule, dict) for rule in rules)):
        raise ValueError("live S3 lifecycle response has invalid Rules")
    statuses = []
    for rule in rules:
        identifier = rule.get("ID")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("live S3 lifecycle response has invalid rule ID")
        statuses.append(
            _enum(rule, "Status", frozenset({"Enabled", "Disabled"})))
    enabled = "Enabled" in statuses
    return ControlEvaluation(
        confirmed=not enabled,
        reason=("bucket has an enabled lifecycle rule" if enabled else
                "bucket has no enabled lifecycle rule"),
    )


def _object_lock(values) -> ControlEvaluation:
    value = _document(values, "object_lock", absent=True)
    if value is None:
        return ControlEvaluation(confirmed=True, reason="bucket Object Lock is disabled")
    configuration = value.get("ObjectLockConfiguration")
    if not isinstance(configuration, dict):
        raise ValueError("live S3 Object Lock response has invalid configuration")
    enabled = _enum(
        configuration, "ObjectLockEnabled", frozenset({"Enabled"})) == "Enabled"
    return ControlEvaluation(
        confirmed=not enabled,
        reason=("bucket Object Lock is enabled" if enabled else
                "bucket Object Lock is disabled"),
    )


def _mfa_delete(values) -> ControlEvaluation:
    value = _document(values, "versioning")
    # Status is part of the same response contract even though this control's
    # truth condition depends only on MFADelete.
    _enum(value, "Status", frozenset({"Enabled", "Suspended"}), optional=True)
    status = _enum(
        value, "MFADelete", frozenset({"Enabled", "Disabled"}), optional=True)
    enabled = status == "Enabled"
    return ControlEvaluation(
        confirmed=not enabled,
        reason=f"bucket MFA Delete status is {status!r}",
    )


def _validation_control(rule_id: str, aspect: str, evaluator) -> ControlDefinition:
    return ControlDefinition(
        pack_id="aws-s3", provider="aws", rule_id=rule_id,
        resource_family="s3_bucket", resource_types=("awss3bucket",),
        live_validation=True, remediation_planning=False, live_execution=False,
        evidence_aspects=(aspect,), evaluator=evaluator,
        evidence_grade="contract_tested",
    )


AWS_S3_PACK = ControlPack(
    pack_id="aws-s3",
    evidence_grade="e2e_measured",
    controls=(
        ControlDefinition(
            pack_id="aws-s3", provider="aws",
            rule_id="s3_bucket_object_versioning",
            resource_family="s3_bucket",
            resource_types=("awss3bucket",),
            live_validation=True, remediation_planning=True,
            live_execution=False, evidence_aspects=("versioning",),
            evaluator=_object_versioning,
        ),
        _validation_control("s3_bucket_kms_encryption", "encryption", _kms_encryption),
        _validation_control(
            "s3_bucket_server_access_logging_enabled", "logging",
            _server_access_logging),
        _validation_control(
            "s3_bucket_event_notifications_enabled", "notification",
            _event_notifications),
        _validation_control(
            "s3_bucket_lifecycle_enabled", "lifecycle", _lifecycle_enabled),
        _validation_control("s3_bucket_object_lock", "object_lock", _object_lock),
        _validation_control("s3_bucket_no_mfa_delete", "versioning", _mfa_delete),
    ),
)
