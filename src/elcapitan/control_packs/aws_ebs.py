"""Deterministic AWS EBS volume control definitions.

Both checks consume minimized booleans derived from exact-resource EC2 reads.
Planning and execution remain deliberately out of scope.
"""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _bool(values, aspect: str) -> bool:
    value = require(values, aspect)
    if not isinstance(value, bool):
        raise ValueError(f"live EBS state has invalid {aspect} {value!r}")
    return value


def _volume_encryption(values) -> ControlEvaluation:
    encrypted = _bool(values, "ebs_volume_encrypted")
    return ControlEvaluation(
        confirmed=not encrypted,
        reason=f"EBS volume encryption is {'enabled' if encrypted else 'disabled'}",
    )


def _snapshot_exists(values) -> ControlEvaluation:
    present = _bool(values, "ebs_volume_owned_snapshot_present")
    return ControlEvaluation(
        confirmed=not present,
        reason=("EBS volume has an owned snapshot" if present else
                "EBS volume has no owned snapshot"),
    )


def _control(rule_id: str, aspect: str, evaluator) -> ControlDefinition:
    return ControlDefinition(
        pack_id="aws-ebs-volume", provider="aws", rule_id=rule_id,
        resource_family="ebs_volume", resource_types=("awsec2volume",),
        live_validation=True, remediation_planning=False, live_execution=False,
        evidence_aspects=(aspect,), evaluator=evaluator,
        evidence_grade="contract_tested",
    )


AWS_EBS_VOLUME_PACK = ControlPack(
    pack_id="aws-ebs-volume",
    evidence_grade="contract_tested",
    controls=(
        _control(
            "ec2_ebs_volume_encryption", "ebs_volume_encrypted",
            _volume_encryption),
        _control(
            "ec2_ebs_volume_snapshots_exists", "ebs_volume_owned_snapshot_present",
            _snapshot_exists),
    ),
)
