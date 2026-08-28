"""Deterministic AWS S3 control definitions."""
from __future__ import annotations

from .models import ControlDefinition, ControlEvaluation, ControlPack, require


def _object_versioning(values) -> ControlEvaluation:
    value = require(values, "versioning")
    enabled = isinstance(value, dict) and value.get("Status") == "Enabled"
    reason = (
        f"bucket versioning status is {value.get('Status')!r}"
        if isinstance(value, dict)
        else f"bucket versioning response is {value!r}")
    return ControlEvaluation(confirmed=not enabled, reason=reason)


AWS_S3_PACK = ControlPack(
    pack_id="aws-s3",
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
    ),
)
