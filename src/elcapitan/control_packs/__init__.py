"""Installed deterministic control packs.

The platform workflow is provider-neutral. Each pack keeps service-specific
evidence semantics explicit and testable without implying remediation or
execution coverage.
"""
from .aws_s3 import AWS_S3_PACK
from .azure_sql import AZURE_SQL_PACK
from .azure_storage import AZURE_STORAGE_PACK
from .models import ControlDefinition, ControlEvaluation, ControlPack
from .registry import ControlPackRegistry

BUILTIN_CONTROL_PACKS = (
    AWS_S3_PACK,
    AZURE_SQL_PACK,
    AZURE_STORAGE_PACK,
)


def builtin_registry() -> ControlPackRegistry:
    return ControlPackRegistry(BUILTIN_CONTROL_PACKS)


__all__ = (
    "BUILTIN_CONTROL_PACKS", "ControlDefinition", "ControlEvaluation",
    "ControlPack", "ControlPackRegistry", "builtin_registry",
)
