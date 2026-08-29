"""Installed deterministic control packs.

The platform workflow is provider-neutral. Each pack keeps service-specific
evidence semantics explicit and testable without implying remediation or
execution coverage.
"""
from .aws_s3 import AWS_S3_PACK
from .azure_app_service import AZURE_APP_SERVICE_PACK
from .azure_container_registry import AZURE_CONTAINER_REGISTRY_PACK
from .azure_cosmos_db import AZURE_COSMOS_DB_PACK
from .azure_key_vault import AZURE_KEY_VAULT_PACK
from .azure_network import AZURE_NETWORK_PACK
from .azure_openai import AZURE_OPENAI_PACK
from .azure_sql import AZURE_SQL_PACK
from .azure_storage import AZURE_STORAGE_PACK
from .models import ControlDefinition, ControlEvaluation, ControlPack
from .registry import ControlPackRegistry

BUILTIN_CONTROL_PACKS = (
    AWS_S3_PACK,
    AZURE_APP_SERVICE_PACK,
    AZURE_CONTAINER_REGISTRY_PACK,
    AZURE_COSMOS_DB_PACK,
    AZURE_KEY_VAULT_PACK,
    AZURE_NETWORK_PACK,
    AZURE_OPENAI_PACK,
    AZURE_SQL_PACK,
    AZURE_STORAGE_PACK,
)


def builtin_registry() -> ControlPackRegistry:
    return ControlPackRegistry(BUILTIN_CONTROL_PACKS)


__all__ = (
    "BUILTIN_CONTROL_PACKS", "ControlDefinition", "ControlEvaluation",
    "ControlPack", "ControlPackRegistry", "builtin_registry",
)
