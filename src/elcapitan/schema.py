"""JSON Schema loading and validation for product records."""

import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_FORMAT_CHECKER = FormatChecker()


@_FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _is_rfc3339_date_time(instance: object) -> bool:
    """Require a complete, timezone-aware RFC 3339 timestamp."""
    if not isinstance(instance, str):
        return True
    if not re.match(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}", instance):
        return False
    return datetime.fromisoformat(instance.replace("Z", "+00:00")).tzinfo is not None


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text())


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    return _read_json(SCHEMA_DIR / f"{name}.schema.json")


@lru_cache(maxsize=None)
def _registry() -> Registry:
    resources = [
        (
            path.name,
            Resource.from_contents(
                _read_json(path), default_specification=DRAFT202012
            ),
        )
        for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
    ]
    return Registry().with_resources(resources)


@lru_cache(maxsize=None)
def validator_for(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        load_schema(name), registry=_registry(), format_checker=_FORMAT_CHECKER
    )


def validate_doc(name: str, doc: dict) -> list[str]:
    """Return human-readable validation errors; an empty list means valid."""
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: "
        f"{error.message}"
        for error in sorted(
            validator_for(name).iter_errors(doc),
            key=lambda error: list(error.absolute_path),
        )
    ]
