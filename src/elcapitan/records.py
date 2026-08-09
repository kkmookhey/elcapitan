"""Schema loading with working $ref resolution and real format checking.

jsonschema does not enforce `format` unless a FormatChecker is supplied, and
relative $ref only resolves when the sibling schemas are in a registry.
Both were missing in the first draft, which made the schemas decorative.

One more trap: jsonschema's own "date-time" checker is registered only when
the optional `rfc3339-validator` package is importable (see jsonschema's
_format.py). That package is not a project dependency and we are not adding
one, so a bare `FormatChecker()` would silently accept `"not-a-date"` for
`format: date-time` — format-checking would still be decorative even with a
checker "supplied". We register our own date-time check below so the format
is actually enforced without a new dependency.
"""
import datetime
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"

RESOLUTION_TYPES = ("patch", "runtime_change", "risk_accepted",
                    "false_positive", "needs_design")
TERMINAL_STATUSES = ("READY_FOR_REVIEW", "NEEDS_HUMAN_CONTEXT")

_FORMAT_CHECKER = FormatChecker()

@_FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _is_date_time(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    datetime.datetime.fromisoformat(instance)
    return True

@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text())

@lru_cache(maxsize=None)
def _registry() -> Registry:
    resources = [
        (path.name, Resource.from_contents(json.loads(path.read_text()),
                                           default_specification=DRAFT202012))
        for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
    ]
    return Registry().with_resources(resources)

@lru_cache(maxsize=None)
def validator_for(name: str) -> Draft202012Validator:
    return Draft202012Validator(load_schema(name), registry=_registry(),
                                format_checker=_FORMAT_CHECKER)

def validate_doc(name: str, doc: dict) -> list[str]:
    """Human-readable errors. Empty list means valid."""
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator_for(name).iter_errors(doc),
                          key=lambda e: list(e.absolute_path))
    ]
