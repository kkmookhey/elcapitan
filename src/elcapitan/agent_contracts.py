"""Strict output contracts for model-backed remediation roles."""
from __future__ import annotations

from copy import deepcopy

from jsonschema import Draft202012Validator


_STRING_ARRAY = {"type": "array", "items": {"type": "string", "minLength": 1}}


TERRAFORM_REMEDIATION_PROPOSAL = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "objective": {"type": "string", "minLength": 1},
        "files": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "content": {"type": "string", "minLength": 1},
                },
                "required": ["path", "content"],
            },
        },
        "prerequisites": _STRING_ARRAY,
        "steps": _STRING_ARRAY,
        "rollout_steps": _STRING_ARRAY,
        "verification_steps": _STRING_ARRAY,
        "rollback_steps": _STRING_ARRAY,
        "rollback_triggers": _STRING_ARRAY,
        "blast_radius": _STRING_ARRAY,
    },
    "required": [
        "objective", "files", "prerequisites", "steps", "rollout_steps",
        "verification_steps", "rollback_steps", "rollback_triggers",
        "blast_radius",
    ],
}

SRE_REVIEW = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "decision": {
            "type": "string",
            "enum": ["approve", "reject", "needs_human_context"],
        },
        "risk_level": {
            "type": "string", "enum": ["low", "medium", "high", "critical"],
        },
        "summary": {"type": "string", "minLength": 1},
        "dependencies": _STRING_ARRAY,
        "failure_modes": _STRING_ARRAY,
        "required_controls": _STRING_ARRAY,
        "verification_requirements": _STRING_ARRAY,
    },
    "required": [
        "decision", "risk_level", "summary", "dependencies", "failure_modes",
        "required_controls", "verification_requirements",
    ],
}

CHANGE_WINDOW_SELECTION = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "selected_candidate_id": {"type": "string", "minLength": 1},
        "rationale": _STRING_ARRAY,
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "risks": _STRING_ARRAY,
    },
    "required": ["selected_candidate_id", "rationale", "confidence", "risks"],
}

ROLLBACK_REVIEW = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "decision": {
            "type": "string",
            "enum": ["approve", "reject", "needs_human_context"],
        },
        "summary": {"type": "string", "minLength": 1},
        "verified_steps": _STRING_ARRAY,
        "trigger_coverage": _STRING_ARRAY,
        "failure_modes": _STRING_ARRAY,
        "required_changes": _STRING_ARRAY,
    },
    "required": [
        "decision", "summary", "verified_steps", "trigger_coverage",
        "failure_modes", "required_changes",
    ],
}


OUTPUT_CONTRACTS = {
    "TerraformRemediationProposal.v1": TERRAFORM_REMEDIATION_PROPOSAL,
    "SREReview.v1": SRE_REVIEW,
    "ChangeWindowSelection.v1": CHANGE_WINDOW_SELECTION,
    "RollbackReview.v1": ROLLBACK_REVIEW,
}


def output_schema(contract: str) -> dict:
    try:
        return deepcopy(OUTPUT_CONTRACTS[contract])
    except KeyError:
        raise ValueError(f"unknown agent output contract: {contract}") from None


def agent_result_schema(contract: str) -> dict:
    """Strict envelope returned by every model-backed role."""
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "status": {
                "type": "string",
                "enum": [
                    "succeeded", "needs_more_evidence",
                    "needs_human_context", "failed",
                ],
            },
            "output": output_schema(contract),
            "evidence_cited": {
                "type": "array", "items": {"type": "string", "minLength": 1},
            },
            "missing_evidence": {
                "type": "array", "items": {"type": "string", "minLength": 1},
            },
        },
        "required": ["status", "output", "evidence_cited", "missing_evidence"],
    }


def validate_output(contract: str, document) -> tuple[str, ...]:
    """Return stable, human-readable contract violations."""
    errors = sorted(
        Draft202012Validator(output_schema(contract)).iter_errors(document),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    return tuple(
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: "
        f"{error.message}"
        for error in errors
    )
