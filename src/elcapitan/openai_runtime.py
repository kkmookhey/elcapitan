"""OpenAI Responses API adapter for the provider-neutral AgentRuntime."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Callable, Mapping, Protocol

from jsonschema import Draft202012Validator

from .agent_contracts import agent_result_schema
from .agents import AgentResult, AgentResultStatus, AgentTask
from .hashing import canonical_json


class OpenAIRuntimeError(RuntimeError):
    pass


class ResponsesTransport(Protocol):
    def create(self, payload: Mapping) -> Mapping: ...


class UrlLibResponsesTransport:
    def __init__(self, *, api_key: str, base_url: str = "https://api.openai.com/v1",
                 timeout_seconds: float = 180) -> None:
        if not api_key:
            raise ValueError("OpenAI API key is required")
        if timeout_seconds <= 0:
            raise ValueError("OpenAI timeout must be positive")
        self.api_key = api_key
        self.endpoint = base_url.rstrip("/") + "/responses"
        self.timeout_seconds = timeout_seconds

    def create(self, payload: Mapping) -> Mapping:
        request = urllib.request.Request(
            self.endpoint,
            data=canonical_json(payload),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise OpenAIRuntimeError(
                        "OpenAI Responses API response exceeded 8 MiB")
                document = json.loads(raw)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise OpenAIRuntimeError(
                f"OpenAI Responses API returned HTTP {exc.code}: {detail}"
            ) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise OpenAIRuntimeError(f"OpenAI Responses API request failed: {exc}") from exc
        if not isinstance(document, Mapping):
            raise OpenAIRuntimeError("OpenAI Responses API returned a non-object response")
        return document


_ROLE_INSTRUCTIONS = {
    "remediation_engineer": (
        "Act as a security remediation engineer. Produce the smallest reversible "
        "Terraform change supported by the supplied finding, live validation, and "
        "source. Never claim a command ran or a dependency is safe without evidence."
    ),
    "sre_reviewer": (
        "Act as an independent SRE reviewer. Evaluate availability, dependencies, "
        "blast radius, health signals, rollout controls, and verification. Reject or "
        "request context when the supplied evidence cannot establish safety."
    ),
    "window_planner": (
        "Act as a change-window reviewer. Select only one supplied candidate using "
        "the usage summary and policy. Do not invent a window or telemetry."
    ),
    "rollback_verifier": (
        "Act as an independent rollback reviewer. Verify that every material failure "
        "mode has an observable trigger and executable reversal. Do not approve vague "
        "or circular rollback instructions."
    ),
}


def _thaw(value):
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _output_text(response: Mapping) -> str:
    direct = response.get("output_text")
    if isinstance(direct, str) and direct:
        return direct
    texts = []
    for item in response.get("output", ()):
        if not isinstance(item, Mapping):
            continue
        for content in item.get("content", ()):
            if not isinstance(content, Mapping):
                continue
            if content.get("type") == "refusal":
                raise OpenAIRuntimeError(
                    f"model refused the agent task: {content.get('refusal', '')}"
                )
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                texts.append(content["text"])
    if not texts:
        raise OpenAIRuntimeError("OpenAI response contained no output text")
    return "".join(texts)


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite JSON number {value}")


@dataclass(frozen=True)
class OpenAIResponsesRuntime:
    model: str
    transport: ResponsesTransport
    now: Callable[[], str]
    max_output_tokens: int = 6000

    def __post_init__(self) -> None:
        if not self.model:
            raise ValueError("an explicit OpenAI model is required")
        if (isinstance(self.max_output_tokens, bool)
                or not isinstance(self.max_output_tokens, int)
                or self.max_output_tokens <= 0):
            raise ValueError("max_output_tokens must be a positive integer")

    @classmethod
    def from_environment(cls, *, model: str, now: Callable[[], str] | None = None,
                         api_key: str | None = None,
                         base_url: str = "https://api.openai.com/v1",
                         timeout_seconds: float = 180,
                         max_output_tokens: int = 6000) -> "OpenAIResponsesRuntime":
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        return cls(
            model=model,
            transport=UrlLibResponsesTransport(
                api_key=key, base_url=base_url, timeout_seconds=timeout_seconds,
            ),
            now=now or (lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")),
            max_output_tokens=max_output_tokens,
        )

    @property
    def name(self) -> str:
        return "openai-responses"

    def run(self, task: AgentTask) -> AgentResult:
        schema = agent_result_schema(task.output_contract)
        role = task.role.value
        instructions = _ROLE_INSTRUCTIONS.get(role)
        if instructions is None:
            raise OpenAIRuntimeError(f"OpenAI runtime has no prompt for role {role}")
        format_name = re.sub(r"[^A-Za-z0-9_-]", "_", task.output_contract)[:64]
        task_document = {
            "task_id": task.task_id,
            "case_id": task.case_id,
            "role": role,
            "objective": task.objective,
            "input_record_ids": list(task.input_record_ids),
            "available_evidence_ids": list(task.evidence_ids),
            "constraints": list(task.constraints),
            "context": _thaw(task.metadata),
        }
        payload = {
            "model": self.model,
            "instructions": (
                instructions
                + " Return only the strict structured result. Cite only evidence IDs "
                  "listed in available_evidence_ids."
            ),
            "input": [{
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": canonical_json(task_document).decode("utf-8"),
                }],
            }],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": format_name,
                    "schema": schema,
                    "strict": True,
                }
            },
            "store": False,
            "max_output_tokens": self.max_output_tokens,
            "metadata": {"case_id": task.case_id, "task_id": task.task_id},
            "safety_identifier": sha256(task.case_id.encode("utf-8")).hexdigest()[:32],
        }
        started_at = self.now()
        response = self.transport.create(payload)
        if response.get("status") not in (None, "completed"):
            raise OpenAIRuntimeError(
                f"OpenAI response did not complete: {response.get('status')}"
            )
        try:
            document = json.loads(
                _output_text(response),
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise OpenAIRuntimeError(f"model returned malformed structured JSON: {exc}") from exc
        errors = sorted(
            Draft202012Validator(schema).iter_errors(document),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            detail = "; ".join(
                f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: "
                f"{error.message}" for error in errors
            )
            raise OpenAIRuntimeError(f"model output violated {task.output_contract}: {detail}")
        usage = response.get("usage") or {}
        normalized_usage = {
            key: value for key, value in usage.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        return AgentResult(
            task_id=task.task_id,
            case_id=task.case_id,
            role=task.role,
            status=AgentResultStatus(document["status"]),
            output=document["output"],
            evidence_cited=tuple(document["evidence_cited"]),
            missing_evidence=tuple(document["missing_evidence"]),
            runtime=self.name,
            model=str(response.get("model") or self.model),
            started_at=started_at,
            completed_at=self.now(),
            usage=normalized_usage,
        )
