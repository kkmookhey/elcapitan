"""Anthropic and Gemini adapters for the provider-neutral AgentRuntime."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, Mapping, Protocol

from jsonschema import Draft202012Validator

from .agent_contracts import agent_result_schema
from .agent_prompt import instructions, task_document
from .agents import AgentResult, AgentResultStatus, AgentTask
from .hashing import canonical_json


class ProviderRuntimeError(RuntimeError):
    pass


class ProviderTransport(Protocol):
    def create(self, payload: Mapping) -> Mapping: ...


class _JsonTransport:
    def __init__(self, *, endpoint: str, headers: Mapping[str, str],
                 timeout_seconds: float) -> None:
        if timeout_seconds <= 0:
            raise ValueError("provider timeout must be positive")
        self.endpoint, self.headers, self.timeout_seconds = endpoint, dict(headers), timeout_seconds

    def create(self, payload: Mapping) -> Mapping:
        request = urllib.request.Request(
            self.endpoint, data=canonical_json(payload), headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise ProviderRuntimeError("model provider response exceeded 8 MiB")
            document = json.loads(raw)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise ProviderRuntimeError(
                f"model provider returned HTTP {exc.code}: {detail}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderRuntimeError(f"model provider request failed: {exc}") from exc
        if not isinstance(document, Mapping):
            raise ProviderRuntimeError("model provider returned a non-object response")
        return document


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _anthropic_schema(contract: str) -> dict:
    """Compile the strict local contract to Anthropic's supported subset."""
    unsupported = {"maxItems", "maxLength"}

    def compile_value(value):
        if isinstance(value, Mapping):
            return {
                key: compile_value(item)
                for key, item in value.items() if key not in unsupported
            }
        if isinstance(value, list):
            return [compile_value(item) for item in value]
        return value

    return compile_value(agent_result_schema(contract))


def _parse_result(task: AgentTask, *, text: str, runtime: str, model: str,
                  started_at: str, completed_at: str, usage: Mapping) -> AgentResult:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProviderRuntimeError(f"model returned malformed structured JSON: {exc}") from exc
    schema = agent_result_schema(task.output_contract)
    errors = sorted(Draft202012Validator(schema).iter_errors(document),
                    key=lambda error: [str(item) for item in error.absolute_path])
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(item) for item in error.absolute_path) or '<root>'}: "
            f"{error.message}" for error in errors)
        raise ProviderRuntimeError(
            f"model output violated {task.output_contract}: {detail}")
    normalized_usage = {
        key: value for key, value in usage.items()
        if isinstance(value, int) and not isinstance(value, bool)
    }
    return AgentResult(
        task_id=task.task_id, case_id=task.case_id, role=task.role,
        status=AgentResultStatus(document["status"]), output=document["output"],
        evidence_cited=tuple(document["evidence_cited"]),
        missing_evidence=tuple(document["missing_evidence"]), runtime=runtime,
        model=model, started_at=started_at, completed_at=completed_at,
        usage=normalized_usage)


@dataclass(frozen=True)
class AnthropicMessagesRuntime:
    model: str
    transport: ProviderTransport
    now: Callable[[], str] = _now
    max_output_tokens: int = 6000

    def __post_init__(self) -> None:
        if not self.model or self.max_output_tokens <= 0:
            raise ValueError("Anthropic runtime requires a model and positive token limit")

    @classmethod
    def from_environment(cls, *, model: str, api_key: str | None = None,
                         now: Callable[[], str] = _now,
                         base_url: str = "https://api.anthropic.com",
                         timeout_seconds: float = 180,
                         max_output_tokens: int = 6000) -> "AnthropicMessagesRuntime":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise ValueError("ANTHROPIC_API_KEY is required")
        return cls(
            model=model,
            transport=_JsonTransport(
                endpoint=base_url.rstrip("/") + "/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                timeout_seconds=timeout_seconds),
            now=now, max_output_tokens=max_output_tokens)

    @property
    def name(self) -> str:
        return "anthropic-messages"

    def run(self, task: AgentTask) -> AgentResult:
        payload = {
            "model": self.model, "max_tokens": self.max_output_tokens,
            "system": instructions(task),
            "messages": [{"role": "user", "content": canonical_json(
                task_document(task)).decode("utf-8")}],
            "output_config": {"format": {
                "type": "json_schema",
                "schema": _anthropic_schema(task.output_contract)}},
        }
        started_at = self.now()
        response = self.transport.create(payload)
        if response.get("stop_reason") not in (None, "end_turn"):
            raise ProviderRuntimeError(
                f"Anthropic response stopped with {response.get('stop_reason')}")
        texts = [block["text"] for block in response.get("content", ())
                 if isinstance(block, Mapping) and block.get("type") == "text"
                 and isinstance(block.get("text"), str)]
        if not texts:
            raise ProviderRuntimeError("Anthropic response contained no text output")
        return _parse_result(
            task, text="".join(texts), runtime=self.name,
            model=str(response.get("model") or self.model), started_at=started_at,
            completed_at=self.now(), usage=response.get("usage") or {})


@dataclass(frozen=True)
class GeminiGenerateContentRuntime:
    model: str
    transport: ProviderTransport
    now: Callable[[], str] = _now
    max_output_tokens: int = 6000

    def __post_init__(self) -> None:
        if not self.model or self.max_output_tokens <= 0:
            raise ValueError("Gemini runtime requires a model and positive token limit")

    @classmethod
    def from_environment(cls, *, model: str, api_key: str | None = None,
                         now: Callable[[], str] = _now,
                         base_url: str = "https://generativelanguage.googleapis.com/v1beta",
                         timeout_seconds: float = 180,
                         max_output_tokens: int = 6000) -> "GeminiGenerateContentRuntime":
        key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
        if not key:
            raise ValueError("GEMINI_API_KEY or GOOGLE_API_KEY is required")
        model_name = model.removeprefix("models/")
        endpoint = (base_url.rstrip("/") + "/models/"
                    + urllib.parse.quote(model_name, safe="-._") + ":generateContent")
        return cls(
            model=model_name,
            transport=_JsonTransport(
                endpoint=endpoint,
                headers={"x-goog-api-key": key, "content-type": "application/json"},
                timeout_seconds=timeout_seconds),
            now=now, max_output_tokens=max_output_tokens)

    @property
    def name(self) -> str:
        return "gemini-generate-content"

    def run(self, task: AgentTask) -> AgentResult:
        payload = {
            "systemInstruction": {"parts": [{"text": instructions(task)}]},
            "contents": [{"role": "user", "parts": [{"text": canonical_json(
                task_document(task)).decode("utf-8")}]}],
            "generationConfig": {
                "maxOutputTokens": self.max_output_tokens,
                "responseFormat": {"text": {
                    "mimeType": "application/json",
                    "schema": agent_result_schema(task.output_contract),
                }},
            },
            "store": False,
        }
        started_at = self.now()
        response = self.transport.create(payload)
        candidates = response.get("candidates") or []
        if not candidates or not isinstance(candidates[0], Mapping):
            raise ProviderRuntimeError(
                "Gemini response contained no candidate: " + str(response.get("promptFeedback", "")))
        candidate = candidates[0]
        if candidate.get("finishReason") not in (None, "STOP"):
            raise ProviderRuntimeError(
                f"Gemini response stopped with {candidate.get('finishReason')}")
        content = candidate.get("content") or {}
        texts = [part["text"] for part in content.get("parts", ())
                 if isinstance(part, Mapping) and isinstance(part.get("text"), str)]
        if not texts:
            raise ProviderRuntimeError("Gemini response contained no text output")
        raw_usage = response.get("usageMetadata") or {}
        usage = {
            "input_tokens": raw_usage.get("promptTokenCount"),
            "output_tokens": raw_usage.get("candidatesTokenCount"),
            "total_tokens": raw_usage.get("totalTokenCount"),
        }
        return _parse_result(
            task, text="".join(texts), runtime=self.name,
            model=str(response.get("modelVersion") or self.model), started_at=started_at,
            completed_at=self.now(), usage=usage)
