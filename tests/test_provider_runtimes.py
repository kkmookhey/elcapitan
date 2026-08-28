import json

import pytest

from elcapitan.agents import AgentRole, AgentTask
from elcapitan.provider_runtimes import (
    _anthropic_schema, AnthropicMessagesRuntime, GeminiGenerateContentRuntime,
    ProviderRuntimeError,
)
from elcapitan.agent_contracts import agent_result_schema


NOW = "2026-08-26T12:00:00Z"


class Transport:
    def __init__(self, response):
        self.response, self.payloads = response, []

    def create(self, payload):
        self.payloads.append(payload)
        return self.response


def task():
    return AgentTask(
        task_id="TASK-001", case_id="CASE-001", role=AgentRole.RELEASE_AUDITOR,
        objective="audit release", output_contract="PostChangeReview.v1",
        input_record_ids=("EXEC-001",), evidence_ids=("EVD-001",),
        constraints=("cite evidence",), metadata={"probes": [{"passed": True}]})


def envelope():
    return {
        "status": "succeeded",
        "output": {
            "decision": "accept", "summary": "all mandatory checks passed",
            "validated_outcomes": ["finding cleared"], "residual_risks": [],
            "handoff_notes": ["continue monitoring"],
        },
        "evidence_cited": ["EVD-001"], "missing_evidence": [],
    }


def test_anthropic_runtime_uses_current_structured_output_contract():
    transport = Transport({
        "model": "claude-test", "stop_reason": "end_turn",
        "content": [{"type": "text", "text": json.dumps(envelope())}],
        "usage": {"input_tokens": 10, "output_tokens": 5},
    })
    runtime = AnthropicMessagesRuntime(
        model="claude-test", transport=transport, now=lambda: NOW)
    result = runtime.run(task())
    assert result.runtime == "anthropic-messages"
    assert result.output["decision"] == "accept"
    payload = transport.payloads[0]
    assert payload["output_config"]["format"]["type"] == "json_schema"
    assert payload["system"].startswith("Act as an independent post-change")


def test_anthropic_schema_compiles_size_limits_but_local_contract_keeps_them():
    local = agent_result_schema("RollbackReview.v1")
    provider = _anthropic_schema("RollbackReview.v1")

    assert local["properties"]["output"]["properties"]["summary"]["maxLength"]
    assert local["properties"]["output"]["properties"]["verified_steps"][
        "maxItems"]
    assert "maxLength" not in provider["properties"]["output"]["properties"][
        "summary"]
    assert "maxItems" not in provider["properties"]["output"]["properties"][
        "verified_steps"]
    assert "never placeholders" in provider["properties"]["output"]["properties"][
        "verified_steps"]["description"]
    assert "never placeholder" in provider["properties"]["output"]["properties"][
        "verified_steps"]["items"]["description"]


def test_gemini_runtime_uses_current_response_format_and_disables_storage():
    transport = Transport({
        "modelVersion": "gemini-test", "candidates": [{
            "finishReason": "STOP",
            "content": {"parts": [{"text": json.dumps(envelope())}]},
        }],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5,
                          "totalTokenCount": 15},
    })
    runtime = GeminiGenerateContentRuntime(
        model="gemini-test", transport=transport, now=lambda: NOW)
    result = runtime.run(task())
    assert result.runtime == "gemini-generate-content"
    assert result.usage["total_tokens"] == 15
    payload = transport.payloads[0]
    assert payload["store"] is False
    assert payload["generationConfig"]["responseFormat"]["text"]["mimeType"] == (
        "application/json")


def test_provider_runtime_rejects_contract_violations():
    invalid = envelope()
    del invalid["output"]["summary"]
    runtime = AnthropicMessagesRuntime(
        model="claude-test", transport=Transport({
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": json.dumps(invalid)}],
        }), now=lambda: NOW)
    with pytest.raises(ProviderRuntimeError, match="summary"):
        runtime.run(task())
