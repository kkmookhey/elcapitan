import json

import pytest

from elcapitan.agents import AgentRole, AgentTask
from elcapitan.openai_runtime import OpenAIResponsesRuntime, OpenAIRuntimeError


NOW = "2026-08-26T12:00:00Z"


class Transport:
    def __init__(self, response):
        self.response = response
        self.payloads = []

    def create(self, payload):
        self.payloads.append(payload)
        return self.response


def task():
    return AgentTask(
        task_id="TASK-001",
        case_id="CASE-001",
        role=AgentRole.SRE_REVIEWER,
        objective="review availability risk",
        output_contract="SREReview.v1",
        input_record_ids=("PLAN-001",),
        evidence_ids=("EVD-001",),
        constraints=("do not invent evidence",),
        metadata={"plan": {"objective": "disable public access"}},
    )


def output(**overrides):
    body = {
        "status": "succeeded",
        "output": {
            "decision": "approve",
            "risk_level": "medium",
            "summary": "canary and rollback controls are sufficient",
            "dependencies": ["private endpoint"],
            "failure_modes": ["clients lose storage connectivity"],
            "required_controls": ["canary deployment"],
            "verification_requirements": ["verify request success rate"],
        },
        "evidence_cited": ["EVD-001"],
        "missing_evidence": [],
    }
    body.update(overrides)
    return body


def runtime(response):
    transport = Transport(response)
    return OpenAIResponsesRuntime(
        model="explicit-test-model", transport=transport,
        now=lambda: NOW, max_output_tokens=1234,
    ), transport


def test_runtime_uses_strict_responses_schema_and_does_not_store_output():
    adapter, transport = runtime({
        "status": "completed", "model": "resolved-model",
        "output_text": json.dumps(output()),
        "usage": {"input_tokens": 20, "output_tokens": 10, "details": {}},
    })
    result = adapter.run(task())
    assert result.output["decision"] == "approve"
    assert result.runtime == "openai-responses"
    assert result.model == "resolved-model"
    assert result.usage == {"input_tokens": 20, "output_tokens": 10}

    payload = transport.payloads[0]
    assert payload["store"] is False
    assert payload["model"] == "explicit-test-model"
    assert payload["max_output_tokens"] == 1234
    assert payload["text"]["format"]["type"] == "json_schema"
    assert payload["text"]["format"]["strict"] is True
    sent = json.loads(payload["input"][0]["content"][0]["text"])
    assert sent["available_evidence_ids"] == ["EVD-001"]


def test_runtime_reads_output_items_when_output_text_helper_is_absent():
    adapter, _ = runtime({
        "status": "completed",
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": json.dumps(output())}],
        }],
    })
    assert adapter.run(task()).status.value == "succeeded"


def test_contract_violation_is_rejected_even_if_transport_claims_success():
    invalid = output()
    del invalid["output"]["failure_modes"]
    adapter, _ = runtime({"status": "completed", "output_text": json.dumps(invalid)})
    with pytest.raises(OpenAIRuntimeError, match="failure_modes"):
        adapter.run(task())


def test_refusal_is_a_named_runtime_failure():
    adapter, _ = runtime({
        "status": "completed",
        "output": [{"content": [{"type": "refusal", "refusal": "cannot comply"}]}],
    })
    with pytest.raises(OpenAIRuntimeError, match="refused"):
        adapter.run(task())


def test_incomplete_response_is_not_treated_as_agent_output():
    adapter, _ = runtime({"status": "incomplete", "output": []})
    with pytest.raises(OpenAIRuntimeError, match="did not complete"):
        adapter.run(task())
