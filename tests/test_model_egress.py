from elcapitan.agents import AgentResult, AgentResultStatus, AgentRole, AgentTask
from elcapitan.model_egress import ModelEgressRuntime, sanitize_for_model


class CaptureRuntime:
    name = "capture"

    def __init__(self):
        self.task = None

    def run(self, task):
        self.task = task
        return AgentResult(
            task_id=task.task_id,
            case_id=task.case_id,
            role=task.role,
            status=AgentResultStatus.SUCCEEDED,
            output={},
            evidence_cited=(),
            missing_evidence=(),
            runtime=self.name,
            model="test",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:00Z",
        )


def test_sanitize_for_model_redacts_secrets_identifiers_and_embedded_values():
    resource_id = (
        "/subscriptions/12345678-1234-1234-1234-123456789abc/"
        "resourceGroups/customer-rg/providers/Microsoft.Storage/storageAccounts/customer1"
    )
    clean, receipt = sanitize_for_model({
        "api_key": "top-secret",
        "tenant_id": "TEN-CUSTOMER",
        "context": f"Target {resource_id} owned by person@example.com at 10.1.2.3",
        "workspace": "/Users/customer/private/repo/main.tf",
        "safe": "health check passed",
    })
    rendered = repr(clean)
    assert "top-secret" not in rendered
    assert "TEN-CUSTOMER" not in rendered
    assert resource_id not in rendered
    assert "person@example.com" not in rendered
    assert "10.1.2.3" not in rendered
    assert "/Users/customer" not in rendered
    assert clean["safe"] == "health check passed"
    assert receipt.redactions == 6


def test_model_egress_runtime_only_sends_sanitized_metadata():
    capture = CaptureRuntime()
    runtime = ModelEgressRuntime(capture)
    task = AgentTask(
        task_id="TASK-1",
        case_id="CASE-1",
        role=AgentRole.SRE_REVIEWER,
        objective="review",
        output_contract="SREReview.v1",
        input_record_ids=(),
        evidence_ids=(),
        metadata={"password": "never-send", "service": "checkout"},
    )
    result = runtime.run(task)
    assert result.task_id == task.task_id
    assert capture.task.metadata["password"] == "[SECRET_REDACTED]"
    assert capture.task.metadata["service"] == "checkout"
    assert runtime.last_receipt.redactions == 1
