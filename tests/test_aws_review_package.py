import json
from pathlib import Path

from elcapitan.agents import (
    AgentResult, AgentResultStatus, AgentRole, AgentTask,
)
from elcapitan.case_store import SqliteCaseStore
from elcapitan.case_validation import (
    CaseValidationService, FindingValidationStatus,
)
from elcapitan.cases import CaseState
from elcapitan.cloud import CloudState
from elcapitan.evidence import Collector
from elcapitan.finding_store import SqliteFindingStore
from elcapitan.intake import IntakeContext, RemediationIntake
from elcapitan.observability import UsageSample, WindowPolicy
from elcapitan.orchestration import PreApprovalOrchestrator
from elcapitan.product_records import SqliteProductRecordStore
from elcapitan.remediation_planning import TerraformCheck


NOW = "2026-09-03T12:00:00Z"
AWS_FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-sample.json"
BUCKET_ARN = "arn:aws:s3:::training-assets"


class Ids:
    def __init__(self):
        self.counts = {}

    def __call__(self, prefix):
        self.counts[prefix] = self.counts.get(prefix, 0) + 1
        return f"{prefix}-{self.counts[prefix]:03d}"


class AWSReviewRuntime:
    name = "recorded-aws-review"

    def run(self, task: AgentTask) -> AgentResult:
        if task.role is AgentRole.REMEDIATION_ENGINEER:
            source = str(task.metadata["source"])
            output = {
                "objective": "enable versioning for the S3 bucket",
                "files": {
                    task.metadata["link"]["source_path"]:
                        source.replace('status = "Disabled"', 'status = "Enabled"'),
                },
                "prerequisites": ["retain the captured state digest"],
                "steps": ["set the versioning status to Enabled"],
                "rollout_steps": ["apply only the state-linked S3 versioning resource"],
                "verification_steps": ["confirm GetBucketVersioning reports Enabled"],
                "rollback_steps": ["set the versioning status to Suspended"],
                "rollback_triggers": ["the targeted Terraform apply fails"],
                "blast_radius": ["new object versions in training-assets"],
            }
            model = "maker-model"
        elif task.role is AgentRole.SRE_REVIEWER:
            output = {
                "decision": "approve",
                "risk_level": "low",
                "summary": (
                    "The proposed pre-change package enables bucket versioning and "
                    "keeps deployment subject to human authorization."
                ),
                "dependencies": ["S3 bucket training-assets"],
                "failure_modes": ["unexpected growth in retained object versions"],
                "required_controls": ["monitor bucket storage growth after change"],
                "verification_requirements": [
                    "confirm GetBucketVersioning returns Enabled after deployment"
                ],
            }
            model = "sre-model"
        elif task.role is AgentRole.WINDOW_PLANNER:
            output = {
                "selected_candidate_id": task.metadata["candidates"][0][
                    "candidate_id"],
                "rationale": ["use the supplied low-usage fixed window"],
                "confidence": 1.0,
                "risks": ["new object versions can increase storage consumption"],
            }
            model = "window-model"
        elif task.role is AgentRole.ROLLBACK_VERIFIER:
            output = {
                "decision": "approve",
                "summary": (
                    "Suspending versioning is a bounded rollback for the proposed "
                    "status change; existing versions remain retained."
                ),
                "verified_steps": ["restore versioning status to Suspended"],
                "trigger_coverage": ["apply failure stops further rollout"],
                "failure_modes": ["retained versions increase storage use"],
                "required_changes": [],
            }
            model = "rollback-model"
        else:  # pragma: no cover - the orchestrator uses only these four roles
            raise AssertionError(task.role)
        return AgentResult(
            task_id=task.task_id,
            case_id=task.case_id,
            role=task.role,
            status=AgentResultStatus.SUCCEEDED,
            output=output,
            evidence_cited=tuple(task.evidence_ids),
            missing_evidence=(),
            runtime=self.name,
            model=model,
            started_at=NOW,
            completed_at=NOW,
            usage={"input": 10, "output": 10},
        )


class ExactAWSPlanRunner:
    def check(self, workspace, link, *, state_document=None):
        assert link.resource_address == "aws_s3_bucket_versioning.assets"
        assert link.state_sha256
        assert state_document["lineage"] == "aws-review-package-fixture"
        changed = (workspace / link.source_path).read_text()
        assert 'status = "Enabled"' in changed
        return tuple(
            TerraformCheck(name, ("terraform", name), 0, stdout="verified")
            for name in ("fmt", "init", "validate", "plan", "plan_scope")
        )


def _raw_finding():
    document = json.loads(AWS_FIXTURE.read_text())
    document["metadata"]["event_code"] = "s3_bucket_object_versioning"
    document["finding_info"]["uid"] = "prowler-aws-s3-versioning-001"
    document["finding_info"]["title"] = "S3 bucket versioning is not enabled"
    document["resources"][0]["uid"] = BUCKET_ARN
    document["unmapped"]["prowler_check_id"] = "s3_bucket_object_versioning"
    return document


def _terraform_state():
    return {
        "version": 4,
        "serial": 1,
        "lineage": "aws-review-package-fixture",
        "outputs": {},
        "resources": [{
            "mode": "managed",
            "type": "aws_s3_bucket_versioning",
            "name": "assets",
            "instances": [{"attributes": {
                "id": "training-assets,111122223333",
                "bucket": "training-assets",
                "versioning_configuration": [{
                    "mfa_delete": "Disabled", "status": "Disabled",
                }],
            }}],
        }],
    }


def test_aws_s3_finding_reaches_a_state_grounded_human_review_package(tmp_path):
    database = tmp_path / "product.db"
    cases = SqliteCaseStore(database)
    findings = SqliteFindingStore(database)
    records = SqliteProductRecordStore(database)
    ids = Ids()
    artifacts = tmp_path / "artifacts"
    opened = RemediationIntake(
        case_store=cases,
        finding_store=findings,
        artifact_root=artifacts,
        collector=Collector("prowler", "5.37.1", "scanner-reader"),
        now=lambda: NOW,
        id_factory=ids,
    ).ingest(
        _raw_finding(),
        tenant_id="TEN-AWS-001",
        context=IntakeContext(
            asset_criticality=0.8,
            internet_exposed=False,
            service_ids=("training-assets",),
        ),
    )
    validated = CaseValidationService(
        case_store=cases,
        finding_store=findings,
        record_store=records,
        artifact_root=artifacts,
        now=lambda: NOW,
        id_factory=ids,
        reader=lambda finding, env: CloudState(
            provider="aws",
            resource_uid=BUCKET_ARN,
            region="us-east-1",
            config=(("versioning", "{}"),),
        ),
    ).validate(opened.case.case_id, host_env={})
    assert validated.case.state is CaseState.VALIDATED
    assert validated.findings[0].status is FindingValidationStatus.CONFIRMED

    repository = tmp_path / "customer-repo"
    repository.mkdir()
    (repository / "bucket.tf").write_text('''
resource "aws_s3_bucket_versioning" "assets" {
  bucket = "training-assets"
  versioning_configuration {
    status = "Disabled"
  }
}
''')
    outcome = PreApprovalOrchestrator(
        case_store=cases,
        finding_store=findings,
        record_store=records,
        artifact_root=artifacts,
        runtime=AWSReviewRuntime(),
        runner=ExactAWSPlanRunner(),
        now=lambda: NOW,
        minimum_distinct_agent_models=2,
        require_state_grounded_plan=True,
        id_factory=ids,
    ).prepare(
        validated.case.case_id,
        repository=repository,
        state_document=_terraform_state(),
        service_context={
            "service": "training-assets",
            "environment": "test",
            "owner": "platform-team",
            "health_signals": ["GetBucketVersioning status"],
            "dependencies": ["S3"],
            "evidence_phase": "pre_change",
        },
        usage_samples=(UsageSample(
            timestamp="2026-09-03T11:00:00Z", requests=0),),
        window_policy=WindowPolicy(
            notice_hours=0,
            fixed_start_delay_minutes=60,
            duration_minutes=30,
        ),
    )

    package = outcome.human_review.review_package
    assert outcome.human_review.case.state is CaseState.AWAITING_APPROVAL
    assert package.record_type == "HumanReviewPackage.v1"
    assert package.body["execution_status"] == "not_started"
    assert package.body["risk_assessment"]["score"] > 0
    assert package.body["validation"]["body"]["findings"][0][
        "status"] == "confirmed"
    assert package.body["iac_link"]["body"]["link"][
        "resource_address"] == "aws_s3_bucket_versioning.assets"
    plan = package.body["remediation_plan"]["body"]
    assert plan["verification"]["mode"] == "targeted_state_plan"
    assert plan["change"]["materialization"] == "deterministic_control_patch"
    assert plan["scope"]["rule_ids"] == ("s3_bucket_object_versioning",)
    assert any(
        check["name"] == "plan_scope" and check["passed"] is True
        for check in plan["checks"]
    )
    assert all(
        check["passed"] is True
        for check in package.body["policy_decision"]["body"]["checks"]
    )
    assert (repository / "bucket.tf").read_text().count(
        'status = "Disabled"') == 1
