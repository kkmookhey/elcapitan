from elcapitan.demo_control import DemoControlPlane


def test_demo_control_requires_human_approval_and_completes_handoff(tmp_path):
    control = DemoControlPlane(tmp_path)
    assert control.state()["demo"]["phase"] == "ready"

    prepared = control.prepare()
    assert prepared["demo"]["phase"] == "awaiting_approval"
    assert prepared["case"]["state"] == "awaiting_approval"
    assert prepared["change_diff"]
    assert all(check["passed"] for check in prepared["demo"]["terraform_checks"])

    approved = control.approve(approver="Security Change Manager")
    assert approved["demo"]["phase"] == "approved"
    assert approved["case"]["record_ids"]["approval_id"]
    assert approved["case"]["record_ids"]["execution_job_id"]

    completed = control.execute(outcome="success")
    types = {record["record_type"] for record in completed["records"]}
    assert completed["case"]["state"] == "remediated"
    assert completed["demo"]["deployment_target_changed"] is True
    assert "RemediationCertificate.v1" in types
    assert "OriginatorHandoff.v1" in types


def test_demo_control_rolls_back_on_health_policy_failure(tmp_path):
    control = DemoControlPlane(tmp_path)
    control.prepare()
    control.approve(approver="Security Change Manager")

    completed = control.execute(outcome="rollback")
    types = {record["record_type"] for record in completed["records"]}
    assert completed["case"]["state"] == "rolled_back"
    assert completed["demo"]["deployment_target_restored"] is True
    assert "RollbackExecution.v1" in types
    assert "RollbackVerification.v1" in types
