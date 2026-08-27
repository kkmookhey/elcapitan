from elcapitan.agent_prompt import instructions
from elcapitan.agents import AgentRole, AgentTask


def test_remediation_prompt_keeps_post_change_proof_in_verification():
    task = AgentTask(
        task_id="TASK-001", case_id="CASE-001",
        role=AgentRole.REMEDIATION_ENGINEER,
        objective="prepare the bounded change",
        output_contract="TerraformRemediationProposal.v1",
        input_record_ids=("VAL-001",), evidence_ids=("EVD-001",),
    )

    text = instructions(task)

    assert "pre-change planning" in text
    assert "post-change proof in verification steps" in text
