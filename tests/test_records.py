import copy, pytest
from elcapitan.records import (RESOLUTION_TYPES, TERMINAL_STATUSES,
                               validate_doc, validator_for)

CMD = {"command_id": "CMD-001", "tool": "terraform",
       "argv": ["plan", "-detailed-exitcode"], "exit_code": 2,
       "started_at": "2026-08-08T12:00:00Z", "completed_at": "2026-08-08T12:00:05Z",
       "stdout_evidence_id": "EVD-002", "stderr_evidence_id": "EVD-003"}

PROPOSAL = {
    "proposal_id": "PROP-001", "schema_version": 1,
    "created_at": "2026-08-08T12:00:00Z", "finding_id": "FIND-001",
    "input_bundle_hash": "a"*64,
    "validation": {"confirmed": True, "evidence": ["EVD-001"], "confidence": 0.9},
    "linking": {"iac_managed": False, "system_detected": "aws-cdk",
                "method": "grep", "confidence": 0.4, "evidence": ["EVD-001"],
                "files": []},
    "root_cause": "runtime creation", "resolution_type": "runtime_change",
    "remediation": {"objective": "o", "approach": "a", "patch_file": None},
    "verification": {"commands_run": [CMD], "output": [], "passed": True},
    "production_impact": {"expected": "none", "dependencies": [], "unknowns": [],
                          "risk": "low"},
    "context": {"severity": "High", "asset_id": "arn", "owner": "",
                "exploitability": ""},
    "status": "READY_FOR_REVIEW",
}

def test_valid_proposal_passes():
    assert validate_doc("remediation-proposal", PROPOSAL) == []

def test_ref_to_evidence_schema_resolves():
    # Would raise RefResolutionError if the registry were not wired up.
    validator_for("finding-record")

def test_format_checker_rejects_a_malformed_timestamp():
    doc = copy.deepcopy(PROPOSAL); doc["created_at"] = "not-a-date"
    assert validate_doc("remediation-proposal", doc) != []

def test_command_record_requires_exit_code():
    doc = copy.deepcopy(PROPOSAL); del doc["verification"]["commands_run"][0]["exit_code"]
    assert validate_doc("remediation-proposal", doc) != []

def test_command_record_rejects_arbitrary_shape():
    doc = copy.deepcopy(PROPOSAL); doc["verification"]["commands_run"] = ["terraform plan"]
    assert validate_doc("remediation-proposal", doc) != []

def test_confirmed_finding_must_cite_evidence():
    doc = copy.deepcopy(PROPOSAL); doc["validation"]["evidence"] = []
    assert validate_doc("remediation-proposal", doc) != []

def test_iac_managed_true_requires_linked_files():
    doc = copy.deepcopy(PROPOSAL)
    doc["linking"].update({"iac_managed": True, "files": []})
    assert validate_doc("remediation-proposal", doc) != []

def test_patch_resolution_requires_patch_file():
    doc = copy.deepcopy(PROPOSAL); doc["resolution_type"] = "patch"
    assert validate_doc("remediation-proposal", doc) != []

def test_ready_for_review_requires_non_empty_impact():
    doc = copy.deepcopy(PROPOSAL); doc["production_impact"]["expected"] = ""
    assert validate_doc("remediation-proposal", doc) != []

def test_needs_human_context_may_have_empty_impact():
    doc = copy.deepcopy(PROPOSAL)
    doc["status"] = "NEEDS_HUMAN_CONTEXT"; doc["production_impact"]["expected"] = ""
    assert validate_doc("remediation-proposal", doc) == []

def test_all_five_resolution_types_exist():
    assert set(RESOLUTION_TYPES) == {"patch","runtime_change","risk_accepted",
                                     "false_positive","needs_design"}

def test_both_terminal_statuses_exist():
    assert set(TERMINAL_STATUSES) == {"READY_FOR_REVIEW","NEEDS_HUMAN_CONTEXT"}
