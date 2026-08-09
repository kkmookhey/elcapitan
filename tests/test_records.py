import copy, pytest
from elcapitan.records import (RESOLUTION_TYPES, TERMINAL_STATUSES,
                               validate_doc)

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
    # $ref resolution in `referencing` is LAZY — constructing the validator
    # succeeds even with a broken registry, and a document that never touches
    # the `raw_event` key never dereferences it either (the `properties`
    # keyword only applies to keys actually present). So the document below
    # deliberately includes `raw_event` with an invalid inner value, forcing
    # the $ref to actually resolve during iter_errors. With the registry wired
    # correctly this surfaces the evidence-ref schema's own field errors
    # (proving real resolution, not just "any string got accepted"); with a
    # broken registry, `referencing` raises Unresolvable instead of yielding
    # errors, which fails this test loudly rather than passing vacuously.
    doc = {"finding_id": "FIND-001", "raw_event": {"evidence_id": "not-a-match"}}
    errors = validate_doc("finding-record", doc)
    assert errors, "expected schema errors, not a resolution failure"
    assert any(e.startswith("raw_event") for e in errors), (
        f"expected errors from inside the resolved evidence-ref schema: {errors}")

def test_format_checker_rejects_a_malformed_timestamp():
    doc = copy.deepcopy(PROPOSAL); doc["created_at"] = "not-a-date"
    assert validate_doc("remediation-proposal", doc) != []

def test_format_checker_rejects_a_date_only_string():
    doc = copy.deepcopy(PROPOSAL); doc["created_at"] = "2026-08-08"
    assert validate_doc("remediation-proposal", doc) != []

def test_format_checker_rejects_a_datetime_with_no_offset():
    doc = copy.deepcopy(PROPOSAL); doc["created_at"] = "2026-08-08T12:00:00"
    assert validate_doc("remediation-proposal", doc) != []

def test_format_checker_accepts_a_z_offset():
    doc = copy.deepcopy(PROPOSAL); doc["created_at"] = "2026-08-08T12:00:00Z"
    assert validate_doc("remediation-proposal", doc) == []

def test_format_checker_accepts_a_numeric_offset():
    doc = copy.deepcopy(PROPOSAL); doc["created_at"] = "2026-08-08T12:00:00+05:30"
    assert validate_doc("remediation-proposal", doc) == []

def test_format_checker_leaves_non_strings_to_the_type_keyword():
    doc = copy.deepcopy(PROPOSAL); doc["created_at"] = 12345
    errors = validate_doc("remediation-proposal", doc)
    assert errors != []
    assert any("is not of type 'string'" in e for e in errors)

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
