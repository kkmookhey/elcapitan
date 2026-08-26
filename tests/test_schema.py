from copy import deepcopy

from elcapitan.schema import load_schema, validate_doc


EVIDENCE_REF = {
    "evidence_id": "EVD-001",
    "type": "scanner-event",
    "artifact_path": "evidence/EVD-001.bin",
    "sha256": "a" * 64,
    "collected_at": "2026-08-26T12:00:00Z",
    "sensitivity": "internal",
    "command_id": "",
    "collector": {"tool": "prowler", "version": "5.2.1", "identity": "scanner"},
}


def test_schema_loader_reads_product_schema():
    assert load_schema("evidence-ref")["title"] == "EvidenceRef"


def test_valid_evidence_ref_passes():
    assert validate_doc("evidence-ref", EVIDENCE_REF) == []


def test_relative_schema_reference_is_resolved():
    finding = {"finding_id": "FIND-001", "raw_event": {"evidence_id": "bad"}}
    errors = validate_doc("finding-record", finding)
    assert any(error.startswith("raw_event") for error in errors)


def test_timestamp_requires_timezone():
    evidence = deepcopy(EVIDENCE_REF)
    evidence["collected_at"] = "2026-08-26T12:00:00"
    assert validate_doc("evidence-ref", evidence)


def test_timestamp_rejects_date_only_value():
    evidence = deepcopy(EVIDENCE_REF)
    evidence["collected_at"] = "2026-08-26"
    assert validate_doc("evidence-ref", evidence)
