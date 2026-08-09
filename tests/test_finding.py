import json
from pathlib import Path
import pytest
from elcapitan.evidence import Collector, EvidenceRef, verify_evidence
from elcapitan.finding import normalise_ocsf
from elcapitan.records import validate_doc

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-sample.json"
C = Collector(tool="prowler", version="5.2.1", identity="anna-scanner")
NOW = "2026-08-08T12:00:00Z"

@pytest.fixture
def rec(tmp_path):
    raw = json.loads(FIXTURE.read_text())
    return normalise_ocsf(raw, run_dir=tmp_path, finding_id="FIND-001",
                          collector=C, now=NOW), tmp_path

def test_output_validates_against_its_schema(rec):
    record, _ = rec
    assert validate_doc("finding-record", record) == []

def test_provenance_is_fully_preserved(rec):
    record, _ = rec
    p = record["provenance"]
    assert (p["product"], p["product_version"]) == ("Prowler", "5.2.1")
    assert (p["provider"], p["account"], p["region"]) == ("aws", "111122223333", "us-east-1")
    assert p["observed_at"] == "2026-08-08T11:00:00Z"

def test_ocsf_identifiers_preserved(rec):
    record, _ = rec
    assert record["ocsf"]["class_uid"] == 2004
    assert record["ocsf"]["original_uid"] == "prowler-aws-s3-123"
    assert record["ocsf"]["version"] == "1.3.0"

def test_resource_preserved(rec):
    record, _ = rec
    assert record["resource"]["uid"] == "arn:aws:s3:::anna-assets"

def test_raw_artifact_lives_inside_the_run_dir(rec):
    record, run_dir = rec
    assert (run_dir / record["raw_event"]["artifact_path"]).is_file()

def test_raw_artifact_hash_verifies(rec):
    record, run_dir = rec
    ref = EvidenceRef(**{**record["raw_event"],
                         "collector": Collector(**record["raw_event"]["collector"])})
    assert verify_evidence(run_dir, ref) is True

def test_vendor_fields_namespaced_not_discarded(rec):
    record, _ = rec
    assert record["vendor_extensions"]["prowler_check_id"] == "s3_bucket_public_access"

def test_rejects_non_ocsf_input(tmp_path):
    with pytest.raises(ValueError, match="class_uid"):
        normalise_ocsf({"metadata": {}}, run_dir=tmp_path, finding_id="FIND-001",
                       collector=C, now=NOW)
