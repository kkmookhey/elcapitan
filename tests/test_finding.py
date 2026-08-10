import json
from pathlib import Path
import pytest
from elcapitan.evidence import Collector, EvidenceRef, verify_evidence
from elcapitan.finding import cloud_target, normalise_ocsf
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


# --- an explicit null region must not reach a str-typed field ---------------
#
# `{"cloud": {"region": null}}` is legal OCSF/JSON. `.get("region", "")`
# returns None for it (the default only fires when the key is absent), and
# that None used to flow into cloud.CloudState.region, get written as literal
# `"region": null` in cloud-state-before.json, and only be rejected by
# cloud.from_dict's `isinstance(region, str)` check at validation time —
# after the trial had already burned its immutable id. cloud_target coerces
# at the source so both importers (run-trial.sh's pre-flight capture and
# normalise_ocsf) get a plain "" instead.

def test_cloud_target_coerces_a_null_region_to_the_empty_string():
    raw = {"cloud": {"provider": "aws", "region": None},
          "resources": [{"uid": "arn:aws:s3:::anna-assets"}]}
    provider, resource_uid, region = cloud_target(raw)
    assert (provider, resource_uid, region) == ("aws", "arn:aws:s3:::anna-assets", "")
    assert isinstance(region, str)


def test_cloud_target_coerces_a_non_string_region_to_a_string():
    raw = {"cloud": {"provider": "aws", "region": 5},
          "resources": [{"uid": "arn:aws:s3:::anna-assets"}]}
    _, _, region = cloud_target(raw)
    assert region == "5" and isinstance(region, str)


def test_a_null_region_still_produces_a_schema_valid_finding_record(tmp_path):
    # The same null region, exercised through normalise_ocsf: before the
    # coercion this wrote "region": null into the record, which
    # finding-record.schema.json rejects (region is typed "string").
    raw = json.loads(FIXTURE.read_text())
    raw["cloud"]["region"] = None
    record = normalise_ocsf(raw, run_dir=tmp_path, finding_id="FIND-001",
                            collector=C, now=NOW)
    assert record["provenance"]["region"] == ""
    assert validate_doc("finding-record", record) == []
