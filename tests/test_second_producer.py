"""The second OCSF producer — a spec-mandated gate.

The spec (§3.3) commits to "one OCSF finding, not the Prowler JSON". Until a
finding from a second producer is normalised, that is an untested claim: an
intake written against one scanner's dialect and called format-agnostic is
exactly the shape of thing this project keeps catching.

**GATE STATUS: NOT SATISFIED.** These tests use a Security Hub OCSF finding
built to the shape Security Hub's Security Lake export emits, NOT a live
export — account 331145994818 is not subscribed to Security Hub
(`InvalidAccessException`, measured 2026-08-24), and subscribing is a paid,
ongoing change to someone else's AWS account.

So what these tests prove is narrower than the gate asks, and the difference
matters: they prove the intake does not *structurally* depend on Prowler, and
they pin the dialect differences that were anticipated. They do not prove the
intake survives a real Security Hub export, because no real Security Hub
export has been through it. Task 6 stays open.
"""
import json
from pathlib import Path

import pytest

from elcapitan.evidence import Collector
from elcapitan.finding import cloud_target, normalise_ocsf
from elcapitan.records import validate_doc

NOW = "2026-08-24T23:00:00Z"
COLLECTOR = Collector(tool="securityhub", version="2026-08-24", identity="sara-sales")


def security_hub_finding() -> dict:
    """The shape Security Hub emits through Security Lake's OCSF export.

    Three deliberate differences from Prowler's dialect, each one a thing the
    intake could have been quietly depending on:

      severity_id (int) and no `severity` string
      `time` as epoch millis, no `time_dt`
      no `unmapped` block at all
    """
    return {
        "class_uid": 2001,
        "class_name": "Compliance Finding",
        "activity_id": 1,
        "category_uid": 2,
        "severity_id": 4,
        "time": 1787616000000,
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "Security Hub", "vendor_name": "AWS",
                        "version": "2018-10-26"},
        },
        "cloud": {"provider": "AWS", "region": "ap-south-1",
                  "account": {"uid": "331145994818", "type": "AWS Account"}},
        "resources": [{
            "uid": "arn:aws:s3:::anna-assets",
            "type": "AwsS3Bucket",
            "cloud_partition": "aws",
            "region": "ap-south-1",
        }],
        "finding_info": {
            "uid": "arn:aws:securityhub:ap-south-1:331145994818:subscription/"
                   "aws-foundational-security-best-practices/v/1.0.0/S3.8/finding/abc",
            "title": "S3 Block Public Access setting should be enabled at the bucket level",
        },
        "compliance": {"status": "FAILED", "control": "S3.8"},
    }


@pytest.fixture
def run_dir(tmp_path):
    d = tmp_path / "runs" / "r"
    d.mkdir(parents=True)
    return d


def test_a_security_hub_finding_normalises(run_dir):
    record = normalise_ocsf(security_hub_finding(), run_dir=run_dir,
                            finding_id="FIND-900", collector=COLLECTOR, now=NOW)
    assert validate_doc("finding-record", record) == [], \
        "the intake structurally depends on Prowler's dialect"


def test_the_resource_target_is_found_in_the_other_dialect():
    provider, uid, region = cloud_target(security_hub_finding())
    assert uid == "arn:aws:s3:::anna-assets"
    assert region == "ap-south-1"


def test_the_provider_is_normalised_to_lower_case():
    # Prowler writes "aws"; Security Hub writes "AWS". Downstream this string
    # keys SCANNER_ENV_MAPS and the cloud-capture dispatch, so an unnormalised
    # "AWS" would raise "no scanner credential map for provider 'AWS'" — a
    # confusing way to say "wrong case".
    provider, _, _ = cloud_target(security_hub_finding())
    assert provider == "aws"


def test_an_integer_severity_is_carried_not_dropped(run_dir):
    # Security Hub sends severity_id (int) and no severity string. Dropping it
    # silently would make every Security Hub finding look severity-less, and
    # severity is in the challenger's context.
    record = normalise_ocsf(security_hub_finding(), run_dir=run_dir,
                            finding_id="FIND-900", collector=COLLECTOR, now=NOW)
    assert record["severity"], "severity was dropped for the second producer"


def test_an_epoch_timestamp_becomes_an_observed_at(run_dir):
    record = normalise_ocsf(security_hub_finding(), run_dir=run_dir,
                            finding_id="FIND-900", collector=COLLECTOR, now=NOW)
    assert record["provenance"]["observed_at"], "observed_at was dropped"


def test_a_missing_unmapped_block_is_not_a_crash(run_dir):
    finding = security_hub_finding()
    assert "unmapped" not in finding
    record = normalise_ocsf(finding, run_dir=run_dir, finding_id="FIND-900",
                            collector=COLLECTOR, now=NOW)
    assert record["vendor_extensions"] == {}


def test_prowler_findings_still_normalise_unchanged(run_dir):
    # The regression that would matter most: widening the intake for a second
    # producer must not change what the first one produces, or every trial run
    # so far is bound to a manifest the code no longer reproduces.
    raw = json.loads(Path("tests/fixtures/prowler-ocsf-azure-sample.json").read_text())
    record = normalise_ocsf(raw, run_dir=run_dir, finding_id="FIND-002",
                            collector=COLLECTOR, now=NOW)
    assert validate_doc("finding-record", record) == []
    assert record["provenance"]["provider"] == "azure"
    assert record["resource"]["uid"].startswith("/subscriptions/")
