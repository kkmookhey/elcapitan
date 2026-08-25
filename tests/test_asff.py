"""ASFF -> OCSF, against a REAL AWS Security Hub finding.

## What the gate asked for, and what is actually possible

The plan's Task 6 says "take one finding from AWS Security Hub's OCSF export".
**Security Hub does not have an OCSF export.** Its native format is ASFF
(`SchemaVersion: 2018-10-08`), and the OCSF form comes from Amazon Security
Lake — a separate, substantially more expensive service.

So the conversion here is OURS, not AWS's, and that is stated rather than
implied. What this buys is still real and is what the gate was protecting: a
**genuine second producer's genuine output**, captured live from account
331145994818 on 2026-08-25, driven through the same intake Prowler uses.

`tests/fixtures/securityhub-asff-real.json` is that finding, verbatim. Security
Hub and AWS Config were enabled to obtain it and **torn down immediately
afterwards** — the account is not left subscribed.

## Why a real finding rather than a shaped one

The first pass at this gate used a finding built to the shape Security Lake
emits, and it found three real dialect gaps. It could not have found the
fourth: Security Hub identifies a resource as `AWS::::Account:331145994818`,
which is not an ARN and does not parse as one. A shaped fixture would have
carried an ARN, because an ARN is what one writes when imagining a resource
id.
"""
import json
from pathlib import Path

import pytest

from elcapitan.evidence import Collector
from elcapitan.finding import cloud_target, normalise_ocsf
from elcapitan.records import validate_doc

NOW = "2026-08-25T04:00:00Z"
COLLECTOR = Collector(tool="securityhub", version="2018-10-08", identity="sara-sales")
REAL_ASFF = Path(__file__).parent / "fixtures" / "securityhub-asff-real.json"


def real_finding() -> dict:
    return json.loads(REAL_ASFF.read_text())


@pytest.fixture
def run_dir(tmp_path):
    d = tmp_path / "runs" / "r"
    d.mkdir(parents=True)
    return d


def test_the_fixture_is_the_real_thing():
    f = real_finding()
    assert f["SchemaVersion"] == "2018-10-08", "this is ASFF, not OCSF"
    assert f["AwsAccountId"] == "331145994818"
    assert f["GeneratorId"] == "security-control/Config.1"


def test_asff_converts_to_something_normalise_ocsf_accepts(run_dir):
    from elcapitan.asff import asff_to_ocsf

    record = normalise_ocsf(asff_to_ocsf(real_finding()), run_dir=run_dir,
                            finding_id="FIND-900", collector=COLLECTOR, now=NOW)
    assert validate_doc("finding-record", record) == []


def test_the_provider_and_region_survive():
    from elcapitan.asff import asff_to_ocsf

    provider, uid, region = cloud_target(asff_to_ocsf(real_finding()))
    assert provider == "aws"
    assert region == "ap-south-1"


def test_an_account_scoped_resource_id_is_carried_verbatim():
    # THE gap a shaped fixture could not have found. Security Hub reports this
    # control against `AWS::::Account:331145994818` — not an ARN, and not
    # parseable as one. Anything downstream that assumed "resource uid implies
    # ARN" breaks here, and it breaks on a real finding from a real account.
    from elcapitan.asff import asff_to_ocsf

    _, uid, _ = cloud_target(asff_to_ocsf(real_finding()))
    assert uid == "AWS::::Account:331145994818"
    assert not uid.startswith("arn:"), "the real one is not an ARN"


def test_the_cloud_capture_refuses_that_uid_rather_than_guessing():
    # And the consequence, made explicit: cloud.py cannot re-query an
    # account-scoped finding, so a trial over one must fail loudly at
    # pre-flight rather than produce an unverifiable run.
    from elcapitan.asff import asff_to_ocsf
    from elcapitan.cloud import capture_cloud_state

    _, uid, _ = cloud_target(asff_to_ocsf(real_finding()))
    with pytest.raises(ValueError):
        capture_cloud_state(uid, provider="aws", region="ap-south-1",
                            env={"PATH": "/usr/bin", "HOME": "/tmp",
                                 "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y",
                                 "AWS_SESSION_TOKEN": "z"})


def test_severity_comes_across(run_dir):
    from elcapitan.asff import asff_to_ocsf

    record = normalise_ocsf(asff_to_ocsf(real_finding()), run_dir=run_dir,
                            finding_id="FIND-900", collector=COLLECTOR, now=NOW)
    assert record["severity"] == "Critical"


def test_the_control_id_survives_as_the_title_or_uid(run_dir):
    from elcapitan.asff import asff_to_ocsf

    record = normalise_ocsf(asff_to_ocsf(real_finding()), run_dir=run_dir,
                            finding_id="FIND-900", collector=COLLECTOR, now=NOW)
    blob = json.dumps(record)
    assert "Config.1" in blob, "the control id is the only thing identifying the check"


def test_the_producer_is_identified_as_security_hub(run_dir):
    # Provenance has to say WHICH scanner, or a result cannot be attributed.
    from elcapitan.asff import asff_to_ocsf

    record = normalise_ocsf(asff_to_ocsf(real_finding()), run_dir=run_dir,
                            finding_id="FIND-900", collector=COLLECTOR, now=NOW)
    assert "Security Hub" in record["provenance"]["product"]


def test_the_conversion_is_marked_as_ours_not_awss():
    # Honesty in the artifact itself: someone reading this record later must
    # be able to tell the OCSF shape was produced by this repo and not by AWS,
    # because the mapping is ours and could be wrong.
    from elcapitan.asff import asff_to_ocsf

    converted = asff_to_ocsf(real_finding())
    assert converted["unmapped"]["converted_by"] == "elcapitan.asff"
    assert converted["unmapped"]["source_format"] == "ASFF"


def test_a_non_asff_document_is_refused():
    from elcapitan.asff import asff_to_ocsf

    with pytest.raises(ValueError) as exc:
        asff_to_ocsf({"class_uid": 2001, "cloud": {"provider": "aws"}})
    assert "ASFF" in str(exc.value)
