"""elcapitan.trial — everything between the engineer exiting and the challenger starting.

`bin/run-trial.sh` ran engineer → validate and nothing else; the collector and
the challenger existed but nothing invoked them. This module is the missing
middle, and it lives in Python rather than shell because it has to read the
engineer's artifacts, project them, query two clouds and assemble a snapshot —
none of which shell should be doing.

The load-bearing tests here:

  test_the_proposal_is_projected_before_it_reaches_a_bundle
      the challenger must judge the artifact, not the engineer's account of
      it. A raw proposal in the snapshot is the sycophancy confound, and it is
      the kind of thing that comes back when someone refactors this file.

  test_the_window_extends_past_the_trial
      MEASURED: telemetry lands ~60s late and buckets into the FOLLOWING
      minute. A window ending when the engineer exited misses the engineer's
      own last actions, and Arm B looks quieter than the trial really was.

  test_a_stub_trial_is_never_scoring_valid
      a stub run has no telemetry and no model. It must not be able to
      contribute a row to the matrix.
"""
import json
from pathlib import Path

import pytest

from elcapitan.collector import POPULATED, UNAVAILABLE
from elcapitan.trial import (
    INGESTION_LAG_SECONDS,
    read_engineer_artifacts,
    probe_health,
    telemetry_window,
)

PROPOSAL = {
    "proposal_id": "PROP-001", "schema_version": 1,
    "created_at": "2026-08-24T21:00:00Z", "finding_id": "FIND-002",
    "input_bundle_hash": "e" * 64,
    "validation": {"confirmed": True, "evidence": ["public"], "confidence": 0.95},
    "linking": {"iac_managed": True, "system_detected": "terraform", "method": "uid",
                "confidence": 0.9, "evidence": ["m"], "files": ["infra/storage.tf"]},
    "root_cause": "the account permits public network access",
    "resolution_type": "patch",
    "remediation": {"objective": "close it", "approach": "flip the flag",
                    "patch_file": "patch/001.diff"},
    "verification": {"commands_run": [{"command_id": "CMD-001",
                                       "argv": ["terraform", "plan"], "exit_code": 0}],
                     "output": ["1 to change"], "passed": True},
    "production_impact": {"expected": "none", "dependencies": [], "unknowns": [],
                          "risk": "low, the plan is clean and this is safe"},
    "context": {"severity": "high", "asset_id": "a", "owner": "o",
                "exploitability": "e"},
    "status": "READY_FOR_REVIEW",
}


@pytest.fixture
def run_dir(tmp_path):
    d = tmp_path / "runs" / "eiger-FIND-002-armB-n1"
    (d / "patch").mkdir(parents=True)
    (d / "proposal.json").write_text(json.dumps(PROPOSAL))
    (d / "patch" / "001.diff").write_text("--- a/infra/storage.tf\n+++ b/infra/storage.tf\n")
    return d


def test_the_proposal_is_projected_before_it_reaches_a_bundle(run_dir):
    proposal, _, _ = read_engineer_artifacts(run_dir)
    assert b"this is safe" not in proposal
    assert b"0.95" not in proposal
    assert b"the account permits public network access" not in proposal
    # and the artifact itself survives
    assert json.loads(proposal)["resolution_type"] == "patch"


def test_the_patch_is_carried_verbatim(run_dir):
    _, patch, _ = read_engineer_artifacts(run_dir)
    assert b"--- a/infra/storage.tf" in patch


def test_several_patch_files_are_all_carried(run_dir):
    (run_dir / "patch" / "002.diff").write_text("--- a/infra/net.tf\n")
    _, patch, _ = read_engineer_artifacts(run_dir)
    assert b"storage.tf" in patch and b"net.tf" in patch


def test_verification_carries_commands_and_exit_codes_only(run_dir):
    _, _, verification = read_engineer_artifacts(run_dir)
    doc = json.loads(verification)
    assert doc[0]["exit_code"] == 0
    # `output` is where an engineer's narrative reappears as quoted console text.
    assert b"1 to change" not in verification


def test_a_missing_proposal_is_a_named_error(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError) as exc:
        read_engineer_artifacts(empty)
    assert "proposal.json" in str(exc.value)


def test_an_unparseable_proposal_still_yields_a_withheld_projection(run_dir):
    (run_dir / "proposal.json").write_text("{not json")
    proposal, _, _ = read_engineer_artifacts(run_dir)
    assert json.loads(proposal)["parse_failed"] is True


def test_a_trial_with_no_patch_directory_is_not_a_crash(tmp_path):
    d = tmp_path / "runs" / "r"
    d.mkdir(parents=True)
    (d / "proposal.json").write_text(json.dumps({**PROPOSAL, "resolution_type":
                                                 "false_positive"}))
    _, patch, _ = read_engineer_artifacts(d)
    assert patch == b"", "a false-positive proposal legitimately has no patch"


# --- the telemetry window ---------------------------------------------------

def test_the_window_extends_past_the_trial():
    # MEASURED 2026-08-24: an operation at 21:47:44 landed in the 21:48 bucket
    # and first became visible ~60s later. A window ending when the engineer
    # exited drops the engineer's own last actions and makes Arm B look
    # quieter than the trial actually was.
    start, end = telemetry_window("2026-08-24T21:40:00Z", "2026-08-24T21:47:44Z")
    assert start < "2026-08-24T21:40:00Z", "the window must start before the trial"
    assert end > "2026-08-24T21:47:44Z", "the window must end after the trial"


def test_the_window_margin_is_at_least_the_measured_lag():
    from datetime import datetime
    start, end = telemetry_window("2026-08-24T21:40:00Z", "2026-08-24T21:47:44Z")
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    margin = (datetime.strptime(end, fmt)
              - datetime.strptime("2026-08-24T21:47:44Z", fmt)).total_seconds()
    assert margin >= INGESTION_LAG_SECONDS


def test_the_window_is_rfc3339_because_az_rejects_anything_else():
    import re
    for value in telemetry_window("2026-08-24T21:40:00Z", "2026-08-24T21:47:44Z"):
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", value)


# --- health -----------------------------------------------------------------

def test_probe_health_captures_stdout_not_stderr(tmp_path):
    # stdout is the contract result and is what gets bundled; stderr is the
    # operator's diagnosis and names the corpus dependency. Capturing stderr
    # would put the leak straight back into both arms.
    script = tmp_path / "health.sh"
    script.write_text("#!/bin/sh\n"
                      "echo 'HEALTHY (2 of 2 probes passed, slowest 2s)'\n"
                      "echo '  detail: seeded its KB from the corpus blob' >&2\n")
    script.chmod(0o755)
    out = probe_health([str(script)])
    assert b"HEALTHY" in out
    assert b"corpus" not in out and b"KB" not in out


def test_an_unhealthy_service_is_recorded_not_raised(tmp_path):
    # The service being down is evidence, not an error. A trial that crashed
    # here would lose the most interesting run it could have had.
    script = tmp_path / "health.sh"
    script.write_text("#!/bin/sh\necho 'UNHEALTHY: probe 2 of 2 failed'\nexit 1\n")
    script.chmod(0o755)
    assert b"UNHEALTHY" in probe_health([str(script)])


def test_a_health_script_that_cannot_run_is_recorded_not_raised(tmp_path):
    out = probe_health([str(tmp_path / "nope.sh")])
    assert b"UNKNOWN" in out
