"""Host-side validator — the final authority on a trial.

build_run() assembles a well-formed run directory (finding record + its raw
evidence, a CommandRecord with its stdout/stderr evidence, an input manifest
whose bundle_hash() matches the proposal, and a transcript) against a real
git repository, then each test perturbs exactly one thing and checks that
validate_run reports a structured failure rather than raising.
"""
import json
import subprocess
from pathlib import Path

import pytest

from elcapitan.evidence import Collector, write_evidence
from elcapitan.finding import normalise_ocsf
from elcapitan.manifest import build_manifest, bundle_hash
from elcapitan.repo import capture_repo_state
from elcapitan.validate import validate_run

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-sample.json"
COLLECTOR = Collector(tool="prowler", version="5.2.1", identity="anna-scanner-reader")
NOW = "2026-08-08T12:00:00Z"


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "canonical-repo"
    r.mkdir()
    git(r, "init", "-q")
    git(r, "config", "user.email", "t@t")
    git(r, "config", "user.name", "t")
    (r / "main.tf").write_text("resource {}\n")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "init")
    return r


def build_run(tmp_path, repo, *, overrides=None, finding_overrides=None,
              mutate_evidence=False, evidence_path=None,
              command_tool="terraform", command_argv=None, command_exit=2,
              transcript="ran: aws s3api get-bucket-acl\n"):
    if command_argv is None:
        command_argv = ["plan", "-detailed-exitcode"]

    run = tmp_path / "runs" / "R1"
    (run / "inputs").mkdir(parents=True)

    raw = json.loads(FIXTURE.read_text())
    finding = normalise_ocsf(raw, run_dir=run, finding_id="FIND-001",
                             collector=COLLECTOR, now=NOW)
    finding.update(finding_overrides or {})
    (run / "inputs" / "finding.json").write_text(json.dumps(finding))

    stdout_ref = write_evidence(run, "EVD-002", "command_stdout",
                                b"Refreshing state...\n", COLLECTOR,
                                command_id="CMD-001", now=NOW)
    stderr_ref = write_evidence(run, "EVD-003", "command_stderr", b"",
                                COLLECTOR, command_id="CMD-001", now=NOW)

    if mutate_evidence:
        (run / stdout_ref.artifact_path).write_bytes(b"tampered")

    command = {"command_id": "CMD-001", "tool": command_tool, "argv": command_argv,
              "exit_code": command_exit, "started_at": NOW, "completed_at": NOW,
              "stdout_evidence_id": "EVD-002", "stderr_evidence_id": "EVD-003"}

    before = capture_repo_state(repo)

    manifest = build_manifest(run, files=["inputs/finding.json"],
                              repository_commit=before.commit,
                              runtime_image_id="sha256:" + "d" * 64,
                              runtime_lock_sha256="e" * 64,
                              profile_config_sha256="f" * 64,
                              environment_adapter_sha256="0" * 64)
    (run / "inputs" / "input-manifest.json").write_text(json.dumps(manifest))

    proposal = {
        "proposal_id": "PROP-001", "schema_version": 1, "created_at": NOW,
        "finding_id": "FIND-001", "input_bundle_hash": bundle_hash(manifest),
        "validation": {"confirmed": True, "evidence": ["EVD-001"], "confidence": 0.9},
        "linking": {"iac_managed": False, "system_detected": "aws-cdk",
                    "method": "grep", "confidence": 0.4,
                    "evidence": ["EVD-001"], "files": []},
        "root_cause": "runtime creation", "resolution_type": "runtime_change",
        "remediation": {"objective": "o", "approach": "a", "patch_file": None},
        "verification": {"commands_run": [command], "output": [], "passed": True},
        "production_impact": {"expected": "none", "dependencies": [],
                              "unknowns": [], "risk": "low"},
        "context": {"severity": "High", "asset_id": "arn", "owner": "",
                    "exploitability": ""},
        "status": "READY_FOR_REVIEW",
    }
    proposal.update(overrides or {})
    (run / "proposal.json").write_text(json.dumps(proposal))

    index = [stdout_ref.to_dict(), stderr_ref.to_dict(), dict(finding["raw_event"])]
    if evidence_path is not None:
        index[0]["artifact_path"] = evidence_path
    (run / "evidence-index.json").write_text(json.dumps(index))

    (run / "transcript.log").write_text(transcript)

    return run, before


def test_well_formed_run_passes(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    assert validate_run(run, canonical_repo=repo, repo_state_before=before).passed


def test_schema_violation_fails(tmp_path, repo):
    run, before = build_run(tmp_path, repo, overrides={"resolution_type": "nope"})
    assert not validate_run(run, canonical_repo=repo, repo_state_before=before).passed


def test_tampered_evidence_fails(tmp_path, repo):
    run, before = build_run(tmp_path, repo, mutate_evidence=True)
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("hash mismatch" in f for f in r.failures)


def test_escaping_evidence_path_is_a_structured_failure_not_an_exception(tmp_path, repo):
    run, before = build_run(tmp_path, repo, evidence_path="../escape")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed and any("escape" in f or "containment" in f for f in r.failures)


def test_malformed_json_is_a_structured_failure_not_an_exception(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (run / "proposal.json").write_text("{not json")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed and any("proposal.json" in f for f in r.failures)


def test_missing_file_is_a_structured_failure_not_an_exception(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (run / "evidence-index.json").unlink()
    assert not validate_run(run, canonical_repo=repo, repo_state_before=before).passed


def test_finding_record_is_validated_too(tmp_path, repo):
    run, before = build_run(tmp_path, repo, finding_overrides={"ocsf": {}})
    assert not validate_run(run, canonical_repo=repo, repo_state_before=before).passed


def test_bundle_hash_mismatch_fails(tmp_path, repo):
    run, before = build_run(tmp_path, repo, overrides={"input_bundle_hash": "0" * 64})
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("input_bundle_hash" in f for f in r.failures)


def test_repository_modification_is_detected(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (repo / "main.tf").write_text("mutated\n")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("canonical repository" in f for f in r.failures)


def test_terraform_plan_exit_2_is_not_a_failure(tmp_path, repo):
    run, before = build_run(tmp_path, repo)  # fixture CommandRecord uses exit_code 2
    assert validate_run(run, canonical_repo=repo, repo_state_before=before).passed


def test_terraform_plan_exit_1_is_a_failure(tmp_path, repo):
    run, before = build_run(tmp_path, repo, command_exit=1)
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("terraform" in f for f in r.failures)


def test_ground_truth_inside_run_dir_fails(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (run / "ground-truth.json").write_text("{}")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("ground truth" in f.lower() for f in r.failures)


def test_mutation_in_transcript_is_reported_as_a_diagnostic(tmp_path, repo):
    run, before = build_run(tmp_path, repo, transcript="terraform apply -auto-approve\n")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("DIAGNOSTIC" in f for f in r.failures)


# --- Two changes since the brief was written -------------------------------

def test_ambiguous_exit_code_is_surfaced_not_scored_as_a_pass(tmp_path, repo):
    # cdk diff --fail exit 1 cannot distinguish "differences present" from a
    # tool error. Scoring that green would be worse than a normal failure —
    # it would look like a passing verification that never actually ran.
    run, before = build_run(tmp_path, repo, command_tool="cdk",
                            command_argv=["diff", "--fail"], command_exit=1)
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("AMBIGUOUS" in f for f in r.failures)


def test_unambiguous_ok_verdict_does_not_raise_ambiguous(tmp_path, repo):
    # trivy --exit-code 0 is an unambiguous pass; must not be flagged.
    run, before = build_run(tmp_path, repo, command_tool="trivy",
                            command_argv=["image", "--exit-code", "1", "x"],
                            command_exit=0)
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not any("AMBIGUOUS" in f for f in r.failures)


def test_canonical_repo_that_cannot_be_inspected_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    # repo.py's capture_repo_state raises ValueError for a missing path or a
    # non-repository. The validator must convert that into a failure string,
    # not let it propagate — a crashed validator looks like an un-run trial.
    run, before = build_run(tmp_path, repo)
    missing_repo = tmp_path / "does-not-exist"
    r = validate_run(run, canonical_repo=missing_repo, repo_state_before=before)
    assert not r.passed
    assert any("could not be inspected" in f for f in r.failures)


def test_non_repository_canonical_path_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    not_a_repo = tmp_path / "just-a-dir"
    not_a_repo.mkdir()
    r = validate_run(run, canonical_repo=not_a_repo, repo_state_before=before)
    assert not r.passed
    assert any("could not be inspected" in f for f in r.failures)


# --- Malformed proposal substructure must not crash the interpret_exit pass.
#
# validate_doc() already reports a schema failure for each of these; the bug
# these tests guard is that the *same* malformed data was then handed
# unguarded to interpret_exit()/dict indexing on a second pass, crashing the
# validator instead of only adding the schema failure. A trial that kills the
# validator is indistinguishable from one that never ran.

def test_command_record_missing_exit_code_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    del proposal["verification"]["commands_run"][0]["exit_code"]
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed


def test_command_record_wrong_shape_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["verification"]["commands_run"] = ["terraform plan"]
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed


def test_verification_field_wrong_shape_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["verification"] = "bogus"
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed


def test_remediation_field_wrong_shape_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["remediation"] = "bogus"
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
