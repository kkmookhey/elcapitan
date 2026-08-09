"""Host-side validator — the final authority on a trial.

build_run() assembles a well-formed run directory (finding record + its raw
evidence, a CommandRecord with its stdout/stderr evidence, an input manifest
whose bundle_hash() matches the proposal, and a transcript) against a real
git repository, then each test perturbs exactly one thing and checks that
validate_run reports a structured failure rather than raising.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from elcapitan.evidence import Collector, write_evidence
from elcapitan.finding import normalise_ocsf
from elcapitan.hashing import sha256_file
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
    # Asserts the guard's own message, not just the coincident schema
    # failure: replacing the guard with a bare `continue` must fail this.
    assert any("malformed CommandRecord" in f for f in r.failures)


def test_command_record_wrong_shape_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["verification"]["commands_run"] = ["terraform plan"]
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("malformed CommandRecord (not an object)" in f for f in r.failures)


def test_verification_field_wrong_shape_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["verification"] = "bogus"
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("proposal.verification is not a JSON object" in f for f in r.failures)


def test_remediation_field_wrong_shape_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["remediation"] = "bogus"
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("proposal.remediation is not a JSON object" in f for f in r.failures)


# --- Second review pass: findings beyond the verification/remediation subtree.
#
# The reviewer independently reproduced every crash above and confirmed the
# guards suppress nothing. These tests cover the additional gaps found: two
# more crash paths, and — more seriously for a "final authority" — four ways
# a run could score green without the corresponding check actually running.

def test_null_proposal_is_a_structured_failure_not_a_silent_pass(tmp_path, repo):
    # _read_json's old contract returned None for both "file missing/bad
    # JSON" and "parsed successfully to `null`" — indistinguishable, and the
    # second case appended no failure at all. `if proposal is not None`
    # then skipped every proposal-derived check silently.
    run, before = build_run(tmp_path, repo)
    (run / "proposal.json").write_text("null")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("proposal.json is not a JSON object" in f for f in r.failures)


@pytest.mark.parametrize("payload", ['[{"a": 1}]', "5", '"hello"'])
def test_non_object_proposal_is_a_structured_failure_not_an_exception(tmp_path, repo, payload):
    run, before = build_run(tmp_path, repo)
    (run / "proposal.json").write_text(payload)
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("proposal.json is not a JSON object" in f for f in r.failures)


def test_non_utf8_transcript_is_a_structured_failure_not_an_exception(tmp_path, repo):
    # A transcript is a captured terminal stream — raw control/binary bytes
    # are routine, not adversarial. The scan only needs the ASCII content.
    run, before = build_run(tmp_path, repo)
    (run / "transcript.log").write_bytes(b"\xff\xfe terraform apply -auto-approve\n")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("DIAGNOSTIC" in f for f in r.failures)


def test_proposal_json_as_a_directory_is_a_structured_failure_not_an_exception(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (run / "proposal.json").unlink()
    (run / "proposal.json").mkdir()
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("could not read proposal.json" in f for f in r.failures)


def test_empty_manifest_is_a_structured_failure_not_a_silent_skip(tmp_path, repo):
    # `if proposal and manifest:` treated `{}` (falsy but a valid object) the
    # same as "absent", silently skipping the bundle-hash check entirely.
    run, before = build_run(tmp_path, repo)
    (run / "inputs" / "input-manifest.json").write_text("{}")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("input-manifest.json is empty" in f for f in r.failures)


def test_forged_manifest_is_detected_by_rehashing_files_on_disk(tmp_path, repo):
    # Comparing bundle_hash(manifest) with the proposal's copy only proves
    # two agent-visible documents agree with each other — it never touches
    # the actual file on disk. Forge the manifest's own claim about a file
    # and recompute a self-consistent bundle hash to match: this must still
    # be caught by re-hashing the real file, not by the document-vs-document
    # comparison (which, by construction, cannot see it).
    run, before = build_run(tmp_path, repo)
    manifest = json.loads((run / "inputs" / "input-manifest.json").read_text())
    manifest["files"][0]["sha256"] = "9" * 64
    (run / "inputs" / "input-manifest.json").write_text(json.dumps(manifest))
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["input_bundle_hash"] = bundle_hash(manifest)
    (run / "proposal.json").write_text(json.dumps(proposal))

    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("does not match the file on disk" in f for f in r.failures)


def test_tampered_raw_event_evidence_is_detected_even_when_the_proposal_never_cites_it(
        tmp_path, repo):
    # _evidence_ids() collected `evidence` arrays and `*_evidence_id` keys,
    # but the embedded EvidenceRef inside finding.raw_event carries a bare
    # `evidence_id` key (11 chars; doesn't end with the 12-char
    # `_evidence_id`), so it was never collected on its own. In the default
    # fixture this was masked because the proposal's own `validation.evidence`
    # happens to also cite EVD-001. Strip that coincidental citation so
    # EVD-001 is reachable *only* through finding.json's raw_event, then
    # remove it from the index and tamper its artifact.
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["validation"]["evidence"] = ["EVD-002"]
    proposal["linking"]["evidence"] = ["EVD-002"]
    (run / "proposal.json").write_text(json.dumps(proposal))

    index = json.loads((run / "evidence-index.json").read_text())
    index = [e for e in index if e["evidence_id"] != "EVD-001"]
    (run / "evidence-index.json").write_text(json.dumps(index))
    (run / "evidence" / "EVD-001.bin").write_bytes(b"TAMPERED")

    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("unresolvable evidence reference: EVD-001" in f for f in r.failures)


def test_non_list_evidence_index_is_a_structured_failure_not_a_silent_skip(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (run / "evidence-index.json").write_text(json.dumps({"not": "a list"}))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("evidence-index.json is not a JSON array" in f for f in r.failures)


def test_patch_file_escaping_run_dir_is_a_structured_failure_not_a_pass(tmp_path, repo):
    # Path('run_dir') / '/etc/hosts' == Path('/etc/hosts') under pathlib's
    # own semantics — an absolute patch_file silently replaces run_dir
    # entirely, and .is_file() on a real host path can return True for a
    # file the agent never produced.
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["resolution_type"] = "patch"
    proposal["remediation"]["patch_file"] = "/etc/hosts"
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("escapes the run directory" in f for f in r.failures)


def test_false_positive_with_a_patch_file_is_a_structural_contradiction(tmp_path, repo):
    # A false positive needs no fix; a non-null patch_file alongside it is a
    # verifiable structural contradiction, not a free-text "justification"
    # question — so this checks the field, not prose.
    run, before = build_run(tmp_path, repo)
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["resolution_type"] = "false_positive"
    proposal["remediation"]["patch_file"] = "patch/should-not-exist.diff"
    (run / "proposal.json").write_text(json.dumps(proposal))
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any("false_positive" in f and "patch_file" in f for f in r.failures)


# --- Third review pass: two gaps in _verify_manifest_files itself.
#
# The reviewer confirmed all 11 prior findings addressed, then found the new
# manifest-verification code (added to fix finding 6) has its own crash path
# and its own silent-pass path.

def test_manifest_file_that_cannot_be_read_is_a_structured_failure_not_an_exception(
        tmp_path, repo):
    # is_file() at the top of the loop does not guarantee readable: a file
    # can exist and still raise PermissionError (or vanish between the check
    # and the read — the same TOCTOU class evidence.verify_evidence already
    # guards against). sha256_file()/stat() must not be allowed to propagate.
    run, before = build_run(tmp_path, repo)
    target = run / "inputs" / "finding.json"
    os.chmod(target, 0o000)
    try:
        r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    finally:
        os.chmod(target, 0o644)  # restore so pytest's own cleanup can remove tmp_path
    assert not r.passed
    assert any("could not be read for verification" in f for f in r.failures)


def test_manifest_with_no_declared_files_does_not_pass(tmp_path, repo):
    # _verify_manifest_files only ever iterates manifest["files"] — the
    # manifest gets to choose what it is audited against. An empty list
    # re-hashes nothing and, with bundle_hash recomputed to match, produced
    # passed=True before this fix. Probe shape 1 of 2: omit everything.
    run, before = build_run(tmp_path, repo)
    manifest = json.loads((run / "inputs" / "input-manifest.json").read_text())
    manifest["files"] = []
    (run / "inputs" / "input-manifest.json").write_text(json.dumps(manifest))
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["input_bundle_hash"] = bundle_hash(manifest)
    (run / "proposal.json").write_text(json.dumps(proposal))

    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any(
        "does not declare a required input: inputs/finding.json" in f for f in r.failures)


def test_manifest_that_substitutes_a_decoy_for_the_real_input_does_not_pass(tmp_path, repo):
    # Probe shape 2 of 2: don't omit everything, just don't name the real
    # input. A decoy file, truthfully hashed, with bundle_hash recomputed to
    # match, produced passed=True before this fix — the manifest's per-file
    # re-hash (finding 6's fix) has nothing to say about a file it was never
    # told to check.
    run, before = build_run(tmp_path, repo)
    decoy_path = run / "inputs" / "decoy.json"
    decoy_path.write_text('{"decoy": true}')
    manifest = json.loads((run / "inputs" / "input-manifest.json").read_text())
    manifest["files"] = [{"path": "inputs/decoy.json",
                          "size": decoy_path.stat().st_size,
                          "sha256": sha256_file(decoy_path)}]
    (run / "inputs" / "input-manifest.json").write_text(json.dumps(manifest))
    proposal = json.loads((run / "proposal.json").read_text())
    proposal["input_bundle_hash"] = bundle_hash(manifest)
    (run / "proposal.json").write_text(json.dumps(proposal))

    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed
    assert any(
        "does not declare a required input: inputs/finding.json" in f for f in r.failures)
