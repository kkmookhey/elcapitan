"""bin/run-trial.sh — the deterministic orchestrator, exercised end to end.

Every test here runs the real script as a subprocess against a real git
repository, with tests/stub_engineer.py standing in for the model. Nothing is
mocked: the manifest is really built, the anchors are really captured, and
bin/validate-trial-artifacts.sh really runs.

The load-bearing test is
test_coherent_forgery_is_caught_only_by_the_out_of_band_anchor. It rewrites
inputs/finding.json, that file's entry in inputs/input-manifest.json, and
proposal.json's input_bundle_hash together, so every consistency check the
validator can make from inside the run directory still holds — and then
asserts the run is still rejected. That can only pass while the anchor comes
from outside run_dir.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from elcapitan.hashing import sha256_file
from elcapitan.manifest import bundle_hash

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "run-trial.sh"
VALIDATOR = ROOT / "bin" / "validate-trial-artifacts.sh"
FIXTURE = ROOT / "tests" / "fixtures" / "prowler-ocsf-sample.json"

TRIAL = ("anna", "FIND-001", "A", "1")
RUN_ID = "anna-FIND-001-armA-n1"


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def make_workspace(workspace: Path) -> dict:
    """A repo WITH a commit, a real finding file, and an environment adapter.

    ELCAP_ENV_ADAPTER is set explicitly: environments/anna/env.yaml is Task
    13's deliverable and does not exist yet, and a test must not write into
    the checkout to make the harness runnable.
    """
    repo = workspace / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@t")
    git(repo, "config", "user.name", "t")
    (repo / "main.tf").write_text("resource {}\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")

    findings = workspace / "findings"
    findings.mkdir()
    shutil.copyfile(FIXTURE, findings / "FIND-001.json")

    adapter_dir = workspace / "adapter"
    adapter_dir.mkdir()
    adapter = adapter_dir / "env.yaml"
    adapter.write_text("name: test\n")

    gt = workspace / "gt-outside"
    gt.mkdir()

    return {"ELCAP_WORKSPACE": str(workspace), "ELCAP_CANONICAL_REPO": str(repo),
            "ELCAP_GROUND_TRUTH_DIR": str(gt), "ELCAP_ENV_ADAPTER": str(adapter),
            "ELCAP_STUB": "1"}


def run_trial(env: dict, args=TRIAL) -> subprocess.CompletedProcess:
    return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True,
                          env={**os.environ, **env})


def run_validator(run_dir, canonical_repo, repo_state_before,
                  anchor=None) -> subprocess.CompletedProcess:
    argv = [str(VALIDATOR), str(run_dir), str(canonical_repo), str(repo_state_before)]
    if anchor is not None:
        argv.append(anchor)
    return subprocess.run(argv, capture_output=True, text=True)


@pytest.fixture(scope="module")
def completed(tmp_path_factory):
    """One successful stub trial, shared by the read-only assertions below.

    Module-scoped only for the tests that do not mutate it; anything that
    perturbs the run directory builds its own workspace.
    """
    workspace = tmp_path_factory.mktemp("workspace")
    env = make_workspace(workspace)
    result = run_trial(env)
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    return workspace, env, result


# --- basic contract --------------------------------------------------------

def test_script_is_executable():
    assert os.access(SCRIPT, os.X_OK)


def test_refuses_without_required_env():
    result = subprocess.run([str(SCRIPT), *TRIAL], capture_output=True, text=True,
                            env={"PATH": os.environ["PATH"]})
    assert result.returncode != 0
    assert "ELCAP_" in result.stderr


def test_stub_run_produces_a_validating_trial(completed):
    workspace, _, result = completed
    run = workspace / "runs" / RUN_ID
    for name in ("proposal.json", "transcript.log", "evidence-index.json",
                 "prompt.md", "inputs/input-manifest.json", "inputs/finding.json",
                 "evidence/EVD-001.bin"):
        assert (run / name).is_file(), f"{name} missing"
    # The harness runs the validator itself and `set -e` would have stopped it,
    # so a zero exit is also the assertion that it passed FOUR arguments: with
    # three, validate_run reports the run as unanchored and fails it.
    assert "complete" in result.stdout


def test_rerunning_the_same_trial_id_is_refused(tmp_path):
    env = make_workspace(tmp_path)
    assert run_trial(env).returncode == 0
    again = run_trial(env)
    assert again.returncode != 0
    assert "immutable" in again.stderr
    # Both leftovers named: an operator retrying a failed trial has to remove
    # the run directory AND the anchors directory, and "immutable" alone does
    # not say that.
    assert str(tmp_path / "runs" / RUN_ID) in again.stderr
    assert str(tmp_path / "anchors" / RUN_ID) in again.stderr


def test_missing_model_api_key_is_refused_before_the_run_id_is_burned(tmp_path):
    """Non-stub mode needs ELCAP_MODEL_API_KEY. Checked before anything is
    created: dying inside agent-run.sh instead would leave runs/<id> and
    anchors/<id> behind, and trials are immutable, so the id would be spent."""
    env = make_workspace(tmp_path)
    env.pop("ELCAP_STUB")
    result = subprocess.run(
        [str(SCRIPT), *TRIAL], capture_output=True, text=True,
        env={k: v for k, v in {**os.environ, **env}.items()
             if k != "ELCAP_MODEL_API_KEY"})
    assert result.returncode != 0
    assert "ELCAP_MODEL_API_KEY" in result.stderr
    assert not (tmp_path / "runs" / RUN_ID).exists()
    assert not (tmp_path / "anchors" / RUN_ID).exists()


# --- ground truth containment ---------------------------------------------

def test_ground_truth_inside_runs_tree_is_refused(tmp_path):
    env = make_workspace(tmp_path)
    inside = tmp_path / "runs" / "gt"
    inside.mkdir(parents=True)
    env["ELCAP_GROUND_TRUTH_DIR"] = str(inside)
    result = run_trial(env)
    assert result.returncode != 0
    assert "ground truth" in result.stderr.lower()


def test_ground_truth_inside_the_canonical_repo_is_refused(tmp_path):
    """The repository is mounted into the agent container read-only. Ground
    truth placed inside it is just as readable as ground truth in the runs
    tree — the harness refuses both."""
    env = make_workspace(tmp_path)
    inside = Path(env["ELCAP_CANONICAL_REPO"]) / "gt"
    inside.mkdir()
    env["ELCAP_GROUND_TRUTH_DIR"] = str(inside)
    result = run_trial(env)
    assert result.returncode != 0
    assert "ground truth" in result.stderr.lower()


# --- the out-of-band anchor ------------------------------------------------

def test_anchors_are_held_outside_the_run_directory(completed):
    workspace, _, _ = completed
    anchors = workspace / "anchors" / RUN_ID
    run = workspace / "runs" / RUN_ID

    assert (anchors / "bundle.sha256").is_file()
    assert (anchors / "repo-state-before.json").is_file()
    # Sibling of runs/, never inside it: container.py refuses any mount that is
    # an ancestor of run_dir, so nothing under anchors/ can reach a container.
    assert not str(anchors.resolve()).startswith(str((workspace / "runs").resolve()) + os.sep)

    manifest = json.loads((run / "inputs" / "input-manifest.json").read_text())
    assert (anchors / "bundle.sha256").read_text().strip() == bundle_hash(manifest)


def test_no_agent_writable_copy_of_the_anchor_is_left_in_the_run_dir(completed):
    """The plan's draft wrote inputs/bundle.sha256 and had the engineer read
    it back. It is not written at all: it carries nothing the agent cannot
    recompute from inputs/input-manifest.json, and its only real effect would
    be to offer a future caller an agent-writable value to pass to the
    validator as the anchor."""
    workspace, _, _ = completed
    run = workspace / "runs" / RUN_ID
    assert not (run / "inputs" / "bundle.sha256").exists()
    assert not (run / "repo-state-before.json").exists()


def test_validator_passes_with_the_anchor_and_fails_loudly_without_it(completed):
    workspace, env, _ = completed
    run = workspace / "runs" / RUN_ID
    anchors = workspace / "anchors" / RUN_ID
    state = anchors / "repo-state-before.json"
    anchor = (anchors / "bundle.sha256").read_text().strip()

    with_anchor = run_validator(run, env["ELCAP_CANONICAL_REPO"], state, anchor)
    assert with_anchor.returncode == 0, with_anchor.stderr
    assert "PASS" in with_anchor.stdout

    without = run_validator(run, env["ELCAP_CANONICAL_REPO"], state)
    assert without.returncode != 0
    assert "unanchored" in without.stderr


def test_agent_side_forgery_during_the_trial_is_rejected_by_the_harness(tmp_path):
    """The same forgery, but committed from inside the agent's own turn — the
    moment it would really happen — and judged by run-trial.sh's own validator
    call rather than by a hand-built one.

    This is the test that pins the *harness's* anchor handling, not just
    validate_run's. A run-trial.sh that computed the anchor after the agent
    step, or read it back out of the run directory, would let this trial pass.
    """
    env = {**make_workspace(tmp_path), "ELCAP_STUB_FORGE": "1"}
    result = run_trial(env)
    assert result.returncode != 0, result.stdout
    assert "pre-trial anchor" in result.stderr
    assert "FAILED" in result.stdout
    for internal_check in ("does not match the file on disk",
                           "input_bundle_hash does not match",
                           "hash mismatch"):
        assert internal_check not in result.stderr, result.stderr


def test_coherent_forgery_is_caught_only_by_the_out_of_band_anchor(tmp_path):
    """Rewrite the input, its manifest entry, and the proposal's copy of the
    bundle hash — all three agent-writable — so that every check the validator
    can make from inside the run directory still passes. Only the pre-trial
    anchor, captured before the agent ran and held outside run_dir, is left to
    catch it."""
    env = make_workspace(tmp_path)
    assert run_trial(env).returncode == 0
    run = tmp_path / "runs" / RUN_ID
    anchors = tmp_path / "anchors" / RUN_ID
    finding_path = run / "inputs" / "finding.json"

    finding = json.loads(finding_path.read_text())
    finding["severity"] = "Low"          # still valid against finding-record
    finding_path.write_text(json.dumps(finding, indent=2))

    manifest_path = run / "inputs" / "input-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "inputs/finding.json":
            entry["sha256"] = sha256_file(finding_path)
            entry["size"] = finding_path.stat().st_size
    manifest_path.write_text(json.dumps(manifest, indent=2))

    proposal_path = run / "proposal.json"
    proposal = json.loads(proposal_path.read_text())
    proposal["input_bundle_hash"] = bundle_hash(manifest)
    proposal_path.write_text(json.dumps(proposal, indent=2))

    result = run_validator(run, env["ELCAP_CANONICAL_REPO"],
                           anchors / "repo-state-before.json",
                           (anchors / "bundle.sha256").read_text().strip())
    assert result.returncode != 0
    assert "pre-trial anchor" in result.stderr

    # ...and it really is only the anchor. If any of these fired, the forgery
    # was incoherent and this test would be proving something weaker than it
    # claims — it would pass even with the anchor sourced from inside run_dir.
    for internal_check in ("does not match the file on disk",
                           "input_bundle_hash does not match",
                           "hash mismatch"):
        assert internal_check not in result.stderr, result.stderr


# --- Hermes home lifecycle -------------------------------------------------

def test_every_trial_gets_a_fresh_hermes_home_and_it_is_removed_afterwards(tmp_path):
    """Trial independence rests entirely on this: Hermes has no hard gate on
    skill self-authoring (skills.creation_nudge_interval: 0 only suppresses
    the nudge), so a reused home would carry an agent-written skill into the
    next trial. stub_engineer.py exits 4 if the home is not seeded and live at
    the moment the agent step runs, so a zero exit above also pins the
    sequencing that lets run_agent copy state.db out before cleanup."""
    env = make_workspace(tmp_path)
    homes = []
    for n in ("1", "2"):
        assert run_trial(env, ("anna", "FIND-001", "A", n)).returncode == 0
        meta = json.loads(
            (tmp_path / "anchors" / f"anna-FIND-001-armA-n{n}" / "trial-meta.json").read_text())
        homes.append(meta["hermes_home"])

    assert homes[0] != homes[1], "two trials shared a Hermes home"
    for home in homes:
        assert not Path(home).exists(), f"{home} outlived its trial"


# --- configuration errors --------------------------------------------------

def test_missing_environment_adapter_is_refused(tmp_path):
    env = make_workspace(tmp_path)
    env["ELCAP_ENV_ADAPTER"] = str(tmp_path / "nope.yaml")
    result = run_trial(env)
    assert result.returncode != 0
    assert "environment adapter" in result.stderr


@pytest.mark.parametrize("args,expected", [
    (("../escape", "FIND-001", "A", "1"), "env must be"),
    (("anna", "../../etc/passwd", "A", "1"), "finding id must be"),
    (("anna", "FIND-1", "A", "1"), "finding id must be"),
    (("anna", "FIND-001", "C", "1"), "arm must be"),
    (("anna", "FIND-001", "A", "1; rm -rf /"), "n must be"),
])
def test_trial_identifiers_that_would_escape_the_runs_tree_are_refused(
        tmp_path, args, expected):
    """All four arguments become path components of the run and anchor
    directories, and the finding id also indexes into findings/."""
    env = make_workspace(tmp_path)
    result = run_trial(env, args)
    assert result.returncode != 0
    assert expected in result.stderr


def test_missing_finding_is_refused(tmp_path):
    env = make_workspace(tmp_path)
    result = run_trial(env, ("anna", "FIND-999", "A", "1"))
    assert result.returncode != 0
    assert "missing finding" in result.stderr
