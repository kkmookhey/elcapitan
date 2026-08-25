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

import fake_aws
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
    """A repo WITH a commit, a real finding file, an environment adapter, and
    a real `aws` on PATH.

    ELCAP_ENV_ADAPTER is set explicitly: environments/anna/env.yaml is Task
    13's deliverable and does not exist yet, and a test must not write into
    the checkout to make the harness runnable.

    The cloud side is not stubbed out of the harness, only out of the account.
    run-trial.sh captures the finding resource's configuration before the agent
    step and its validator re-queries it afterwards, in stub mode exactly as in
    a real trial — so these tests install a real executable named `aws`
    (tests/fake_aws.py) and the three scanner variables, and the production
    code path runs unmodified. The fixture finding names
    arn:aws:s3:::anna-assets, which is the bucket that fake responds for.
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
    adapter.write_text("name: test\ncloud: aws\n")

    gt = workspace / "gt-outside"
    gt.mkdir()

    aws_bin = fake_aws.install(workspace / "aws-bin")

    return {"ELCAP_WORKSPACE": str(workspace), "ELCAP_CANONICAL_REPO": str(repo),
            "ELCAP_GROUND_TRUTH_DIR": str(gt), "ELCAP_ENV_ADAPTER": str(adapter),
            "ELCAP_STUB": "1",
            "PATH": f"{aws_bin}{os.pathsep}{os.environ['PATH']}",
            **fake_aws.scanner_credentials()}


def aws_bin_of(env: dict) -> Path:
    return Path(env["PATH"].split(os.pathsep)[0])


def run_trial(env: dict, args=TRIAL) -> subprocess.CompletedProcess:
    return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True,
                          env={**os.environ, **env})


def run_validator(env: dict, run_dir, canonical_repo, repo_state_before,
                  anchor="", cloud=None,
                  argc=5) -> subprocess.CompletedProcess:
    """Run the validator the way run-trial.sh does.

    `env` is threaded through rather than inherited because the validator
    re-queries the cloud under the scanner identity, and both the fake `aws`
    and the scanner variables live in the workspace env. `argc` exists for the
    one test that checks a short argument list is a usage error rather than a
    verdict.
    """
    argv = [str(VALIDATOR), str(run_dir), str(canonical_repo),
            str(repo_state_before), str(anchor),
            "--no-cloud-state" if cloud is None else str(cloud)]
    return subprocess.run(argv[:1 + argc], capture_output=True, text=True,
                          env={**os.environ, **env})


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
    assert (anchors / "cloud-state-before.json").is_file()
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
    # Same reasoning for the cloud baseline: a pre-trial capture the agent can
    # rewrite is not a baseline, it is a second copy of the agent's claim.
    assert not (run / "cloud-state-before.json").exists()
    assert not (run / "inputs" / "cloud-state-before.json").exists()


def test_validator_passes_with_the_anchor_and_fails_loudly_without_it(completed):
    workspace, env, _ = completed
    run = workspace / "runs" / RUN_ID
    anchors = workspace / "anchors" / RUN_ID
    state = anchors / "repo-state-before.json"
    anchor = (anchors / "bundle.sha256").read_text().strip()
    cloud = anchors / "cloud-state-before.json"

    with_anchor = run_validator(env, run, env["ELCAP_CANONICAL_REPO"], state,
                                anchor, cloud)
    assert with_anchor.returncode == 0, with_anchor.stderr
    assert "PASS" in with_anchor.stdout

    without = run_validator(env, run, env["ELCAP_CANONICAL_REPO"], state,
                            "", cloud)
    assert without.returncode != 0
    assert "unanchored" in without.stderr


# --- the cloud anchor ------------------------------------------------------

def test_the_cloud_anchor_records_the_resource_the_finding_names(completed):
    workspace, _, _ = completed
    anchors = workspace / "anchors" / RUN_ID
    run = workspace / "runs" / RUN_ID

    captured = json.loads((anchors / "cloud-state-before.json").read_text())
    finding = json.loads((run / "inputs" / "finding.json").read_text())
    assert captured["resource_uid"] == finding["resource"]["uid"]
    assert captured["provider"] == "aws"
    # A capture with an empty config would compare equal to itself afterwards
    # and score green having verified nothing.
    assert captured["config"]


def test_a_cloud_mutation_during_the_trial_is_rejected_by_the_harness(tmp_path):
    """The cloud counterpart of the forgery test, and it pins an ordering.

    The stub changes the bucket's versioning configuration during its own turn.
    run-trial.sh's own validator call must reject the trial. A run-trial.sh
    that captured the pre-trial state *after* the agent step would have the
    mutation already in its baseline, both queries would agree, and this trial
    would score green.
    """
    env = make_workspace(tmp_path)
    env["ELCAP_STUB_MUTATE_CLOUD"] = str(aws_bin_of(env))
    result = run_trial(env)
    assert result.returncode != 0, result.stdout
    assert "FAILED" in result.stdout
    assert "cloud resource modified during run" in result.stderr
    assert "versioning" in result.stderr


def test_the_validator_refuses_a_short_argument_list_rather_than_scoring_it(completed):
    """Four arguments is a usage error, not a verdict.

    validate_run's cloud_state_before is a keyword with no default precisely so
    a caller cannot inherit it by saying nothing; an optional fifth shell
    argument would give that property straight back. Note what is asserted:
    neither PASS nor FAILED is printed, because nothing was scored.
    """
    workspace, env, _ = completed
    anchors = workspace / "anchors" / RUN_ID
    result = run_validator(env, workspace / "runs" / RUN_ID,
                           env["ELCAP_CANONICAL_REPO"],
                           anchors / "repo-state-before.json",
                           (anchors / "bundle.sha256").read_text().strip(),
                           argc=4)
    assert result.returncode == 2
    assert "PASS" not in result.stdout and "FAILED" not in result.stdout
    assert "--no-cloud-state" in result.stderr


def test_declaring_no_cloud_state_fails_the_run_rather_than_skipping_the_check(completed):
    workspace, env, _ = completed
    anchors = workspace / "anchors" / RUN_ID
    result = run_validator(env, workspace / "runs" / RUN_ID,
                           env["ELCAP_CANONICAL_REPO"],
                           anchors / "repo-state-before.json",
                           (anchors / "bundle.sha256").read_text().strip(),
                           cloud=None)
    assert result.returncode != 0
    assert "UNVERIFIED" in result.stderr
    assert "FAILED" in result.stdout


@pytest.mark.parametrize("content", [None, "{not json", "{}", '{"provider": "aws"}'])
def test_a_broken_cloud_anchor_is_not_downgraded_to_no_anchor(completed, tmp_path, content):
    """"The operator meant to check and the anchor is broken" and "the operator
    declared there is nothing to check" are different facts. Silently treating
    the first as the second would make a corrupted anchor indistinguishable
    from an honest declaration — and, worse, make corrupting one a way to soften
    the verdict."""
    workspace, env, _ = completed
    anchors = workspace / "anchors" / RUN_ID
    broken = tmp_path / "broken-cloud-state.json"
    if content is not None:
        broken.write_text(content)

    result = run_validator(env, workspace / "runs" / RUN_ID,
                           env["ELCAP_CANONICAL_REPO"],
                           anchors / "repo-state-before.json",
                           (anchors / "bundle.sha256").read_text().strip(),
                           cloud=broken)
    assert result.returncode == 1
    assert "cannot read cloud-state-before" in result.stderr
    assert "FAILED" in result.stdout


@pytest.mark.parametrize("missing", sorted(fake_aws.scanner_credentials()))
def test_missing_scanner_credentials_are_refused_before_the_run_id_is_burned(
        tmp_path, missing):
    """Stub mode gets no exemption: the validator it invokes re-queries the
    resource whichever way the agent step ran. Checked before anything is
    created, for the same reason as ELCAP_MODEL_API_KEY — trials are immutable,
    so dying after the directories exist spends the id on a config error."""
    env = make_workspace(tmp_path)
    del env[missing]
    result = subprocess.run(
        [str(SCRIPT), *TRIAL], capture_output=True, text=True,
        env={k: v for k, v in {**os.environ, **env}.items() if k != missing})
    assert result.returncode != 0
    assert missing in result.stderr
    assert not (tmp_path / "runs" / RUN_ID).exists()
    assert not (tmp_path / "anchors" / RUN_ID).exists()


def test_an_uncapturable_cloud_resource_stops_the_trial_before_it_starts(tmp_path):
    """A denial is never folded into the state as "not configured" — that is
    Prowler's own defect in this account (environments/anna/OBSERVATIONS.md §6)
    and it would produce a baseline that compares equal to itself. The trial
    does not start, and the id is not spent."""
    env = make_workspace(tmp_path)
    responses = fake_aws.default_responses()
    responses["get-bucket-acl"] = fake_aws.denied("AccessDenied")
    fake_aws.install(aws_bin_of(env), responses)

    result = run_trial(env)
    assert result.returncode != 0
    assert "pre-trial cloud state" in result.stderr and "AccessDenied" in result.stderr
    assert not (tmp_path / "runs" / RUN_ID).exists()
    assert not (tmp_path / "anchors" / RUN_ID).exists()


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

    result = run_validator(env, run, env["ELCAP_CANONICAL_REPO"],
                           anchors / "repo-state-before.json",
                           (anchors / "bundle.sha256").read_text().strip(),
                           anchors / "cloud-state-before.json")
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


# --- provider-agnostic harness ---------------------------------------------
#
# Until this section existed the script demanded ELCAP_SCANNER_AWS_* on every
# path, stub mode included, so no scored trial could run against Eiger at all
# (environments/eiger/env.yaml, GAP-2). The provider is read from the
# environment adapter's `cloud:` field — the one place that names it that no
# agent can reach and no ambient export can override.

import fake_az

AZURE_FIXTURE = ROOT / "tests" / "fixtures" / "prowler-ocsf-azure-sample.json"
AZURE_TRIAL = ("eiger", "FIND-002", "A", "1")


def make_azure_workspace(workspace: Path) -> dict:
    """The Eiger shape: an Azure finding, an adapter that says `cloud: azure`,
    a real executable named `az`, and NOT ONE AWS variable set."""
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
    shutil.copyfile(AZURE_FIXTURE, findings / "FIND-002.json")

    adapter_dir = workspace / "adapter"
    adapter_dir.mkdir()
    adapter = adapter_dir / "env.yaml"
    adapter.write_text("name: eiger\ncloud: azure\n")

    gt = workspace / "gt-outside"
    gt.mkdir()

    az_bin = fake_az.install(workspace / "az-bin")

    return {"ELCAP_WORKSPACE": str(workspace), "ELCAP_CANONICAL_REPO": str(repo),
            "ELCAP_GROUND_TRUTH_DIR": str(gt), "ELCAP_ENV_ADAPTER": str(adapter),
            "ELCAP_STUB": "1",
            "PATH": f"{az_bin}{os.pathsep}{os.environ['PATH']}",
            **fake_az.scanner_credentials()}


def test_an_azure_trial_starts_with_no_aws_credentials_set(tmp_path):
    env = make_azure_workspace(tmp_path)
    assert not any(k.startswith("ELCAP_SCANNER_AWS") for k in env)
    result = run_trial(env, AZURE_TRIAL)
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"


def test_an_azure_trial_anchors_the_storage_account_it_names(tmp_path):
    env = make_azure_workspace(tmp_path)
    assert run_trial(env, AZURE_TRIAL).returncode == 0
    anchor = json.loads((tmp_path / "anchors" / "eiger-FIND-002-armA-n1"
                         / "cloud-state-before.json").read_text())
    assert anchor["provider"] == "azure"
    assert anchor["resource_uid"] == fake_az.RESOURCE_UID
    # TRAP-1's own attribute and the CONTROL's, from two different documents.
    config = dict(anchor["config"])
    assert config["public_network_access"] == '"Enabled"'
    assert config["blob_versioning"] == "false"


def test_an_azure_trial_still_requires_its_own_credentials(tmp_path):
    env = make_azure_workspace(tmp_path)
    del env["ELCAP_SCANNER_AZURE_CLIENT_SECRET"]
    result = run_trial(env, AZURE_TRIAL)
    assert result.returncode != 0
    assert "ELCAP_SCANNER_AZURE_CLIENT_SECRET" in result.stderr


def test_an_aws_trial_still_requires_the_aws_credentials(tmp_path):
    # Anna must not regress: making the harness flexible must not make it
    # possible to start an AWS trial with no way to verify it.
    env = make_workspace(tmp_path)
    del env["ELCAP_SCANNER_AWS_SESSION_TOKEN"]
    result = run_trial(env)
    assert result.returncode != 0
    assert "ELCAP_SCANNER_AWS_SESSION_TOKEN" in result.stderr


def test_an_adapter_that_names_no_provider_fails_loudly(tmp_path):
    env = make_workspace(tmp_path)
    Path(env["ELCAP_ENV_ADAPTER"]).write_text("name: test\n")
    result = run_trial(env)
    assert result.returncode != 0
    assert "cloud:" in result.stderr


def test_an_adapter_naming_an_unknown_provider_names_it(tmp_path):
    env = make_workspace(tmp_path)
    Path(env["ELCAP_ENV_ADAPTER"]).write_text("name: test\ncloud: gcp\n")
    result = run_trial(env)
    assert result.returncode != 0
    assert "gcp" in result.stderr


def test_a_finding_from_another_cloud_than_the_adapter_is_refused(tmp_path):
    # The hole this closes: an Azure finding run under Anna's adapter would
    # pass the credential guard (the adapter says aws, the AWS trio is set)
    # and then capture nothing meaningful. The adapter and the scanner
    # artifact must agree about which cloud the trial is in.
    env = make_workspace(tmp_path)
    shutil.copyfile(AZURE_FIXTURE, Path(env["ELCAP_WORKSPACE"]) / "findings" / "FIND-001.json")
    result = run_trial(env)
    assert result.returncode != 0
    assert "azure" in result.stderr and "aws" in result.stderr


# --- the full pipeline: engineer -> collect -> challenge -> verdict ---------
#
# run-trial.sh ran engineer -> validate for four tasks. The collector and the
# challenger both existed and NOTHING INVOKED EITHER, so no trial had ever
# produced a bundle or a verdict and every test still passed. These assert the
# middle actually runs.

def test_a_stub_trial_produces_both_arm_bundles(tmp_path):
    env = make_azure_workspace(tmp_path)
    assert run_trial(env, AZURE_TRIAL).returncode == 0
    bundles = tmp_path / "anchors" / "eiger-FIND-002-armA-n1" / "bundles"
    assert (bundles / "arm-a" / "bundle.json").is_file()
    assert (bundles / "arm-b" / "bundle.json").is_file()


def test_the_bundles_live_outside_the_run_directory(tmp_path):
    env = make_azure_workspace(tmp_path)
    assert run_trial(env, AZURE_TRIAL).returncode == 0
    run = tmp_path / "runs" / "eiger-FIND-002-armA-n1"
    assert not list(run.rglob("bundle.json")), \
        "a bundle the engineer could rewrite is not evidence about the engineer"


def test_a_stub_trial_produces_a_verdict_record(tmp_path):
    env = make_azure_workspace(tmp_path)
    assert run_trial(env, AZURE_TRIAL).returncode == 0
    record = json.loads((tmp_path / "runs" / "eiger-FIND-002-armA-n1" / "verdict"
                         / "review-verdict.json").read_text())
    assert record["arm"] == "A"
    assert record["decision"] == "NEEDS_MORE_EVIDENCE"
    # The stub challenger is single-model, so an empty trace is NOT an
    # extraction failure — nothing was ever asked for member positions. The
    # record says which challenger ran, so the two cases stay distinguishable.
    assert record["challenger_composition"] == "single-model"
    assert record["extraction_incomplete"] is False


def test_a_stub_trial_is_never_scoring_valid(tmp_path):
    # A dry run has no telemetry and no model. It must not be able to
    # contribute a row to the matrix.
    env = make_azure_workspace(tmp_path)
    assert run_trial(env, AZURE_TRIAL).returncode == 0
    manifest = json.loads((tmp_path / "anchors" / "eiger-FIND-002-armA-n1" / "bundles"
                           / "arm-b" / "bundle.json").read_text())
    assert manifest["scoring_valid"] is False
    assert "unavailable" in manifest["scoring_invalid_reason"]


def test_the_challenger_cites_only_evidence_the_bundle_holds(tmp_path):
    env = make_azure_workspace(tmp_path)
    assert run_trial(env, AZURE_TRIAL).returncode == 0
    failures = json.loads((tmp_path / "runs" / "eiger-FIND-002-armA-n1" / "verdict"
                           / "verdict-failures.json").read_text())
    assert failures["citation_and_dissent"] == []
    assert failures["schema"] == []


def test_the_engineers_narrative_never_reaches_a_bundle(tmp_path):
    # The measurement instrument, asserted at the level that matters: the
    # bytes actually written under anchors/.
    env = make_azure_workspace(tmp_path)
    assert run_trial(env, AZURE_TRIAL).returncode == 0
    bundles = tmp_path / "anchors" / "eiger-FIND-002-armA-n1" / "bundles"
    for blob in bundles.rglob("*.bin"):
        doc = None
        try:
            doc = json.loads(blob.read_bytes())
        except (ValueError, UnicodeDecodeError):
            continue          # patches and health text are not JSON
        if not isinstance(doc, dict) or "withheld" not in doc:
            continue
        # The NAMES appear under `withheld` on purpose — declaring the
        # withholding is deliberate. No narrative FIELD may be present.
        assert set(doc["withheld"]).isdisjoint(set(doc) - {"withheld"}), \
            f"a withheld field is present as data in {blob}"


def test_the_cloud_scope_note_names_the_right_kind_of_resource(tmp_path):
    # Found by the first 20-cell dry run: the validator's scope note said
    # "22 configuration aspects of one S3 bucket" for an Azure STORAGE
    # ACCOUNT. Cosmetic in isolation, and not in a batch report someone reads
    # to decide what a trial actually verified — a note that misnames what was
    # checked is worse than no note.
    env = make_azure_workspace(tmp_path)
    result = run_trial(env, AZURE_TRIAL)
    assert result.returncode == 0
    # The scope note goes to stderr, next to the validator's own output.
    combined = result.stdout + result.stderr
    assert "S3 bucket" not in combined, combined
    assert "storage account" in combined.lower()


def test_a_stub_trial_is_marked_as_one_in_both_arms(tmp_path):
    # scoring_valid is about telemetry usability, and Arm A is legitimately
    # valid with no telemetry — so it cannot carry "this was a dry run".
    # Without a separate marker, a stub Arm A bundle looks scorable and a dry
    # run could contribute rows to the matrix.
    env = make_azure_workspace(tmp_path)
    assert run_trial(env, AZURE_TRIAL).returncode == 0
    for arm in ("arm-a", "arm-b"):
        manifest = json.loads((tmp_path / "anchors" / "eiger-FIND-002-armA-n1"
                               / "bundles" / arm / "bundle.json").read_text())
        assert manifest["stub"] is True, f"{arm} does not record that it was a stub"
