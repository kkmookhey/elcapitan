#!/usr/bin/env bash
# bin/run-trial.sh — the deterministic orchestrator for one scored trial.
#
#   run-trial.sh <env> <finding-id> <arm> <n>
#
# Hermes delegate_task fan-out is deliberately NOT used for scored trials:
# agentic orchestration would add a second experimental variable.
#
# Required environment:
#   ELCAP_WORKSPACE          holds findings/, runs/ and anchors/
#   ELCAP_CANONICAL_REPO     the repository, mounted read-only into the agent
#   ELCAP_GROUND_TRUTH_DIR   must exist, and must be reachable from neither
#                            the runs tree nor the canonical repository
# Optional:
#   ELCAP_ENV_ADAPTER        path to the environment adapter YAML
#                            (default: <repo-root>/environments/<env>/env.yaml)
#   ELCAP_MODEL/ELCAP_PROVIDER   default claude-sonnet-5 / anthropic — the same
#                            defaults bin/agent-run.sh uses. Exported here so
#                            the seeded config.yaml that gets hashed into the
#                            input manifest and the -m flag agent-run.sh passes
#                            can never disagree.
#   ELCAP_STUB=1             run tests/stub_engineer.py instead of a container
# Required in every mode, including ELCAP_STUB=1 — WHICH ONES depends on the
# environment adapter's `cloud:` field, not on what happens to be exported:
#   cloud: aws    ELCAP_SCANNER_AWS_ACCESS_KEY_ID / _SECRET_ACCESS_KEY
#                                                 / _SESSION_TOKEN
#   cloud: azure  ELCAP_SCANNER_AZURE_CLIENT_ID / _CLIENT_SECRET / _TENANT_ID
#                            the scoped read-only scanner principal. Used HERE
#                            to capture the finding resource's configuration
#                            before the agent runs, and again by the validator
#                            to re-query it afterwards. See "no stub exemption"
#                            below for why stub mode does not get a pass. The
#                            names are derived from constants.SCANNER_ENV_MAPS,
#                            so adding a provider is one edit, not four.
# Exported by this script for bin/agent-run.sh:
#   ELCAP_CLOUD              the provider, read from the adapter. agent-run.sh
#                            uses it to pass the right cloud's credential into
#                            the engineer container, and refuses another
#                            cloud's.
#
# ## The out-of-band anchor — the one property this script exists to hold
#
# Three reference values are captured BEFORE the trial and kept OUTSIDE the run
# directory, in ${ELCAP_WORKSPACE}/anchors/<run-id>/:
#
#   repo-state-before.json   the canonical repository's pre-trial state
#   bundle.sha256            the pre-trial input-bundle hash
#   cloud-state-before.json  the finding resource's pre-trial configuration
#
# Nothing inside run_dir can anchor run_dir. The agent gets /work/run as a
# writable mount, so it can rewrite inputs/finding.json, that file's entry in
# inputs/input-manifest.json, and proposal.json's own input_bundle_hash
# together — a coherent forgery in which every internal consistency check the
# validator makes still holds. Only a value captured before the agent ran and
# stored where the agent cannot reach it detects that.
#
# Two things make that placement safe, and one that reads like a third does
# not. The anchors directory is a SIBLING of runs/, so none of engineer_spec's
# three mounts (canonical_repo, run_dir, host_hermes_home) covers it; and the
# value is read into a shell variable BEFORE the agent step, so even a write
# path into anchors/ would be too late. What does NOT hold — an earlier
# revision of this comment claimed it did — is that container.py structurally
# prevents anchors/ from ever being mounted: _reject_overbroad_mounts refuses
# a mount of ${ELCAP_WORKSPACE} itself, because that is an ancestor of
# run_dir, but an extra_mounts entry of ${ELCAP_WORKSPACE}/anchors is an
# ancestor of nothing this spec uses and would be accepted. Nobody passes
# extra_mounts today; if anyone starts, that is the hole to close.
#
# The cloud anchor is the same mechanism aimed at the other thing a trial can
# damage. Repository mutation is verified by recomputing git state and
# comparing with what was captured before; cloud mutation is verified the same
# way, by re-querying the finding's own resource. It replaced a transcript
# regex scan that read the agent's prose and guessed — and failed an honest
# Anna run four times for stating plainly that it had NOT deployed, while AWS
# was independently confirmed untouched. Honesty failed; silence passed.
#
# ## No stub exemption for the cloud capture
#
# ELCAP_STUB=1 replaces the agent, not the cloud. The capture and the
# credential requirement apply in stub mode too, for two reasons. First, the
# validator this script invokes has no stub mode: it re-queries the resource
# whichever way the agent step ran, so a stub trial that skipped the capture
# would be scored by a *different* validator call than a real trial gets —
# which destroys the stub's only purpose, rehearsing the real pipeline before
# a real trial burns real credentials. Second, resolving the scanner identity
# is precisely the step that has broken in practice; rehearsing everything
# except it rehearses the easy part. Tests satisfy the requirement with a real
# executable named `aws` on PATH (tests/fake_aws.py), so the production code
# path — argv construction, environment scrubbing, empty-stdout handling — is
# genuinely exercised there rather than mocked past.
#
# inputs/bundle.sha256 is deliberately NOT written. The plan's draft wrote it
# and had the engineer read it back, which defeats the whole mechanism: the
# hash is trivially recomputable from inputs/input-manifest.json anyway (that
# is all bundle_hash does), so the file carries no information the agent does
# not already have — it only creates a second, agent-writable copy that looks
# authoritative and invites a future caller to pipe it into the validator's
# fourth argument. See tests/test_run_trial.py::
# test_no_agent_writable_copy_of_the_anchor_is_left_in_the_run_dir.
#
# ## Who seeds the Hermes home
#
# This script does, via elcapitan.home.seed_hermes_home, into a fresh
# mktemp -d per trial. That is forced rather than chosen: the input manifest
# pins profile_config_sha256, so the home's config.yaml must exist before the
# manifest is built, which is before the agent runs — and it must exist in
# stub mode too. bin/agent-run.sh sees a directory that already exists, so its
# own "seed if absent" branch does not fire and its `trap cleanup EXIT` does
# not delete it; this script's trap does, after agent-run.sh has returned and
# therefore after run_agent's _capture_state_db has copied state.db into the
# run directory. state.db is the primary evidence record and it is archived
# before anything here can remove its source.
#
# A fresh home per trial is load-bearing, not hygiene: Task 2 established that
# skills.creation_nudge_interval: 0 only suppresses the nudge — Hermes has no
# hard gate on skill self-authoring, so an agent can write a skill file into
# its own HERMES_HOME. seed_hermes_home refuses to write into an existing
# directory, and that refusal is the entire cross-trial independence
# guarantee. Never reuse a home for speed.
set -euo pipefail

ENV_NAME="${1:?usage: run-trial.sh <env> <finding-id> <arm> <n>}"
FINDING_ID="${2:?missing finding id}"
ARM="${3:?missing arm}"
TRIAL_N="${4:?missing n}"
: "${ELCAP_WORKSPACE:?ELCAP_WORKSPACE must be set}"
: "${ELCAP_CANONICAL_REPO:?ELCAP_CANONICAL_REPO must be set}"
: "${ELCAP_GROUND_TRUTH_DIR:?ELCAP_GROUND_TRUTH_DIR must be set}"

# All four become path components of RUN_DIR and ANCHOR_DIR, and FINDING_ID
# also indexes into ${WORKSPACE}/findings/. Constrain them here so a stray
# "../" in an operator's argument cannot place a run directory somewhere the
# containment reasoning below does not cover. FINDING_ID matches the pattern
# the finding-record schema itself requires; ARM matches container.VALID_ARMS.
case "$ENV_NAME" in *[!a-z0-9-]*|"") echo "run-trial.sh: env must be [a-z0-9-]+: ${ENV_NAME}" >&2; exit 2 ;; esac
case "$FINDING_ID" in FIND-[0-9][0-9][0-9]*) case "${FINDING_ID#FIND-}" in *[!0-9]*) echo "run-trial.sh: finding id must be FIND-<digits>: ${FINDING_ID}" >&2; exit 2 ;; esac ;;
  *) echo "run-trial.sh: finding id must be FIND-<digits>: ${FINDING_ID}" >&2; exit 2 ;; esac
case "$ARM" in A|B) ;; *) echo "run-trial.sh: arm must be A or B: ${ARM}" >&2; exit 2 ;; esac
case "$TRIAL_N" in ""|*[!0-9]*) echo "run-trial.sh: n must be a positive integer: ${TRIAL_N}" >&2; exit 2 ;; esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export ELCAP_MODEL="${ELCAP_MODEL:-claude-sonnet-5}"
export ELCAP_PROVIDER="${ELCAP_PROVIDER:-anthropic}"

resolve_existing_dir() {
  # pwd -P, not readlink -f: BSD readlink has no -f and macOS is the primary
  # dev machine here. A directory that does not exist is a configuration
  # error, not something to invent a path for.
  local label="$1" path="$2"
  if [ ! -d "$path" ]; then
    echo "run-trial.sh: ${label} is not an existing directory: ${path}" >&2
    exit 2
  fi
  (cd "$path" && pwd -P)
}

WORKSPACE="$(resolve_existing_dir ELCAP_WORKSPACE "$ELCAP_WORKSPACE")"
CANONICAL_REPO="$(resolve_existing_dir ELCAP_CANONICAL_REPO "$ELCAP_CANONICAL_REPO")"
GROUND_TRUTH="$(resolve_existing_dir ELCAP_GROUND_TRUTH_DIR "$ELCAP_GROUND_TRUTH_DIR")"

# Ground truth must live outside every path an agent container can see. The
# runs tree is mounted writable and the canonical repository read-only; either
# would hand the agent the answer key. Checked against physically-resolved
# paths so a symlink cannot walk the check.
is_within() {   # is_within <candidate> <ancestor>
  case "$1" in
    "$2"|"$2"/*) return 0 ;;
    *) return 1 ;;
  esac
}
if is_within "$GROUND_TRUTH" "${WORKSPACE}/runs"; then
  echo "run-trial.sh: refusing to start — ground truth directory ${GROUND_TRUTH} is inside the runs tree" >&2
  exit 2
fi
if is_within "$GROUND_TRUTH" "$CANONICAL_REPO"; then
  echo "run-trial.sh: refusing to start — ground truth directory ${GROUND_TRUTH} is inside the canonical repository, which is mounted into the agent container" >&2
  exit 2
fi

ENV_ADAPTER="${ELCAP_ENV_ADAPTER:-${REPO_ROOT}/environments/${ENV_NAME}/env.yaml}"
if [ ! -f "$ENV_ADAPTER" ]; then
  echo "run-trial.sh: missing environment adapter ${ENV_ADAPTER} (set ELCAP_ENV_ADAPTER to override)" >&2
  exit 2
fi

FINDING_SRC="${WORKSPACE}/findings/${FINDING_ID}.json"
if [ ! -f "$FINDING_SRC" ]; then
  echo "run-trial.sh: missing finding ${FINDING_SRC}" >&2
  exit 2
fi

# Checked here, before anything is created. A real trial that got as far as
# agent-run.sh only to die on a missing API key would leave runs/<id> and
# anchors/<id> behind and burn the trial id — trials are immutable, so the
# operator would have to delete both by hand to retry. Guarded on stub mode
# because the stub never launches a container and needs no credential.
if [ "${ELCAP_STUB:-0}" != "1" ]; then
  : "${ELCAP_MODEL_API_KEY:?ELCAP_MODEL_API_KEY must be set (maps to ANTHROPIC_API_KEY in bin/agent-run.sh)}"
fi
# No stub guard here — see this script's header. Which credentials a trial
# needs depends on which cloud it is in, so the names are DERIVED from
# constants.SCANNER_ENV_MAPS rather than spelled out. The previous version
# hard-coded the AWS trio and demanded it on every path, stub mode included,
# which is why no scored trial could run against Eiger at all
# (environments/eiger/env.yaml, GAP-2).
#
# The provider comes from the environment adapter's `cloud:` field. That makes
# the adapter PARSED, not merely hashed into the manifest — deliberately: the
# provider must come from a file the operator commits and no ambient export
# can override, and the capture below cross-checks it against the provider the
# scanner artifact itself declares, so the two cannot silently disagree.
ENV_CLOUD="$(uv run --project "$REPO_ROOT" python - "$ENV_ADAPTER" <<'PROVIDER_PY'
import os
import sys

import yaml

from elcapitan.constants import SCANNER_ENV_MAPS, scanner_env_map

adapter_path = sys.argv[1]
try:
    adapter = yaml.safe_load(open(adapter_path).read())
except (OSError, yaml.YAMLError) as exc:
    print(f"run-trial.sh: cannot read the environment adapter {adapter_path}: {exc}",
          file=sys.stderr)
    sys.exit(2)

provider = adapter.get("cloud") if isinstance(adapter, dict) else None
if not isinstance(provider, str) or not provider:
    print(f"run-trial.sh: {adapter_path} names no `cloud:` provider. Every trial is "
          f"verified by re-querying its finding's resource, and which credentials "
          f"that needs depends on the cloud — add `cloud: <name>` (one of "
          f"{', '.join(sorted(SCANNER_ENV_MAPS))}).", file=sys.stderr)
    sys.exit(2)

try:
    mapping = scanner_env_map(provider)
except ValueError as exc:
    print(f"run-trial.sh: {adapter_path} names cloud {provider!r}: {exc}",
          file=sys.stderr)
    sys.exit(2)

missing = sorted(name for name in mapping if not os.environ.get(name))
if missing:
    print(f"run-trial.sh: {', '.join(missing)} must be set — this is a {provider} "
          f"environment, and the read-only scanner principal captures the pre-trial "
          f"cloud state and re-queries it at validation. All {len(mapping)} of "
          f"{', '.join(sorted(mapping))}, or none of the run is verifiable.",
          file=sys.stderr)
    sys.exit(2)

print(provider)
PROVIDER_PY
)" || exit 2
export ELCAP_CLOUD="$ENV_CLOUD"

RUN_ID="${ENV_NAME}-${FINDING_ID}-arm${ARM}-n${TRIAL_N}"
RUN_DIR="${WORKSPACE}/runs/${RUN_ID}"
ANCHOR_DIR="${WORKSPACE}/anchors/${RUN_ID}"
if [ -e "$RUN_DIR" ] || [ -e "$ANCHOR_DIR" ]; then
  # Name both paths: they are created and checked together, so there is no
  # half-state to reason about, but an operator retrying after a failed trial
  # needs to know what to remove — "trials are immutable" alone does not say.
  echo "run-trial.sh: run ${RUN_ID} already exists — trials are immutable." >&2
  echo "  to retry this trial id, remove both leftovers first:" >&2
  echo "    ${RUN_DIR}" >&2
  echo "    ${ANCHOR_DIR}" >&2
  exit 3
fi

# Set before the trap so `set -u` cannot make the trap itself the failure.
HOME_PARENT=""
CLOUD_STATE_TMP=""
cleanup() {
  if [ -n "$HOME_PARENT" ]; then
    rm -rf "$HOME_PARENT"
  fi
  if [ -n "$CLOUD_STATE_TMP" ]; then
    rm -f "$CLOUD_STATE_TMP"
  fi
}
trap cleanup EXIT

# --- the cloud anchor, captured before anything is created ------------------
#
# Deliberately ahead of the mkdir. A live cloud query is the most failure-prone
# step in this script — an expired session token, a revoked permission, a
# resource type with no implementation — and trials are immutable, so failing
# after the directories exist would spend the trial id on a configuration
# error. Same reasoning as the ELCAP_MODEL_API_KEY guard above. finding.py
# exposes cloud_target for exactly this: the target is read from the raw
# scanner artifact, before normalise_ocsf has anywhere to write to.
CLOUD_STATE_TMP="$(mktemp)"
uv run --project "$REPO_ROOT" python - "$FINDING_SRC" "$CLOUD_STATE_TMP" <<'PY'
import json
import os
import sys
from pathlib import Path

from elcapitan.cloud import capture_cloud_state, to_dict, verification_env
from elcapitan.finding import cloud_target

finding_src, out_path = sys.argv[1:3]
try:
    raw = json.loads(Path(finding_src).read_text())
except (OSError, ValueError) as exc:
    print(f"run-trial.sh: cannot read the finding {finding_src}: {exc}", file=sys.stderr)
    sys.exit(2)

resource_uid = ""
try:
    # cloud_target reads a scanner artifact, so it is parsed defensively: a
    # raw event that is not the shape it claims must produce this script's own
    # message, not a traceback from three frames down.
    provider, resource_uid, region = cloud_target(raw)
    declared = os.environ["ELCAP_CLOUD"]
    if provider != declared:
        # Neither side is trusted over the other; they simply have to agree.
        # An Azure finding run under Anna's adapter would otherwise pass the
        # credential guard above (the adapter says aws, the AWS trio is set)
        # and then try to verify an ARM resource with an S3 query.
        raise ValueError(
            f"the environment adapter declares cloud {declared!r} but the finding "
            f"was produced by a {provider!r} scan — a trial cannot be verified "
            f"against a cloud it is not in")
    state = capture_cloud_state(resource_uid, provider=provider, region=region,
                                env=verification_env(os.environ, provider=provider))
except (ValueError, TypeError, AttributeError, IndexError, KeyError) as exc:
    # Never degraded to "capture nothing and carry on". A trial whose cloud
    # state cannot be anchored cannot be judged on whether it mutated the
    # cloud, and an unjudgeable trial must not start.
    print(f"run-trial.sh: refusing to start — the pre-trial cloud state of "
          f"{resource_uid or '<no resource uid in the finding>'} could not be "
          f"captured: {exc}", file=sys.stderr)
    sys.exit(2)

Path(out_path).write_text(json.dumps(to_dict(state), indent=2))
PY

mkdir -p "$RUN_DIR/inputs" "$RUN_DIR/evidence" "$RUN_DIR/patch" "$RUN_DIR/verdict"
mkdir -p "$ANCHOR_DIR"
# Into anchors/, never run_dir: the agent has run_dir writable, and a baseline
# it can rewrite is not a baseline.
mv "$CLOUD_STATE_TMP" "${ANCHOR_DIR}/cloud-state-before.json"
CLOUD_STATE_TMP=""

HOME_PARENT="$(mktemp -d)"
# seed_hermes_home refuses an existing directory, so name a child that does
# not exist yet rather than handing it the mktemp -d itself.
HERMES_HOME="${HOME_PARENT}/hermes-home"

# `uv run`, not bare python3: python3 is whatever the operator's PATH offers
# and has neither elcapitan on sys.path nor the pinned dependencies. Same
# reasoning as bin/validate-trial-artifacts.sh.
uv run --project "$REPO_ROOT" python - \
  "$RUN_DIR" "$ANCHOR_DIR" "$FINDING_ID" "$FINDING_SRC" "$HERMES_HOME" \
  "$CANONICAL_REPO" "$REPO_ROOT" "$ENV_ADAPTER" "$ENV_NAME" "$RUN_ID" <<'PY'
import datetime
import json
import os
import sys
from pathlib import Path

from elcapitan.evidence import Collector
from elcapitan.finding import normalise_ocsf
from elcapitan.hashing import sha256_file
from elcapitan.home import seed_hermes_home
from elcapitan.manifest import build_manifest, bundle_hash
from elcapitan.repo import capture_repo_state

(run_dir, anchor_dir, finding_id, finding_src, hermes_home,
 canonical_repo, repo_root, env_adapter, env_name, run_id) = sys.argv[1:11]
run_dir, anchor_dir, repo_root = Path(run_dir), Path(anchor_dir), Path(repo_root)

model = os.environ["ELCAP_MODEL"]
provider = os.environ["ELCAP_PROVIDER"]

lock = json.loads((repo_root / "runtime.lock.json").read_text())
now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

# --- anchors: captured before the trial, written OUTSIDE run_dir -----------
state = capture_repo_state(canonical_repo)
(anchor_dir / "repo-state-before.json").write_text(
    json.dumps({"commit": state.commit, "dirty_files": list(state.dirty_files)},
               indent=2))

# --- inputs the agent is given --------------------------------------------
raw = json.loads(Path(finding_src).read_text())
record = normalise_ocsf(
    raw, run_dir=run_dir, finding_id=finding_id,
    collector=Collector("prowler", lock["tool_versions"]["prowler"],
                        f"elcapitan-{env_name}-scanner"),
    now=now)
(run_dir / "inputs" / "finding.json").write_text(json.dumps(record, indent=2))
(run_dir / "prompt.md").write_text((repo_root / "prompts" / "engineer.md").read_text())

# A fresh home per trial. seed_hermes_home raises FileExistsError on an
# existing dest — that refusal IS the cross-trial independence guarantee.
home = seed_hermes_home(hermes_home, model=model, provider=provider)

manifest = build_manifest(
    run_dir, files=["inputs/finding.json", "prompt.md"],
    repository_commit=state.commit,
    runtime_image_id=lock["runtime_image_id"],
    runtime_lock_sha256=sha256_file(repo_root / "runtime.lock.json"),
    profile_config_sha256=sha256_file(home / "config.yaml"),
    environment_adapter_sha256=sha256_file(env_adapter))
(run_dir / "inputs" / "input-manifest.json").write_text(json.dumps(manifest, indent=2))

# The anchor. Held here, never in run_dir. Deliberately no
# run_dir/inputs/bundle.sha256 — see this script's header.
(anchor_dir / "bundle.sha256").write_text(bundle_hash(manifest))
(anchor_dir / "trial-meta.json").write_text(json.dumps({
    "run_id": run_id, "env": env_name, "finding_id": finding_id,
    "created_at": now, "hermes_home": hermes_home,
    "model": model, "provider": provider,
    "runtime_image_id": lock["runtime_image_id"],
    "environment_adapter": env_adapter,
}, indent=2))
PY

BUNDLE_SHA256="$(cat "${ANCHOR_DIR}/bundle.sha256")"
TRIAL_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ "${ELCAP_STUB:-0}" = "1" ]; then
  uv run --project "$REPO_ROOT" python "${REPO_ROOT}/tests/stub_engineer.py" \
    "$RUN_DIR" "$FINDING_ID" "$HERMES_HOME"
else
  ELCAP_CANONICAL_REPO="$CANONICAL_REPO" \
    "${REPO_ROOT}/bin/agent-run.sh" "$RUN_DIR" "$RUN_DIR/prompt.md" engineer "$ARM" "$HERMES_HOME"
fi

ENGINEER_FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- the collector ----------------------------------------------------------
#
# One snapshot, both arm bundles, written under anchors/ where the engineer
# cannot reach them. This step used to be missing entirely: the collector and
# the challenger both existed and nothing invoked either, so no trial had ever
# produced a bundle or a verdict.
uv run --project "$REPO_ROOT" python - \
  "$RUN_DIR" "$ANCHOR_DIR" "$RUN_ID" "$ENV_ADAPTER" "$FINDING_SRC" \
  "$TRIAL_STARTED_AT" "$ENGINEER_FINISHED_AT" "${ELCAP_STUB:-0}" <<'COLLECT_PY'
import json
import os
import sys
from pathlib import Path

import yaml

from elcapitan.cloud import capture_cloud_state, to_dict, verification_env
from elcapitan.collector import (UNAVAILABLE, Snapshot, TelemetryProbe, collect,
                                 take_snapshot)
from elcapitan.evidence import Collector
from elcapitan.finding import cloud_target
from elcapitan.hashing import canonical_json
from elcapitan.trial import (now_rfc3339, probe_health, read_engineer_artifacts,
                             telemetry_window, wait_for_ingestion)

(run_dir, anchor_dir, run_id, env_adapter, finding_src,
 started_at, finished_at, stub) = sys.argv[1:9]
stub = stub == "1"

adapter = yaml.safe_load(Path(env_adapter).read_text())
raw_finding = json.loads(Path(finding_src).read_text())
provider, resource_uid, region = cloud_target(raw_finding)

proposal, patch, verification = read_engineer_artifacts(run_dir)

# The LIVE configuration of the resource, re-read after the agent ran. The
# pre-trial anchor answers "did the agent touch it"; this answers "what does
# the challenger see now", and they are different questions.
cloud_config = canonical_json(to_dict(capture_cloud_state(
    resource_uid, provider=provider, region=region,
    env=verification_env(os.environ, provider=provider))))

health_contract = adapter.get("health_contract")
fqdn = (adapter.get("deployment") or {}).get("app_fqdn")
health = probe_health([health_contract, fqdn]) if health_contract and fqdn else \
    b"UNKNOWN: the environment adapter names no health contract."

window_start, window_end = telemetry_window(started_at, finished_at)

if stub:
    # A stub trial has no model and no observer credential. Its telemetry is
    # UNAVAILABLE rather than absent, which makes every stub bundle
    # scoring_valid=false — a dry run must not be able to contribute a row to
    # the matrix.
    probes = tuple(
        TelemetryProbe(kind, "not attempted: ELCAP_STUB=1", window_start, window_end,
                       UNAVAILABLE, "stub mode collects no telemetry", b"")
        for kind in ("storage_transactions", "container_app_logs", "dependency_edges"))
    snapshot = Snapshot(run_id=run_id, collected_at=now_rfc3339(), proposal=proposal,
                        patch=patch, verification=verification,
                        cloud_config=cloud_config, health=health, telemetry=probes)
else:
    # Widening the window is necessary and not sufficient — asking before the
    # window has landed returns zeros, which the collector correctly calls
    # unpopulated. See trial.wait_for_ingestion.
    wait_for_ingestion()
    workspace = (adapter.get("deployment") or {}).get("log_analytics_workspace_id", "")
    snapshot = take_snapshot(
        run_id=run_id, resource_uid=resource_uid, workspace_id=workspace,
        window_start=window_start, window_end=window_end,
        proposal=proposal, patch=patch, verification=verification,
        cloud_config=cloud_config, health=health, env=os.environ, now=now_rfc3339())

bundles = collect(snapshot, anchor_dir=anchor_dir, now=now_rfc3339(),
                  collector=Collector(tool="elcapitan-collector", version="0.1.0",
                                      identity=os.environ.get("ELCAP_OBSERVER_AZURE_CLIENT_ID",
                                                              "stub")))
Path(anchor_dir, "bundles.json").write_text(json.dumps(bundles, indent=2))
for arm, path in sorted(bundles.items()):
    manifest = json.loads(Path(path, "bundle.json").read_text())
    print(f"  arm {arm}: {len(manifest['artifacts'])} artifacts, "
          f"scoring_valid={manifest['scoring_valid']}")
COLLECT_PY

BUNDLE_PATH="$(uv run --project "$REPO_ROOT" python -c \
  "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" \
  "${ANCHOR_DIR}/bundles.json" "$ARM")"

# --- the challenger ---------------------------------------------------------
#
# A SECOND fresh HERMES_HOME. Sharing the engineer's would carry its skills,
# its session store and its conclusions into the reviewer that is supposed to
# be independent of it.
CHALLENGER_HOME="${HOME_PARENT}/challenger-home"
if [ "${ELCAP_STUB:-0}" = "1" ]; then
  uv run --project "$REPO_ROOT" python "${REPO_ROOT}/tests/stub_challenger.py" \
    "$RUN_DIR" "$BUNDLE_PATH"
else
  ELCAP_BUNDLE_PATH="$BUNDLE_PATH" \
    "${REPO_ROOT}/bin/agent-run.sh" "$RUN_DIR" "${REPO_ROOT}/prompts/challenger.md" \
    challenger "$ARM" "$CHALLENGER_HOME"
fi

# --- the verdict record -----------------------------------------------------
uv run --project "$REPO_ROOT" python - \
  "$RUN_DIR" "$BUNDLE_PATH" "$RUN_ID" "$ARM" <<'VERDICT_PY'
import json
import sys
from pathlib import Path

from elcapitan.records import validate_doc
from elcapitan.trial import now_rfc3339
from elcapitan.verdict import assemble_verdict, verdict_to_dict

run_dir, bundle_path, run_id, arm = sys.argv[1:5]

raw = Path(run_dir, "verdict", "verdict.json")
doc = json.loads(raw.read_text()) if raw.is_file() else {}

trace_path = Path(run_dir, "verdict", "moa-trace.json")
trace = json.loads(trace_path.read_text()) if trace_path.is_file() else []

manifest = json.loads(Path(bundle_path, "bundle.json").read_text())
evidence_ids = [r["evidence_id"] for r in manifest["artifacts"]]

verdict, failures = assemble_verdict(
    verdict_doc=doc, raw_trace=trace, run_id=run_id, arm=arm,
    verdict_id="VERD-001", now=now_rfc3339(), bundle_evidence_ids=evidence_ids)

record = verdict_to_dict(verdict)
Path(run_dir, "verdict", "review-verdict.json").write_text(json.dumps(record, indent=2))
schema_errors = validate_doc("review-verdict", record)
Path(run_dir, "verdict", "verdict-failures.json").write_text(
    json.dumps({"citation_and_dissent": failures, "schema": schema_errors}, indent=2))

print(f"  verdict: {verdict.decision} (dissent={verdict.dissent}, "
      f"extraction_incomplete={verdict.extraction_incomplete})")
for failure in failures + schema_errors:
    print(f"  VERDICT FAILURE: {failure}")
VERDICT_PY

# Five arguments, all three anchors from anchors/ and none from run_dir. An
# empty fourth would make validate_run report the run as unanchored;
# --no-cloud-state in the fifth would make it report the cloud as UNVERIFIED.
# Both fail the trial — deliberately, so a missing anchor is loud rather than
# a check that quietly did not run.
"${REPO_ROOT}/bin/validate-trial-artifacts.sh" "$RUN_DIR" "$CANONICAL_REPO" \
  "${ANCHOR_DIR}/repo-state-before.json" "$BUNDLE_SHA256" \
  "${ANCHOR_DIR}/cloud-state-before.json"

echo "run ${RUN_ID} complete"
