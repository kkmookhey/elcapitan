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
#
# ## The out-of-band anchor — the one property this script exists to hold
#
# Two reference values are captured BEFORE the trial and kept OUTSIDE the run
# directory, in ${ELCAP_WORKSPACE}/anchors/<run-id>/:
#
#   repo-state-before.json   the canonical repository's pre-trial state
#   bundle.sha256            the pre-trial input-bundle hash
#
# Nothing inside run_dir can anchor run_dir. The agent gets /work/run as a
# writable mount, so it can rewrite inputs/finding.json, that file's entry in
# inputs/input-manifest.json, and proposal.json's own input_bundle_hash
# together — a coherent forgery in which every internal consistency check the
# validator makes still holds. Only a value captured before the agent ran and
# stored where the agent cannot reach it detects that. The anchors directory
# is a SIBLING of runs/, and container.py's _reject_overbroad_mounts already
# refuses any mount that is an ancestor of run_dir, so no agent container can
# be given a view of it.
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

RUN_ID="${ENV_NAME}-${FINDING_ID}-arm${ARM}-n${TRIAL_N}"
RUN_DIR="${WORKSPACE}/runs/${RUN_ID}"
ANCHOR_DIR="${WORKSPACE}/anchors/${RUN_ID}"
if [ -e "$RUN_DIR" ] || [ -e "$ANCHOR_DIR" ]; then
  echo "run-trial.sh: run ${RUN_ID} exists — trials are immutable" >&2
  exit 3
fi
mkdir -p "$RUN_DIR/inputs" "$RUN_DIR/evidence" "$RUN_DIR/patch" "$RUN_DIR/verdict"
mkdir -p "$ANCHOR_DIR"

# Set before the trap so `set -u` cannot make the trap itself the failure.
HOME_PARENT=""
cleanup() {
  if [ -n "$HOME_PARENT" ]; then
    rm -rf "$HOME_PARENT"
  fi
}
trap cleanup EXIT
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

if [ "${ELCAP_STUB:-0}" = "1" ]; then
  uv run --project "$REPO_ROOT" python "${REPO_ROOT}/tests/stub_engineer.py" \
    "$RUN_DIR" "$FINDING_ID" "$HERMES_HOME"
else
  ELCAP_CANONICAL_REPO="$CANONICAL_REPO" \
    "${REPO_ROOT}/bin/agent-run.sh" "$RUN_DIR" "$RUN_DIR/prompt.md" engineer "$ARM" "$HERMES_HOME"
fi

# Four arguments. Three would make validate_run report the run as unanchored
# and fail it — deliberately, so a missing anchor is loud.
"${REPO_ROOT}/bin/validate-trial-artifacts.sh" "$RUN_DIR" "$CANONICAL_REPO" \
  "${ANCHOR_DIR}/repo-state-before.json" "$BUNDLE_SHA256"

echo "run ${RUN_ID} complete"
