#!/usr/bin/env bash
# bin/agent-run.sh — the engineer-stage entry point for elcapitan.shim.run_agent.
#
# Positional args (matches the calling convention sketched for bin/run-trial.sh
# in docs/superpowers/plans/2026-08-08-probe-substrate-and-shakedown.md, Task
# 12 — that script does not yet exist, this is written to be ready for it):
#
#   agent-run.sh <run-dir> <prompt-path> <stage> <arm> <host-hermes-home>
#
# <stage> is currently only "engineer" — challenger_spec is out of scope for
# this task. <arm> is accepted (Task 12's draft always passes one) but is not
# used by engineer_spec; it exists on the interface for forward compatibility.
#
# <host-hermes-home> may already exist (a caller that pre-seeded it, as
# Task 12's draft run-trial.sh does) or not (this script seeds it itself, per
# this task's own instructions, and cleans up after itself since nobody else
# owns that lifecycle in that case).
#
# ELCAP_CANONICAL_REPO must be set — read from the environment rather than
# taken as a positional argument so this matches the same variable
# run-trial.sh already requires (docs/superpowers/plans/2026-08-08-probe-
# substrate-and-shakedown.md, Task 12 draft), and so agent-run.sh can be
# invoked standalone with the same env-var contract a harness would use.
#
# Required secrets (see src/elcapitan/shim.py's SCANNER_ENV_MAP/MODEL_ENV_MAP):
#   ELCAP_MODEL_API_KEY                    -> ANTHROPIC_API_KEY   (required)
#   ELCAP_SCANNER_AWS_ACCESS_KEY_ID        -> AWS_ACCESS_KEY_ID   (optional, all-or-nothing)
#   ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY    -> AWS_SECRET_ACCESS_KEY
#   ELCAP_SCANNER_AWS_SESSION_TOKEN        -> AWS_SESSION_TOKEN
#
# Scanner credentials are optional here: a smoke run of the shim (e.g. "count
# the files in /work/run") needs no cloud credentials at all, and requiring
# them unconditionally would make agent-run.sh unusable for that. When any of
# the three ELCAP_SCANNER_* variables is set, all three must be — a partial
# AWS credential trio is a configuration error, not something to run with.
#
# ELCAP_MODEL / ELCAP_PROVIDER select the model (default: claude-sonnet-5 /
# anthropic, matching the model docs/spike-findings.md proved end to end).
#
# Exit status is NOT the underlying process's exit code — per docs/spike-
# findings.md §6, that is 0 even for a run that never produced a completion.
# This script exits 0 only when AgentResult.succeeded is true; nonzero
# otherwise, so a caller running under `set -e` (as Task 12's draft
# run-trial.sh does) stops rather than treating a failed trial as done.
set -euo pipefail

RUN_DIR="${1:?usage: agent-run.sh <run-dir> <prompt-path> <stage> <arm> <host-hermes-home>}"
PROMPT_PATH="${2:?missing prompt path}"
STAGE="${3:?missing stage}"
ARM="${4:?missing arm}"
HOST_HERMES_HOME="${5:?missing host hermes home}"
: "${ELCAP_MODEL_API_KEY:?ELCAP_MODEL_API_KEY must be set (maps to ANTHROPIC_API_KEY)}"

# The two stages want DIFFERENT inputs, and the difference is the experiment's
# only structural guarantee. The engineer reads the repository; the challenger
# reads one bundle and has no repository at all, because "Arm A has no
# telemetry" must be a fact about what it could know, not about what it was
# politely handed.
case "$STAGE" in
  engineer)
    : "${ELCAP_CANONICAL_REPO:?ELCAP_CANONICAL_REPO must be set for the engineer stage}"
    BUNDLE_PATH=""
    ;;
  challenger)
    : "${ELCAP_BUNDLE_PATH:?ELCAP_BUNDLE_PATH must be set for the challenger stage — the bundle it judges}"
    [ -d "$ELCAP_BUNDLE_PATH" ] || {
      echo "agent-run.sh: bundle $ELCAP_BUNDLE_PATH does not exist" >&2; exit 2; }
    # Deliberately empty. The challenger gets no repository, and passing one
    # here would be the quietest possible way to break the arms apart.
    ELCAP_CANONICAL_REPO=""
    BUNDLE_PATH="$ELCAP_BUNDLE_PATH"
    ;;
  *)
    # Plain "$STAGE" quoting, not "${STAGE@Q}" — @Q is a bash 4.4+ operator
    # and stock macOS ships bash 3.2, which dies with "bad substitution" on
    # this exact line — the error path meant to give a clear message instead
    # gave a confusing one on the most common dev machine for this project.
    echo "agent-run.sh: unsupported stage '$STAGE' (expected \"engineer\" or \"challenger\")" >&2
    exit 2
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="$REPO_ROOT/runtime.lock.json"
[ -f "$LOCK_FILE" ] || { echo "agent-run.sh: missing $LOCK_FILE" >&2; exit 2; }

SEEDED_HOME=0
if [ ! -e "$HOST_HERMES_HOME" ]; then
  SEEDED_HOME=1
fi
cleanup() {
  if [ "$SEEDED_HOME" = "1" ]; then
    rm -rf "$HOST_HERMES_HOME"
  fi
}
trap cleanup EXIT

# `uv run`, not bare `python3` — see bin/validate-trial-artifacts.sh for why:
# a bare python3 has no elcapitan on sys.path and no pinned dependencies.
uv run --project "$REPO_ROOT" python - \
  "$RUN_DIR" "$PROMPT_PATH" "$ELCAP_CANONICAL_REPO" "$HOST_HERMES_HOME" \
  "$LOCK_FILE" "$SEEDED_HOME" "$ARM" "$STAGE" "$BUNDLE_PATH" <<'PY'
import json
import os
import sys

from elcapitan.container import challenger_spec, engineer_spec
from elcapitan.home import seed_hermes_home
from elcapitan.shim import (ALL_SCANNER_ENV_NAMES, MODEL_ENV_MAP,
                            resolve_secret_env, run_agent, scanner_env_map)

(run_dir, prompt_path, canonical_repo, host_hermes_home,
 lock_path, seeded_home, arm, stage, bundle_path) = sys.argv[1:10]

model = os.environ.get("ELCAP_MODEL", "claude-sonnet-5")
provider = os.environ.get("ELCAP_PROVIDER", "anthropic")

if seeded_home == "1":
    seed_hermes_home(host_hermes_home, model=model, provider=provider)

lock = json.loads(open(lock_path).read())

secret_env = resolve_secret_env(os.environ, MODEL_ENV_MAP)
env_passthrough = list(MODEL_ENV_MAP.values())

# HERMES_UID/HERMES_GID are not secrets, but they travel the same way — by
# value through the subprocess environment, never through argv — because
# that is what ContainerSpec.env_passthrough -> `--env NAME` already does.
# docs/spike-findings.md §5: the image chowns /opt/data to uid 10000 on
# start; on Linux the host validator would otherwise face files it cannot
# read. Passing the real host uid/gid remaps the hermes user at boot instead.
secret_env["HERMES_UID"] = str(os.getuid())
secret_env["HERMES_GID"] = str(os.getgid())
env_passthrough += ["HERMES_UID", "HERMES_GID"]

# Which scanner credential the engineer gets depends on which cloud the
# environment is in. ELCAP_CLOUD is set by bin/run-trial.sh from the
# environment adapter's `cloud:` field; it is not defaulted here, because a
# default is how every entry point in this harness came to demand AWS.
# THE CHALLENGER GETS NO CLOUD CREDENTIAL, and the check is here rather than
# only in challenger_spec because reaching that raise would mean this script
# had already decided to hand one over. challenger_spec still refuses — two
# independent guards on the one property the whole comparison rests on.
scanner_present = (sorted(ALL_SCANNER_ENV_NAMES & set(os.environ))
                   if stage == "engineer" else [])
if scanner_present:
    cloud = os.environ.get("ELCAP_CLOUD", "")
    if not cloud:
        print(f"agent-run.sh: scanner credentials are set ({scanner_present}) but "
              f"ELCAP_CLOUD names no provider, so there is no way to tell which of "
              f"them this environment needs", file=sys.stderr)
        sys.exit(2)
    try:
        scanner_map = scanner_env_map(cloud)
    except ValueError as exc:
        print(f"agent-run.sh: {exc}", file=sys.stderr)
        sys.exit(2)

    missing = sorted(set(scanner_map) - set(scanner_present))
    if missing:
        print(f"agent-run.sh: partial {cloud} scanner credentials set; "
              f"missing {missing}", file=sys.stderr)
        sys.exit(2)
    # A second cloud's credentials in the same environment would be handed to
    # the agent alongside the first. The engineer holds exactly one cloud's
    # read-only scanner credential — the one its environment is in.
    foreign = sorted(set(scanner_present) - set(scanner_map))
    if foreign:
        print(f"agent-run.sh: this is a {cloud} environment but credentials for "
              f"another cloud are also set: {foreign}", file=sys.stderr)
        sys.exit(2)

    secret_env.update(resolve_secret_env(os.environ, scanner_map))
    env_passthrough += list(scanner_map.values())

if stage == "challenger":
    spec = challenger_spec(runtime_image_id=lock["runtime_image_id"], run_dir=run_dir,
                           bundle_path=bundle_path, host_hermes_home=host_hermes_home,
                           arm=arm, env_passthrough=env_passthrough)
else:
    spec = engineer_spec(runtime_image_id=lock["runtime_image_id"], run_dir=run_dir,
                         canonical_repo=canonical_repo,
                         host_hermes_home=host_hermes_home,
                         env_passthrough=env_passthrough)

result = run_agent(spec, prompt_path, secret_env=secret_env,
                   model=f"{provider}/{model}")

summary = {
    "exit_code": result.exit_code,
    "succeeded": result.succeeded,
    "session_id": result.session_id,
    "finish_reason": result.finish_reason,
    "tool_call_count": result.tool_call_count,
    "usage": result.usage,
    # False means run_dir/state.db — the primary evidence record — is absent
    # or was not archived. run_agent degrades rather than raising on that
    # (see _capture_state_db), so without this field a silent capture failure
    # is invisible to anyone reading this script's output.
    "state_db_captured": result.state_db_captured,
    "arm": arm,
    "stage": stage,
}
print(json.dumps(summary, indent=2))
sys.exit(0 if result.succeeded else 1)
PY
