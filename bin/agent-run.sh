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
: "${ELCAP_CANONICAL_REPO:?ELCAP_CANONICAL_REPO must be set}"
: "${ELCAP_MODEL_API_KEY:?ELCAP_MODEL_API_KEY must be set (maps to ANTHROPIC_API_KEY)}"

if [ "$STAGE" != "engineer" ]; then
  # Plain "$STAGE" quoting, not "${STAGE@Q}" — @Q is a bash 4.4+ operator
  # and stock macOS ships bash 3.2, which dies with "bad substitution" on
  # this exact line — the error path meant to give a clear message instead
  # gave a confusing one on the most common dev machine for this project.
  echo "agent-run.sh: unsupported stage '$STAGE' (only \"engineer\" is implemented)" >&2
  exit 2
fi

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
  "$LOCK_FILE" "$SEEDED_HOME" "$ARM" <<'PY'
import json
import os
import sys

from elcapitan.container import engineer_spec
from elcapitan.home import seed_hermes_home
from elcapitan.shim import MODEL_ENV_MAP, SCANNER_ENV_MAP, resolve_secret_env, run_agent

(run_dir, prompt_path, canonical_repo, host_hermes_home,
 lock_path, seeded_home, arm) = sys.argv[1:8]

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

scanner_present = [k for k in SCANNER_ENV_MAP if k in os.environ]
if scanner_present:
    if len(scanner_present) != len(SCANNER_ENV_MAP):
        missing = sorted(set(SCANNER_ENV_MAP) - set(scanner_present))
        print(f"agent-run.sh: partial scanner credentials set; missing {missing}",
              file=sys.stderr)
        sys.exit(2)
    secret_env.update(resolve_secret_env(os.environ, SCANNER_ENV_MAP))
    env_passthrough += list(SCANNER_ENV_MAP.values())

spec = engineer_spec(runtime_image_id=lock["runtime_image_id"], run_dir=run_dir,
                     canonical_repo=canonical_repo, host_hermes_home=host_hermes_home,
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
}
print(json.dumps(summary, indent=2))
sys.exit(0 if result.succeeded else 1)
PY
