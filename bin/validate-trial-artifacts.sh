#!/usr/bin/env bash
# bin/validate-trial-artifacts.sh
#
# Host-side wrapper around elcapitan.validate.validate_run — the final
# authority on whether a trial's artifacts hold up. Takes the run directory,
# the canonical repository path, and a JSON snapshot of the repository state
# captured before the trial started (RepoState: {"commit": ..., "dirty_files":
# [...]}). validate_run recomputes the repository's current state itself; it
# is never handed a caller-supplied digest to compare against its own copy.
set -euo pipefail

RUN_DIR="${1:?usage: validate-trial-artifacts.sh <run-dir> <canonical-repo> <repo-state-before.json>}"
CANONICAL_REPO="${2:?missing canonical repository path}"
REPO_STATE_BEFORE="${3:?missing repo-state-before.json path}"

python3 - "$RUN_DIR" "$CANONICAL_REPO" "$REPO_STATE_BEFORE" <<'PY'
import json
import sys

from elcapitan.repo import RepoState
from elcapitan.validate import validate_run

run_dir, canonical_repo, repo_state_path = sys.argv[1:4]

with open(repo_state_path) as fh:
    state = json.load(fh)
repo_state_before = RepoState(commit=state["commit"],
                              dirty_files=tuple(state.get("dirty_files", ())))

result = validate_run(run_dir, canonical_repo=canonical_repo,
                      repo_state_before=repo_state_before)
for failure in result.failures:
    print(f"FAIL: {failure}", file=sys.stderr)
print("PASS" if result.passed else "FAILED")
sys.exit(0 if result.passed else 1)
PY
