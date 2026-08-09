#!/usr/bin/env bash
# bin/validate-trial-artifacts.sh
#
# Host-side wrapper around elcapitan.validate.validate_run — the final
# authority on whether a trial's artifacts hold up. Takes the run directory,
# the canonical repository path, and a JSON snapshot of the repository state
# captured before the trial started (RepoState: {"commit": ..., "dirty_files":
# [...]}). validate_run recomputes the repository's current state itself; it
# is never handed a caller-supplied digest to compare against its own copy.
#
# The optional fourth argument is the input bundle hash computed BEFORE the
# trial and held outside the run directory. Nothing inside the run directory
# can anchor the run directory, so omitting it is not neutral: the validator
# reports the run as unanchored and fails it. Supply it whenever you have it.
set -euo pipefail

RUN_DIR="${1:?usage: validate-trial-artifacts.sh <run-dir> <canonical-repo> <repo-state-before.json> [expected-bundle-hash]}"
CANONICAL_REPO="${2:?missing canonical repository path}"
REPO_STATE_BEFORE="${3:?missing repo-state-before.json path}"
EXPECTED_BUNDLE_HASH="${4:-}"

# `uv run`, not bare `python3`: python3 resolves to whatever interpreter the
# operator's PATH happens to offer (system Python 3.14 on this host), which
# has no elcapitan on sys.path and no project dependencies — the script died
# with ModuleNotFoundError before a single check ran. --project pins it to
# this checkout regardless of the caller's working directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

uv run --project "$REPO_ROOT" python - \
  "$RUN_DIR" "$CANONICAL_REPO" "$REPO_STATE_BEFORE" "$EXPECTED_BUNDLE_HASH" <<'PY'
import json
import sys

from elcapitan.repo import RepoState
from elcapitan.validate import validate_run

run_dir, canonical_repo, repo_state_path, expected_bundle_hash = sys.argv[1:5]

try:
    with open(repo_state_path) as fh:
        state = json.load(fh)
    repo_state_before = RepoState(commit=state["commit"],
                                  dirty_files=tuple(state.get("dirty_files", ())))
except (OSError, ValueError, TypeError, KeyError) as exc:
    # The operator's own argument, not agent input — but this wrapper's
    # contract is to print a verdict, so a bad path or a malformed snapshot
    # exits with one rather than a traceback.
    print(f"FAIL: cannot read repo-state-before from {repo_state_path!r}: {exc}",
          file=sys.stderr)
    print("FAILED")
    sys.exit(1)

result = validate_run(run_dir, canonical_repo=canonical_repo,
                      repo_state_before=repo_state_before,
                      expected_bundle_hash=expected_bundle_hash or None)
for failure in result.failures:
    print(f"FAIL: {failure}", file=sys.stderr)
print("PASS" if result.passed else "FAILED")
sys.exit(0 if result.passed else 1)
PY
