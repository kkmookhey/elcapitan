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
# The fourth argument is the input bundle hash computed BEFORE the trial and
# held outside the run directory. Nothing inside the run directory can anchor
# the run directory, so passing "" is not neutral: the validator reports the
# run as unanchored and fails it. Supply it whenever you have it.
#
# ## Why the fifth argument is mandatory
#
# The fifth is the pre-trial cloud state (cloud.to_dict's form, written by
# run-trial.sh to anchors/<run-id>/cloud-state-before.json). validate_run
# re-queries the finding's own resource and compares. This is what replaced
# the transcript mutation scan, which failed an honest Anna run four times for
# saying plainly that it had NOT deployed while AWS was independently
# confirmed untouched.
#
# validate_run's `cloud_state_before` is a keyword with no default that
# accepts None: you cannot forget it, but you can declare that none is
# available. Making the shell argument optional would erase exactly that
# property one layer out — an omitted fifth argument reads like "nothing to
# check", and a check that can be skipped by saying nothing is the failure
# class this whole mechanism exists to remove. So:
#
#   <cloud-state-before.json>   read it, pass it, compare.
#   --no-cloud-state            explicit declaration that no pre-trial capture
#                               exists. Still FAILS, with an UNVERIFIED
#                               failure naming the hole — it is an escape hatch
#                               for inspecting historical runs, not a way to
#                               pass one.
#   omitted                     usage error, exit 2. No verdict is printed,
#                               because none was reached.
#
# A path that is given but unreadable or malformed is a hard FAIL (exit 1),
# never a downgrade to --no-cloud-state: "the operator meant to check and the
# anchor is broken" and "the operator declared there is nothing to check" are
# different facts and must not produce the same verdict.
set -euo pipefail

USAGE="usage: validate-trial-artifacts.sh <run-dir> <canonical-repo> <repo-state-before.json> <expected-bundle-hash|\"\"> <cloud-state-before.json|--no-cloud-state>"

if [ "$#" -lt 5 ]; then
  echo "validate-trial-artifacts.sh: $USAGE" >&2
  if [ "$#" -eq 4 ]; then
    echo "  the fifth argument is required: pass the pre-trial cloud state, or" >&2
    echo "  --no-cloud-state to declare on the record that none was captured" >&2
    echo "  (which fails the run, loudly, rather than skipping the check)." >&2
  fi
  exit 2
fi

RUN_DIR="$1"
CANONICAL_REPO="$2"
REPO_STATE_BEFORE="$3"
EXPECTED_BUNDLE_HASH="$4"
CLOUD_STATE_BEFORE="$5"

# `uv run`, not bare `python3`: python3 resolves to whatever interpreter the
# operator's PATH happens to offer (system Python 3.14 on this host), which
# has no elcapitan on sys.path and no project dependencies — the script died
# with ModuleNotFoundError before a single check ran. --project pins it to
# this checkout regardless of the caller's working directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

uv run --project "$REPO_ROOT" python - \
  "$RUN_DIR" "$CANONICAL_REPO" "$REPO_STATE_BEFORE" "$EXPECTED_BUNDLE_HASH" \
  "$CLOUD_STATE_BEFORE" <<'PY'
import json
import sys

from elcapitan.cloud import read_state_file
from elcapitan.repo import RepoState
from elcapitan.validate import validate_run

(run_dir, canonical_repo, repo_state_path, expected_bundle_hash,
 cloud_state_path) = sys.argv[1:6]

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

if cloud_state_path == "--no-cloud-state":
    # Declared absent. validate_run turns this into the UNVERIFIED failure;
    # it is not swallowed here, and it is not a pass.
    cloud_state_before = None
else:
    try:
        cloud_state_before = read_state_file(cloud_state_path)
    except ValueError as exc:
        # Deliberately NOT degraded to None. A broken anchor the operator
        # believed in must not score the same as one they never had.
        print(f"FAIL: cannot read cloud-state-before from {cloud_state_path!r}: {exc}",
              file=sys.stderr)
        print("FAILED")
        sys.exit(1)

result = validate_run(run_dir, canonical_repo=canonical_repo,
                      repo_state_before=repo_state_before,
                      cloud_state_before=cloud_state_before,
                      expected_bundle_hash=expected_bundle_hash or None)
for failure in result.failures:
    print(f"FAIL: {failure}", file=sys.stderr)
if cloud_state_before is not None:
    # Printed regardless of pass/fail, next to the verdict a human actually
    # reads — not only in the cloud.py module docstring. The dominant failure
    # mode this project keeps finding is an over-trusted check; a bare "PASS"
    # invites reading "cloud mutation verified" as "the account is clean",
    # when the check inspects only the finding's own resource, only its
    # configuration, never its contents, and no other resource in the account.
    #
    # The resource KIND is derived from the provider rather than hard-coded.
    # It said "one S3 bucket" for an Azure storage account until the first
    # 20-cell dry run printed that twenty times: a scope note that misnames
    # what was checked is worse than no scope note, because it is read as
    # precision.
    _KIND = {"aws": ("S3 bucket", "bucket contents"),
             "azure": ("storage account", "blob contents")}
    kind, contents = _KIND.get(cloud_state_before.provider,
                               (f"{cloud_state_before.provider} resource",
                                "resource contents"))
    print(f"NOTE: cloud check scope — {len(cloud_state_before.config)} "
          f"configuration aspects of one {kind} "
          f"({cloud_state_before.resource_uid}); {contents} and every "
          f"other resource in the account are unchecked.", file=sys.stderr)
print("PASS" if result.passed else "FAILED")
sys.exit(0 if result.passed else 1)
PY
