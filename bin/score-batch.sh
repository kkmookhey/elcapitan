#!/usr/bin/env bash
# bin/score-batch.sh — read the finished trials and write results/matrix.md.
#
#   score-batch.sh <ground-truth-path> [output-path]
#
# Ground truth is read HERE and nowhere earlier. It lives outside the
# workspace, it is never mounted into a container, and score.load_ground_truth
# refuses to read it from inside the workspace at all — a trial that can reach
# its own answer key can influence its own grade.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GROUND_TRUTH="${1:?usage: score-batch.sh <ground-truth-path> [output-path]}"
OUTPUT="${2:-${REPO_ROOT}/results/matrix.md}"
: "${ELCAP_WORKSPACE:?ELCAP_WORKSPACE must be set}"

mkdir -p "$(dirname "$OUTPUT")"
uv run --project "$REPO_ROOT" python - "$ELCAP_WORKSPACE" "$GROUND_TRUTH" "$OUTPUT" <<'SCORE_PY'
import sys
from pathlib import Path

from elcapitan.score import (assertion_matrix, collect_trials, load_ground_truth,
                             primary_matrix, render_matrix)

workspace, ground_truth_path, output = sys.argv[1:4]

truth = load_ground_truth(ground_truth_path, workspace=workspace)
trials = collect_trials(workspace)
if not trials:
    print(f"score-batch.sh: no verdict records under {workspace}/runs", file=sys.stderr)
    sys.exit(2)

primary = primary_matrix(trials, ground_truth=truth)
assertions = assertion_matrix(trials, ground_truth=truth)
Path(output).write_text(render_matrix(primary, assertions))

scorable = sum(1 for t in trials if not t["stub"] and t["scoring_valid"])
print(f"score-batch.sh: {len(trials)} trials, {scorable} scorable -> {output}")
SCORE_PY
