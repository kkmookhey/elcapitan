#!/usr/bin/env bash
# bin/run-batch.sh — the scored matrix, in a randomised and reproducible order.
#
#   run-batch.sh --seed <seed> [--env eiger] [--cases FIND-002,FIND-003]
#                [--arms A,B] [--trials 5] [--plan-only] [--continue-on-failure]
#
# ## Why the order is shuffled
#
# A batch that ran all of arm A and then all of arm B would let ANY drift
# during the batch masquerade as an arm effect: a model-service change, a
# quota throttle that kicks in late, environment drift, the corpus warming.
# Interleaving removes that. It does not remove drift; it stops drift from
# aligning with the independent variable.
#
# ## Why the seed is required and recorded
#
# A shuffle nobody can reproduce is indistinguishable from one that never
# happened, and "we randomised" is then an unverifiable claim about a results
# table. The seed is a required argument rather than something this script
# generates, because a generated seed is one more thing that has to be
# remembered to be written down. It is echoed into the plan and into
# batch-manifest.json.
#
# ## Why one failure does not stop the batch
#
# Twenty trials, real money, ~40 minutes of ingestion waits. One trial dying on
# a transient API error must cost one row, not nineteen. Failures are recorded
# as failures — a batch that silently retried would hide a systematic problem
# behind an eventually-green run.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SEED=""
ENV_NAME="eiger"
CASES="FIND-002,FIND-003"
ARMS="A,B"
TRIALS=5
PLAN_ONLY=0
CONTINUE_ON_FAILURE=1
# A HARD ceiling, not a warning. The batch stops when the next trial could
# cross it, because a budget checked only afterwards is a report, not a limit.
BUDGET_USD="${ELCAP_BUDGET_USD:-50}"

while [ $# -gt 0 ]; do
  case "$1" in
    --seed)   SEED="${2:?--seed needs a value}"; shift 2 ;;
    --env)    ENV_NAME="${2:?--env needs a value}"; shift 2 ;;
    --cases)  CASES="${2:?--cases needs a value}"; shift 2 ;;
    --arms)   ARMS="${2:?--arms needs a value}"; shift 2 ;;
    --trials) TRIALS="${2:?--trials needs a value}"; shift 2 ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    --budget-usd) BUDGET_USD="${2:?--budget-usd needs a value}"; shift 2 ;;
    --stop-on-failure) CONTINUE_ON_FAILURE=0; shift ;;
    *) echo "run-batch.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

if [ -z "$SEED" ]; then
  echo "run-batch.sh: --seed is required. It is not generated here on purpose:" >&2
  echo "  a seed this script invented would have to be remembered to be written" >&2
  echo "  down, and an order nobody can reproduce is not a controlled variable." >&2
  exit 2
fi

# The plan is built in Python because shell has no seeded shuffle whose
# behaviour is stable across platforms — `sort -R` and `shuf --random-source`
# differ between GNU and BSD, and a batch whose order depended on which
# coreutils the operator had would be reproducible only by accident.
# Written to a file rather than captured with $( ). A heredoc inside a command
# substitution makes bash scan the heredoc body looking for the closing paren,
# so an apostrophe in a Python comment becomes an unterminated quote and the
# script dies with "unexpected EOF" pointing at a line far from the cause.
# Measured the hard way.
PLAN_FILE="$(mktemp)"
trap 'rm -f "$PLAN_FILE" "${ORDER_FILE:-}"' EXIT

uv run --project "$REPO_ROOT" python - \
  "$SEED" "$ENV_NAME" "$CASES" "$ARMS" "$TRIALS" "$PLAN_FILE" <<'PLAN_PY'
import json
import random
import sys

seed, env_name, cases, arms, trials, out_path = sys.argv[1:7]

cells = []
for finding_id in cases.split(","):
    for arm in arms.split(","):
        for n in range(1, int(trials) + 1):
            cells.append({"env": env_name, "finding_id": finding_id, "arm": arm,
                          "n": n, "run_id": f"{env_name}-{finding_id}-arm{arm}-n{n}"})

# random.Random(seed) seeds from the bytes of the string directly, so
# PYTHONHASHSEED does not affect it: same seed, same order, any machine, any
# run. That is the property the recorded seed is supposed to buy.
random.Random(seed).shuffle(cells)
with open(out_path, "w") as handle:
    json.dump({"seed": seed, "env": env_name, "cells": cells}, handle, indent=2)
PLAN_PY
[ -s "$PLAN_FILE" ] || { echo "run-batch.sh: could not build the plan" >&2; exit 2; }
PLAN="$(cat "$PLAN_FILE")"

if [ "$PLAN_ONLY" = "1" ]; then
  echo "$PLAN"
  exit 0
fi

: "${ELCAP_WORKSPACE:?ELCAP_WORKSPACE must be set}"
BATCH_DIR="${ELCAP_WORKSPACE}/batches/$(date -u +%Y%m%dT%H%M%SZ)-${SEED}"
mkdir -p "$BATCH_DIR"
echo "$PLAN" > "${BATCH_DIR}/plan.json"

echo "run-batch.sh: ${ENV_NAME}, seed ${SEED}, $(echo "$PLAN" | grep -c '"run_id"') cells"
echo "  batch directory: ${BATCH_DIR}"

RESULTS="${BATCH_DIR}/results.jsonl"
: > "$RESULTS"

# The execution order, flattened to TSV before the loop rather than piped into
# it. A process substitution here would put the loop in a subshell on some
# shells, and FAILED would come back zero however many trials died.
ORDER_FILE="${BATCH_DIR}/order.tsv"
uv run --project "$REPO_ROOT" python - "${BATCH_DIR}/plan.json" "$ORDER_FILE" <<'ORDER_PY'
import json
import sys

plan = json.loads(open(sys.argv[1]).read())
with open(sys.argv[2], "w") as handle:
    for cell in plan["cells"]:
        handle.write("\t".join([cell["run_id"], cell["finding_id"],
                                 cell["arm"], str(cell["n"])]) + "\n")
ORDER_PY

FAILED=0
INDEX=0
SPENT=0
BUDGET_STOPPED=0
while IFS=$'\t' read -r RUN_ID FINDING_ID ARM N; do
  INDEX=$((INDEX + 1))
  echo ""
  echo "=== [${INDEX}] ${RUN_ID} ==="
  STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  RUN_DIR_FOR_COST="${ELCAP_WORKSPACE}/runs/${RUN_ID}"
  if "${REPO_ROOT}/bin/run-trial.sh" "$ENV_NAME" "$FINDING_ID" "$ARM" "$N"; then
    STATUS="completed"
  else
    STATUS="failed"
    FAILED=$((FAILED + 1))
    echo "run-batch.sh: ${RUN_ID} FAILED — recorded and continuing" >&2
    if [ "$CONTINUE_ON_FAILURE" = "0" ]; then
      echo "run-batch.sh: --stop-on-failure was set; stopping" >&2
      printf '{"run_id":"%s","order":%d,"status":"%s","started_at":"%s","finished_at":"%s"}\n' \
        "$RUN_ID" "$INDEX" "$STATUS" "$STARTED" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RESULTS"
      break
    fi
  fi
  # Cost is read from what the agents actually reported, never estimated from
  # a per-trial average: an average is exactly wrong on the trial that runs
  # long, which is the one that would cross the ceiling.
  TRIAL_COST="$(uv run --project "$REPO_ROOT" python - "$RUN_DIR_FOR_COST" <<'COST_PY'
import json
import sys
from pathlib import Path

total = 0.0
for name in ("summary.json", "verdict/summary.json"):
    path = Path(sys.argv[1]) / name
    if path.is_file():
        try:
            usage = json.loads(path.read_text()).get("usage") or {}
            total += float(usage.get("estimated_cost_usd") or 0.0)
        except (ValueError, TypeError):
            pass
print(f"{total:.6f}")
COST_PY
)"
  SPENT="$(uv run --project "$REPO_ROOT" python -c "print(f'{float(\'$SPENT\') + float(\'$TRIAL_COST\'):.6f}')")"

  printf '{"run_id":"%s","order":%d,"status":"%s","cost_usd":%s,"spent_usd":%s,"started_at":"%s","finished_at":"%s"}\n' \
    "$RUN_ID" "$INDEX" "$STATUS" "$TRIAL_COST" "$SPENT" "$STARTED" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RESULTS"

  # Stop BEFORE the trial that could cross, using the most expensive trial so
  # far as the estimate for the next one. Stopping after would mean the
  # ceiling was a description of what happened.
  OVER="$(uv run --project "$REPO_ROOT" python - "$RESULTS" "$BUDGET_USD" <<'BUDGET_PY'
import json
import sys

rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
spent = rows[-1]["spent_usd"] if rows else 0.0
worst = max((r.get("cost_usd", 0.0) for r in rows), default=0.0)
print("1" if spent + worst > float(sys.argv[2]) else "0")
BUDGET_PY
)"
  if [ "$OVER" = "1" ]; then
    echo "" >&2
    echo "run-batch.sh: STOPPING — spent \$${SPENT} of \$${BUDGET_USD}, and the next" >&2
    echo "  trial could cross it. ${INDEX} of $(wc -l < "$ORDER_FILE" | tr -d ' ') cells ran." >&2
    echo "  The cells that did NOT run are recorded in the manifest; a partial" >&2
    echo "  batch with a named gap is honest, a silently truncated one is not." >&2
    BUDGET_STOPPED=1
    break
  fi
done < "$ORDER_FILE"

COMPLETED=$(grep -c '"status":"completed"' "$RESULTS" || true)
cat > "${BATCH_DIR}/batch-manifest.json" <<MANIFEST
{
  "seed": "${SEED}",
  "env": "${ENV_NAME}",
  "cells_planned": $(echo "$PLAN" | grep -c '"run_id"'),
  "completed": ${COMPLETED},
  "failed": ${FAILED},
  "budget_usd": ${BUDGET_USD},
  "spent_usd": ${SPENT},
  "stopped_on_budget": ${BUDGET_STOPPED},
  "finished_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
MANIFEST

echo ""
echo "run-batch.sh: ${COMPLETED} completed, ${FAILED} failed, \$${SPENT} of \$${BUDGET_USD}"
echo "  ${BATCH_DIR}/batch-manifest.json"
# A batch with failures still exits 0: the failures are DATA, recorded per
# trial, and a non-zero exit would make a partially-successful batch look like
# a harness error to whatever ran it.
exit 0
