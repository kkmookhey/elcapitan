#!/usr/bin/env bash
# bin/spike-image.sh — reproduces the Task 0 spike against the pinned Hermes image.
#
# Findings live in docs/spike-findings.md. This script exists so they can be
# re-checked against a future image rather than trusted indefinitely.
#
# Requires: docker, sqlite3, and ANTHROPIC_API_KEY in the environment.
set -euo pipefail

IMAGE="${HERMES_IMAGE:-nousresearch/hermes-agent:v2026.8.3}"
MODEL="${HERMES_MODEL:-anthropic/claude-sonnet-5}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
HOME_DIR="$WORK/home"; RUN_DIR="$WORK/run"
mkdir -p "$HOME_DIR" "$RUN_DIR"

: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY (see .env)}"

echo "== Q1: image identity"
docker image inspect "$IMAGE" --format '  digest: {{index .RepoDigests 0}}' 2>/dev/null \
  || { echo "  pulling…"; docker pull -q "$IMAGE"; \
       docker image inspect "$IMAGE" --format '  digest: {{index .RepoDigests 0}}'; }
docker image inspect "$IMAGE" --format '  entrypoint: {{json .Config.Entrypoint}}  user: {{.Config.User}}'

echo "== Q4: does an empty /opt/data suffice? (no setup wizard)"
touch "$RUN_DIR/alpha.txt" "$RUN_DIR/beta.txt" "$RUN_DIR/gamma.txt"

echo "== Q2/Q3: non-interactive run with terminal tools"
set +e
docker run --rm \
  -v "$HOME_DIR:/opt/data" -v "$RUN_DIR:/work/run" \
  -e ANTHROPIC_API_KEY \
  "$IMAGE" \
  chat -q "Use a shell command to count the files in /work/run, then write just that number to /work/run/out.txt" \
  -t terminal --yolo --max-turns 10 -m "$MODEL" \
  >"$WORK/stdout.txt" 2>"$WORK/stderr.txt"
RUN_EXIT=$?
set -e
echo "  exit=$RUN_EXIT   out.txt=$(cat "$RUN_DIR/out.txt" 2>/dev/null || echo MISSING)"
echo "  stdout tool preview (truncated by design — NOT the transcript):"
grep -E "💻" "$WORK/stdout.txt" | sed 's/^/    /' || echo "    (none)"

echo "== Q3: the real transcript and usage live in state.db"
DB="$HOME_DIR/state.db"
echo "  commands issued:"
sqlite3 "$DB" "select tool_calls from messages where tool_calls is not null and tool_calls != ''" \
  | sed 's/^/    /' | cut -c1-160
echo "  tool results (structured, with exit codes):"
sqlite3 "$DB" "select content from messages where role='tool'" | sed 's/^/    /'
echo "  usage:"
sqlite3 -header "$DB" "select model, api_call_count, input_tokens, output_tokens, estimated_cost_usd from session_model_usage" \
  | sed 's/^/    /'

echo "== Q5: --user with an arbitrary uid must be rejected"
set +e
docker run --rm --user 1000:1000 -v "$HOME_DIR:/opt/data" "$IMAGE" chat -q "hi" >"$WORK/user.txt" 2>&1
echo "  --user 1000 exit=$?  (expect 1)"
set -e

echo "== Q6: exit code is NOT a success signal"
set +e
docker run --rm -v "$WORK/nokey:/opt/data" "$IMAGE" \
  chat -q "say ok" -m "$MODEL" --yolo >"$WORK/nokey.txt" 2>&1
echo "  no-api-key exit=$?  (expect 0 — this is the finding)"
docker run --rm -v "$HOME_DIR:/opt/data" -e ANTHROPIC_API_KEY "$IMAGE" \
  chat -q "say ok" -m anthropic/no-such-model-xyz --yolo >"$WORK/badmodel.txt" 2>&1
echo "  bad-model  exit=$?  (expect 0 — $(grep -c 404 "$WORK/badmodel.txt") HTTP 404s)"
set -e

echo
echo "Spike complete. If any 'expect' above did not hold, docs/spike-findings.md is stale."
