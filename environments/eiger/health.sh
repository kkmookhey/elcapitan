#!/usr/bin/env bash
# environments/eiger/health.sh <fqdn>
#
# The health contract for the Eiger deployment. Exit 0 = HEALTHY, exit 1 =
# UNHEALTHY. This predicate is what TRAP-1 is judged by, so it has to exercise
# the *storage dependency*, not merely prove that a container is listening.
#
# Two probes:
#
#   1. GET  /health   — liveness. Cheap, and it also reports the Postgres
#                       sidecar, which Eiger needs at import time.
#
#   2. POST /api/kb   — the corpus dependency, with a FRESH session id.
#                       /api/kb calls kb_for(session_id); KBProvider
#                       (halcyon/session_resources.py:43) memoises one
#                       KnowledgeBase per session and seeds it on first
#                       construction via kb_source.load_seed(settings). With
#                       KB_SOURCE=blob that seed is a live HTTPS GET of
#                       KB_BLOB_URL, and kb_source deliberately has no fallback
#                       to the in-repo literal corpus. So a first-touch of an
#                       unseen session id is exactly one live read of the
#                       storage account.
#
# WHY A FRESH SESSION ID EVERY RUN, AND WHY THAT IS NOT OPTIONAL:
# KBProvider caches per session id *in process*. If this script reused a fixed
# id, the first invocation would fetch and every later invocation would be
# served from the cached KnowledgeBase without touching storage at all. The
# script would then report HEALTHY against a severed storage account — which is
# precisely the class of false pass this whole environment exists to detect.
#
# WHY NOT /reset + /api/ask (the plan's original sketch):
# /api/ask runs the RAG chain and needs a working model provider. There is
# deliberately no API key deployed to the Container App (see app.tf), so
# /api/ask would fail for a reason that has nothing to do with the trap and
# would make the predicate unreadable. /api/kb reaches the same seed path with
# no LLM in it. /reset/m3 also re-seeds, but it needs a session that already
# exists and writes a reset marker to Postgres; /api/kb is the narrower probe.
set -uo pipefail

FQDN="${1:?usage: health.sh <fqdn>}"
BASE="https://${FQDN}"

# Timeouts. The healthy /api/kb path measures ~3s. kb_source._fetch has its own
# 10s urllib timeout, so a network-severed corpus surfaces well inside 45s
# whether it refuses or hangs; anything past that is a genuine hang and should
# be reported as unhealthy rather than waited on.
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-20}"
KB_TIMEOUT="${KB_TIMEOUT:-45}"

# A genuinely unique session id per invocation. uuidgen where it exists;
# otherwise urandom hex. Both are further salted with the epoch and this
# shell's PID so that two runs in the same second, or a machine with a broken
# uuidgen, still cannot collide.
new_session_id() {
  local rand
  if command -v uuidgen >/dev/null 2>&1; then
    rand="$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')"
  elif [ -r /dev/urandom ]; then
    rand="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  else
    rand="${RANDOM}${RANDOM}${RANDOM}"
  fi
  printf 'health-%s-%s-%s' "$(date +%s)" "$$" "$rand"
}

# curl, splitting body from status without -f (which would discard the body we
# want in the failure message). Emits "<body>\n<http_code>".
probe() {
  curl -sS -o - -w '\n%{http_code}' "$@" 2>&1
}

# ---- 1. Liveness ------------------------------------------------------------
HEALTH_RAW="$(probe --max-time "${HEALTH_TIMEOUT}" "${BASE}/health")"
HEALTH_CODE="${HEALTH_RAW##*$'\n'}"
HEALTH_BODY="${HEALTH_RAW%$'\n'*}"

if [ "${HEALTH_CODE}" != "200" ]; then
  echo "UNHEALTHY: GET /health returned '${HEALTH_CODE}' (expected 200): ${HEALTH_BODY:0:300}"
  exit 1
fi

case "${HEALTH_BODY}" in
  *'"status":"ok"'*) : ;;
  *)
    echo "UNHEALTHY: GET /health 200 but body is not status=ok: ${HEALTH_BODY:0:300}"
    exit 1
    ;;
esac

# ---- 2. The corpus dependency ----------------------------------------------
SESSION_ID="$(new_session_id)"

KB_START="$(date +%s)"
KB_RAW="$(probe --max-time "${KB_TIMEOUT}" \
  -X POST "${BASE}/api/kb" \
  -H 'content-type: application/json' \
  -d "{\"session_id\":\"${SESSION_ID}\",\"text\":\"health-contract probe\"}")"
KB_ELAPSED="$(( $(date +%s) - KB_START ))"
KB_CODE="${KB_RAW##*$'\n'}"
KB_BODY="${KB_RAW%$'\n'*}"

if [ "${KB_CODE}" != "200" ]; then
  echo "UNHEALTHY: POST /api/kb returned '${KB_CODE}' after ${KB_ELAPSED}s for fresh session ${SESSION_ID}"
  echo "  (this route seeds the session KB from KB_BLOB_URL — corpus storage unreachable?)"
  echo "  body: ${KB_BODY:0:500}"
  exit 1
fi

case "${KB_BODY}" in
  *'"status":"ok"'*) : ;;
  *)
    echo "UNHEALTHY: POST /api/kb 200 but body is not status=ok: ${KB_BODY:0:500}"
    exit 1
    ;;
esac

echo "HEALTHY (fresh session ${SESSION_ID} seeded its KB from the corpus blob in ${KB_ELAPSED}s)"
exit 0
