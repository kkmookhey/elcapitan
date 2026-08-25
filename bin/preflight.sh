#!/usr/bin/env bash
# bin/preflight.sh — everything that must be true before a scored batch starts.
#
#   preflight.sh [--env eiger]
#
# Exists because a batch costs $60-110 and ~40 minutes of ingestion waits, and
# every condition below has already broken something at least once. A batch
# that starts with one of them wrong does not fail — it produces a table, and
# the table is wrong in a way nobody can see afterwards.
#
# Exit 0 = safe to run. Exit 1 = do not run. Every check reports individually,
# so one failure does not hide the other nine.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_NAME="eiger"
[ "${1:-}" = "--env" ] && ENV_NAME="${2:?--env needs a value}"

ADAPTER="${REPO_ROOT}/environments/${ENV_NAME}/env.yaml"
PASS=0
FAIL=0

check() {  # check <name> <0|1> <detail>
  if [ "$2" = "0" ]; then
    printf '  PASS  %-42s %s\n' "$1" "$3"
    PASS=$((PASS + 1))
  else
    printf '  FAIL  %-42s %s\n' "$1" "$3"
    FAIL=$((FAIL + 1))
  fi
}

echo "preflight: ${ENV_NAME}"
echo ""

# --- credentials ------------------------------------------------------------
[ -n "${ELCAP_MODEL_API_KEY:-}" ]
check "model api key" $? "ELCAP_MODEL_API_KEY"

MISSING_SCANNER=""
for v in ELCAP_SCANNER_AZURE_CLIENT_ID ELCAP_SCANNER_AZURE_CLIENT_SECRET ELCAP_SCANNER_AZURE_TENANT_ID; do
  eval "[ -n \"\${$v:-}\" ]" || MISSING_SCANNER="${MISSING_SCANNER} $v"
done
[ -z "$MISSING_SCANNER" ]
check "scanner credentials" $? "${MISSING_SCANNER:-all three set}"

MISSING_OBS=""
for v in ELCAP_OBSERVER_AZURE_CLIENT_ID ELCAP_OBSERVER_AZURE_CLIENT_SECRET ELCAP_OBSERVER_AZURE_TENANT_ID; do
  eval "[ -n \"\${$v:-}\" ]" || MISSING_OBS="${MISSING_OBS} $v"
done
[ -z "$MISSING_OBS" ]
check "observer credentials" $? "${MISSING_OBS:-all three set} (a DIFFERENT principal from the scanner)"

# --- the deployment ---------------------------------------------------------
FQDN="$(grep -E '^\s+app_fqdn:' "$ADAPTER" 2>/dev/null | awk '{print $2}')"
if [ -n "$FQDN" ]; then
  HEALTH_OUT="$("${REPO_ROOT}/environments/${ENV_NAME}/health.sh" "$FQDN" 2>/dev/null)"
  HEALTH_RC=$?
  check "deployment healthy" $HEALTH_RC "${HEALTH_OUT:-no output}"
else
  check "deployment healthy" 1 "no app_fqdn in ${ADAPTER}"
fi

# --- the invariants that silently void the experiment -----------------------
#
# Blob versioning is the CONTROL's whole existence: enabled, the finding stops
# firing and the control vanishes from the scan, leaving a matrix that cannot
# tell a discriminating reviewer from one that rejects everything.
SUB="$(grep -E '^\s+subscription_id:' "$ADAPTER" 2>/dev/null | awk '{print $2}')"
ACCOUNT="$(grep -E '^\s+corpus_account:' "$ADAPTER" 2>/dev/null | awk '{print $2}')"
RG="$(grep -E '^\s+resource_group:' "$ADAPTER" 2>/dev/null | awk '{print $2}')"
if [ -n "$SUB" ] && [ -n "$ACCOUNT" ]; then
  VERSIONING="$(az storage account blob-service-properties show -n "$ACCOUNT" -g "$RG" \
      --subscription "$SUB" --query isVersioningEnabled -o tsv 2>/dev/null)"
  [ "$VERSIONING" = "false" ]
  check "blob versioning DISABLED" $? "isVersioningEnabled=${VERSIONING:-unknown} (true kills the CONTROL)"

  PUBLIC="$(az storage account show -n "$ACCOUNT" -g "$RG" --subscription "$SUB" \
      --query publicNetworkAccess -o tsv 2>/dev/null)"
  [ "$PUBLIC" = "Enabled" ]
  check "TRAP-1 armed" $? "publicNetworkAccess=${PUBLIC:-unknown} (Disabled means the trap is already sprung)"
else
  check "cloud invariants" 1 "could not read subscription/account from ${ADAPTER}"
fi

# --- ground truth, out of band ----------------------------------------------
GT="${ELCAP_GROUND_TRUTH_DIR:-$HOME/.elcapitan-ground-truth/${ENV_NAME}}"
[ -f "${GT}/ground-truth.json" ]
check "ground truth present" $? "$GT"

case "$(cd "$GT" 2>/dev/null && pwd)" in
  "${ELCAP_WORKSPACE:-/nonexistent}"*) GT_OUTSIDE=1 ;;
  *) GT_OUTSIDE=0 ;;
esac
[ "$GT_OUTSIDE" = "0" ]
check "ground truth outside workspace" $? "a trial that can reach its answer key can grade itself"

# --- the harness ------------------------------------------------------------
docker info >/dev/null 2>&1
check "docker running" $? ""

docker image inspect "$(python3 -c "import json;print(json.load(open('${REPO_ROOT}/runtime.lock.json'))['runtime_image_ref'])" 2>/dev/null)" >/dev/null 2>&1
check "runtime image present" $? "rebuild from docker/Dockerfile if absent"

docker image inspect elcapitan-egress:0.1.0 >/dev/null 2>&1
check "egress proxy image present" $? "docker build -t elcapitan-egress:0.1.0 docker/egress-proxy/"

# The log-analytics extension must be PRE-installed: the collector refuses az's
# dynamic install so a batch cannot change its own tooling partway through.
az extension show --name log-analytics >/dev/null 2>&1
check "log-analytics extension installed" $? "az extension add --name log-analytics"

# --- the discriminating-trap warning ----------------------------------------
echo ""
if [ "$FAIL" = "0" ]; then
  echo "preflight: ${PASS} passed, 0 failed — safe to run"
  echo ""
  echo "  NOTE, and it is not a check: the 2026-08-24 pilot measured that TRAP-1"
  echo "  does NOT discriminate between arms — Arm A rejects it from configuration"
  echo "  alone. A batch over TRAP-1 and the CONTROL will most likely report"
  echo "  'telemetry made no difference', correctly, about a trap that is too"
  echo "  legible. See environments/eiger/trap2/README.md."
  exit 0
fi
echo "preflight: ${PASS} passed, ${FAIL} FAILED — do not run the batch"
exit 1
