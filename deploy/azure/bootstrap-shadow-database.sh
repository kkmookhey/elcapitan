#!/bin/zsh
set -euo pipefail

LAB_SUBSCRIPTION="8cd2b4cc-c789-466d-a8f7-8f51fb20985d"
LAB_RESOURCE_GROUP="elcapitan-remediation-lab-rg"
ENVIRONMENT="elcapitan-shadow-private-env"
IMAGE="ca7b25e7d425acr.azurecr.io/elcapitan-demo@sha256:474cf90f64b71d35787133768b5005750fddfa05ba005bf7211d18a10811486e"
PULL_ID="/subscriptions/${LAB_SUBSCRIPTION}/resourceGroups/${LAB_RESOURCE_GROUP}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/elcapitan-demo-pull"

if [[ $# -ne 7 ]]; then
  echo "usage: $0 SLUG SERVER ADMIN_LOGIN APP_ROLE APP_DATABASE KEYCHAIN_SERVICE CONFIRM-LAB-DATABASE-BOOTSTRAP" >&2
  exit 64
fi

SLUG="$1"
SERVER="$2"
ADMIN_LOGIN="$3"
APP_ROLE="$4"
APP_DATABASE="$5"
KEYCHAIN_SERVICE="$6"
CONFIRMATION="$7"

[[ "${CONFIRMATION}" == "CONFIRM-LAB-DATABASE-BOOTSTRAP" ]]
[[ "${SLUG}" =~ '^[a-z0-9]{2,10}$' ]]
[[ "${SERVER}" =~ '^elcapitan-[a-z0-9-]+$' ]]
[[ "${ADMIN_LOGIN}" =~ '^[a-z][a-z0-9_]{2,62}$' ]]
[[ "${APP_ROLE}" =~ '^[a-z][a-z0-9_]{2,62}$' ]]
[[ "${APP_DATABASE}" =~ '^[a-z][a-z0-9_]{2,62}$' ]]
[[ "${KEYCHAIN_SERVICE}" == "elcapitan-${SLUG}-db-bootstrap-password" ]]
[[ "$(az account show --query id -o tsv)" == "${LAB_SUBSCRIPTION}" ]]

HOST="${SERVER}.postgres.database.azure.com"
JOB_NAME="elcapitan-${SLUG}-db-bootstrap"
ADMIN_PASSWORD="Aa9_$(openssl rand -hex 32)"
APP_PASSWORD="Aa9_$(openssl rand -hex 32)"
ADMIN_URL="postgresql://${ADMIN_LOGIN}:${ADMIN_PASSWORD}@${HOST}/postgres?sslmode=require"
JOB_CREATED=0
ADMIN_NEEDS_SEAL=0
SUCCEEDED=0

cleanup() {
  if [[ "${JOB_CREATED}" == "1" ]]; then
    az containerapp job delete \
      --subscription "${LAB_SUBSCRIPTION}" \
      --resource-group "${LAB_RESOURCE_GROUP}" \
      --name "${JOB_NAME}" --yes --only-show-errors >/dev/null 2>&1 || true
  fi
  if [[ "${ADMIN_NEEDS_SEAL}" == "1" ]]; then
    SEALED_PASSWORD="Aa9_$(openssl rand -hex 32)"
    az postgres flexible-server update \
      --subscription "${LAB_SUBSCRIPTION}" \
      --resource-group "${LAB_RESOURCE_GROUP}" \
      --name "${SERVER}" --admin-password "${SEALED_PASSWORD}" \
      --only-show-errors -o none >/dev/null 2>&1 || true
  fi
  if [[ "${SUCCEEDED}" != "1" ]]; then
    security delete-generic-password -a elcapitan -s "${KEYCHAIN_SERVICE}" \
      >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

SERVER_STATE="$(az postgres flexible-server show \
  --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${SERVER}" \
  --query '[state,network.publicNetworkAccess]' -o tsv)"
[[ "${SERVER_STATE}" == $'Ready\nDisabled' ]]

security add-generic-password -U -a elcapitan -s "${KEYCHAIN_SERVICE}" \
  -w "${APP_PASSWORD}" >/dev/null

echo "Opening the private lab administrator for one scoped role rotation."
az postgres flexible-server update \
  --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${SERVER}" \
  --admin-password "${ADMIN_PASSWORD}" --only-show-errors -o none
ADMIN_NEEDS_SEAL=1

az containerapp job create \
  --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${JOB_NAME}" \
  --environment "${ENVIRONMENT}" --trigger-type Manual \
  --replica-timeout 300 --replica-retry-limit 0 \
  --replica-completion-count 1 --parallelism 1 --image "${IMAGE}" \
  --mi-user-assigned "${PULL_ID}" \
  --registry-server ca7b25e7d425acr.azurecr.io \
  --registry-identity "${PULL_ID}" \
  --secrets admin-url="${ADMIN_URL}" app-password="${APP_PASSWORD}" \
  --env-vars ELCAPITAN_BOOTSTRAP_ADMIN_URL=secretref:admin-url \
    ELCAPITAN_BOOTSTRAP_APP_PASSWORD=secretref:app-password \
  --cpu 0.25 --memory 0.5Gi --command elcapitan \
  --args bootstrap-postgres "${HOST}" "${APP_ROLE}" "${APP_DATABASE}" \
    CREATE-ISOLATED-DATABASE \
  --tags workload=elcapitan environment=customer-shadow purpose=one-time-bootstrap \
  --only-show-errors -o none
JOB_CREATED=1

EXECUTION_NAME="$(az containerapp job start \
  --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${JOB_NAME}" \
  --query name -o tsv --only-show-errors)"
STATUS=""
for attempt in {1..90}; do
  if ! STATUS="$(az containerapp job execution show \
      --subscription "${LAB_SUBSCRIPTION}" \
      --resource-group "${LAB_RESOURCE_GROUP}" --name "${JOB_NAME}" \
      --job-execution-name "${EXECUTION_NAME}" \
      --query properties.status -o tsv --only-show-errors 2>/dev/null)"; then
    echo "Bootstrap status temporarily unavailable; retrying."
    sleep 5
    continue
  fi
  echo "Bootstrap execution status: ${STATUS}"
  case "${STATUS}" in
    Succeeded) break ;;
    Failed|Stopped|Degraded) exit 3 ;;
  esac
  sleep 5
done
[[ "${STATUS}" == "Succeeded" ]]

echo "Deleting the one-time job and its two temporary Azure secrets."
az containerapp job delete \
  --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${JOB_NAME}" \
  --yes --only-show-errors
JOB_CREATED=0

echo "Sealing the server administrator with a discarded random password."
SEALED_PASSWORD="Aa9_$(openssl rand -hex 32)"
az postgres flexible-server update \
  --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${SERVER}" \
  --admin-password "${SEALED_PASSWORD}" --only-show-errors -o none
ADMIN_NEEDS_SEAL=0
SUCCEEDED=1
unset ADMIN_PASSWORD ADMIN_URL APP_PASSWORD SEALED_PASSWORD
echo "Database-scoped credential is ready in Keychain service ${KEYCHAIN_SERVICE}."
