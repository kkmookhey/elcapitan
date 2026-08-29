#!/bin/zsh
set -euo pipefail

LAB_SUBSCRIPTION="8cd2b4cc-c789-466d-a8f7-8f51fb20985d"
LAB_RESOURCE_GROUP="elcapitan-remediation-lab-rg"
ENVIRONMENT="elcapitan-shadow-private-env"
IMAGE="${ELCAPITAN_LAB_IMAGE:?set ELCAPITAN_LAB_IMAGE to an immutable ca7b25e7d425acr.azurecr.io image digest}"
SCANNER_ID="${ELCAPITAN_LAB_SCANNER_ID:?set ELCAPITAN_LAB_SCANNER_ID to the dedicated scanner identity resource ID}"
SCANNER_CLIENT_ID="${ELCAPITAN_LAB_SCANNER_CLIENT_ID:?set ELCAPITAN_LAB_SCANNER_CLIENT_ID to the dedicated scanner identity client ID}"

if [[ $# -ne 8 ]]; then
  echo "usage: $0 SLUG SERVER APP_ROLE APP_DATABASE DB_KEYCHAIN_SERVICE TOKEN_KEYCHAIN_SERVICE TEMPLATE CONFIRM-INTERNAL-SHADOW-APP" >&2
  exit 64
fi

SLUG="$1"
SERVER="$2"
APP_ROLE="$3"
APP_DATABASE="$4"
DB_KEYCHAIN_SERVICE="$5"
TOKEN_KEYCHAIN_SERVICE="$6"
TEMPLATE="$7"
CONFIRMATION="$8"

[[ "${CONFIRMATION}" == "CONFIRM-INTERNAL-SHADOW-APP" ]]
[[ "${SLUG}" =~ '^[a-z0-9]{2,10}$' ]]
[[ "${SERVER}" =~ '^elcapitan-[a-z0-9-]+$' ]]
[[ "${APP_ROLE}" =~ '^[a-z][a-z0-9_]{2,62}$' ]]
[[ "${APP_DATABASE}" =~ '^[a-z][a-z0-9_]{2,62}$' ]]
[[ "${DB_KEYCHAIN_SERVICE}" == "elcapitan-${SLUG}-db-bootstrap-password" ]]
[[ "${TOKEN_KEYCHAIN_SERVICE}" == "elcapitan-${SLUG}-shadow-token" ]]
[[ -f "${TEMPLATE}" ]]
[[ "${IMAGE}" =~ '^ca7b25e7d425acr\.azurecr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$' ]]
[[ "${SCANNER_ID}" == "/subscriptions/${LAB_SUBSCRIPTION}/resourceGroups/${LAB_RESOURCE_GROUP}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/elcapitan-${SLUG}-scanner" ]]
[[ "${SCANNER_CLIENT_ID}" =~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' ]]
[[ "$(az account show --query id -o tsv)" == "${LAB_SUBSCRIPTION}" ]]

APP_NAME="elcapitan-${SLUG}-shadow"
HOST="${SERVER}.postgres.database.azure.com"
APP_PASSWORD="$(security find-generic-password -a elcapitan -s "${DB_KEYCHAIN_SERVICE}" -w)"
ACCESS_TOKEN="$(security find-generic-password -a elcapitan -s "${TOKEN_KEYCHAIN_SERVICE}" -w)"
[[ ${#APP_PASSWORD} -ge 32 ]]
[[ ${#ACCESS_TOKEN} -ge 48 ]]
APP_URL="postgresql://${APP_ROLE}:${APP_PASSWORD}@${HOST}/${APP_DATABASE}?sslmode=require"

if az containerapp show --subscription "${LAB_SUBSCRIPTION}" \
    --resource-group "${LAB_RESOURCE_GROUP}" --name "${APP_NAME}" \
    --only-show-errors -o none >/dev/null 2>&1; then
  echo "Refusing to overwrite existing app ${APP_NAME}." >&2
  exit 2
fi

echo "Creating the internal-ingress shadow app."
sed -e "s|__APP_NAME__|${APP_NAME}|g" \
    -e "s|__DATABASE_URL__|${APP_URL}|g" \
    -e "s|__ACCESS_TOKEN__|${ACCESS_TOKEN}|g" \
    -e "s|__SCANNER_ID__|${SCANNER_ID}|g" \
    -e "s|__SCANNER_CLIENT_ID__|${SCANNER_CLIENT_ID}|g" \
    -e "s|__IMAGE__|${IMAGE}|g" "${TEMPLATE}" | \
  az containerapp create --subscription "${LAB_SUBSCRIPTION}" \
    --resource-group "${LAB_RESOURCE_GROUP}" --name "${APP_NAME}" \
    --environment "${ENVIRONMENT}" --yaml /dev/stdin --only-show-errors -o none

EXTERNAL="$(az containerapp show --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${APP_NAME}" \
  --query properties.configuration.ingress.external -o tsv)"
[[ "${EXTERNAL}" == "false" ]]

security delete-generic-password -a elcapitan -s "${DB_KEYCHAIN_SERVICE}" >/dev/null
unset APP_PASSWORD APP_URL ACCESS_TOKEN

az containerapp show --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${APP_NAME}" \
  --query '{name:name,fqdn:properties.configuration.ingress.fqdn,external:properties.configuration.ingress.external,latestRevision:properties.latestRevisionName,provisioningState:properties.provisioningState,runningStatus:properties.runningStatus,identityType:identity.type}' \
  -o json
