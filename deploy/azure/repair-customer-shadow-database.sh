#!/bin/zsh
set -euo pipefail

LAB_SUBSCRIPTION="8cd2b4cc-c789-466d-a8f7-8f51fb20985d"
LAB_RESOURCE_GROUP="elcapitan-remediation-lab-rg"
IMAGE="ca7b25e7d425acr.azurecr.io/elcapitan-demo@sha256:474cf90f64b71d35787133768b5005750fddfa05ba005bf7211d18a10811486e"

if [[ $# -ne 7 ]]; then
  echo "usage: $0 SLUG SERVER APP_ROLE APP_DATABASE DB_KEYCHAIN_SERVICE TOKEN_KEYCHAIN_SERVICE CONFIRM-INTERNAL-DATABASE-REPAIR" >&2
  exit 64
fi

SLUG="$1"
SERVER="$2"
APP_ROLE="$3"
APP_DATABASE="$4"
DB_KEYCHAIN_SERVICE="$5"
TOKEN_KEYCHAIN_SERVICE="$6"
CONFIRMATION="$7"

[[ "${CONFIRMATION}" == "CONFIRM-INTERNAL-DATABASE-REPAIR" ]]
[[ "${SLUG}" =~ '^[a-z0-9]{2,10}$' ]]
[[ "${DB_KEYCHAIN_SERVICE}" == "elcapitan-${SLUG}-db-bootstrap-password" ]]
[[ "${TOKEN_KEYCHAIN_SERVICE}" == "elcapitan-${SLUG}-shadow-token" ]]
[[ "$(az account show --query id -o tsv)" == "${LAB_SUBSCRIPTION}" ]]

APP_NAME="elcapitan-${SLUG}-shadow"
HOST="${SERVER}.postgres.database.azure.com"
APP_PASSWORD="$(security find-generic-password -a elcapitan -s "${DB_KEYCHAIN_SERVICE}" -w)"
APP_URL="postgresql://${APP_ROLE}:${APP_PASSWORD}@${HOST}/${APP_DATABASE}?sslmode=require"
EXTERNAL="$(az containerapp show --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${APP_NAME}" \
  --query properties.configuration.ingress.external -o tsv)"
[[ "${EXTERNAL}" == "false" ]]

az containerapp secret set --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${APP_NAME}" \
  --secrets database-url="${APP_URL}" --only-show-errors -o none
az containerapp update --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${APP_NAME}" \
  --image "${IMAGE}" --only-show-errors -o none
REVISION="$(az containerapp show --subscription "${LAB_SUBSCRIPTION}" \
  --resource-group "${LAB_RESOURCE_GROUP}" --name "${APP_NAME}" \
  --query properties.latestRevisionName -o tsv)"
unset APP_PASSWORD APP_URL

echo "Database secret updated and corrected internal revision created: ${REVISION}"
echo "Retaining ${DB_KEYCHAIN_SERVICE} until the application health check passes."
