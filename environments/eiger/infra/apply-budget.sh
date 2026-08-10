#!/usr/bin/env bash
# environments/eiger/infra/apply-budget.sh
#
# (Re)creates the eiger-monthly-budget subscription budget from budget.json.
#
# Why this exists outside Terraform: `az consumption budget create` (az CLI
# 2.86.0) returns a 400 ("please use filter interface with 2019-05-01-preview
# version") against this subscription, and even a working `create` lacks a
# --notifications flag in this CLI version. az rest against the ARM API
# directly (Microsoft.Consumption/budgets, api-version 2024-08-01) is what
# actually worked — see task-2-report.md for the full story. This script
# makes that call replayable instead of leaving it only as report prose: if
# the budget is ever deleted out-of-band (e.g. via the portal), running this
# reconstructs it exactly rather than requiring someone to retype the JSON
# shape from markdown.
#
# The PUT is idempotent — safe to re-run at any time to confirm/restore
# the budget's exact configuration.
set -euo pipefail

SUBSCRIPTION_ID="${1:-8cd2b4cc-c789-466d-a8f7-8f51fb20985d}"  # Azure CIS Agent Testing
BUDGET_NAME="${2:-eiger-monthly-budget}"
API_VERSION="2024-08-01"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

az rest --method put \
  --url "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Consumption/budgets/${BUDGET_NAME}?api-version=${API_VERSION}" \
  --body "@${SCRIPT_DIR}/budget.json"

echo "Verifying..."
az rest --method get \
  --url "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Consumption/budgets/${BUDGET_NAME}?api-version=${API_VERSION}" \
  -o json
