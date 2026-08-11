# --- Subscription guard -----------------------------------------------------
#
# var.subscription_id has a default and can be overridden with -var, so
# comparing the authenticated subscription against var.subscription_id would
# be tautological: the azurerm provider is itself configured with
# `subscription_id = var.subscription_id`, so whatever var says, the provider
# connects to it and the two would always match — the check would never fire.
#
# What must never move, regardless of what a future -var or a drifted
# default supplies, is which subscription this environment is *allowed* to
# touch at all. local.expected_subscription_id is that fixed rail: changing
# it means editing this file (visible in review/git history), not passing a
# flag. The precondition below fails the plan before anything is created if
# the two ever diverge — e.g. an accidental `-var
# subscription_id=cb0d6ed4-a7c9-4929-8707-4a477a2cc9b5` (Azure subscription 1,
# which holds transilience-demo-rg and shasta-test-rg) would otherwise
# silently deploy Eiger's deliberately-vulnerable resources next to real work.
locals {
  expected_subscription_id = "8cd2b4cc-c789-466d-a8f7-8f51fb20985d" # Azure CIS Agent Testing — the only subscription this environment may ever target
}

data "azurerm_client_config" "current" {}

# Task 2 deliberately creates only the resource group. Storage (registry.tf,
# storage.tf) and the Container App (app.tf) are Tasks 3-5, each with its own
# gate — see docs/superpowers/plans/2026-08-10-stage2-eiger-azure-trap.md.
resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location

  tags = {
    project    = "eiger-stage2"
    managed_by = "terraform"
    purpose    = "deliberately-vulnerable-trap-target"
  }

  lifecycle {
    precondition {
      condition     = data.azurerm_client_config.current.subscription_id == local.expected_subscription_id
      error_message = "Refusing to apply: the authenticated Azure subscription (${data.azurerm_client_config.current.subscription_id}) is not the Eiger test subscription (${local.expected_subscription_id} — 'Azure CIS Agent Testing'). This environment must never deploy into any other subscription, especially 'Azure subscription 1' (cb0d6ed4-a7c9-4929-8707-4a477a2cc9b5), which holds transilience-demo-rg and shasta-test-rg."
    }
  }
}
