# Task 2 deliberately creates only the resource group. Storage (registry.tf,
# storage.tf) and the Container App (app.tf) are Tasks 3-5, each with its own
# gate — see docs/superpowers/plans/2026-08-10-stage2-eiger-azure-trap.md.
resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location

  tags = {
    project     = "eiger-stage2"
    managed_by  = "terraform"
    purpose     = "deliberately-vulnerable-trap-target"
  }
}
