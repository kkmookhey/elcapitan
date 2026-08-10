# Azure Container Registry for the Eiger image.
#
# Basic SKU with the admin user enabled: Task 5's Container App pulls with
# the admin credential rather than a managed identity. This is a throwaway
# test subscription, and wiring a managed identity + AcrPull role assignment
# would add Terraform surface without changing anything TRAP-1 measures —
# see the plan's Task 3 rationale.
resource "azurerm_container_registry" "main" {
  name                = "${var.prefix}acr"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = true

  tags = {
    project    = "eiger-stage2"
    managed_by = "terraform"
  }
}

output "acr_login_server" {
  description = "Login server for the Eiger ACR (e.g. eigeracr.azurecr.io)."
  value       = azurerm_container_registry.main.login_server
}

output "acr_admin_username" {
  description = "Admin username for the Eiger ACR."
  value       = azurerm_container_registry.main.admin_username
  sensitive   = true
}

output "acr_admin_password" {
  description = "Admin password for the Eiger ACR."
  value       = azurerm_container_registry.main.admin_password
  sensitive   = true
}
