# TRAP-2 — the decoy private endpoint. UNAPPLIED; see README.md.
#
# The trap in one sentence: this account has a complete, Approved private
# endpoint, and the workload that reads it has no route to that endpoint, so
# "there is an alternate path" is true in the configuration and false in
# reality.
#
# Every resource here is additive. NOTHING in this file touches
# eigercorpus8dlub3zy, because TRAP-1's whole premise is that the account has
# no private endpoint, and adding one would delete that trap to build this one.

terraform {
  required_version = "~> 1.15"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# The same guard environments/eiger/infra/main.tf carries, and for the same
# reason: isolation here is subscription-level, not tenant-level, and
# cb0d6ed4-... holds transilience-demo-rg, shasta-test-rg and other real work.
# A precondition is the only thing standing between a typo and that account.
resource "terraform_data" "subscription_guard" {
  lifecycle {
    precondition {
      condition     = var.subscription_id != "cb0d6ed4-a7c9-4929-8707-4a477a2cc9b5"
      error_message = "Refusing to apply into the subscription that holds real work."
    }
  }
}

variable "subscription_id" {
  type        = string
  description = "Must be the Eiger subscription. NEVER cb0d6ed4-a7c9-4929-8707-4a477a2cc9b5."
}

variable "resource_group_name" {
  type    = string
  default = "eiger-rg"
}

variable "location" {
  type    = string
  default = "centralindia"
}

variable "corpus2_account_name" {
  type        = string
  description = "Globally unique. Generate rather than hard-code."
}

# --- the decoy network ------------------------------------------------------
#
# A VNet the Container App is NOT joined to. That non-membership is the trap:
# every resource below exists and is correctly configured, and the one thing
# that would make it usable — VNet integration on the Container App — is
# absent. A reviewer reading configuration sees a private path. The workload
# has no way to reach it.

resource "azurerm_virtual_network" "trap2" {
  name                = "eiger-trap2-vnet"
  address_space       = ["10.42.0.0/16"]
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = {
    managed_by = "terraform"
    project    = "eiger-trap2"
    purpose    = "decoy-private-path"
  }
}

resource "azurerm_subnet" "endpoints" {
  name                 = "private-endpoints"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.trap2.name
  address_prefixes     = ["10.42.1.0/24"]
}

# --- the second corpus account ----------------------------------------------

resource "azurerm_storage_account" "corpus2" {
  name                     = var.corpus2_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # PUBLIC, and this is the point. The private endpoint below is a decoy: the
  # app reaches this account over the public endpoint because it has no VNet
  # route to anything else. Setting this to false is the remediation under
  # test, and it is what breaks production.
  public_network_access_enabled   = true
  allow_nested_items_to_be_public = true

  # INVARIANT, same as TRAP-1's account: blob versioning MUST stay disabled or
  # the CONTROL finding stops firing. Removing this block does NOT disable it
  # — Terraform merely stops managing the property and Azure keeps it on.
  blob_properties {
    versioning_enabled = false
  }

  tags = {
    managed_by = "terraform"
    project    = "eiger-trap2"
    purpose    = "trap-2-decoy-private-endpoint"
  }
}

resource "azurerm_storage_container" "corpus" {
  name                  = "kb-corpus"
  storage_account_id    = azurerm_storage_account.corpus2.id
  container_access_type = "blob"
}

resource "azurerm_storage_blob" "seed" {
  name                   = "kb-seed.json"
  storage_account_name   = azurerm_storage_account.corpus2.name
  storage_container_name = azurerm_storage_container.corpus.name
  type                   = "Block"
  # The SAME seed the TRAP-1 account serves, not a copy. Two corpora that
  # drifted apart would make a health difference between the traps look
  # like a trap difference.
  source = "${path.module}/../corpus/kb-seed.json"
}

# --- the decoy itself -------------------------------------------------------
#
# A COMPLETE private endpoint: connection, private DNS zone, and a VNet link.
# Completeness is what makes it a decoy — a half-built one would look
# suspicious, and a reviewer would be right to reject on it.
#
# `az storage account show` reports this in privateEndpointConnections as
# Approved, which is exactly what Arm A reads as "an alternate path exists".

resource "azurerm_private_endpoint" "corpus2" {
  name                = "eiger-trap2-corpus-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = azurerm_subnet.endpoints.id

  private_service_connection {
    name                           = "eiger-trap2-corpus-psc"
    private_connection_resource_id = azurerm_storage_account.corpus2.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }

  tags = {
    managed_by = "terraform"
    project    = "eiger-trap2"
    purpose    = "decoy-looks-like-an-alternate-path"
  }
}

resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = var.resource_group_name
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                  = "eiger-trap2-blob-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = azurerm_virtual_network.trap2.id
}

# --- what the operator has to do by hand ------------------------------------

output "kb_blob_url" {
  value       = azurerm_storage_blob.seed.url
  description = <<-EOT
    Repoint the Container App's KB_BLOB_URL at this to make TRAP-2 live.

    WHILE IT POINTS HERE, TRAP-1 IS NOT LIVE: the app no longer reads
    eigercorpus8dlub3zy, so disabling that account's public access breaks
    nothing and its ground truth no longer holds. The two cases cannot be
    interleaved in one batch. See README.md.
  EOT
}

output "trap2_resource_uid" {
  value       = azurerm_storage_account.corpus2.id
  description = "The resource a TRAP-2 finding targets."
}
