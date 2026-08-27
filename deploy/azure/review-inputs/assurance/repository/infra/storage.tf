terraform {
  required_version = ">= 1.10, < 2.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id                 = "8cd2b4cc-c789-466d-a8f7-8f51fb20985d"
  resource_provider_registrations = "none"
}

resource "azurerm_storage_account" "assurance" {
  name                            = "elcapassure8f51fb20985d"
  resource_group_name             = "elcapitan-remediation-lab-rg"
  location                        = "centralindia"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  public_network_access_enabled   = true
  allow_nested_items_to_be_public = true

  tags = {
    elcapitan_scope = "lab"
    environment     = "nonproduction"
    project         = "elcapitan"
    purpose         = "assurance-lifecycle"
  }
}
