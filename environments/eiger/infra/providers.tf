terraform {
  required_version = "~> 1.15"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # Added by Task 4: storage account names are globally unique across all of
    # Azure, so "eigercorpus" alone would collide. random_string supplies the
    # suffix — see storage.tf for the 24-character budget it has to fit in.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  subscription_id = var.subscription_id
  features {}
}
