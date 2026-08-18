variable "subscription_id" {
  type        = string
  description = "Azure CIS Agent Testing — the empty, subscription-scoped test target. Never point this at Azure subscription 1 (cb0d6ed4-a7c9-4929-8707-4a477a2cc9b5)."
  default     = "8cd2b4cc-c789-466d-a8f7-8f51fb20985d"
}

variable "location" {
  type        = string
  description = <<-EOT
    Azure region for all resources. Measured, not assumed: Container Apps
    (Microsoft.App/containerApps) availability was checked with
    `az provider show --namespace Microsoft.App --query
    "resourceTypes[?resourceType=='containerApps'].locations"` on 2026-08-10.
    "Central India" is present in that list, so centralindia is used as
    planned — no fallback region was needed.
  EOT
  default     = "centralindia"
}

variable "prefix" {
  type        = string
  description = "Naming prefix for all Eiger stage-2 resources."
  default     = "eiger"
}
