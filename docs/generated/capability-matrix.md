# Generated capability and evidence matrix

This file is generated from the installed control-pack registry. Do not edit it by hand.
`elcapitan capabilities` is the machine-readable authority.

Version: `0.1.0` · validation: 36 · planning: 4 · execution: 2

Validation, planning, and execution are independent columns. Evidence grade describes the strongest completed proof; it does not grant mutation authority.

| Provider | Control | Family | Validation | Planning | Execution | Evidence grade |
|---|---|---|:---:|:---:|:---:|---|
| AWS | `s3_bucket_object_versioning` | s3 bucket | yes | yes | no | E2E measured |
| AZURE | `app_client_certificates_on` | app service web app | yes | no | no | E2E measured |
| AZURE | `app_ensure_auth_is_set_up` | app service web app | yes | no | no | E2E measured |
| AZURE | `app_ensure_using_http20` | app service web app | yes | no | no | E2E measured |
| AZURE | `app_function_ftps_deployment_disabled` | azure function app | yes | no | no | E2E measured |
| AZURE | `app_function_not_publicly_accessible` | azure function app | yes | no | no | E2E measured |
| AZURE | `app_function_vnet_integration_enabled` | azure function app | yes | no | no | E2E measured |
| AZURE | `app_http_logs_enabled` | app service web app | yes | no | no | E2E measured |
| AZURE | `azureopenai_account_public_network_access_disabled` | azure openai | yes | no | no | Contract tested + export observed |
| AZURE | `containerregistry_admin_user_disabled` | container registry | yes | no | no | E2E measured |
| AZURE | `containerregistry_not_publicly_accessible` | container registry | yes | no | no | E2E measured |
| AZURE | `containerregistry_uses_private_link` | container registry | yes | no | no | E2E measured |
| AZURE | `cosmosdb_account_automatic_failover_enabled` | cosmos db | yes | no | no | Contract tested + export observed |
| AZURE | `cosmosdb_account_backup_policy_continuous` | cosmos db | yes | no | no | Contract tested + export observed |
| AZURE | `cosmosdb_account_minimum_tls_version` | cosmos db | yes | no | no | Contract tested + export observed |
| AZURE | `cosmosdb_account_public_network_access_disabled` | cosmos db | yes | no | no | Contract tested + export observed |
| AZURE | `keyvault_logging_enabled` | key vault | yes | no | no | Contract tested |
| AZURE | `keyvault_private_endpoints` | key vault | yes | no | no | E2E measured |
| AZURE | `keyvault_rbac_enabled` | key vault | yes | no | no | E2E measured |
| AZURE | `keyvault_recoverable` | key vault | yes | no | no | E2E measured |
| AZURE | `network_subnet_nsg_associated` | network subnet | yes | no | no | E2E measured |
| AZURE | `sqlserver_tde_encrypted_with_cmk` | sql server | yes | no | no | E2E measured |
| AZURE | `storage_account_key_access_disabled` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_account_public_network_access_disabled` | storage account | yes | yes | yes | E2E measured |
| AZURE | `storage_blob_public_access_level_is_disabled` | storage account | yes | yes | yes | E2E measured |
| AZURE | `storage_blob_versioning_is_enabled` | storage account | yes | yes | no | E2E measured |
| AZURE | `storage_default_network_access_rule_is_denied` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_default_to_entra_authorization_enabled` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_ensure_azure_services_are_trusted_to_access_is_enabled` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_ensure_encryption_with_customer_managed_keys` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_ensure_private_endpoints_in_storage_accounts` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_ensure_soft_delete_is_enabled` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_geo_redundant_enabled` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_infrastructure_encryption_is_enabled` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_key_rotation_90_days` | storage account | yes | no | no | E2E measured |
| AZURE | `storage_smb_channel_encryption_with_secure_algorithm` | storage account | yes | no | no | E2E measured |

Evidence grades:

- **E2E measured:** collector and evaluator ran with a least-privilege identity against an authorized disposable or non-production resource.
- **Contract tested + export observed:** official response contracts and sanitized fixtures are tested, and an authorized scanner export established the rule/resource shape; no live resource measurement is claimed.
- **Contract tested:** official response contracts and sanitized fixtures cover success, failure, malformed, denied, and absent-property behavior; no live resource measurement is claimed.
- **Export observed:** an authorized scanner export established the offline rule/resource shape; no live resource measurement is claimed.
