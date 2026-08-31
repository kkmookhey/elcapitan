# Generated capability and evidence matrix

This file is generated from the installed control-pack registry. Do not edit it by hand.
`elcapitan capabilities` is the machine-readable authority.

Version: `0.1.0` · validation: 70 · planning: 4 · execution: 2

Validation, planning, and execution are independent columns. Evidence grade describes the strongest completed proof; it does not grant mutation authority.

| Provider | Control | Family | Validation | Planning | Execution | Evidence grade |
|---|---|---|:---:|:---:|:---:|---|
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_all_ports` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_allow_wide_open_public_ipv4` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_default_restrict_traffic` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_from_launch_wizard` | ec2 security group | yes | no | no | Contract tested |
| AWS | `ec2_securitygroup_with_many_ingress_egress_rules` | ec2 security group | yes | no | no | Contract tested |
| AWS | `rds_instance_backup_enabled` | rds db instance | yes | no | no | Contract tested |
| AWS | `rds_instance_copy_tags_to_snapshots` | rds db instance | yes | no | no | Contract tested |
| AWS | `rds_instance_enhanced_monitoring_enabled` | rds db instance | yes | no | no | Contract tested |
| AWS | `rds_instance_iam_authentication_enabled` | rds db instance | yes | no | no | Contract tested |
| AWS | `rds_instance_inside_vpc` | rds db instance | yes | no | no | Contract tested |
| AWS | `rds_instance_integration_cloudwatch_logs` | rds db instance | yes | no | no | Contract tested |
| AWS | `rds_instance_minor_version_upgrade_enabled` | rds db instance | yes | no | no | Contract tested |
| AWS | `rds_instance_storage_encrypted` | rds db instance | yes | no | no | Contract tested |
| AWS | `s3_bucket_event_notifications_enabled` | s3 bucket | yes | no | no | Contract tested |
| AWS | `s3_bucket_kms_encryption` | s3 bucket | yes | no | no | Contract tested |
| AWS | `s3_bucket_lifecycle_enabled` | s3 bucket | yes | no | no | Contract tested |
| AWS | `s3_bucket_no_mfa_delete` | s3 bucket | yes | no | no | Contract tested |
| AWS | `s3_bucket_object_lock` | s3 bucket | yes | no | no | Contract tested |
| AWS | `s3_bucket_object_versioning` | s3 bucket | yes | yes | no | E2E measured |
| AWS | `s3_bucket_server_access_logging_enabled` | s3 bucket | yes | no | no | Contract tested |
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
