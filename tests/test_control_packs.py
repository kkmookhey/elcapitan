import json
from pathlib import Path

import pytest

from elcapitan.control_packs import (
    BUILTIN_CONTROL_PACKS, ControlDefinition, ControlPack, ControlPackRegistry,
    builtin_registry,
)
from elcapitan.control_packs.models import ControlEvaluation


def _evaluation(values):
    return ControlEvaluation(False, "fixture")


def definition(*, pack_id="fixture", provider="azure", rule_id="fixture_rule"):
    return ControlDefinition(
        pack_id=pack_id, provider=provider, rule_id=rule_id,
        resource_family="fixture", resource_types=("fixture/type",),
        live_validation=True, remediation_planning=False, live_execution=False,
        evidence_aspects=("fixture",), evaluator=_evaluation,
        evidence_grade="contract_tested")


def test_builtin_registry_is_composed_from_service_packs():
    assert {pack.pack_id for pack in BUILTIN_CONTROL_PACKS} == {
        "aws-ebs-volume", "aws-ec2-security-group", "aws-rds", "aws-s3",
        "azure-app-service", "azure-container-registry",
        "azure-cosmos-db", "azure-key-vault", "azure-network", "azure-openai",
        "azure-sql", "azure-storage"}
    registry = builtin_registry()
    assert len(registry.list()) == 72
    assert len(registry.list(provider="aws")) == 37
    assert registry.get("AZURE", "sqlserver_tde_encrypted_with_cmk").pack_id == (
        "azure-sql")
    assert registry.get(
        "azure", "sqlserver_tde_encrypted_with_cmk",
        "microsoft.storage/storageaccounts") is None
    assert registry.get(
        "azure", "app_client_certificates_on",
        "microsoft.web/sites/config") is not None
    assert registry.get(
        "azure", "app_client_certificates_on",
        "microsoft.web/sites") is None
    assert {item.evidence_grade for item in registry.list()} == {
        "contract_tested", "contract_tested_export_observed", "e2e_measured"}
    assert sum(item.evidence_grade == "e2e_measured"
               for item in registry.list()) == 30
    assert sum(item.evidence_grade == "contract_tested_export_observed"
               for item in registry.list()) == 5
    assert registry.get(
        "azure", "keyvault_logging_enabled").evidence_grade == "contract_tested"


S3_CONTRACT = json.loads(
    (Path(__file__).parent / "fixtures" / "aws-s3-control-contract.json").read_text()
)
EBS_VOLUME_CONTRACT = json.loads(
    (Path(__file__).parent / "fixtures" / "aws-ebs-volume-contract.json").read_text()
)
RDS_CONTRACT = json.loads(
    (Path(__file__).parent / "fixtures" / "aws-rds-db-instance-contract.json").read_text()
)
EC2_SG_CONTRACT = json.loads(
    (Path(__file__).parent / "fixtures" /
     "aws-ec2-security-group-contract.json").read_text()
)

EC2_SG_PORT_RULES = (
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23",
)
EC2_SG_RULES = (
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
    "ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports",
    *EC2_SG_PORT_RULES,
    "ec2_securitygroup_allow_wide_open_public_ipv4",
    "ec2_securitygroup_default_restrict_traffic",
    "ec2_securitygroup_from_launch_wizard",
    "ec2_securitygroup_with_many_ingress_egress_rules",
)


@pytest.mark.parametrize("rule_id", [
    "ec2_ebs_volume_encryption",
    "ec2_ebs_volume_snapshots_exists",
])
def test_ebs_volume_pack_matches_pinned_prowler_truth_conditions(rule_id):
    control = builtin_registry().get("aws", rule_id)

    assert control.evaluator(EBS_VOLUME_CONTRACT["failing"]).confirmed is True
    assert control.evaluator(EBS_VOLUME_CONTRACT["passing"]).confirmed is False
    assert control.live_validation is True
    assert control.remediation_planning is False
    assert control.live_execution is False
    assert control.evidence_grade == "contract_tested"
    assert control.resource_types == ("awsec2volume",)


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("ec2_ebs_volume_encryption", {"ebs_volume_encrypted": "false"}),
        ("ec2_ebs_volume_snapshots_exists", {
            "ebs_volume_owned_snapshot_present": 0,
        }),
    ],
)
def test_ebs_volume_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid"):
        builtin_registry().get("aws", rule_id).evaluator(values)


@pytest.mark.parametrize("rule_id", [
    "s3_bucket_kms_encryption",
    "s3_bucket_server_access_logging_enabled",
    "s3_bucket_event_notifications_enabled",
    "s3_bucket_lifecycle_enabled",
    "s3_bucket_object_lock",
    "s3_bucket_no_mfa_delete",
])
def test_expanded_s3_pack_matches_pinned_prowler_truth_conditions(rule_id):
    control = builtin_registry().get("aws", rule_id)

    assert control.evaluator(S3_CONTRACT["failing"]).confirmed is True
    assert control.evaluator(S3_CONTRACT["passing"]).confirmed is False
    assert control.live_validation is True
    assert control.remediation_planning is False
    assert control.live_execution is False
    assert control.evidence_grade == "contract_tested"


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("s3_bucket_object_versioning", {"versioning": {"Status": "Unknown"}}),
        ("s3_bucket_kms_encryption", {"encryption": {
            "ServerSideEncryptionConfiguration": {"Rules": []}}}),
        ("s3_bucket_server_access_logging_enabled", {
            "logging": {"LoggingEnabled": True}}),
        ("s3_bucket_event_notifications_enabled", {
            "notification": {"QueueConfigurations": {}}}),
        ("s3_bucket_lifecycle_enabled", {
            "lifecycle": {"Rules": [{"Status": "Pending"}]}}),
        ("s3_bucket_object_lock", {
            "object_lock": {"ObjectLockConfiguration": {}}}),
        ("s3_bucket_no_mfa_delete", {
            "versioning": {"MFADelete": None}}),
    ],
)
def test_s3_pack_rejects_malformed_or_unknown_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid"):
        builtin_registry().get("aws", rule_id).evaluator(values)


def test_s3_pack_rejects_an_unrecognized_absent_marker():
    with pytest.raises(ValueError, match="invalid encryption response"):
        builtin_registry().get("aws", "s3_bucket_kms_encryption").evaluator({
            "encryption": "<absent: AccessDenied>",
        })


@pytest.mark.parametrize("rule_id", [
    "rds_instance_backup_enabled",
    "rds_instance_copy_tags_to_snapshots",
    "rds_instance_enhanced_monitoring_enabled",
    "rds_instance_iam_authentication_enabled",
    "rds_instance_inside_vpc",
    "rds_instance_integration_cloudwatch_logs",
    "rds_instance_minor_version_upgrade_enabled",
    "rds_instance_storage_encrypted",
])
def test_rds_pack_matches_pinned_prowler_truth_conditions(rule_id):
    control = builtin_registry().get("aws", rule_id)

    assert control.evaluator(RDS_CONTRACT["failing"]).confirmed is True
    assert control.evaluator(RDS_CONTRACT["passing"]).confirmed is False
    assert control.live_validation is True
    assert control.remediation_planning is False
    assert control.live_execution is False
    assert control.evidence_grade == "contract_tested"
    assert control.resource_types == ("awsrdsdbinstance",)


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("rds_instance_backup_enabled", {
            "rds_backup_retention_period": "7",
            "rds_read_replica_source_present": False,
        }),
        ("rds_instance_copy_tags_to_snapshots", {
            "rds_engine": "postgres",
            "rds_copy_tags_to_snapshot": 0,
        }),
        ("rds_instance_enhanced_monitoring_enabled", {
            "rds_enhanced_monitoring_enabled": "false",
        }),
        ("rds_instance_iam_authentication_enabled", {
            "rds_engine": "postgres",
            "rds_iam_database_authentication_enabled": None,
        }),
        ("rds_instance_inside_vpc", {"rds_in_vpc": 1}),
        ("rds_instance_integration_cloudwatch_logs", {
            "rds_enabled_cloudwatch_logs_exports": ["postgresql", "postgresql"],
        }),
        ("rds_instance_minor_version_upgrade_enabled", {
            "rds_auto_minor_version_upgrade": "true",
        }),
        ("rds_instance_storage_encrypted", {"rds_storage_encrypted": 1}),
    ],
)
def test_rds_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid"):
        builtin_registry().get("aws", rule_id).evaluator(values)


def test_rds_pack_preserves_pinned_prowler_applicability_rules():
    replica = dict(RDS_CONTRACT["failing"])
    replica["rds_read_replica_source_present"] = True
    aurora = dict(RDS_CONTRACT["failing"])
    aurora["rds_engine"] = "aurora-postgresql"
    unsupported_iam = dict(RDS_CONTRACT["failing"])
    unsupported_iam["rds_engine"] = "oracle-ee"

    assert not builtin_registry().get(
        "aws", "rds_instance_backup_enabled").evaluator(replica).confirmed
    assert not builtin_registry().get(
        "aws", "rds_instance_copy_tags_to_snapshots").evaluator(aurora).confirmed
    assert not builtin_registry().get(
        "aws", "rds_instance_iam_authentication_enabled").evaluator(
            unsupported_iam).confirmed


@pytest.mark.parametrize("rule_id", (
    "ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports",
    *EC2_SG_PORT_RULES,
    "ec2_securitygroup_allow_wide_open_public_ipv4",
    "ec2_securitygroup_from_launch_wizard",
))
def test_ec2_security_group_pack_matches_shared_failing_contract(rule_id):
    control = builtin_registry().get("aws", rule_id)

    assert control.evaluator(EC2_SG_CONTRACT["failing"]).confirmed is True
    assert control.evaluator(EC2_SG_CONTRACT["passing"]).confirmed is False
    assert control.live_validation is True
    assert control.remediation_planning is False
    assert control.live_execution is False
    assert control.evidence_grade == "contract_tested"
    assert control.resource_types == ("awsec2securitygroup",)


def test_ec2_security_group_specialized_truth_conditions():
    registry = builtin_registry()
    all_ports = dict(EC2_SG_CONTRACT["failing"])
    all_ports["ec2_sg_ingress_rules"] = [{
        "protocol": "-1", "from_port": None, "to_port": None,
        "ipv4_cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [],
    }]
    default = dict(EC2_SG_CONTRACT["failing"])
    default["ec2_sg_name"] = "default"
    many = dict(EC2_SG_CONTRACT["passing"])
    many["ec2_sg_ingress_rules"] = [
        {
            "protocol": "tcp", "from_port": port, "to_port": port,
            "ipv4_cidrs": ["10.0.0.0/8"], "ipv6_cidrs": [],
        }
        for port in range(51)
    ]

    assert registry.get(
        "aws", "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"
    ).evaluator(all_ports).confirmed
    assert registry.get(
        "aws", "ec2_securitygroup_default_restrict_traffic"
    ).evaluator(default).confirmed
    assert registry.get(
        "aws", "ec2_securitygroup_with_many_ingress_egress_rules"
    ).evaluator(many).confirmed


@pytest.mark.parametrize("rule_id", EC2_SG_RULES)
def test_ec2_security_group_passing_contract_clears_every_control(rule_id):
    assert builtin_registry().get(
        "aws", rule_id).evaluator(EC2_SG_CONTRACT["passing"]).confirmed is False


def test_ec2_security_group_preserves_unused_and_duplicate_suppression():
    registry = builtin_registry()
    unused = dict(EC2_SG_CONTRACT["failing"])
    unused["ec2_sg_in_use"] = False
    all_ports = dict(EC2_SG_CONTRACT["failing"])
    all_ports["ec2_sg_ingress_rules"] = [{
        "protocol": "-1", "from_port": None, "to_port": None,
        "ipv4_cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [],
    }]

    assert not registry.get(
        "aws", "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"
    ).evaluator(unused).confirmed
    assert not registry.get(
        "aws", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    ).evaluator(all_ports).confirmed


@pytest.mark.parametrize("values", [
    {"ec2_sg_in_use": "true", "ec2_sg_ingress_rules": []},
    {"ec2_sg_in_use": True, "ec2_sg_ingress_rules": [{
        "protocol": "tcp", "from_port": 22, "to_port": None,
        "ipv4_cidrs": ["0.0.0.0/0"], "ipv6_cidrs": [],
    }]},
    {"ec2_sg_in_use": True, "ec2_sg_ingress_rules": [{
        "protocol": "tcp", "from_port": 22, "to_port": 22,
        "ipv4_cidrs": ["not-a-cidr"], "ipv6_cidrs": [],
    }]},
])
def test_ec2_security_group_pack_rejects_malformed_evidence(values):
    with pytest.raises(ValueError, match="invalid|incomplete"):
        builtin_registry().get(
            "aws", "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"
        ).evaluator(values)


def test_control_definition_serialization_never_exposes_executable_callable():
    value = definition().to_dict()
    assert "evaluator" not in value
    assert value["evidence_aspects"] == ["fixture"]
    assert value["evidence_grade"] == "contract_tested"
    assert value["resource_types"] == ["fixture/type"]


def test_unknown_evidence_grade_fails_closed():
    with pytest.raises(ValueError, match="unknown evidence grade"):
        ControlPack("bad", (definition(pack_id="bad"),), "inferred")


def test_duplicate_provider_rule_registration_fails_closed():
    first = ControlPack("one", (definition(pack_id="one"),))
    second = ControlPack("two", (definition(pack_id="two"),))
    with pytest.raises(ValueError, match="unique by provider and rule"):
        ControlPackRegistry((first, second))


def test_pack_rejects_a_definition_owned_by_another_pack():
    with pytest.raises(ValueError, match="containing pack"):
        ControlPack("expected", (definition(pack_id="different"),))


@pytest.mark.parametrize(
    ("rule_id", "values", "confirmed"),
    [
        ("storage_ensure_encryption_with_customer_managed_keys", {
            "encryption": {"keySource": "Microsoft.Storage"}}, True),
        ("storage_ensure_encryption_with_customer_managed_keys", {
            "encryption": {"keySource": "Microsoft.Keyvault"}}, False),
        ("storage_geo_redundant_enabled", {
            "sku": {"name": "Standard_LRS"}}, True),
        ("storage_geo_redundant_enabled", {
            "sku": {"name": "Standard_GZRS"}}, False),
        ("storage_infrastructure_encryption_is_enabled", {
            "encryption": {"requireInfrastructureEncryption": None}}, True),
        ("storage_infrastructure_encryption_is_enabled", {
            "encryption": {"requireInfrastructureEncryption": True}}, False),
        ("storage_default_network_access_rule_is_denied", {
            "network_rule_set": {"defaultAction": "Allow"}}, True),
        ("storage_default_network_access_rule_is_denied", {
            "network_rule_set": {"defaultAction": "Deny"}}, False),
        ("storage_ensure_private_endpoints_in_storage_accounts", {
            "private_endpoint_connections": []}, True),
        ("storage_ensure_private_endpoints_in_storage_accounts", {
            "private_endpoint_connections": [{"id": "/privateEndpoints/one"}]},
         False),
        ("storage_account_key_access_disabled", {
            "allow_shared_key_access": None}, True),
        ("storage_account_key_access_disabled", {
            "allow_shared_key_access": False}, False),
        ("storage_default_to_entra_authorization_enabled", {
            "default_to_oauth_authentication": False}, True),
        ("storage_default_to_entra_authorization_enabled", {
            "default_to_oauth_authentication": True}, False),
        ("storage_ensure_soft_delete_is_enabled", {
            "blob_container_delete_retention_policy": {"enabled": False}}, True),
        ("storage_ensure_soft_delete_is_enabled", {
            "blob_container_delete_retention_policy": {"enabled": True}}, False),
        ("storage_ensure_azure_services_are_trusted_to_access_is_enabled", {
            "network_rule_set": {"bypass": "None"}}, True),
        ("storage_ensure_azure_services_are_trusted_to_access_is_enabled", {
            "network_rule_set": {"bypass": "Logging,AzureServices"}}, False),
        ("storage_key_rotation_90_days", {"key_policy": None}, True),
        ("storage_key_rotation_90_days", {
            "key_policy": {"keyExpirationPeriodInDays": 91}}, True),
        ("storage_key_rotation_90_days", {
            "key_policy": {"keyExpirationPeriodInDays": 90}}, False),
        ("storage_smb_channel_encryption_with_secure_algorithm", {
            "file_service_status": "available",
            "file_smb_channel_encryption": []}, True),
        ("storage_smb_channel_encryption_with_secure_algorithm", {
            "file_service_status": "available",
            "file_smb_channel_encryption": ["AES-256-GCM", "AES-128-GCM"]}, True),
        ("storage_smb_channel_encryption_with_secure_algorithm", {
            "file_service_status": "available",
            "file_smb_channel_encryption": ["AES-256-GCM"]}, False),
    ],
)
def test_storage_pack_matches_pinned_prowler_truth_conditions(
        rule_id, values, confirmed):
    assert builtin_registry().get("azure", rule_id).evaluator(values).confirmed is (
        confirmed)


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("storage_ensure_encryption_with_customer_managed_keys", {
            "encryption": []}),
        ("storage_geo_redundant_enabled", {"sku": {"name": None}}),
        ("storage_infrastructure_encryption_is_enabled", {
            "encryption": {"requireInfrastructureEncryption": "false"}}),
        ("storage_default_network_access_rule_is_denied", {
            "network_rule_set": {"defaultAction": "Unknown"}}),
        ("storage_ensure_private_endpoints_in_storage_accounts", {
            "private_endpoint_connections": ["bad"]}),
        ("storage_account_key_access_disabled", {"allow_shared_key_access": 0}),
        ("storage_default_to_entra_authorization_enabled", {
            "default_to_oauth_authentication": "true"}),
        ("storage_ensure_soft_delete_is_enabled", {
            "blob_container_delete_retention_policy": {"enabled": 1}}),
        ("storage_ensure_azure_services_are_trusted_to_access_is_enabled", {
            "network_rule_set": {"bypass": None}}),
        ("storage_key_rotation_90_days", {
            "key_policy": {"keyExpirationPeriodInDays": "90"}}),
        ("storage_key_rotation_90_days", {"key_policy": []}),
        ("storage_smb_channel_encryption_with_secure_algorithm", {
            "file_service_status": "available",
            "file_smb_channel_encryption": "AES-256-GCM"}),
        ("storage_smb_channel_encryption_with_secure_algorithm", {
            "file_service_status": "unknown",
            "file_smb_channel_encryption": []}),
    ],
)
def test_storage_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid|no keySource|no name|not an"):
        builtin_registry().get("azure", rule_id).evaluator(values)


@pytest.mark.parametrize(
    ("rule_id", "values", "confirmed"),
    [
        ("containerregistry_admin_user_disabled",
         {"acr_admin_user_enabled": True}, True),
        ("containerregistry_admin_user_disabled",
         {"acr_admin_user_enabled": False}, False),
        ("containerregistry_not_publicly_accessible",
         {"acr_public_network_access": "Enabled"}, True),
        ("containerregistry_not_publicly_accessible",
         {"acr_public_network_access": "Disabled"}, False),
        ("containerregistry_uses_private_link",
         {"acr_private_endpoint_connection_count": 0}, True),
        ("containerregistry_uses_private_link",
         {"acr_private_endpoint_connection_count": 1}, False),
    ],
)
def test_container_registry_pack_matches_pinned_prowler_truth_conditions(
        rule_id, values, confirmed):
    assert builtin_registry().get("azure", rule_id).evaluator(values).confirmed is (
        confirmed)


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("containerregistry_admin_user_disabled",
         {"acr_admin_user_enabled": "false"}),
        ("containerregistry_not_publicly_accessible",
         {"acr_public_network_access": "Unknown"}),
        ("containerregistry_uses_private_link",
         {"acr_private_endpoint_connection_count": -1}),
    ],
)
def test_container_registry_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid|not an"):
        builtin_registry().get("azure", rule_id).evaluator(values)


@pytest.mark.parametrize(
    ("rule_id", "values", "confirmed"),
    [
        ("cosmosdb_account_automatic_failover_enabled",
         {"cosmosdb_enable_automatic_failover": False}, True),
        ("cosmosdb_account_automatic_failover_enabled",
         {"cosmosdb_enable_automatic_failover": True}, False),
        ("cosmosdb_account_automatic_failover_enabled",
         {"cosmosdb_enable_automatic_failover": None}, True),
        ("cosmosdb_account_backup_policy_continuous",
         {"cosmosdb_backup_policy_type": "Periodic"}, True),
        ("cosmosdb_account_backup_policy_continuous",
         {"cosmosdb_backup_policy_type": "Continuous"}, False),
        ("cosmosdb_account_backup_policy_continuous",
         {"cosmosdb_backup_policy_type": None}, True),
        ("cosmosdb_account_minimum_tls_version",
         {"cosmosdb_minimum_tls_version": "Tls11"}, True),
        ("cosmosdb_account_minimum_tls_version",
         {"cosmosdb_minimum_tls_version": "Tls12"}, False),
        ("cosmosdb_account_minimum_tls_version",
         {"cosmosdb_minimum_tls_version": "Tls13"}, False),
        ("cosmosdb_account_minimum_tls_version",
         {"cosmosdb_minimum_tls_version": None}, True),
        ("cosmosdb_account_public_network_access_disabled",
         {"cosmosdb_public_network_access": "Enabled"}, True),
        ("cosmosdb_account_public_network_access_disabled",
         {"cosmosdb_public_network_access": "Disabled"}, False),
        ("cosmosdb_account_public_network_access_disabled",
         {"cosmosdb_public_network_access": "SecuredByPerimeter"}, False),
        ("cosmosdb_account_public_network_access_disabled",
         {"cosmosdb_public_network_access": None}, True),
    ],
)
def test_cosmos_db_pack_matches_pinned_prowler_truth_conditions(
        rule_id, values, confirmed):
    assert builtin_registry().get("azure", rule_id).evaluator(values).confirmed is (
        confirmed)


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("cosmosdb_account_automatic_failover_enabled",
         {"cosmosdb_enable_automatic_failover": 0}),
        ("cosmosdb_account_backup_policy_continuous",
         {"cosmosdb_backup_policy_type": "Unknown"}),
        ("cosmosdb_account_minimum_tls_version",
         {"cosmosdb_minimum_tls_version": 1.2}),
        ("cosmosdb_account_public_network_access_disabled",
         {"cosmosdb_public_network_access": "Unknown"}),
    ],
)
def test_cosmos_db_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid"):
        builtin_registry().get("azure", rule_id).evaluator(values)


@pytest.mark.parametrize(
    ("values", "confirmed"),
    [
        ({"azureopenai_kind": "OpenAI",
          "azureopenai_public_network_access": "Enabled"}, True),
        ({"azureopenai_kind": "AIServices",
          "azureopenai_public_network_access": "Enabled"}, True),
        ({"azureopenai_kind": "OpenAI",
          "azureopenai_public_network_access": "Disabled"}, False),
    ],
)
def test_azure_openai_pack_matches_exported_producer_truth_conditions(
        values, confirmed):
    control = builtin_registry().get(
        "azure", "azureopenai_account_public_network_access_disabled")
    assert control.evaluator(values).confirmed is confirmed


@pytest.mark.parametrize("values", [
    {"azureopenai_kind": "TextAnalytics",
     "azureopenai_public_network_access": "Enabled"},
    {"azureopenai_kind": "OpenAI",
     "azureopenai_public_network_access": "Unknown"},
])
def test_azure_openai_pack_rejects_other_kinds_and_unknown_states(values):
    control = builtin_registry().get(
        "azure", "azureopenai_account_public_network_access_disabled")
    with pytest.raises(ValueError, match="not an Azure OpenAI kind|invalid"):
        control.evaluator(values)


def test_sql_pack_rejects_partial_database_evidence():
    control = builtin_registry().get("azure", "sqlserver_tde_encrypted_with_cmk")
    with pytest.raises(ValueError, match="does not match"):
        control.evaluator({
            "sql_tde_protector_type": "AzureKeyVault",
            "sql_database_inventory": ["master", "one", "two"],
            "sql_user_database_tde": {"one": "Enabled"},
        })


@pytest.mark.parametrize(
    ("rule_id", "values", "confirmed"),
    [
        ("keyvault_rbac_enabled",
         {"keyvault_enable_rbac_authorization": False}, True),
        ("keyvault_rbac_enabled",
         {"keyvault_enable_rbac_authorization": True}, False),
        ("keyvault_recoverable", {
            "keyvault_enable_soft_delete": True,
            "keyvault_enable_purge_protection": False,
         }, True),
        ("keyvault_recoverable", {
            "keyvault_enable_soft_delete": True,
            "keyvault_enable_purge_protection": True,
         }, False),
        ("keyvault_private_endpoints",
         {"keyvault_private_endpoint_connection_count": 0}, True),
        ("keyvault_private_endpoints",
         {"keyvault_private_endpoint_connection_count": 1}, False),
        ("keyvault_logging_enabled", {
            "keyvault_diagnostic_settings_status": "available",
            "keyvault_diagnostic_log_settings": [],
         }, True),
        ("keyvault_logging_enabled", {
            "keyvault_diagnostic_settings_status": "available",
            "keyvault_diagnostic_log_settings": [{
                "setting": "security", "category": "AuditEvent",
                "category_group": None, "enabled": True,
            }],
         }, False),
        ("keyvault_logging_enabled", {
            "keyvault_diagnostic_settings_status": "available",
            "keyvault_diagnostic_log_settings": [
                {"setting": "security", "category": None,
                 "category_group": "audit", "enabled": True},
                {"setting": "security", "category": None,
                 "category_group": "allLogs", "enabled": True},
            ],
         }, False),
        ("keyvault_logging_enabled", {
            "keyvault_diagnostic_settings_status": "available",
            "keyvault_diagnostic_log_settings": [
                {"setting": "audit-only", "category": None,
                 "category_group": "audit", "enabled": True},
                {"setting": "all-only", "category": None,
                 "category_group": "allLogs", "enabled": True},
            ],
         }, True),
    ],
)
def test_key_vault_pack_matches_pinned_prowler_truth_conditions(
        rule_id, values, confirmed):
    control = builtin_registry().get("azure", rule_id)
    assert control.evaluator(values).confirmed is confirmed


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("keyvault_rbac_enabled",
         {"keyvault_enable_rbac_authorization": "false"}),
        ("keyvault_recoverable", {
            "keyvault_enable_soft_delete": True,
            "keyvault_enable_purge_protection": 1,
         }),
        ("keyvault_private_endpoints",
         {"keyvault_private_endpoint_connection_count": True}),
        ("keyvault_logging_enabled", {
            "keyvault_diagnostic_settings_status": "available",
            "keyvault_diagnostic_log_settings": [{}],
         }),
        ("keyvault_logging_enabled", {
            "keyvault_diagnostic_settings_status": "unavailable",
            "keyvault_diagnostic_log_settings": [],
         }),
    ],
)
def test_key_vault_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid"):
        builtin_registry().get("azure", rule_id).evaluator(values)


def test_key_vault_logging_reports_unavailable_monitor_evidence():
    control = builtin_registry().get("azure", "keyvault_logging_enabled")
    with pytest.raises(ValueError, match="diagnostic settings are unavailable"):
        control.evaluator({
            "keyvault_diagnostic_settings_status": "unavailable",
            "keyvault_diagnostic_log_settings": None,
        })


@pytest.mark.parametrize(
    ("name", "nsg_id", "confirmed"),
    [
        ("application", None, True),
        ("application", "/subscriptions/sub/resourceGroups/rg/providers/"
         "Microsoft.Network/networkSecurityGroups/app", False),
        ("GatewaySubnet", None, False),
        ("AzureFirewallSubnet", None, False),
        ("AzureFirewallManagementSubnet", None, False),
        ("AzureBastionSubnet", None, False),
        ("RouteServerSubnet", None, False),
    ],
)
def test_network_subnet_pack_matches_pinned_prowler_semantics(
        name, nsg_id, confirmed):
    control = builtin_registry().get("azure", "network_subnet_nsg_associated")
    result = control.evaluator({
        "network_subnet_name": name,
        "network_subnet_nsg_id": nsg_id,
    })
    assert result.confirmed is confirmed


def test_network_subnet_pack_rejects_malformed_nsg_id():
    control = builtin_registry().get("azure", "network_subnet_nsg_associated")
    with pytest.raises(ValueError, match="invalid NSG id"):
        control.evaluator({
            "network_subnet_name": "application",
            "network_subnet_nsg_id": {},
        })


@pytest.mark.parametrize(
    ("rule_id", "values", "confirmed"),
    [
        ("app_client_certificates_on", {
            "app_kind": "app,linux",
            "app_client_cert_enabled": True,
            "app_client_cert_mode": "Required",
         }, False),
        ("app_client_certificates_on", {
            "app_kind": "app,linux",
            "app_client_cert_enabled": False,
            "app_client_cert_mode": "Required",
         }, True),
        ("app_ensure_auth_is_set_up", {
            "app_kind": "app,linux",
            "app_auth_platform_enabled": True,
         }, False),
        ("app_ensure_auth_is_set_up", {
            "app_kind": "app,linux",
            "app_auth_platform_enabled": None,
         }, True),
        ("app_ensure_auth_is_set_up", {
            "app_kind": "functionapp,linux",
            "app_auth_platform_enabled": False,
         }, False),
        ("app_ensure_using_http20", {
            "app_kind": "app,linux",
            "app_http20_enabled": True,
         }, False),
        ("app_ensure_using_http20", {
            "app_kind": "app,linux",
            "app_http20_enabled": False,
         }, True),
        ("app_http_logs_enabled", {
            "app_kind": "app,linux",
            "app_diagnostic_log_settings": [{
                "setting": "security",
                "category": "AppServiceHTTPLogs",
                "category_group": None,
                "enabled": True,
            }],
         }, False),
        ("app_function_ftps_deployment_disabled", {
            "app_kind": "functionapp,linux",
            "app_ftps_state": "AllAllowed",
         }, True),
        ("app_function_ftps_deployment_disabled", {
            "app_kind": "functionapp,linux",
            "app_ftps_state": "Disabled",
         }, False),
        ("app_function_not_publicly_accessible", {
            "app_kind": "functionapp,linux",
            "app_public_network_access": "Enabled",
         }, True),
        ("app_function_not_publicly_accessible", {
            "app_kind": "functionapp,linux",
            "app_public_network_access": "Disabled",
         }, False),
        ("app_function_vnet_integration_enabled", {
            "app_kind": "functionapp,linux",
            "app_virtual_network_subnet_id": None,
         }, True),
        ("app_function_vnet_integration_enabled", {
            "app_kind": "functionapp,linux",
            "app_virtual_network_subnet_id": "/subscriptions/sub/resourceGroups/rg/"
                                             "providers/Microsoft.Network/"
                                             "virtualNetworks/vnet/subnets/apps",
         }, False),
        ("app_function_ftps_deployment_disabled", {
            "app_kind": "app,linux",
            "app_ftps_state": "AllAllowed",
         }, False),
        ("app_http_logs_enabled", {
            "app_kind": "app,linux",
            "app_diagnostic_log_settings": [{
                "setting": "security",
                "category": None,
                "category_group": "allLogs",
                "enabled": True,
            }],
         }, False),
        ("app_http_logs_enabled", {
            "app_kind": "app,linux",
            "app_diagnostic_log_settings": [],
         }, True),
        ("app_http_logs_enabled", {
            "app_kind": "functionapp,linux",
            "app_diagnostic_log_settings": [],
         }, False),
    ],
)
def test_app_service_pack_matches_pinned_prowler_truth_conditions(
        rule_id, values, confirmed):
    control = builtin_registry().get("azure", rule_id)
    assert control.evaluator(values).confirmed is confirmed


@pytest.mark.parametrize(
    ("rule_id", "values"),
    [
        ("app_client_certificates_on", {
            "app_kind": "app", "app_client_cert_enabled": "true",
            "app_client_cert_mode": "Required"}),
        ("app_ensure_auth_is_set_up", {
            "app_kind": "app", "app_auth_platform_enabled": 1}),
        ("app_ensure_using_http20", {
            "app_kind": "app", "app_http20_enabled": "false"}),
        ("app_http_logs_enabled", {
            "app_kind": "app", "app_diagnostic_log_settings": [{}]}),
        ("app_function_ftps_deployment_disabled", {
            "app_kind": "functionapp", "app_ftps_state": 1}),
        ("app_function_not_publicly_accessible", {
            "app_kind": "functionapp", "app_public_network_access": False}),
        ("app_function_vnet_integration_enabled", {
            "app_kind": "functionapp", "app_virtual_network_subnet_id": {}}),
    ],
)
def test_app_service_pack_rejects_malformed_evidence(rule_id, values):
    with pytest.raises(ValueError, match="invalid|not a"):
        builtin_registry().get("azure", rule_id).evaluator(values)
