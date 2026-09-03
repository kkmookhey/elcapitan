# Control-pack architecture

El Capitan's workflow is provider-neutral; cloud assertions are not. A control
pack is the boundary between the reusable fleet platform and the exact service
semantics required to validate one scanner control safely.

## Reusable core

The core owns OCSF intake, case correlation, risk assessment, evidence records,
workflow state, scheduling, maker/checker review, approval, audit, and handoff.
None of those components needs to know whether a resource is Azure SQL, S3, or
a future Kubernetes workload.

## Service control packs

Each installed pack registers explicit definitions containing:

- provider and stable scanner rule identity;
- accepted resource types;
- evidence aspects the control consumes;
- a deterministic evaluator;
- separate validation, planning, and execution capability flags.

The built-in v1 packs are currently `aws-s3`, `aws-rds`, `aws-ebs-volume`,
`aws-ec2-security-group`, `azure-storage`, `azure-sql`,
`azure-key-vault`, `azure-network`, `azure-app-service`,
`azure-container-registry`, `azure-cosmos-db`, and `azure-openai`. Registration
is fail-closed: duplicate provider/rule keys,
mismatched pack ownership, missing evidence contracts, and mismatched resource
types are rejected.

Validation coverage never implies mutation coverage. For example,
`sqlserver_tde_encrypted_with_cmk` supports live validation but explicitly has
no remediation-planning or execution capability.

The AWS S3 pack validates seven bucket controls. Object versioning has the one
AWS evidence-to-review path: after live confirmation and contextual priority,
the planner requires an exact Terraform state owner of type
`aws_s3_bucket_versioning`. It materializes only a literal
`Disabled`/`Suspended` to `Enabled` status change in that linked block. The
ephemeral plan gate accepts exactly one in-place update and exactly the nested
path `versioning_configuration[0].status`; create, delete, replacement, MFA
Delete, sibling-resource, and additional-attribute changes fail closed. The
provider-neutral SRE, window, rollback, model-diversity, evidence-chain, and
human-review gates can then issue `HumanReviewPackage.v1` with execution still
`not_started`. This planning/package contract is tested locally; it has not
been measured against a live AWS Terraform estate and grants no AWS execution
authority.

The other six S3 controls validate KMS default encryption, server access
logging, event notifications, at least one enabled lifecycle rule, Object
Lock, and MFA Delete. They consume the S3 API documents already collected for
the bucket, so they add no cloud calls or scanner permissions. Known
not-configured error codes remain explicit absent evidence; an authorization
failure, unknown enum, malformed document, or invented absent marker blocks
validation instead of becoming a confirmed finding. The six additions are
contract tested and have no remediation-planning or live-execution capability.

The AWS RDS pack validates eight DB-instance controls from one exact-resource
`DescribeDBInstances` read: automated backups, copying tags to snapshots,
enhanced monitoring, IAM database authentication, VPC placement, CloudWatch
Logs exports, automatic minor-version upgrades, and storage encryption. The
collector accepts only a DB-instance ARN, derives the query region from that
ARN, rejects a conflicting finding region, and requires exactly one returned
instance whose ARN matches the request. It stores only normalized control
fields—not endpoints, usernames, tags, subnet IDs, or security groups.

The applicability rules remain pinned to Prowler: backup findings exclude read
replicas by default, copy-tags findings exclude Aurora engines, and IAM
database-authentication findings apply only to the engines Prowler recognizes.
An authorization error, absent or multiple resource, pagination marker,
DocumentDB engine, response-ARN mismatch, or malformed field blocks validation.
All eight controls are contract tested and validation-only; the pack adds no
planning or execution authority. The API shape is pinned to AWS's
[DescribeDBInstances contract](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html)
and [DBInstance response type](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html),
and the truth conditions are pinned to Prowler's
[RDS checks](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services/rds).

The AWS EC2 security-group pack validates twenty controls from two bounded
read-only calls: one `DescribeSecurityGroups` request for the exact group ID
and one filtered `DescribeNetworkInterfaces` request capped after the first
attachment. The collector binds region and account to the finding ARN, requires
exactly one matching group, validates any response ARN, and verifies that every
returned interface is attached to the requested group. It persists only the
group name, an in-use boolean, and normalized ingress/egress protocol, port,
IPv4, and IPv6 fields; descriptions, tags, VPC IDs, interface IDs, and account
details are excluded.

The controls cover all-port exposure, Prowler's configured high-risk ports,
fourteen named service-port families, broad globally routable IPv4 ranges,
default-group traffic, Launch Wizard groups, and groups with more than fifty
ingress or egress permission entries. The eighteen attachment-aware checks
preserve Prowler's default exclusion of unused groups. Specific-port findings
also preserve its duplicate suppression when the all-ports check is active.
Denied, absent, multiple, mismatched, partially paginated, or malformed
responses remain unavailable evidence. All twenty controls are contract tested
and validation-only.

The response shapes are pinned to AWS's
[DescribeSecurityGroups](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html),
[IpPermission](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html),
and [DescribeNetworkInterfaces](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkInterfaces.html)
contracts. Truth conditions are pinned to Prowler's
[EC2 security-group checks](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services/ec2).

The AWS EBS volume pack validates two controls from two exact-resource reads:
volume encryption and the presence of at least one snapshot owned by the
audited account. `DescribeVolumes` is limited to the volume ID bound into the
finding ARN. `DescribeSnapshots` is limited to owner `self`, filtered to that
volume ID, and capped after the first result because the Prowler condition is
existence rather than snapshot inventory.

The collector binds region and account to the ARN, requires exactly one
matching volume, and validates the owner and volume of any returned snapshot.
It persists only the encryption boolean and owned-snapshot-presence boolean;
snapshot IDs, KMS identifiers, tags, attachments, descriptions, timestamps,
and sizes are excluded. Denied, absent-volume, multiple-volume, mismatched,
malformed, or empty-partial responses remain unavailable evidence. Both
controls are contract tested and validation-only, with no planning or
execution authority. The shapes are pinned to AWS's
[DescribeVolumes](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html)
and [DescribeSnapshots](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html)
contracts, and the truth conditions to Prowler's
[EBS checks](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/aws/services/ec2).

The Azure SQL evidence contract was also run end to end on 2026-08-28 inside a
no-ingress Container Apps job using a user-assigned identity with `Reader` at
one disposable SQL server and nowhere broader. The measured edge case had TDE
enabled on its user database but a `ServiceManaged` encryption protector. The
collector recorded both facts and the control correctly remained confirmed
because the Prowler rule requires an `AzureKeyVault` customer-managed key.
Sanitized copies of the three ARM response shapes are regression fixtures.

The Azure Storage pack also evaluates ten account-level checks from its
already measured account and blob-service evidence: customer-managed key
encryption, geo-redundant replication, infrastructure encryption, default
network deny, private endpoints, Shared Key disablement, default Entra
authorization, container soft delete, and the trusted-Azure-services bypass.
The tenth control requires account-key rotation within 90 days; an absent
`keyPolicy`, zero days, or more than 90 days remains a confirmed finding.
These controls add no cloud calls and no permissions. Their evaluators pin
Prowler's current defaults, including null Shared Key state behaving as enabled
and only `Standard_GRS`, `Standard_GZRS`, `Standard_RAGRS`, and
`Standard_RAGZRS` satisfying geo redundancy. The real sanitized Eiger lab
account and blob-service fixtures are passed through all ten evaluators as one
regression contract. Planning and execution remain disabled for the new
controls; existing storage remediation authority is not inherited by sibling
checks.

The File Service extension adds
`storage_smb_channel_encryption_with_secure_algorithm` from one bounded
management-plane GET of `fileServices/default`. Its evidence is only File
Service availability plus the normalized SMB channel-encryption algorithm
list. Prowler's current default is pinned exactly: the list must be non-empty
and every entry must be `AES-256-GCM`; mixed 128/256-bit lists fail. A denied,
unsupported, or malformed File Service read marks only this control
unavailable, so it cannot suppress independently complete account/blob
validations. The response shape was measured read-only on 2026-08-28 against
the Eiger lab account; `channelEncryption` was null and correctly normalized
to an empty failing list. Prowler exports may identify the canonical
`fileServices/default` child as the primary resource; the collector resolves
only that exact child to its owning account for bounded reads while retaining
the child ARM ID in the evidence envelope. Planning and execution are disabled.

The blob-service ARM contract makes `containerDeleteRetentionPolicy` optional.
Its explicit absence in a complete response therefore confirms that container
soft delete is not configured; malformed non-null policy shapes still fail
closed as unavailable evidence.

Semantics are pinned to Prowler's [Azure Storage check
implementations](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/storage)
and Microsoft's [Storage Accounts - Get REST
contract](https://learn.microsoft.com/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2025-06-01).
The File Service field is pinned to Microsoft's [File Services - Get Service
Properties REST
contract](https://learn.microsoft.com/rest/api/storagerp/file-services/get-service-properties?view=rest-storagerp-2025-06-01).

The Azure Container Registry pack validates
`containerregistry_admin_user_disabled`,
`containerregistry_not_publicly_accessible`, and
`containerregistry_uses_private_link` from one management-plane GET of the
exact registry. It persists only the admin-user boolean, public-network enum,
and private-endpoint connection count. Missing values follow Microsoft's
documented defaults and Prowler's SDK fallbacks: admin user disabled, public
network enabled, and no private endpoints. The private-link evaluator mirrors
Prowler's current existence check; it does not invent approval-state semantics
that the producer does not apply. Planning and execution are disabled.

The response contract was measured read-only on 2026-08-28 against the
existing El Capitan lab registry. It returned all three failing branches:
admin user enabled, public network enabled, and an empty private-endpoint
connection list. The same collector then ran in a no-ingress Container Apps
job whose scanner identity held `Reader` at only that registry; a separate
identity held only `AcrPull` for the candidate image. The execution succeeded
and emitted only the three normalized aspects. The temporary job, exact Reader
assignment, candidate image tag, and local job definition were deleted and
independently confirmed absent. The sanitized response is a regression
fixture. Semantics are pinned to Prowler's [Container Registry check
implementations](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/containerregistry)
and Microsoft's [Registries - Get REST
contract](https://learn.microsoft.com/rest/api/container-registry/registries/get?view=rest-container-registry-2025-11-01).

The Azure OpenAI pack validates
`azureopenai_account_public_network_access_disabled` with one
management-plane GET of the exact Cognitive Services account. It persists only
the live account kind and `publicNetworkAccess` enum. The account must still be
kind `OpenAI` or `AIServices`; another Cognitive Services kind fails closed
instead of satisfying a stale or misclassified finding. An omitted or unknown
public-network field also fails closed because Microsoft's response contract
does not assign it a GET-time default. Planning and execution are disabled.

This rule is contract-tested against Microsoft's 2025-06-01 response schema
and was checked offline against an authorized private Prowler 5.36.0 export,
which contains two failing `OpenAI` accounts, two failing `AIServices`
accounts, and one passing `OpenAI` account. No customer cloud request was made.
The authorized El Capitan lab subscription contains no Cognitive Services
account, so this pack does not yet claim the no-ingress managed-identity
evidence grade earned by the other measured Azure packs. Fields are pinned to
Microsoft's [Accounts - Get
REST contract](https://learn.microsoft.com/rest/api/aifoundry/accountmanagement/accounts/get?view=rest-aifoundry-accountmanagement-2025-06-01).

The Azure Cosmos DB pack validates four account checks from one bounded
management-plane GET: automatic failover enabled, continuous backup, TLS 1.2
or higher, and disabled public network access. It persists only the automatic
failover boolean, backup-policy type, minimum-TLS enum, and public-network
enum. Missing properties remain explicit `null` evidence and match Prowler's
failing branches instead of becoming a successful observation. TLS accepts
`Tls12` and Prowler's forward-compatible `Tls13`; public access is acceptable
only when `Disabled` or `SecuredByPerimeter`.

This pack is contract tested and export observed, not E2E measured. Its
synthetic fixture is pinned to Microsoft's 2026-03-15 Database Accounts Get
schema and contains no customer observation. Malformed types and unknown enums
fail collection, and an authorization denial remains unavailable evidence.
Planning and execution are disabled for all four controls. Semantics are pinned
to Prowler's [Cosmos DB check
implementations](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/cosmosdb)
and Microsoft's [Database Accounts - Get REST
contract](https://learn.microsoft.com/rest/api/cosmos-db-resource-provider/database-accounts/get?view=rest-cosmos-db-resource-provider-2026-03-15).

The Azure Key Vault pack pins the current Prowler truth conditions for
`keyvault_rbac_enabled`, `keyvault_private_endpoints`,
`keyvault_recoverable`, and `keyvault_logging_enabled`. The first three consume
one Key Vault management-plane GET; they never list keys, secrets, or
certificates. A no-ingress managed-identity run on 2026-08-28 measured an
important absent-property contract: a vault with purge protection disabled
omitted `enablePurgeProtection`, and a vault with no private endpoints omitted
`privateEndpointConnections`. The collector records those states as `null` and
zero respectively, so they remain confirmed failures instead of becoming
unavailable evidence. The sanitized ARM document is a regression fixture.

The logging control adds one bounded diagnostic-settings list GET and retains
only the setting name, category, category group, and enabled state. It mirrors
Prowler's exact current condition: an enabled `AuditEvent` category passes, or
enabled `audit` and `allLogs` groups must coexist in the same diagnostic
setting. Destination IDs, metrics, and retention policies are excluded. A
denied or malformed Monitor response marks only the logging evidence
unavailable; it cannot suppress the independently complete vault-property
controls or become an empty-list finding. This extension is contract tested
with a synthetic Microsoft-schema fixture, not E2E measured. Planning and
execution remain disabled for all four Key Vault controls.

Semantics are pinned to the official [Prowler Key Vault check
implementations](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/keyvault)
and fields to Microsoft's [Vaults - Get 2024-11-01 REST
contract](https://learn.microsoft.com/rest/api/keyvault/keyvault/vaults/get?view=rest-keyvault-keyvault-2024-11-01)
and [Diagnostic Settings - List
contract](https://learn.microsoft.com/rest/api/monitor/diagnostic-settings/list?view=rest-monitor-2021-05-01-preview).

The first Azure Network control, `network_subnet_nsg_associated`, consumes one
management-plane GET of the exact nested subnet resource. Its evaluator follows
Prowler's explicit exclusions for `GatewaySubnet`, `AzureFirewallSubnet`,
`AzureFirewallManagementSubnet`, `AzureBastionSubnet`, and
`RouteServerSubnet`; all other subnets require a non-empty
`networkSecurityGroup.id`. Planning and execution are disabled. Broader NSG
port/rule analysis is intentionally a separate future contract because Azure
priority and default-rule resolution cannot be inferred from association.
The nested-resource parser and exact-subnet collector were run end to end on
2026-08-28 in a no-ingress managed-identity job. The scanner held `Reader` at
only one empty subnet; it correctly captured an omitted
`networkSecurityGroup` as `null`. The sanitized ARM response is the regression
fixture.

Semantics are pinned to Prowler's [subnet NSG association
check](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/network/network_subnet_nsg_associated)
and the Microsoft [Subnets - Get REST
contract](https://learn.microsoft.com/rest/api/virtualnetwork/subnets/get?view=rest-virtualnetwork-2025-05-01).

The first Azure App Service pack covers four web-app checks:
`app_client_certificates_on`, `app_ensure_auth_is_set_up`,
`app_ensure_using_http20`, and `app_http_logs_enabled`. Collection is bounded
to the site, web configuration, Auth Settings V2, and diagnostic-settings ARM
documents. Persisted evidence contains only app kind, client-certificate
enablement/mode, authentication-platform enablement, HTTP/2 enablement, and
normalized diagnostic log category states. It excludes application settings,
authentication provider configuration, destinations, code, and content. The
client-certificate control deliberately accepts Prowler's
`microsoft.web/sites/config` OCSF type even though Prowler retains the parent
site ARM id. Every web-app evaluator also verifies that the live Azure kind
still starts with `app`, preventing a reclassified Function App from satisfying
a stale web-app finding.

The collector was run end to end on 2026-08-28 in a no-ingress Container Apps
job. Its managed identity held `Reader` at one tagged, empty disposable web app
and nowhere broader. The lab measured Azure's counterintuitive default of
`clientCertMode: Required` together with `clientCertEnabled: false`, explicit
disabled Auth Settings V2, and an empty diagnostic-settings collection. HTTP/2
was deliberately disabled on the disposable app to exercise the failing
branch. The job returned only the six normalized evidence aspects, succeeded,
and the job, role assignment, web app, plan, and candidate image were deleted
and independently confirmed absent. Sanitized ARM documents preserve those
shapes as regression fixtures.

The same bounded collector now supports the three distinct Function App
controls `app_function_ftps_deployment_disabled`,
`app_function_not_publicly_accessible`, and
`app_function_vnet_integration_enabled`. Their evaluators first require a live
kind beginning with `functionapp`, then independently require `ftpsState` to be
`Disabled`, `publicNetworkAccess` to be `Disabled`, and a non-empty
`virtualNetworkSubnetId`. Validation coverage does not imply change authority:
planning and execution remain disabled for all seven App Service controls.

This Function App contract was measured on 2026-08-28 against a tagged, empty
disposable Linux Function App on its own temporary Basic plan and dedicated
empty storage account. A no-ingress job with `Reader` only at that Function App
captured `FtpsOnly`, `Enabled`, and a null subnet ID, confirming all three
intentional failure branches. No function code was deployed. The job, exact
role assignment, Function App, plan, storage account, and candidate image were
then deleted and independently confirmed absent. Sanitized measurements are
regression fixtures.

Semantics are pinned to Prowler's [App Service check
implementations](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/app),
Microsoft's [web configuration REST
contract](https://learn.microsoft.com/rest/api/appservice/web-apps/get-configuration?view=rest-appservice-2024-11-01),
and the [diagnostic settings list
contract](https://learn.microsoft.com/rest/api/monitor/diagnostic-settings/list?view=rest-monitor-2021-05-01-preview).

## Provider adapters

Packs evaluate typed evidence; provider adapters collect it. Collection remains
service-aware because auth, API pagination, absent-state semantics, and resource
addressing differ by provider. Azure SQL's collector must read the encryption
protector, every database page, and every user-database TDE state. S3 versioning
has a different absent/error contract.

This separation permits shared Azure ARM, AWS, GCP, Kubernetes, repository, and
telemetry transports without pretending that service semantics are universal.

## Adding a control

A control is ready only when all applicable steps are complete:

1. Pin the producer's stable rule ID and resource types.
2. Define the minimum complete evidence contract from primary API documentation.
3. Implement read-only collection with pagination, bounds, and denied/unknown
   states that fail closed.
4. Implement deterministic confirmed/not-confirmed evaluation.
5. Add sanitized fixtures and negative tests for partial, malformed, denied,
   duplicated, and mismatched evidence.
6. Register planning only when authoritative code/config linking is verified.
7. Register execution only after preconditions, exact scope, rollback,
   monitoring, and post-change validation are independently tested.

Simple scalar controls may eventually use declarative selectors. Compound
controls remain small audited code modules. A declarative form must meet the
same evidence and failure requirements; it is not a shortcut around them.

## V1 scope

The target is two clouds and roughly ten high-value services per cloud, chosen
by customer finding volume and remediation value. Unsupported services remain
visible in coverage reports and are never inferred from neighboring controls.
