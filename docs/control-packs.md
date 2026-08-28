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

The built-in v1 packs are currently `aws-s3`, `azure-storage`, `azure-sql`,
`azure-key-vault`, `azure-network`, and `azure-app-service`. Registration is fail-closed: duplicate
provider/rule keys,
mismatched pack ownership, missing evidence contracts, and mismatched resource
types are rejected.

Validation coverage never implies mutation coverage. For example,
`sqlserver_tde_encrypted_with_cmk` supports live validation but explicitly has
no remediation-planning or execution capability.

The Azure SQL evidence contract was also run end to end on 2026-08-28 inside a
no-ingress Container Apps job using a user-assigned identity with `Reader` at
one disposable SQL server and nowhere broader. The measured edge case had TDE
enabled on its user database but a `ServiceManaged` encryption protector. The
collector recorded both facts and the control correctly remained confirmed
because the Prowler rule requires an `AzureKeyVault` customer-managed key.
Sanitized copies of the three ARM response shapes are regression fixtures.

The Azure Storage pack also evaluates nine account-level checks from its
already measured account and blob-service evidence: customer-managed key
encryption, geo-redundant replication, infrastructure encryption, default
network deny, private endpoints, Shared Key disablement, default Entra
authorization, container soft delete, and the trusted-Azure-services bypass.
These controls add no cloud calls and no permissions. Their evaluators pin
Prowler's current defaults, including null Shared Key state behaving as enabled
and only `Standard_GRS`, `Standard_GZRS`, `Standard_RAGRS`, and
`Standard_RAGZRS` satisfying geo redundancy. The real sanitized Eiger lab
account and blob-service fixtures are passed through all nine evaluators as one
regression contract. Planning and execution remain disabled for the new
controls; existing storage remediation authority is not inherited by sibling
checks.

Semantics are pinned to Prowler's [Azure Storage check
implementations](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/storage)
and Microsoft's [Storage Accounts - Get REST
contract](https://learn.microsoft.com/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2025-06-01).

The Azure Key Vault pack pins the current Prowler truth conditions for
`keyvault_rbac_enabled`, `keyvault_private_endpoints`, and
`keyvault_recoverable`. All three consume one Key Vault management-plane GET;
they never list keys, secrets, or certificates. A no-ingress managed-identity
run on 2026-08-28 measured an important absent-property contract: a vault with
purge protection disabled omitted `enablePurgeProtection`, and a vault with no
private endpoints omitted `privateEndpointConnections`. The collector records
those states as `null` and zero respectively, so they remain confirmed failures
instead of becoming unavailable evidence. The sanitized ARM document is a
regression fixture. Planning and execution remain disabled for this pack.

Semantics are pinned to the official [Prowler Key Vault check
implementations](https://github.com/prowler-cloud/prowler/tree/master/prowler/providers/azure/services/keyvault)
and fields to Microsoft's [Vaults - Get 2024-11-01 REST
contract](https://learn.microsoft.com/rest/api/keyvault/keyvault/vaults/get?view=rest-keyvault-keyvault-2024-11-01).

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
