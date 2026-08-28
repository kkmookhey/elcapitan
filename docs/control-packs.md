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
`azure-key-vault`, and `azure-network`. Registration is fail-closed: duplicate
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
