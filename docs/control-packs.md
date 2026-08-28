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

The built-in v1 packs are currently `aws-s3`, `azure-storage`, and
`azure-sql`. Registration is fail-closed: duplicate provider/rule keys,
mismatched pack ownership, missing evidence contracts, and mismatched resource
types are rejected.

Validation coverage never implies mutation coverage. For example,
`sqlserver_tde_encrypted_with_cmk` supports live validation but explicitly has
no remediation-planning or execution capability.

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
