# Threat model

## Scope and assets

This model covers the self-hosted shadow, review, scheduler, and bounded action
planes described in [product architecture](product-architecture.md). The assets
to protect are customer finding exports, normalized evidence, tenant ownership,
cloud and repository identities, model manifests and responses, review
packages, approval hashes, durable jobs and leases, execution checkpoints,
rollback proof, release artifacts, and audit records.

The public synthetic demo is not a customer-data boundary. PostgreSQL is the
durable production-shaped state and artifact boundary; local SQLite and files
exist for development and the cloud-free quickstart.

## Trust boundaries

```text
scanner export -> shadow intake -> tenant state/evidence -> human browser
                         |                 |
read-only cloud identity +-> validator    +-> isolated review preparation
                                               |
bounded model manifest (optional) -> typed maker/checker records
                                               |
package hash -> named human decision -> durable scheduler -> action worker
                                                        -> checkpoint/verify/rollback
```

Each arrow crosses a validation or authorization boundary. Input identity,
tenant, schema, freshness, resource scope, evidence aspect, package hash, and
role are checked again at the receiving boundary. A prior successful check does
not confer ambient authority downstream.

## Threats and controls

### Identity collapse and privilege escalation

One identity spanning scanner, observer, planner, and executor could turn a
read-only defect into a cloud change. Deployments use separate identities and
reject ambient personal sessions. Shadow and review processes contain no
mutation endpoint. Executor roles are absent by default and, when separately
authorized, are restricted to exact operations and resources.

Residual risk: cloud role configuration is operator-controlled. A release or
pilot review must independently inspect granted and denied operations.

### Model egress and prompt injection

Finding text, Terraform, or evidence can contain instructions or secrets. No
shadow or review route invokes a model. Model-backed preparation is optional,
requires an explicit provider and bounded field manifest, sends typed minimized
inputs, validates typed outputs, and cannot own state transitions. Customer
fields require written authorization before egress.

Residual risk: authorized fields may still contain hostile content. Runtime
responses remain untrusted proposals subject to deterministic gates.

### Tenant confusion and cross-tenant disclosure

Forged identifiers, shared databases, or unscoped queries could mix customer
records. Stores bind cases, findings, evidence, and review requests to a tenant;
services require the tenant on reads and writes. A real pilot uses a dedicated
database and identity boundary rather than relying on logical separation alone.

Residual risk: the technical preview does not claim public multi-tenant SaaS
isolation. A reverse proxy must provide named-user identity and external access
control for customer exposure.

### Evidence tampering, truncation, and replay

Partial provider responses, stale exports, altered artifacts, or re-used
records could produce a false conclusion. Evidence is schema-validated,
content-addressed, minimized to named aspects, and appended rather than edited.
Collectors reject malformed, absent, denied, incomplete, and out-of-scope
responses. Case transitions cite immutable record and evidence identifiers.

Residual risk: host or database administrators can alter storage. Operators
must restrict database administration, back up audit records, and retain
external access logs. A future release may add independent transparency-log
anchoring.

### Approval replay or package substitution

An approval applied to a changed plan, evidence set, or target could authorize
unreviewed work. The human decision binds to the exact review-package hash.
Preparation changes supersede prior records. Scheduling and execution verify
the approved hash and current case state; an approval does not imply connector
or identity availability.

Residual risk: shared pilot tokens do not prove a named person. Public customer
approval requires SSO and named-user audit.

### Worker-lease races and duplicate execution

Crashes, retry races, or two workers could execute a job twice. Durable jobs use
leases and compare-and-set state. Workers claim one due job and release or
expire leases deterministically. Execution logic must be idempotent or reject a
changed checkpoint before mutation.

Residual risk: a provider operation can time out after applying remotely but
before acknowledgement. Connector-specific reconciliation must inspect current
state before retrying.

### Connector scope expansion and confused deputy

User-controlled resource IDs, Terraform links, or provider responses could
redirect an action. Connectors support explicit provider/resource/control
tuples, snapshot the exact prior property, reject unsupported plans, and do not
accept the scanner identity for execution. Validation capability never implies
planning or execution capability.

Residual risk: cloud authorization remains the final enforcement layer. Exact
resource scopes and deny tests are mandatory before an action pilot.

### Rollback failure and unsafe recovery

A change can apply while health verification or rollback fails. The worker
checkpoints the prior setting, verifies deterministic security and health
contracts, and automatically restores on failure. A failed restore is a
terminal high-severity outcome with retained evidence; it must never be called
successful remediation.

Residual risk: rollback cannot guarantee recovery from provider outages,
irreversible operations, data-plane effects, or dependencies outside the
declared health contract. v0.1 action connectors are therefore narrow and
non-production pilots require canary/disposable resources.

### Build and release compromise

A poisoned dependency, workflow action, base image, leaked credential, or
mutable artifact could compromise users. Dependencies and base images are
version-pinned, CI performs dependency, secret, and image scanning, images run
as a non-root UID, and the guarded workflow emits checksums, an SBOM, maximum
BuildKit provenance, and GitHub-signed attestations for distributions and image
digests. Publication requires a protected environment and an exact approval
phrase.

Residual risk: several GitHub Actions use immutable release tags rather than
commit SHAs and must remain under Dependabot review. Consumers must verify
attestations and digests, not tags alone.

## Required deployment controls

- HTTPS and SSO or an identity-aware proxy for any non-local browser exposure.
- Customer-specific database, tenant, identities, encryption, logs, retention,
  deletion agreement, and incident contact.
- No action identity in shadow or review services.
- No model credential unless the exact provider and egress manifest are
  approved.
- Read-only role review plus an independent denied-mutation test.
- Backups and restore rehearsal appropriate to the retention agreement.

## Security acceptance

A release candidate passes this model only when the controls above have tests
or linked run evidence, the capability matrix matches the registry, current
and historical secret scans have been adjudicated, and all residual risks are
visible in release notes. A customer pilot adds the gates in
[the pilot profile](first-customer-pilot.md).
