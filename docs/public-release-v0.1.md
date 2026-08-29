# El Capitan v0.1 public release blueprint

**Proposed label:** `v0.1.0` technical preview

**Product category:** evidence-bound cloud remediation control plane

**Default posture:** self-hosted, read-only shadow mode, human-gated action

## The promise

El Capitan turns scanner findings into a prioritized queue, validates supported
claims against live cloud configuration, and assembles an auditable remediation
package for human review. Every material conclusion must point to typed,
immutable evidence. Missing, stale, malformed, or unsupported evidence fails
closed.

The public release must not be described as an autonomous replacement for an
SRE or DevOps team. It is an operational control plane that coordinates those
roles, automates bounded work, and makes the remaining human decision explicit.

## What a user can do

The primary ten-minute journey is:

1. Run locally with Docker or `uv`, or deploy the supplied Azure Container Apps
   templates.
2. Import a Prowler OCSF or AWS Security Hub ASFF export.
3. Inspect exact FAIL/PASS/MANUAL accounting, deduplication, risk factors, and
   deterministic coverage.
4. Connect a least-privilege read-only scanner identity and validate eligible
   findings against the exact resource.
5. Inspect normalized evidence, unavailable/cleared/confirmed outcomes, and the
   immutable case timeline.
6. For explicitly supported controls, attach an IaC snapshot and operational
   context, run maker/checker review, and inspect the exact patch, SRE review,
   window, verification, and rollback records.
7. Stop at a package-bound human decision. Approval creates durable approval
   and scheduling records; it does not imply that a cloud change is executable.

The synthetic browser lifecycle remains a separate demonstration of healthy
deployment and automatic rollback. It must never be presented as evidence that
every validation control has a production action connector.

## Capability contract at release

The machine-readable output of `elcapitan capabilities` is authoritative. At
the time of this blueprint it reports:

| Capability | Count | Public interpretation |
|---|---:|---|
| Deterministic live-validation rules | 35 | 34 Azure, 1 AWS |
| Verified remediation-planning rules | 4 | 3 Azure Storage, 1 AWS S3 |
| Live execution rules | 2 | Azure Storage only; disabled from the shadow service |

The documentation and UI must never collapse these three columns into a single
"supported" badge. Each control also receives an evidence grade:

- **E2E measured:** collector and evaluator ran with a least-privilege identity
  against a disposable or approved non-production resource.
- **Contract tested:** official response schema and sanitized fixtures exercise
  success, failure, malformed, and absent-property branches.
- **Export observed:** real scanner output proves rule/resource shapes offline,
  without a customer cloud call.

Azure OpenAI and Cosmos DB enter v0.1 as contract tested and export observed,
not E2E measured. That distinction is a feature of the trust model, not a
footnote.

## Shape of the release

### Repository

A public GitHub repository is the source of truth, containing the core engine,
control packs, UI assets, schemas, tests, Dockerfiles, safe sample data, Azure
deployment examples, architecture, threat model, and operator guides. Customer
exports, credentials, generated databases, model traces, and private deployment
values are excluded from the repository and its history.

### Installable artifacts

- A pinned Python 3.12 wheel and source distribution.
- A versioned, non-root, multi-architecture OCI image published to GHCR.
- A source checkout path using `uv` for contributors.
- A local quickstart using Docker Compose with PostgreSQL and no cloud
  credentials.
- Checksums, an SBOM, build provenance, and signatures for release artifacts.

Kubernetes/Helm and a public multi-tenant SaaS are not v0.1 requirements.
Container Apps remains a documented deployment example, not the product's
portable runtime contract.

### Interfaces

- Shadow fleet browser console for intake, coverage, validation, and evidence.
- Separate human review browser service over the durable database.
- CLI for intake, offline reports, validation, promotion, review preparation,
  capabilities, demos, and controlled operations.
- Typed JSON records and schemas as the stable integration surface.

The first public release does not promise a general REST API, plugin marketplace,
or arbitrary agent graph designer.

## Trust and security posture

- Shadow mode has no approval, model, scheduling, or execution route.
- Review mode has no cloud mutation or model route.
- Customer evidence is not sent to an external model without an explicit,
  bounded manifest and provider authorization.
- Workload identity or short-lived federation is preferred; personal cloud
  sessions and broad administrator roles are rejected operationally.
- Evidence is minimized to named control aspects rather than whole provider
  responses, source repositories, Terraform state, or log bodies.
- Unknown resource types, kinds, states, permissions, and response shapes fail
  closed.
- Approval is bound to the exact package hash. Execution additionally requires
  a separately implemented connector, policy, identity, health contract,
  checkpoint, and rollback proof.
- Shared access tokens are demo/pilot bridges. Public customer approval requires
  SSO, initially Microsoft Entra ID, and named-user audit.

## Release gates

### Must pass before the tag

- Full test suite and distribution build pass from a clean checkout.
- CI runs tests, formatting/static checks, dependency review, secret scanning,
  and container scanning on every pull request.
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, changelog,
  support policy, and versioning policy exist.
- The license and project name have explicit legal/business approval. The
  repository currently has no license, so publication must not occur by
  accident.
- Git history and built artifacts pass a customer-name, credential, private
  endpoint, and secret audit.
- Safe sample fixtures contain synthetic identifiers only; measured lab
  fixtures are sanitized and labeled.
- A threat model covers identity separation, model egress, tenant isolation,
  evidence integrity, approval replay, worker leases, action connectors, and
  rollback failure.
- The quickstart works on a new machine and reaches a useful result in ten
  minutes without cloud credentials or model keys.
- The UI shows synthetic/live, confirmed/cleared/unavailable, validation/
  planning/execution, and evidence grade without ambiguity.
- A documented upgrade, backup, restore, retention, and uninstall path exists.

### Must pass before a real customer pilot

- Customer-specific database and identity boundary.
- SSO or identity-aware proxy, HTTPS, access logs, retention, and deletion
  agreement.
- Exact read-only role review and independent denial of mutation operations.
- Dry-run intake accounting reconciled with the source export.
- Customer approval for every bounded model-egress field and provider, if models
  are used at all.
- No action identity in the shadow deployment.

### Deliberately deferred

- Unattended production changes.
- Broad AWS execution.
- Generic remediation for every resource sharing a cloud type.
- Multi-tenant hosted SaaS guarantees.
- Marketplace integrations and ticketing/chat notifications.
- Claims of complete benchmark, cloud, or service coverage.

## Launch package

The launch should include:

1. A concise landing README with one architecture diagram, a five-minute local
   quickstart, screenshots, and the trust boundary.
2. A recorded seven-minute demo: offline import, live lab validation, evidence
   inspection, package review, and a separate synthetic rollback scenario.
3. A published capability/evidence matrix generated from the registry rather
   than maintained by hand.
4. One engineering article explaining why deterministic gates own transitions
   while models produce bounded typed artifacts.
5. One security article showing read-only identities, evidence minimization,
   fail-closed behavior, and package-bound human approval.
6. Release notes that state limitations as prominently as features.

## Recommended sequence

1. Finish the top Azure/AWS validation packs and generate the support matrix.
2. Add Entra authentication to the review plane and harden tenant isolation.
3. Add release governance, CI, artifact signing, SBOM, and repository hygiene.
4. Produce the Docker Compose quickstart and clean-machine acceptance test.
5. Run one authorized customer shadow pilot without model egress or action
   identity; publish only anonymized aggregate lessons with consent.
6. Tag `v0.1.0`, publish artifacts, and call it a technical preview.

Success for v0.1 is not the number of checks. It is whether a skeptical security
or SRE reviewer can trace every supported claim, understand every unsupported
boundary, reproduce the demo, and see exactly where human authority begins.
