# El Capitan product architecture

**Status:** initial product direction, 2026-08-25

## Decision

Hermes is not a product dependency or control plane.

The product owns workflow state, evidence, isolation, policy, credentials,
approvals, retries, and audit history. Model-backed work runs through the
provider-neutral `AgentRuntime` contract. A Hermes adapter may be retained for
evaluation, but no domain record or workflow transition may depend on Hermes
profiles, homes, sessions, memory, completion contracts, or MoA traces.

This is not a judgement that Hermes is useless. It helped establish valuable
properties in the capability probe. It is a decision that an agent runtime and
a remediation operating system have different responsibilities.

## Product boundary

The product is a durable remediation-case workflow:

```text
finding intake
  -> correlate and prioritize
  -> validate live state
  -> link to source and prepare change
  -> SRE availability review
  -> select a change window
  -> policy and human approval
  -> execute progressively
  -> verify
       -> close
       -> stop and roll back
```

Agents recommend and produce typed artifacts. Deterministic code controls
transitions and side effects. No agent can approve its own work, grant itself
credentials, skip a required stage, or decide that an uncited claim is
evidence.

## Planes

### Evidence plane

Append-only evidence and provenance. Existing OCSF normalization, evidence
hashing, manifests, cloud-state capture, and tool-exit semantics are retained.
Large artifacts belong in object storage; immutable metadata and relationships
belong in the operational datastore.

### Knowledge plane

The customer graph connects findings, assets, services, repositories, source
constructs, owners, vulnerabilities, runtime dependencies, SLOs, and previous
changes. Prioritization and remediation operate on this graph rather than on
an isolated scanner row.

### Decision plane

Specialized roles receive bounded evidence bundles and emit typed records:

- Prioritizer: risk assessment and queue position.
- Validator: true/false/unknown finding status and live evidence.
- Remediation engineer: patch or runtime change and complete change plan.
- SRE reviewer: blast radius, capacity, dependency, and SLO assessment.
- Window planner: candidate windows derived from historical usage and policy.
- Rollback/verifier: preconditions, success criteria, rollback triggers, and
  post-change verification.

Multiple model opinions are optional. Epistemic separation is required only
where one role reviews another role's work.

### Control plane

A durable workflow engine persists every transition, supports pauses and
retries, and uses optimistic concurrency to prevent two workers from advancing
the same case. Policy and approval gates are deterministic. Production work
uses short-lived, case-scoped credentials.

The first implementation is `SqliteCaseStore`, which persists projections and
append-only events transactionally in WAL mode. It is the local/single-node
store, not the final multi-tenant database. The `CaseStore` contract keeps the
domain and agent layers independent of the later PostgreSQL implementation.

### Action plane

Connectors create PRs and, later, execute approved deployment operations.
Execution is progressive: preflight, checkpoint, canary, verification, wider
rollout. A rollback path must exist and be validated before production
execution becomes eligible.

## Initial vertical slice

The first customer-facing slice remains deliberately narrow:

1. Ingest Prowler OCSF findings from Azure.
2. Correlate findings on the same asset into one remediation case.
3. Prioritize using severity, exposure, exploitability, asset criticality,
   runtime use, and compensating controls.
4. Confirm the finding with a read-only identity.
5. Link the resource to Terraform and prepare a patch.
6. Produce an SRE review, change window, deployment steps, verification steps,
   rollback procedure, and rollback triggers.
7. Require human approval and create a GitHub PR.
8. Do not deploy automatically in this slice.

Implemented so far: durable cases and events, deterministic priority,
idempotent OCSF/ASFF intake, exact-asset correlation, one-active-case
concurrency enforcement, provider-neutral agent contracts, read-only live
validation for the first Azure/AWS rule set, immutable typed product records,
and a local CLI. Terraform linking, model runtime adapters, SRE/window workers,
and GitHub PR creation are the remaining parts of this slice.

The next slice adds staging/canary execution. Production execution is enabled
only after the connector, health contract, rollback, identity, and audit gates
are independently exercised.

## Archived prototype

The A/B arms, ground-truth traps, batch scorer, fresh Hermes homes, and
experimental result matrix are preserved on the
`archive/claude-code-probe-2026-08-25` branch. They are not part of the product
runtime, package, test suite, or request lifecycle.
