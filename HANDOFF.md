# El Capitan — fresh-session handoff

**Prepared:** 2026-08-28

**Baseline before this handoff:** `f5e1c86`

**Release direction:** Azure-first `v0.1.0` technical preview; AWS coming soon

This file is the durable context for a fresh Codex session. Read it completely,
then read `README.md`, `docs/public-release-v0.1.md`,
`docs/product-architecture.md`, and `docs/control-packs.md`. Verify the current
branch, latest commit, and worktree before acting. Do not reconstruct or repeat
completed work from an earlier conversation.

## Product identity

El Capitan is an evidence-bound cloud remediation control plane. It is not an
agent capability probe and must not be marketed yet as an autonomous
replacement for a DevOps or SRE team.

The honest current product promise is:

1. Import scanner findings and preserve exact outcome accounting.
2. Correlate and prioritize resource-oriented cases.
3. Re-query explicitly supported controls with a bounded read-only identity.
4. Persist minimized, typed, immutable evidence and decision records.
5. For explicitly supported controls, link one exact Terraform resource and
   prepare a verified remediation package.
6. Run independent SRE, change-window, and rollback review.
7. Stop at a package-hash-bound human decision by default.
8. Execute only through a separately proven connector, identity, health
   contract, checkpoint, monitor, and rollback path.

Hermes is not a runtime dependency. Model-backed workers implement the
provider-neutral `AgentRuntime` contract. Deterministic code owns workflow
state, evidence admission, retries, credentials, approvals, scheduling,
execution, rollback, audit, and handoff.

## Verified repository state

At the baseline commit:

- the full test suite passes: **476 tests**;
- both the Python wheel and source distribution build successfully;
- the built-in registry contains **31 deterministic validation controls**:
  **30 Azure** and **1 AWS**;
- four controls have remediation-planning capability;
- only two Azure Storage controls have live-execution capability;
- the latest private Azure export was analyzed offline only and showed 131 of
  238 explicit FAIL findings supported (55.0% for that export, not a general
  Azure coverage claim);
- the worktree was clean and synchronized with `origin/main`.

The completed agent-run budget slice following that baseline passes **484
tests**, and both the Python wheel and source distribution build successfully.

The completed Cosmos DB slice passes **518 tests**, and both the Python wheel
and source distribution build successfully. At that point the built-in
registry contained **35 deterministic validation controls**: **34 Azure** and
**1 AWS**.

The completed Key Vault diagnostic logging slice passes **533 tests**, and both
the Python wheel and source distribution build successfully. The current
built-in registry contains **36 deterministic validation controls**: **35
Azure** and **1 AWS**.

The completed local `v0.1.0` release-preparation slices pass **538 tests**. They
add release governance and guarded CI/publication workflows, dependency and
secret prevention checks, digest/hash-pinned container inputs, generated
capability/evidence artifacts, a PostgreSQL Compose quickstart, and a
clean-clone release rehearsal. The rehearsal passed at `4fb9dbd` with inspected
wheel/source distributions, checksums, a 370-component CycloneDX container
SBOM, local OCI provenance, and an authenticated synthetic quickstart in 10
seconds. See `docs/release-readiness.md` and
`docs/release-rehearsal-2026-08-28.md`.

Run the complete suite with:

```bash
UV_CACHE_DIR=/private/tmp/elcapitan-uv-cache uv run pytest -q
```

Build distributions with:

```bash
UV_CACHE_DIR=/private/tmp/elcapitan-uv-cache uv build
```

Run `uv run elcapitan capabilities` for the authoritative live-validation,
planning, and execution matrix. Never collapse those three capability columns
into one generic "supported" claim.

## What is actually implemented

- OCSF and ASFF intake with explicit FAIL/PASS/MANUAL handling.
- Replay deduplication, exact-asset correlation, tenant isolation, transparent
  priority factors, and one-active-case concurrency control.
- Authenticated shadow console for intake, portfolio inspection, connector
  readiness, bounded batch validation, evidence, and immutable timelines.
- Read-only deterministic Azure packs for selected Storage, SQL Server, Key
  Vault, subnet, App Service, Function App, Container Registry, Cosmos DB, and
  Azure OpenAI controls.
- One AWS S3 validation/planning proof. AWS must be described as coming soon,
  not as equivalent current coverage.
- Conservative literal or state-grounded Terraform linkage.
- Isolated complete-file remediation proposals with format, validation, and
  no-refresh plan checks. Planning never modifies the supplied repository and
  never runs `terraform apply`.
- Strict OpenAI, Anthropic, and Gemini runtime adapters with provider-neutral
  typed contracts and optional role separation.
- SRE review, bounded telemetry-based window selection, rollback review,
  package assembly, and a separate authenticated human review service.
- Durable approval/rejection, scheduling, worker leases, missed-window
  protection, monitored deployment, rollback, post-change validation,
  certificate issuance, and originator handoff.
- Proven live Azure action connectors only for Storage public-network access
  and anonymous Blob access, exercised in the tagged non-production lab.
- Synthetic browser demonstrations for healthy execution and automatic
  rollback. Synthetic evidence is labeled and is not live-cloud proof.

## Important limitations

- No blind or unattended production remediation.
- No generic VM/OS patching or arbitrary application-code remediation.
- No broad UI/application-behavior validation.
- No general action connector for every validated control.
- No customer-grade business prioritization without asset criticality,
  ownership, dependencies, health signals, and maintenance policy.
- No production-grade Entra authentication yet; shared tokens are demo/pilot
  bridges.
- No public multi-tenant SaaS guarantee.
- Azure OpenAI is contract-tested and observed in authorized private scanner
  output, but not yet run against a lab Cognitive Services account.
- Cosmos DB is contract-tested and observed in authorized private scanner
  output, but not yet run against a lab Cosmos DB account.
- Key Vault diagnostic logging is contract-tested, but its Monitor read has not
  yet been run against a lab vault; the other three Key Vault controls retain
  their existing E2E-measured evidence grade.
- License and project-name clearance, historical-secret adjudication, protected
  release-environment configuration, remote CI evidence, signing, and public
  artifact publication/provenance remain external release gates.

## Non-negotiable safety boundaries

- Customer cloud environments are read-only. Never make even a small change.
- Customer exports may be read only from explicitly supplied local paths. They
  and any derived customer-specific details must never be committed.
- Never commit `.env`, tokens, API keys, credentials, connection strings,
  Terraform state, model traces containing private evidence, or customer
  identifiers.
- Eiger is a separate active repository and training lab. It must never be
  deleted, archived, or modified as El Capitan product work.
- Use only an explicitly confirmed El Capitan non-production lab target for
  cloud experiments. Resolve exact subscription, resource, identity, and role
  scope read-only before any action.
- The next bounded objective below requires no cloud calls, no model calls, and
  no customer data.
- External model egress over customer evidence requires a separate explicit
  authorization naming the provider and bounded evidence fields.
- Validation capability never grants planning or execution authority.

## Completed bounded objective: agent-run budgets and circuit breakers

Before adding another Azure control pack, implement durable protection against
open-ended or repeatedly failing model work.

Required outcome:

1. Define a central per-case agent-run budget covering at least model-call
   count, attempts per role/package, and elapsed-run limits.
2. Make role/package replay idempotent by binding execution to the case, role,
   task contract, and evidence-package hash.
3. Detect repeated equivalent failure signatures and open a circuit instead of
   dispatching the same work again.
4. Persist every attempted invocation and the terminal budget/circuit outcome
   as typed product records suitable for review and audit.
5. Produce a durable, visible needs-human/blocked outcome when a budget is
   exhausted. Never silently restart from the beginning.
6. Preserve the existing stricter local limits: provider correction is
   currently capped at three total attempts, decision/citation correction at
   two retries, preapproval orchestration at 14 state advances, ARM pagination
   at 100 pages, and provider/subprocess calls have explicit timeouts.
7. Keep recorded-runtime and local tests free of real provider keys and calls.
8. Document the policy and operator-visible behavior.

Inspect the existing retry boundaries in `review_worker.py`, `preapproval.py`,
`orchestration.py`, `scheduler.py`, `provider_runtimes.py`, and
`openai_runtime.py` before designing the smallest coherent change. Reuse the
existing `ProductRecord` and durable store boundaries where possible; do not
introduce a second workflow engine.

### Acceptance criteria

- No open-ended agent or worker loop exists in the implemented path.
- Every retry path exercised by the slice has an explicit maximum.
- Replaying the same completed case/role/evidence package does not call the
  runtime again.
- Repeated equivalent failures trip a deterministic circuit breaker.
- Exhaustion creates a durable record visible to an operator and returns
  control without further dispatch.
- Existing successful review preparation remains compatible.
- Focused tests cover success, idempotent replay, retry exhaustion, repeated
  failure, restart/durable reload, and independent cases.
- The full test suite and package build pass.
- Documentation describes defaults, overrides, records, and limitations.
- The completed slice is one reviewable commit. Do not add Cosmos DB or another
  cloud control in the same slice.

### Completion status

This objective is complete. Do not reconstruct or repeat it in a fresh
session. The implementation now:

- enforces central per-case model-call, role/package attempt, elapsed-time, and
  equivalent-failure limits at the provider-neutral runtime boundary;
- binds idempotent replay to the case, role, task contract, and immutable
  input-record/evidence package hash;
- persists `AgentInvocation.v1`, `AgentInvocationOutcome.v1`, and
  `AgentRunTerminal.v1` records, while keeping complete result payloads in the
  existing hashed case-artifact boundary;
- blocks the durable case with an operator-visible needs-human outcome on
  exhaustion, an open circuit, ambiguous interrupted work, or unavailable
  replay evidence;
- exposes explicit CLI limit and terminal-record overrides without weakening
  the existing provider, semantic, orchestration, pagination, or timeout caps;
- is documented in `docs/agent-run-policy.md` and covered by cloud-free,
  provider-free tests for success, replay, exhaustion, circuit opening,
  restart, elapsed limits, invalid runtime identity, and independent cases.

### Stop and retry rules

- Do not retry the same development blocker more than twice. On the third
  occurrence, stop, preserve evidence, and report the exact blocker.
- Do not repeat completed commands or reimplement completed features.
- Do not weaken a failing test, evidence requirement, type contract, or safety
  gate merely to make the suite pass.
- Stop and request direction before destructive actions, external writes not
  explicitly authorized in the fresh-session request, cloud mutations, model
  calls, new credentials, purchases, or material scope expansion.

## Completed bounded objective: Azure Cosmos DB validation pack

This objective is complete. Do not reconstruct or repeat it in a fresh
session. The implementation now:

- registers four validation-only Cosmos DB account controls: automatic
  failover, continuous backup, minimum TLS, and public network access;
- collects their complete minimized evidence contract through one read-only
  Database Accounts Get request for both service-principal and managed-identity
  authentication paths;
- preserves omitted optional fields as explicit null evidence matching
  Prowler's failing semantics, while rejecting malformed types and unknown
  enums;
- treats `Tls12` and `Tls13` as secure and treats both `Disabled` and
  `SecuredByPerimeter` as non-public network states;
- uses a synthetic Microsoft-schema fixture containing no customer data and
  makes no cloud or model call;
- keeps remediation planning and live execution disabled for all four rules.

## Completed bounded objective: Key Vault diagnostic logging validation

This objective is complete. Do not reconstruct or repeat it in a fresh
session. The implementation now:

- registers `keyvault_logging_enabled` as validation-only, with no planning or
  execution authority;
- lists diagnostic settings through one bounded Monitor management-plane GET
  after the existing vault GET for both service-principal and managed-identity
  authentication paths;
- persists only setting names, categories, category groups, and enabled state,
  excluding destination IDs, metrics, and retention policy;
- mirrors Prowler's exact condition: enabled `AuditEvent`, or enabled `audit`
  and `allLogs` groups in the same diagnostic setting;
- marks only the logging evidence unavailable when the independent Monitor read
  is denied or malformed, preserving complete RBAC, recoverability, and
  private-endpoint validation;
- uses a synthetic Microsoft-schema fixture and makes no cloud call, model
  call, or use of customer data.

## Subsequent roadmap

1. The local `v0.1.0` release-preparation work is complete: feature freeze,
   governance, CI and guarded publication mechanisms, preventive security
   scanning, clean packaging metadata, reproducible container inputs,
   SBOM/provenance generation, capability/evidence matrix generation,
   PostgreSQL quickstart, and release-candidate rehearsal.
2. Do not tag or publish until authorized owners approve the license and name,
   adjudicate and remediate the historical secret baseline, configure the
   protected release environment, and obtain successful remote CI/container
   scan evidence.
3. The remaining customer shadow pilot requires a separately authorized
   read-only customer boundary, identities, data handling, and consent. It is
   prohibited under the current no-customer-data objective.

The retired Claude/Hermes capability probe remains on
`archive/claude-code-probe-2026-08-25`. It is not part of the product runtime,
package, tests, or request lifecycle.
