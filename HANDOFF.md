# El Capitan — fresh-session handoff

**Prepared:** 2026-09-03

**Checkpoint parent:** `f21a51e` (`feat(shadow): add guided evidence-to-outcome trial`)

**Release direction:** self-hosted `v0.1.0` technical preview with explicit
Azure/AWS validation breadth, AWS S3 evidence-to-review packaging, Azure-only
live execution, and evidence grades

This file is the durable context for a fresh Codex session. Read it completely,
then read `README.md`, `docs/public-release-v0.1.md`,
`docs/product-architecture.md`, and `docs/control-packs.md`. Verify the current
branch, latest commit, and worktree before acting. Do not reconstruct or repeat
completed work from an earlier conversation.

## Resume here — authoritative current checkpoint

The Guided Shadow Trial, exact-resource asset-context prioritization, Azure live
validation, and evidence-to-outcome UI checkpoint is preserved in `f21a51e`.
The AWS-only evidence-to-review checkpoint is complete on top of that commit:
S3 object versioning now has exact Terraform state/IaC linking, deterministic
source materialization, a fail-closed nested plan-scope gate, provider-isolated
planner credentials, and a contract-tested path through the canonical
`HumanReviewPackage.v1` gate. Do not reset, reconstruct, split, or overwrite
either checkpoint. The owner screen recording remains an untracked local review
artifact and must not be committed.

Current registry authority:

- **72 deterministic validation controls:** 35 Azure and 37 AWS;
- **4 remediation-planning controls:** 3 Azure Storage and 1 AWS S3;
- **2 live-execution controls:** Azure Storage only;
- evidence grades: 30 E2E measured, 37 contract tested, and 5 contract tested
  plus export observed;
- AWS validation: 7 S3, 8 RDS DB-instance, 20 EC2 security-group, and 2 EBS
  volume controls;
- only S3 object versioning has AWS planning capability; no AWS control has
  live-execution capability.

The current AWS checkpoint passes **725 tests**, compile and
the repository's narrow Ruff gates, JavaScript syntax checks, generated-matrix
and release-tree checks, wheel/source builds, distribution inspection, and
`git diff --check`. The AWS extension used only local recorded fixtures and made
no AWS request. The preceding Guided Shadow pass made owner-authorized read-only
Azure management-plane queries against one test subscription to build observed
exposure context. That
inventory pass made no cloud mutation, data-plane read, model call, approval,
scheduling, deployment, tag, release, or publication. An authenticated local Chrome pass
covered desktop, tablet, and mobile layouts; synthetic-sample and checked-in
ASFF native-file and paste preview/import; supported and unsupported results;
evidence detail; keyboard paths; workspace persistence; and
connector-offline/fail-closed behavior. A subsequent owner screen recording
also drove the final supported-versus-ready, disabled batch-action,
return-to-start, import-destination, and grouped-observation corrections. See
`docs/guided-shadow-trial-browser-acceptance-2026-08-31.md`.

A second authenticated Chrome acceptance used the owner's 274-observation
Prowler Azure test export and a generated 45-row asset inventory. Exact joins
contextualized 123 failing observations on 26 resources while preserving 33
finding-context gaps and 19 inventory rows without failures. The final 59-case
portfolio contains 2 high, 44 normal, and 13 low priorities. The drill-down now
identifies one score-driving observation and lists the other grouped findings
independently. See `docs/azure-asset-context-trial-2026-09-01.md`.

The local shadow UI now presents the product in two explicit layers. The
read-only layer shows finding source and format, normalized resource cases,
validation outcomes, transparent priority, and the current outcome. A visible
human-authority boundary separates it from remediation preparation, package
assembly, human review, deployment, and monitoring. Those downstream stages
are descriptive and locked in shadow mode; the shadow API still exposes no
approval, scheduling, or execution route. Fleet summaries now report source,
format, priority, validation-outcome, planning-capable, and execution-capable
counts. An optional `tenant` query parameter selects a local review workspace
without weakening authentication.

Read these current authorities before acting:

1. `HANDOFF.md` — safety boundaries, completed work, and resume contract.
2. `docs/generated/capability-matrix.md` — generated per-control capability and
   evidence authority.
3. `docs/control-packs.md` — collector/evaluator semantics and proof grades.
4. `docs/elcapitan-v0.1-overview.html` — local-only living product briefing.
5. `docs/customer-shadow-run.md` and `docs/first-customer-pilot.md` — operator
   scope and identity boundaries.

First fresh-session actions should be read-only:

```bash
git status --short
git diff --check
uv run python scripts/generate_capability_matrix.py --check
```

Do not redo S3, RDS, EC2 security-group, EBS volume, the AWS S3 review-package
path, Guided Shadow Trial, or asset-context prioritization work. GCP is
explicitly deferred. The next bounded AWS step, if the owner authorizes it, is a
real non-production S3 shadow/promotion pilot with a dedicated scanner identity,
authoritative IaC and sanitized state, a separate short-lived planner session,
service/usage context, and named independent reviewer routes. Do not add AWS
execution authority. Any further planning or execution expansion requires
separate service-specific design, identity, operational, rollback, and
authorization work.

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
the Python wheel and source distribution build successfully. At that
checkpoint the built-in registry contained **36 deterministic validation
controls**: **35 Azure** and **1 AWS**.

The completed local `v0.1.0` release-preparation slices pass **538 tests**. They
add release governance and guarded CI/publication workflows, dependency and
secret prevention checks, digest/hash-pinned container inputs, generated
capability/evidence artifacts, a PostgreSQL Compose quickstart, and a
clean-clone release rehearsal. The rehearsal passed at `44dd79e` with inspected
wheel/source distributions, checksums, a 370-component CycloneDX container
SBOM, local OCI provenance, and an authenticated synthetic quickstart in 14
seconds. See `docs/release-readiness.md` and
`docs/release-rehearsal-2026-08-28.md`.

The local launch-package drafts also exist: the README architecture/trust
boundary, engineering and security articles, limitation-forward release notes,
and a timed demo/screenshot runbook. Actual screenshots could not be captured
because no browser surface was connected in the completing session. The live
lab recording segment and all publication remain separately authorized work.

The authorized synthetic Azure lab E2E run on 2026-08-29 deployed the current
candidate with a fresh scanner identity and isolated PostgreSQL database,
proved authenticated intake and live validation for both executable Storage
controls, independently proved scanner mutation denial, and exercised both
success and automatic rollback through a separately scoped managed-identity
worker. The exact Storage baseline was restored and every temporary app, job,
database, role, identity, assignment, image, and local secret was deleted. See
`docs/azure-e2e-2026-08-29.md`. Visual browser acceptance remains unexecuted
because no browser surface was connected.

The completed Azure E2E/deployment-hardening slice passes **540 tests**, the
release-tree and shell-syntax checks, and both Python distribution builds.

The browser/release-gate slice passes **546 tests** locally after the final
manual-browser corrections. The authenticated
PostgreSQL quickstart now checks the hardened session cookie, UI assets and
semantic labels, cross-origin rejection, and absence of a shadow execution
route. The public runtime rebuilds pinned Terraform 1.16.0 source with patched
Go 1.26.6 and a refreshed Python base; Trivy 0.70.0 reports zero fixed
high/critical findings in the local Linux arm64 image. See
`docs/release-verification-2026-08-29.md`. Manual Chromium acceptance completed
on 2026-08-30 after correcting copy, focus, typography, hidden-state, and
recursive-detail defects; see `docs/manual-browser-acceptance-2026-08-30.md`.
Sanitized viewport-only launch images remain pending because the supplied
acceptance captures included browser chrome or profile indicators.

Post-rewrite CI run `33358160306` passed the 549-test/package job,
complete-history secret scan, Linux amd64 high/critical container scan with
zero findings, and the expanded PostgreSQL/UI quickstart at sanitized commit
`6ea9663`.

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
- Read-only deterministic AWS packs for seven S3, eight RDS DB-instance,
  twenty EC2 security-group, and two EBS volume controls. Validator counts do
  not imply equal service breadth, evidence strength, planning, or execution.
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
- The six added S3 validators, all eight RDS validators, all twenty EC2
  security-group validators, and both EBS volume validators are contract tested
  rather than E2E measured. Validation counts must not be described as
  execution or proof parity.
- Apache-2.0 and the El Capitan name were explicitly approved by Transilience,
  Inc. on 2026-08-30 and are recorded in
  `docs/owner-decisions-2026-08-30.md`. Historical-secret adjudication,
  GitHub's retained PR-ref/cache cleanup, protected release-environment
  configuration, signing, and public artifact publication/provenance remain
  external release gates.
- The authorized historical-secret review found two generated
  Azure Storage account keys duplicated across Trap-2 state and backup files,
  plus one false positive on a Container App secret-name identifier. The
  temporary account's recorded destroy state contains zero resources. The two
  state paths were purged from all reachable Git refs and the 11 resolved Eiger
  fingerprints were removed. A later owner-authorized review classified ten
  Azure deployment-template detections as credential-free ACR demo-image
  references and removed them from the baseline under an exact-field rule. A
  complete current-tree/history audit found no named private-customer
  identifier or finding data; only the previously recorded aggregate coverage
  count remains. A final exact-line review found that the Anna detector matched
  model termination metadata following the phrase `API calls`, not a
  credential. All 22 fingerprints are dispositioned, `.gitleaksignore` is
  empty, and the isolated all-ref scan passes. GitHub Support ticket `#4715479`
  is open for removal of the eight affected read-only PR refs and cached views.
  Keep the repository private until GitHub confirms cleanup. No credential
  value was printed. See
  `docs/historical-secret-review-2026-08-30.md`.

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
- The 2026-08-29 Azure authorization ended with the recorded cleanup. Make no
  further cloud call, model call, or customer-data access without a fresh
  bounded objective and authorization.
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

## Completed bounded objective: authorized Azure release-candidate E2E

This objective is complete. Do not recreate the deleted E2E resources or
repeat its cloud operations in a fresh session. The completed run:

- built and ran the current shadow candidate from an immutable ACR digest;
- used a fresh managed identity with `Reader` only at the approved lab resource
  group and a fresh executor identity with the two-action custom role only at
  the exact assurance Storage account;
- created an isolated PostgreSQL database, ingested two synthetic lab findings,
  correlated one case, and confirmed both findings from minimized live Azure
  evidence;
- proved the scanner identity received `AuthorizationFailed` for Storage write;
- ran success and injected-failure rollback for both live Storage controls;
- restored the Storage account to its initial `Enabled` / `true` state; and
- deleted all temporary apps, jobs, identities, role assignments, images,
  database objects, and local secrets, with independent absence checks.

No customer data, Eiger operation, or model call occurred. The dated evidence
and remaining visual-browser limitation are in
`docs/azure-e2e-2026-08-29.md`.

## Subsequent roadmap

1. The local `v0.1.0` release-preparation work is complete: feature freeze,
   governance, CI and guarded publication mechanisms, preventive security
   scanning, clean packaging metadata, reproducible container inputs,
   SBOM/provenance generation, capability/evidence matrix generation,
   PostgreSQL quickstart, and release-candidate rehearsal.
2. Do not tag or publish until GitHub Support confirms PR-ref/cache cleanup,
   the repository is made public under the recorded owner authorization, and
   the protected `release` environment is configured with required reviewer
   `kkmookhey`. Keep self-review prevention disabled unless a different
   reviewer is approved. Record the completed gates in a committed
   `RELEASE_APPROVAL.json` based on the checked-in example and pass its exact
   SHA-256 to the manual release workflow; the release-tree check now rejects
   missing, pending, mismatched, or baseline-waiving records.
3. The remaining customer shadow pilot requires a separately authorized
   read-only customer boundary, identities, data handling, and consent. It is
   prohibited under the current no-customer-data objective.
4. Manual rendered UI acceptance is complete. Capture release-safe synthetic
   screenshots only from a clean browser profile with application-viewport
   crops, and run the live-lab demo segment only after its exact non-production
   resource and read-only identity are approved. Recording and publication are
   external writes and remain unapproved.
5. The private repository's current GitHub plan does not expose protected
   environments or rulesets. The owner authorized public visibility on
   2026-08-31, but only after GitHub Support ticket `#4715479` confirms removal
   of the retained PR refs and cached views. Do not change visibility or weaken
   the guarded release workflow before that confirmation.

The retired Claude/Hermes capability probe remains on
`archive/claude-code-probe-2026-08-25`. It is not part of the product runtime,
package, tests, or request lifecycle.

## Completed checkpoint: AWS S3 + RDS + EC2 validation expansion

This checkpoint was added on 2026-08-31 from source base `499382d`. It contains
the completed AWS S3, RDS, and EC2 security-group validation slices plus the
living HTML capability briefing; do not discard or reconstruct this work.

The completed S3 slice:

- expands the `aws-s3` pack from one to seven deterministic validators;
- adds KMS default encryption, server access logging, event notifications,
  lifecycle configuration, Object Lock, and MFA Delete;
- reuses the existing bounded S3 evidence capture and adds no AWS calls or
  scanner permissions;
- rejects malformed documents, unknown enums, authorization errors disguised
  as absence, and unrecognized absent markers;
- keeps all six additions validation-only and contract tested;
- preserves object versioning as the only AWS planning control and preserves
  zero AWS live-execution controls.

The completed RDS slice:

- adds the `aws-rds` pack with eight deterministic DB-instance validators for
  automated backups, snapshot tag copying, enhanced monitoring, IAM database
  authentication, VPC placement, CloudWatch Logs exports, automatic minor
  upgrades, and storage encryption;
- uses one bounded `DescribeDBInstances` call for the exact DB-instance ARN,
  derives region from the ARN, and rejects a conflicting finding region;
- requires exactly one response instance with the requested ARN and rejects
  denied, absent, multiple, paginated, mismatched, DocumentDB, and malformed
  responses instead of inferring configuration;
- persists only normalized control fields and excludes endpoints, usernames,
  tags, subnet IDs, and security groups;
- preserves Prowler's read-replica, Aurora, and engine applicability rules;
- keeps all eight additions validation-only and contract tested, with no RDS
  planning or execution authority.

The completed EC2 security-group slice:

- adds the `aws-ec2-security-group` pack with twenty deterministic validators
  for all-port and high-risk exposure, fourteen named service-port families,
  broad public IPv4 ranges, default-group traffic, Launch Wizard groups, and
  excessive permission-entry counts;
- uses one exact-ID `DescribeSecurityGroups` call and one group-filtered
  `DescribeNetworkInterfaces` call capped after the first attachment;
- binds region and account to the ARN, validates exact group identity and any
  response ARN, and rejects interfaces outside the group filter;
- preserves Prowler's default unused-group exclusion and its suppression of
  duplicate specific-port findings when the all-ports check is active;
- persists only group name, in-use state, and normalized protocol, port, IPv4,
  and IPv6 rule fields; tags, descriptions, VPC IDs, interface IDs, and account
  details are excluded;
- keeps all twenty controls validation-only and contract tested, with no EC2
  planning or execution authority;
- brings the generated matrix to 70 validators: 35 Azure and 35 AWS, with
  planning still 4 and execution still 2;
- updates shadow UI labels, pilot/control-pack documentation, the changelog,
  and `docs/elcapitan-v0.1-overview.html`; and
- passes 680 tests, narrow Ruff checks, wheel/source builds, distribution
  inspection, generated matrix verification, release-tree checks, and
  `git diff --check` without a cloud or model call.

The HTML overview is now an explicitly maintained living briefing built on the
v0.1 foundation. Keep its headline metrics, capability cards, evidence grades,
verification counts, roadmap, and honest-boundary copy synchronized with each
future capability slice. It remains local-only unless publication is separately
authorized.

This completed parity checkpoint is preserved in commit `f441de9`. Do not
reconstruct or repeat it.

## Committed checkpoint: AWS EBS volume validation

This checkpoint was committed on 2026-08-31 as `7e2b0b4`. It:

- adds the validation-only `aws-ebs-volume` pack for
  `ec2_ebs_volume_encryption` and `ec2_ebs_volume_snapshots_exists`;
- accepts only an `AwsEc2Volume` finding with an exact EC2 volume ARN whose
  partition, region, account, and volume ID are validated;
- uses one exact-ID `DescribeVolumes` read and one owner-`self`, volume-filtered
  `DescribeSnapshots` read capped after the first result;
- requires exactly one matching volume and validates the owner and volume of
  any returned snapshot;
- rejects denied, absent-volume, multiple-volume, mismatched, malformed, and
  empty-partial responses instead of inferring configuration;
- persists only encryption and owned-snapshot-presence booleans, excluding
  snapshot IDs, KMS identifiers, tags, attachments, descriptions, timestamps,
  and sizes;
- keeps both controls contract tested and validation-only, with no planning or
  live-execution authority;
- brings the generated matrix to 72 validators: 35 Azure and 37 AWS, with
  planning still 4 and execution still 2;
- updates shadow UI labels, operator/pilot documentation, release material,
  the changelog, generated capability artifacts, and the living HTML briefing;
  and
- passes 703 tests, compile checks, narrow Ruff checks, wheel/source builds,
  distribution inspection, generated-matrix verification, release-tree checks,
  and `git diff --check` without a cloud or model call.

Do not reconstruct or recommit this completed checkpoint.

## Completed checkpoint: Guided Shadow Trial and asset context

This checkpoint was added on 2026-08-31 from source base `7e2b0b4`. It:

- replaces the first-use marketing-heavy hero with three concrete entry paths:
  preview a scanner export, try a safe synthetic sample, or inspect read-only
  connector status;
- adds authenticated `POST /api/intake-preview`, which reuses the exact intake
  provider, source-identity, outcome, normalization, schema, resource, control,
  and priority checks without a persistent product write;
- reports submitted and accepted failures, skipped PASS/MANUAL results, input
  formats, providers, accounts, resources, supported findings, and unsupported
  controls before the user confirms import;
- removes every temporary preview artifact before returning and explicitly
  reports that preview made no persistent write, cloud request, model call, or
  execution request;
- keeps durable intake as a separate explicit confirmation and re-runs the
  fail-closed preflight before writing;
- changes the portfolio and drill-down language to customer outcomes including
  **Confirmed in cloud**, **No longer detected**, **Could not check**, and **Not
  supported yet**, while retaining capability grades, immutable evidence,
  timelines, and exact safety boundaries under progressively disclosed detail;
- adds responsive onboarding, preview, empty, supported, unsupported, and
  connector-offline states without introducing a new frontend framework;
- updates the changelog, quickstart, customer shadow-run guide, API tests, and
  control-plane tests;
- accepts a strict per-resource asset-context manifest keyed by exact normalized
  ARM ID, rejects duplicates, ambiguous types, unknown fields, and unsupported
  environments, and binds a canonical SHA-256 row digest to every enriched
  finding;
- previews exact asset matches, finding resources without context, inventory
  rows without failures, contextualized findings, critical resources, observed
  exposure, and synthetic business labels without retaining data or querying a
  cloud;
- replaces the UI's implicit 0.5 asset criticality with a zero fallback for
  unmatched resources and shows owner, environment, criticality, exposure,
  source, synthetic status, and digest in each enriched result;
- orders grouped observations by independent deterministic score, identifies
  the score-driving observation, and states explicitly that resource-case
  scores use the maximum rather than summing vulnerabilities;
- generates private mode-0600 trial inputs outside the repository from one
  owner-authorized Azure test export and read-only management-plane inventory,
  with synthetic business labels separated from observed exposure and no
  invented reachability or dependency evidence;
- passes 717 tests, compile and narrow Ruff gates, JavaScript syntax checks,
  generated-matrix verification, release-tree checks, wheel/source builds,
  distribution inspection, and `git diff --check`; and
- completes authenticated Chrome acceptance across default desktop, 1024 × 768
  tablet, and 390-pixel-class mobile layouts, including safe-sample and
  checked-in ASFF native-file and paste preview/import, supported and
  unsupported results, evidence disclosure, workspace switching and reload
  persistence, keyboard paths, and connector-offline/fail-closed behavior.

The browser pass found and corrected preview placement, overly internal result
language, narrow-screen result ordering/layout, workspace persistence, stale
status, unsupported-control next-step, and shadow-login-copy defects. After
enabling file-URL access for the Chrome automation extension, the native file
chooser also selected the checked-in ASFF fixture and rendered the expected
no-write preview. A 2026-09-01 owner recording then exposed and corrected the
remaining supported-versus-ready contradiction, enabled batch action with no
runnable resources, misleading workspace-return label, implicit import
destination, and unexplained multi-observation resource grouping. See
`docs/guided-shadow-trial-browser-acceptance-2026-08-31.md`.

The realistic Azure pass then corrected an expanded manifest editor that hid
the useful preview, synthetic dependency points without dependency evidence,
and a grouped-resource detail that showed the first finding instead of the
score-driving finding. See `docs/azure-asset-context-trial-2026-09-01.md`.

The evidence-to-outcome UI and living overview were then refreshed around the
same private Azure test trial. The tracked repository contains only aggregate
trial numbers and sanitized learnings; the export, exact resource identifiers,
asset manifest, and populated shadow database remain private local artifacts.
The authenticated live API confirms 179 `Prowler 5.36.0` / `OCSF 1.5.0`
findings grouped into 59 cases with the expected 2 high, 44 normal, and 13 low
distribution, while approval, scheduling, and execution remain prohibited.

The owner then explicitly authorized real validation against the same test
subscription. A temporary `elcapitan-test-shadow-scanner` service principal
was created with Reader on only that subscription because no dedicated scanner
identity existed and the product correctly rejected the ambient human Azure
CLI session. After the read-only evidence collection finished, the Reader role
assignment, service principal, application registration, credential file, and
cleanup metadata were removed on 2026-09-03 and verified absent. This temporary
identity setup and its cleanup were the only cloud-side mutations in this pass.

All 23 cases containing supported controls were queried through that isolated
Reader identity. The active local workspace now contains 93 confirmed and 2
unavailable supported findings: 21 cases advanced to validated and 2 stayed
blocked because the live account kind was `CognitiveServices`, outside the
OpenAI evaluator's admitted `AIServices`/`OpenAI` kinds. Nineteen unsupported
sibling findings remain explicit in mixed cases, and 36 unsupported-only cases
remain prioritized. The pass made no data-plane read, resource-configuration
change, model call, plan, approval, scheduling, deployment, or execution
request. It also corrected File Service child-resource collection and the
semantics of an explicitly absent optional container-retention policy. The
first live run and pre-validation database are preserved privately under
`/private/tmp`; do not commit them.

The Layer 2 handoff now treats mixed-resource cases as scoped promotions rather
than all-or-nothing bundles. Six validated Azure Storage cases are preparation
candidates. Each promotion token binds only the exact findings that are both
confirmed and planning-capable, includes only their validation evidence, and
reports every incomplete or confirmed-but-unplannable sibling as excluded.
The downstream planner receives that same finding-ID scope and persists it in
the plan record. This corrects the earlier misleading `0 ready` display without
claiming that a plan exists.

No authoritative IaC checkout for those six private test resources exists in
this repository. The two checked-in Azure review-input directories target
different prior lab resources and must not be substituted. Therefore the
active trial correctly contains 6 preparation candidates, 0 prepared plans,
0 packages, and 0 cases awaiting human review. Continue only after the owner
supplies the actual IaC/state (or explicitly authorizes a clearly labeled
generated baseline), service ownership and health context, usage telemetry,
and distinct maker/SRE/window/rollback reviewer routes. Do not infer approval,
run a model, deploy, mutate cloud configuration, use production data, publish,
or perform release work from this checkpoint.

The owner subsequently authorized a clearly labeled generated baseline for
the first single-control Azure Storage pilot. A fresh read-only management-
plane query confirmed that the planning target is public network access while
the account already has anonymous access disabled, HTTPS-only and TLS 1.2,
blob versioning, and 90-day blob/container retention. The private baseline is
stored outside the repository under `/private/tmp/elcapitan-generated-baseline-*`
with a mode-`0700` directory, an explicit non-authoritative marker,
`prevent_destroy`, no embedded subscription ID, and no credentials. Terraform
1.15.8 initialized AzureRM 4.81.0 and validated the configuration. The provider
cache was moved outside the baseline directory after validation.

No Terraform import, state write, plan, apply, Azure mutation, model call,
package assembly, or review decision occurred. Do not run a plan against this
baseline as if it owned the existing resource: without an owner-approved state
mapping it would misleadingly propose creation. The next authority decision is
whether to generate a clearly labeled read-only state mapping for this pilot or
replace the baseline with authoritative IaC/state supplied by the owner.

The owner then authorized a disposable state mapping and remediation plan for
that pilot. The first Terraform import attempt failed closed because default
Shared Key behavior requested `listKeys`; the Reader identity was not broadened.
AzureRM's Azure AD storage mode then produced a one-resource local state without
any access key or connection string. The state, plan, plan JSON, source, review
document, and checksums are private mode-`0600` artifacts in a mode-`0700`
workspace under `/private/tmp/elcapitan-remediation-plan-*`.

The saved `-refresh=false`, exact-target plan passed the scope gate: one in-place
update, zero creates, zero deletes, and only
`public_network_access_enabled: true -> false`. A first candidate plan was
rejected because it also attempted to materialize Azure's implicit network-rule
default; the redundant block was removed and the plan rerun before acceptance.

The plan is technically verified. A final read-only configuration check found
no private endpoint connections, virtual-network rules, or IP rules, so
disabling public access removes the only configured network path. The owner
subsequently confirmed that the test resource is unused and authorized human-
review package preparation. This attestation resolves the dependency question
for package preparation but is not approval to schedule or execute a change.
No `terraform apply`, Azure resource mutation, model call, approval, scheduling,
or deployment occurred.

At the owner's request, a subsequent 30-day Azure Monitor assessment checked
recent usage without reading storage objects. It found 15 total transactions
across four hourly buckets: 13 Account Key service-property reads and 2 OAuth
service-property reads, with no object/blob read, write, list, or delete API in
the dimensioned series. The OAuth reads coincide with the disposable Terraform
mapping workflow. Latest and maximum used capacity was 374 bytes; Azure Activity
Log returned no resource events in the same window. This pattern is consistent
with scanner/provider inspection rather than workload use, but it does not prove
intentional abandonment or identify an owner.

The private remediation workspace now contains the hash-bound usage assessment,
owner attestation, cleanup record, machine-readable review body, review guide,
and large-type HTML review page under `review-package/`. The candidate body has
canonical SHA-256
`40b5547350985d20ab26a99f9d17492447eaeea3a2b1a076e9c62e7ab1b19d8f`.
It is deliberately `HumanReviewPackageCandidate.v1`, not an admitted
`HumanReviewPackage.v1`: the shadow case remains `validated`, and formal
`IaCLink.v1`, `RemediationPlan.v1`, independent `SREReview.v1`, future
`ChangeWindowRecommendation.v1`, independent `RollbackReview.v1`, and model-
diversity checks remain pending. The next bounded step is to name the independent
review routes and select a future window, then run the normal preapproval stages
and let `HumanReviewGate` issue the canonical package mechanically. No data-plane
content, container, blob name, filename, key, connection string, or object
content was read.

## Completed checkpoint: AWS evidence to canonical human review

On 2026-09-03 the owner authorized completing AWS—but not GCP—through the
validated review-package boundary. The implementation retains all 37 AWS
validators and advances only `s3_bucket_object_versioning`, the registry's sole
AWS planning-capable control.

The S3 planner now selects only `aws_s3_bucket_versioning`, including Terraform
state IDs shaped as either a bucket name or `bucket,account`. It deterministically
changes one literal status in the linked block and admits only one in-place plan
change at `versioning_configuration[0].status` from `Disabled` or `Suspended` to
`Enabled`. Create/delete/replacement, sibling changes, MFA Delete, and any other
attribute fail closed. Raw state and plan artifacts remain ephemeral; durable
records retain only exact address and digests.

AWS Terraform subprocesses receive only a complete
`ELCAP_PLANNER_AWS_ACCESS_KEY_ID`,
`ELCAP_PLANNER_AWS_SECRET_ACCESS_KEY`, and
`ELCAP_PLANNER_AWS_SESSION_TOKEN` set. Ambient profiles/roles, scanner variables,
shared credential files, and the Azure planner identity are excluded. A missing
field returns a failed planning check before Terraform runs.

An end-to-end contract test proves Prowler OCSF intake, exact bucket correlation,
contextual priority, deterministic live-state evaluation, exact state/IaC link,
verified plan record, independent SRE/window/rollback records, model-diversity
and evidence-chain policy checks, and issuance of `HumanReviewPackage.v1` in
`awaiting_approval` with `execution_status: not_started`. The original repository
remains unchanged. This proof uses recorded fixtures; it made no AWS request,
model-provider call, apply, deployment, or mutation.

The final checkpoint passes 725 tests, compile checks, the repository's narrow
Ruff gate, generated capability-matrix and release-tree checks, hash-locked
requirements comparison, wheel/source builds, distribution inspection, and
`git diff --check`. See
`docs/aws-evidence-to-review-checkpoint-2026-09-03.md`. GCP and AWS execution
remain out of scope.
