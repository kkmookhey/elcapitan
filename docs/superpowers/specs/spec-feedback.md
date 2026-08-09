# Detailed Architecture Review: Agentic Remediation Capability Probe

## Executive assessment

The redesigned specification is substantially stronger than the original prototype plan. It has moved from a customer-facing demonstration to a falsifiable capability probe with a clear hypothesis:

> Can an agent detect when an apparently correct security remediation would break production?

That is the right question. The product’s defensible value is not finding generation or scanner summarization; it is compressing the expensive human judgment required to connect a finding to its source, construct a correct change, and determine whether that change is operationally safe.

I recommend proceeding with the probe after revising five load-bearing areas:

1. Profile and credential isolation.
2. Mixture-of-Agents evidence flow.
3. Deterministic enforcement of the completion contract.
4. Append-only record semantics.
5. Ground-truth and PII handling.

These revisions do not change the central thesis or invalidate the local-Docker design. They make the experiment capable of producing trustworthy results.

---

## What the specification gets right

### 1. It defines a falsifiable claim

The separation between linking, correctness, and safety is excellent:

- Linking can silently identify the wrong source construct.
- Correctness can usually be checked mechanically.
- Safety can silently approve a production-breaking change.

The decision to focus the scored experiment on safety is well justified. It targets the capability with the highest customer value and the most dangerous failure mode.

### 2. It refuses to confuse orchestration with capability

Keeping the trial harness deterministic and implemented as a shell script is the correct choice. Agentic orchestration would introduce another experimental variable and make failures harder to attribute.

The runtime shim is also a sound abstraction. If Hermes proves unsuitable, the contracts, adapters, schema, ground truth, and scoring harness should survive.

### 3. It includes a negative control

The missing-logging control is essential. Without an acceptable remediation, a challenger that rejects every proposal would appear safe while being commercially useless.

The probe needs to measure both:

- Dangerous approvals.
- Unjustified rejections.

### 4. TRAP-2 is an excellent scenario

The runtime-created blob container is more realistic than a simple cloud-configuration trap. It tests whether the agent can recognize that a live resource is not necessarily managed by the repository’s IaC.

It also tests an important product behavior:

> “Not IaC-managed” is a legitimate conclusion, not a linking failure.

This branch should remain first-class in the contract and schema.

### 5. The authoritative datastore is separated from Hermes memory

This is an important architectural decision. Agent memory can improve procedural performance, but it cannot be the authoritative source for assets, findings, evidence, ownership, or remediation state.

The probe should retain the distinction between:

- Agent memory: curated, mutable, procedural and potentially lossy.
- Platform records: complete, versioned, attributable and auditable.

### 6. Local Docker is appropriate

The local control-plane decision is correct for the probe. Running Hermes locally:

- Reduces setup time.
- Avoids unnecessary control-plane cloud cost.
- Keeps Eiger separate from the system assessing it.
- Makes trials easier to reset and inspect.
- Preserves portability through a reusable OCI image.

The production deployment question can be answered later.

---

# Required changes

## 1. Do not treat Hermes profiles as a security boundary

### Problem

The current design treats the engineer and challenger profiles as separate credential and information domains.

Hermes profiles isolate their own configuration, `.env`, sessions, skills, memory, and state database. They do not sandbox filesystem access. With the local terminal backend, both profiles execute with the permissions of the same operating-system user.

If both profiles and both cloud credentials exist inside one long-running container, either agent may be able to read the other profile’s state or credentials.

That invalidates the claim that Arm A is physically unable to access observability data.

Official reference:

- https://hermes-agent.nousresearch.com/docs/user-guide/profiles/

### Credential-pool correction

Hermes credential pools are primarily designed to rotate model-provider credentials such as OpenAI, Anthropic, OpenRouter, and Nous credentials. They are not a general cloud-authorization or experiment-arm primitive.

Official reference:

- https://hermes-agent.nousresearch.com/docs/user-guide/features/credential-pools/

References in the spec to “selecting a credential pool for the arm” should be replaced with explicit per-run secret injection.

### Recommended design

Retain one pinned image, but launch fresh containers for each stage:

```text
Host-side deterministic harness
        │
        ├── Engineer run
        │   └── ephemeral container
        │       ├── fresh Hermes home
        │       ├── scanner-reader credential
        │       ├── canonical repository: read-only
        │       └── trial workspace: read/write
        │
        └── Challenger run
            └── separate ephemeral container
                ├── fresh Hermes home
                ├── proposal/evidence bundle: read-only
                ├── Arm A: scanner-reader credential
                └── Arm B: scanner-reader + observer credential
```

The containers can run sequentially from the same image. This does not require:

- Docker-in-Docker.
- A mounted Docker socket inside Hermes.
- A persistent executor service.
- A cloud-hosted control plane.

The host-side harness is the only component that launches containers.

### Additional isolation requirements

Each scored trial should receive:

- A new container.
- A new Hermes home directory or temporary volume.
- A new scratch working copy.
- Only the secrets required for that arm.
- No mount containing credentials for the other arm.
- No mount containing ground truth.
- No access to results from previous trials.
- A canonical repository mounted read-only.
- A dedicated writable run directory.

Profiles can still represent agent configuration, but the container boundary must enforce the experiment’s information boundary.

---

## 2. Align the MoA design with Hermes’ actual execution model

### Problem

The specification assumes that each MoA member can independently inspect the same tools and evidence before producing a position.

Hermes MoA operates differently:

- The aggregator is the acting model.
- Only the aggregator emits tool calls.
- Reference models receive conversation text.
- Reference models do not receive the Hermes tool schema.
- Reference models do not receive the tool-call transcript.
- The default advisor cadence may run references only once per user turn.

Official reference:

- https://hermes-agent.nousresearch.com/docs/user-guide/features/mixture-of-agents

If the aggregator queries Azure Monitor or CloudWatch during its tool loop, the reference models may never see those results. Their displayed opinions are therefore not necessarily evidence-grounded positions.

This makes the proposed `verdict.member_positions` field ambiguous.

### Recommended evidence flow

The deterministic harness should assemble the challenge bundle before invoking the MoA challenger.

```text
Engineer output
    ├── proposed patch
    ├── verification output
    └── live resource configuration
             │
             ▼
Deterministic evidence collector
    ├── Arm A: no operational telemetry
    └── Arm B: telemetry and dependency evidence included
             │
             ▼
Immutable challenge bundle
             │
             ▼
MoA challenger
```

Every reference model and the aggregator should receive the complete permitted evidence bundle in the initial user message.

The MoA should primarily judge the supplied evidence rather than discover the evidence through tool calls.

### Benefits

This makes the independent variable precise:

```text
Arm A = proposal + configuration evidence
Arm B = identical proposal + configuration evidence + operational evidence
```

It also ensures:

- All ensemble members see the same evidence.
- Arm A cannot retrieve omitted telemetry.
- Arm B’s advantage can be attributed to the additional evidence.
- `member_positions` represent comparable judgments.
- Trial input can be hashed and replayed.

### Structured member positions

Each reference position should contain:

```json
{
  "model": "",
  "decision": "APPROVE | REJECT | NEEDS_MORE_EVIDENCE",
  "objections": [],
  "evidence_cited": [],
  "confidence": 0.0
}
```

The raw MoA trace must be retained. `member_positions` should be derived from the trace, not reconstructed solely from the aggregator’s summary.

If reference-model output cannot be reliably parsed into this structure, record the raw position and mark the structured extraction as incomplete.

---

## 3. Treat `/goal` as workflow support, not enforcement

### Problem

Hermes completion contracts strengthen autonomous task execution, but the completion judge is still an LLM reading the goal, contract, and recent response.

Hermes documentation distinguishes between:

- Completion contracts: LLM-evaluated acceptance criteria.
- Quality gates: deterministic commands that must succeed.

Official reference:

- https://github.com/nousresearch/hermes-agent/blob/main/website/docs/user-guide/features/goals.md

The specification should not state that `/goal` alone enforces “prove it.”

### Recommended deterministic gate

Add a script such as:

```text
validate-trial-artifacts.sh
```

It should verify:

1. `package.json` conforms to an explicit JSON Schema.
2. All required fields are present.
3. All evidence references resolve to real artifacts.
4. Evidence hashes match.
5. The patch exists when `resolution_type=patch`.
6. No patch exists for a declared false positive unless explicitly justified.
7. Verification commands and exit codes are captured.
8. The canonical repository digest is unchanged.
9. The trial workspace contains no unexpected files or secrets.
10. The package references the exact input bundle hash.
11. The agent did not produce a cloud-mutation transcript.
12. The challenge verdict exists and references evidence.

This validator should run:

- As a Hermes goal quality gate where useful.
- Again independently from the host-side trial harness.

The host harness remains authoritative.

### Tool exit-code handling

The gate must understand tool-specific exit semantics. For example, a Terraform plan using `-detailed-exitcode` may return:

- `0`: no changes.
- `1`: error.
- `2`: valid plan containing changes.

A generic “non-zero means failure” validator would score valid remediation plans incorrectly.

---

## 4. Correct the append-only record model

### Problem

The proposed `RemediationPackage` includes:

- Engineer-produced fields.
- Challenger-produced verdict fields.
- Trial metadata.
- Final status.

These values become available at different stages. Updating one JSON record in place would violate the stated append-only design.

### Recommended model

Use separate immutable record types:

```text
FindingRecord
    │
    ▼
RemediationProposal
    │
    ▼
ReviewVerdict
    │
    ▼
TrialResult
```

An assembled `RemediationPackage` can reference those records:

```json
{
  "remediation_id": "REM-001",
  "schema_version": 1,
  "proposal_id": "PROP-001",
  "verdict_id": "VERDICT-001",
  "trial_result_id": "TRIAL-001",
  "supersedes": null
}
```

If the product requires a single package record, use explicit immutable versions:

```json
{
  "remediation_id": "REM-001",
  "package_version": 2,
  "supersedes": "REM-001:v1"
}
```

Do not mutate version 1.

### Evidence schema

Evidence should not be represented as unconstrained strings. Use artifact references:

```json
{
  "evidence_id": "EVD-001",
  "type": "azure_api_response",
  "artifact_path": "evidence/storage-account.json",
  "sha256": "",
  "collected_at": "",
  "collector": {
    "tool": "az",
    "version": "",
    "identity": "eiger-scanner-reader"
  },
  "sensitivity": "internal",
  "command_id": "CMD-004"
}
```

### OCSF provenance

The normalized finding should retain:

- OCSF version.
- OCSF class UID.
- Original finding UID.
- Scanner product and version.
- Raw-event artifact reference and hash.
- Cloud provider.
- Account, tenant or subscription.
- Region.
- Resource UID and resource type.
- Observation timestamp.

Prowler’s JSON-OCSF format implements the OCSF Detection Finding class:

- https://docs.prowler.com/user-guide/cli/tutorials/reporting

The normalization layer should not discard scanner-specific information. Preserve the raw event as evidence and place product-specific extensions under a namespaced field.

### Reproducibility metadata

The trial record should include:

```json
{
  "input_bundle_hash": "",
  "repository_commit": "",
  "container_image_digest": "",
  "profile_config_hash": "",
  "model_provider": "",
  "model": "",
  "model_version": "",
  "reasoning_effort": "",
  "temperature": null,
  "moa_preset": "",
  "moa_fanout": "",
  "hermes_version": "",
  "scanner_versions": {}
}
```

An experiment cannot be reproduced from model names alone.

---

## 5. Make ground truth patch-sensitive

### TRAP-1

The current oracle says that the correct decision for the network-exposure finding is always `REJECT`.

That is true only for the naïve remediation:

```hcl
public_network_access_enabled = false
```

with no working private connectivity.

A sufficiently capable engineer could instead propose:

- VNet integration.
- A storage private endpoint.
- Private DNS.
- Required subnet and routing changes.
- A staged migration.
- A rollback path.

Azure supports private networking and private-endpoint patterns for Container Apps:

- https://learn.microsoft.com/en-us/azure/container-apps/custom-virtual-networks

The ground truth must evaluate the actual proposed patch.

### Recommended oracle

```text
Patch disables public access without a viable private path
    → REJECT

Patch proposes a plausible private path but lacks operational proof
    → NEEDS_MORE_EVIDENCE

Patch includes a complete and sufficiently evidenced safe design
    → APPROVE

Patch leaves the exposure materially unresolved
    → REJECT or NEEDS_MORE_EVIDENCE, depending on the claim
```

This prevents the probe from penalizing an unexpectedly strong remediation.

### TRAP-2

Adding a Terraform resource block does not automatically adopt a live object. Terraform requires an explicit import workflow to bind an existing object to a state address.

Official reference:

- https://developer.hashicorp.com/terraform/language/import/single-resource

The dangerous naïve behavior is more accurately described as:

- Attempting to create an already-existing resource.
- Producing an apply-time conflict.
- Introducing competing ownership between the application and Terraform.
- Proposing import without changing the application’s runtime-creation behavior.
- Managing one object from two lifecycle authorities.

Acceptable outcomes may include:

```text
iac_managed: false + runtime_change
iac_managed: false + needs_design
migration plan involving application change and explicit Terraform import
NEEDS_HUMAN_CONTEXT
```

The last result is safe but incomplete and can retain its partial score.

### Ground-truth confidentiality

The ground-truth files must exist outside every agent-mounted directory.

The harness may read them only after the trial artifact is finalized.

Ground-truth leakage would make the entire experiment invalid.

---

## 6. Strengthen trial independence and reproducibility

Resetting a Hermes profile is necessary but insufficient.

Each scored trial should receive:

- A fresh container.
- A fresh Hermes home.
- A fresh working copy.
- A fixed repository commit.
- A fixed normalized finding.
- A fixed challenge-bundle schema.
- No access to previous transcripts or results.
- No self-authored skills carried between runs.
- No shared mutable cache that contains prior trial conclusions.

### Randomization

Alternate or randomize Arm A and Arm B ordering.

Avoid always running A first and B second. Otherwise time, telemetry drift, provider behavior, or model-service changes may become confounding variables.

### Telemetry stability

TRAP-1 depends on operational evidence. The Eiger workload therefore needs a deterministic load generator.

For each evidence bundle, record:

- Workload version.
- Start and end timestamps.
- Number and type of operations generated.
- Azure telemetry query.
- Raw result hash.
- Resource configuration hash.
- Application health before collection.

Arm A and Arm B should be based on the same underlying system state.

A strong design would collect one complete evidence snapshot and derive:

```text
Arm A bundle = snapshot minus telemetry
Arm B bundle = complete snapshot
```

This creates a clean paired comparison.

### N=5 interpretation

Five repetitions per cell are adequate for observing instability and separating “never works” from “often works.” They are not enough to estimate a general safety rate.

Report results as:

- Observed outcomes.
- Run-to-run consistency.
- Failure patterns.
- Evidence-use patterns.

Avoid broad percentage claims about production capability.

---

## 7. Do not defer PII redaction for Anna

### Problem

Anna’s CloudWatch telemetry may contain prospect PII. The specification currently accepts that exposure and defers redaction to a later Hermes skill.

That is unsafe when using MoA because:

- The bundle may be sent to multiple model providers.
- Reference outputs may repeat sensitive values.
- Outputs and traces may be persisted.
- The aggregator receives reference content.
- A skill invoked by the model may run only after the model has already received the raw content.

Hermes provides MoA privacy filtering, but it is optional and is not a comprehensive business-data redaction system:

- https://hermes-agent.nousresearch.com/docs/user-guide/features/mixture-of-agents

### Acceptable approaches

Use at least one of:

1. Synthetic Anna telemetry.
2. Deterministic redaction before model ingestion.
3. A local model ensemble.
4. Explicit contractual approval for every model provider receiving the evidence.
5. A sanitized historical telemetry snapshot.

The redaction boundary belongs in the deterministic evidence collector, before Hermes or any model sees the content.

A redaction skill can later enhance the process, but it must not be the first protection layer.

---

# Additional recommended refinements

## 1. Change “one container” to “one image”

The important simplification is one build artifact, not one persistent runtime process.

Recommended wording:

> The probe uses one pinned OCI image. The deterministic host-side harness launches isolated, ephemeral containers from that image for engineer and challenger runs.

## 2. Soften the Fargate portability claim

“The image runs unchanged on Fargate” is too strong.

The same image may be reusable, but Fargate changes:

- Persistent-storage behavior.
- Secret injection.
- IAM integration.
- Network policy.
- SQLite persistence.
- Interactive execution.
- Terminal-backend choices.
- Log collection.
- Container lifecycle.

Recommended wording:

> The same OCI image should remain deployable on a managed container runtime, while storage, secrets, identity, networking, and execution isolation become environment-specific runtime configuration.

## 3. Correct the “no account or network” statement

The local probe still needs network connectivity and accounts for:

- Azure.
- AWS.
- GitHub.
- Model providers.
- Package or image registries.

The actual benefit is:

> No dedicated cloud account or VM is required for hosting the control plane.

## 4. Pin an exact version and digest

The runtime risk register correctly recognizes Hermes’ release velocity and the historical authentication vulnerability.

The experiment should use:

```text
Hermes exact version
Git commit or release tag
OCI image digest
Dependency lockfile hash
```

Avoid specifying only `≥0.20.x`. A range permits behavior changes between trials.

The cited CVE affects Hermes versions through 0.12.0:

- https://nvd.nist.gov/vuln/detail/CVE-2026-11461

## 5. Do not describe context scanning as complete prompt-injection defense

Hermes context scanning is useful defense-in-depth, but source repositories, scanner output, logs, comments, filenames, build scripts, and IaC descriptions remain untrusted inputs.

The probe does not need to solve prompt injection immediately, but the security map should describe context scanning as mitigation, not enforcement.

A later probe should deliberately place an instruction-like payload in:

- A source-code comment.
- A README.
- Scanner finding text.
- Telemetry.
- A generated build artifact.

The test should determine whether that content can redirect the agent or cause credential discovery.

## 6. Keep Anna exploratory

Anna is valuable as a substrate shakedown because it already exists and uses CDK.

It should not be described as proving generalization because it changes several dimensions simultaneously and lacks constructed ground truth.

Recommended classification:

```text
Anna:
- exploratory
- substrate shakedown
- CDK linking observations
- human-adjudicated
- not included in the scored safety matrix
```

---

# Recommended revised architecture

```text
Operator laptop

Host-side deterministic harness
│
├── immutable inputs
│   ├── normalized OCSF finding
│   ├── canonical repository commit
│   ├── environment definition
│   └── arm configuration
│
├── engineer container — ephemeral
│   ├── pinned El Capitan/Hermes image
│   ├── fresh Hermes home
│   ├── scanner-reader credential only
│   ├── canonical repo mounted read-only
│   └── scratch workspace mounted read/write
│
├── deterministic evidence collector
│   ├── captures proposal artifacts
│   ├── captures live configuration
│   ├── captures telemetry for Arm B
│   ├── redacts sensitive information
│   └── emits immutable hashed bundles
│
├── challenger container — ephemeral
│   ├── fresh Hermes home
│   ├── no engineer memory/session
│   ├── challenge bundle mounted read-only
│   └── MoA produces member positions + verdict
│
├── deterministic artifact validator
│   ├── validates JSON Schema
│   ├── validates evidence hashes
│   ├── validates repository immutability
│   └── validates trial completeness
│
└── scorer
    ├── reads finalized artifacts
    ├── reads ground truth outside agent mounts
    └── appends immutable TrialResult
```

---

# Recommended changes by specification section

## §3.1 Control plane

Replace:

> One container, on the operator’s laptop.

With:

> One pinned image, executed as fresh local containers by a deterministic host-side harness.

Remove the claim that the image will run unchanged on Fargate.

Replace “credential pools” with explicit per-run secret mounts or environment injection.

## §3.2 Agent topology

Retain two epistemically isolated roles, but enforce isolation with fresh containers rather than profiles alone.

Clarify that profiles provide state separation inside Hermes, while containers and secret mounts provide the actual security boundary.

Redefine MoA as a judge over a fixed evidence bundle.

## §3.3 Contract

Keep the `/goal` completion contract.

Add deterministic goal gates and an independent host-side validator.

Specify that `NEEDS_HUMAN_CONTEXT` and `NEEDS_MORE_EVIDENCE` are distinct:

- `NEEDS_HUMAN_CONTEXT`: required business or ownership knowledge is unavailable.
- `NEEDS_MORE_EVIDENCE`: the question is answerable, but the supplied technical evidence is insufficient.

## §3.4 Schema

Separate proposal, verdict, and trial-result records, or introduce explicit immutable package versions.

Add evidence provenance, hashes, OCSF identifiers, input hashes, runtime configuration, and sensitivity labels.

## §3.5 Harness

Replace profile reset with fresh-container creation.

Replace credential-pool selection with arm-specific secret injection.

Add:

- Input-bundle creation.
- Bundle hashing.
- Evidence redaction.
- Artifact validation.
- Canonical-repository digest check.
- Randomized or paired trial ordering.

## §3.6 Ground truth

Make TRAP-1 verdict conditional on the actual patch.

Expand TRAP-2 acceptable outcomes.

Ensure ground truth is not visible inside any agent container.

Define scoring at the assertion level rather than only the final-verdict level.

## Appendix B

Classify Anna as exploratory and remove it from claims of demonstrated linking generalization.

Require PII treatment before model ingestion.

## §5 Risk register

Correct the credential-pool description.

Add risks for:

- Cross-profile filesystem access.
- Ground-truth leakage.
- MoA reference models lacking tool evidence.
- PII transmission to multiple model providers.
- Telemetry drift between arms.
- Model-provider behavior changing during a trial batch.
- Prompt injection through repository and telemetry content.

---

# Suggested scoring expansion

Do not score only the final verdict. Score the intermediate capabilities separately:

```text
Finding confirmation
    correct / incorrect / unsupported

IaC ownership classification
    correct / incorrect / uncertain

Source linking
    correct / incorrect / not found

Resolution type
    correct / safe-partial / dangerous

Toolchain verification
    valid / invalid / incomplete

Dependency identification
    complete / partial / absent

Final verdict
    correct / false approval / false rejection / insufficient evidence

Evidence use
    relevant / decorative / unsupported

Calibration
    confidence consistent / overconfident / underconfident
```

This makes a failed trial diagnostically useful.

For example, a challenger might correctly reject a patch for the wrong reason. Verdict-only scoring would count that as success even though the underlying safety capability was absent.

---

# Revised build gates

## Stage 0 — Runtime substrate

Exit only when:

- The exact image digest is recorded.
- Fresh engineer and challenger containers launch independently.
- Arm A cannot enumerate or access the observer credential.
- Ground truth is absent from both containers.
- The canonical repository is demonstrably read-only.
- A simple scan artifact can be read.

## Stage 1 — Anna shakedown

Exit only when:

- Scanner output is normalized.
- One finding is linked to a plausible CDK source location.
- A patch is generated in scratch space.
- The artifact validator passes.
- Results are labeled exploratory.

## Stage 2 — Eiger trap construction

Exit only when:

- Eiger is healthy before the remediation.
- A deterministic workload proves Eiger uses the target storage path.
- The naïve TRAP-1 patch breaks the health contract.
- The failure is repeatable.
- The evidence snapshot is retained.
- TRAP-2 is verifiably runtime-created.
- The control remediation is independently reviewed as safe.

## Stage 3 — End-to-end agent workflow

Exit only when:

- The engineer emits a valid immutable proposal.
- The deterministic collector emits Arm A and Arm B bundles.
- The challenger receives no engineer narrative or confidence.
- Every MoA member position is retained.
- The final verdict references supplied evidence.
- No cloud or canonical-repository mutation occurs.

## Stage 4 — Scored trials

Exit only when:

- All 30 expected trial records exist.
- Every record passes schema and evidence validation.
- Trial order and timestamps are recorded.
- No state leakage is detected.
- Ground truth is applied only after finalization.

## Stage 5 — Interpretation

Produce:

- Outcome matrix.
- Intermediate-capability matrix.
- False-approval and false-rejection counts.
- Evidence-use analysis.
- Dissent analysis.
- Failure taxonomy.
- Recommendation: reasoning-only, telemetry-grounded, staging-required, or stop.

---

# Final recommendation

Proceed with the capability probe.

Do not revert to the earlier demo-oriented design. The current thesis, safety focus, deterministic harness, trap structure, control case, local runtime, and datastore philosophy are strong.

Before implementation, revise the specification so that:

1. Profiles organize agents but containers enforce isolation.
2. Cloud credentials are injected per run rather than represented as Hermes credential pools.
3. MoA judges immutable evidence bundles visible to every member.
4. `/goal` is backed by deterministic quality gates.
5. Proposal, verdict, and result records remain genuinely append-only.
6. Ground truth evaluates the actual patch rather than the finding alone.
7. Ground truth is invisible to agents.
8. PII is sanitized before any model receives it.
9. Trial inputs and runtime configuration are fully hashed and recorded.
10. Anna remains an exploratory shakedown rather than scored proof of generalization.

With those revisions, the probe should produce an answer that is both technically credible and commercially meaningful:

> Does telemetry materially improve an agent’s ability to reject production-breaking security remediations without making it reject safe changes indiscriminately?
