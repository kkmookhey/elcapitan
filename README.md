# El Capitan

El Capitan is becoming a durable vulnerability-remediation platform. It turns
scanner findings into auditable remediation cases that move through priority,
validation, change planning, SRE review, scheduling, approval, execution,
verification, and rollback.

Hermes is not required. Model-backed workers use a provider-neutral runtime
contract; deterministic workflow and policy code owns state and side effects.

## Current product slice

The current implementation can:

- ingest OCSF findings and ASFF findings converted to OCSF;
- deduplicate replayed scanner events by source identity;
- correlate findings on the same tenant/cloud/account/resource;
- calculate a transparent, configurable priority;
- re-query supported Azure and AWS resources with a scoped read-only identity;
- deterministically confirm, clear, or block supported finding rules;
- link a validated Azure or AWS resource to one unambiguous Terraform block;
- constrain a remediation proposal to the linked Terraform source file;
- verify the isolated change with Terraform format, validation, and plan gates;
- run an independent SRE review against explicit service health context;
- derive bounded future change-window candidates from historical usage;
- independently verify rollback steps and observable rollback triggers;
- assemble a policy-checked human review package and stop for approval;
- persist immutable workflow events and projections in SQLite/WAL;
- prevent concurrent workers from opening two active cases for one asset;
- require typed records at every later workflow gate, including rollback.

Ingest one finding locally:

```bash
UV_CACHE_DIR=/tmp/elcapitan-uv-cache uv run elcapitan intake \
  tests/fixtures/prowler-ocsf-azure-sample.json \
  --tenant demo \
  --db /tmp/elcapitan-demo/product.db \
  --artifacts /tmp/elcapitan-demo/artifacts \
  --asset-criticality 0.8 \
  --reachable
```

The command prints the normalized finding id, correlated case id, priority,
workflow state, and whether the event was a duplicate.

Validate the resulting case with the provider's read-only scanner credential:

```bash
UV_CACHE_DIR=/tmp/elcapitan-uv-cache uv run elcapitan validate \
  --case CASE-... \
  --db /tmp/elcapitan-demo/product.db \
  --artifacts /tmp/elcapitan-demo/artifacts
```

For Azure, the validator consumes `ELCAP_SCANNER_AZURE_CLIENT_ID`,
`ELCAP_SCANNER_AZURE_CLIENT_SECRET`, and `ELCAP_SCANNER_AZURE_TENANT_ID`.
For AWS it consumes the corresponding `ELCAP_SCANNER_AWS_*` session
credential. Ambient cloud profiles are deliberately ignored.

Prepare a Terraform remediation after validation:

```bash
UV_CACHE_DIR=/tmp/elcapitan-uv-cache uv run elcapitan plan \
  --case CASE-... \
  --db /tmp/elcapitan-demo/product.db \
  --artifacts /tmp/elcapitan-demo/artifacts \
  --repo /path/to/customer/terraform \
  --agent-result /path/to/terraform-remediation-result.json \
  --state-json /path/to/terraform-state.json
```

`--state-json` accepts either raw Terraform state JSON or
`terraform show -json` output. It is optional for literal resource names and
required when state is needed to resolve computed names or `for_each`
instances. El Capitan stores only the matched address and a hash of the state,
not the full potentially sensitive state document.

The recorded agent result uses the provider-neutral
`TerraformRemediationProposal.v1` contract. Its `output` contains `objective`,
`files`, `prerequisites`, `steps`, `rollout_steps`, `verification_steps`,
`rollback_steps`, `rollback_triggers`, and `blast_radius`. `files` must contain
exactly one `{path, content}` complete-file replacement for the linked
repository-relative path. Recorded results may also use the legacy path-to-text
mapping accepted by the local adapter.

Planning never edits the supplied repository and never runs `terraform apply`.
It copies the repository into a case artifact workspace, rejects symlinks and
path escapes, excludes common credential and Terraform-state files, records
source and proposal hashes, and advances the case to
`plan_ready` only when `terraform fmt -check`, `terraform validate`, and
`terraform plan -refresh=false -lock=false` succeed. A failed check is retained
as an immutable `RemediationPlanAttempt.v1`, while the case remains validated.
Provider initialization uses `-backend=false -lockfile=readonly`, and the local
runner uses an isolated home with no ambient AWS or Azure credential files.
Commands have a five-minute default timeout and bounded captured output.

## Run the whole safe workflow locally

The quickest manual test requires Terraform, but no cloud credentials, model
API key, or customer repository:

```bash
UV_CACHE_DIR=/tmp/elcapitan-uv-cache uv run elcapitan demo-review
```

The demo creates a disposable finding, confirms it through a recorded
read-only cloud observation, links it to a built-in `terraform_data` resource,
runs real `terraform fmt`, `init`, `validate`, and `plan`, completes the SRE,
window, and rollback reviews, and stops in `awaiting_approval`. Its JSON output
includes a `show-review` command for the complete review package. It also
reports `source_repository_unchanged: true` and `execution_status:
not_started`. No `apply` or cloud mutation code is part of this path.

To exercise an already validated customer case with recorded agent results:

```bash
UV_CACHE_DIR=/tmp/elcapitan-uv-cache uv run elcapitan prepare-review \
  --case CASE-... \
  --db /tmp/elcapitan/product.db \
  --artifacts /tmp/elcapitan/artifacts \
  --repo /path/to/customer/terraform \
  --state-json /path/to/terraform-show.json \
  --usage-json /path/to/usage-samples.json \
  --service-context-json /path/to/service-context.json \
  --agent-results /path/to/recorded-results
```

The result directory must contain `terraform-remediation-proposal.json`,
`sre-review.json`, `change-window-selection.json`, and
`rollback-review.json`. Each file implements its corresponding strict `v1`
contract. Usage input is `{ "samples": [...] }`; every sample has an RFC3339
`timestamp`, `requests`, and optional `errors` and `p95_latency_ms`. Service
context must name the `service`, `environment`, `owner`, `health_signals`, and
`dependencies`.

For an Azure case, `--azure-monitor` can replace `--usage-json`. It queries the
case resource's historical `Transactions` metric (or `--azure-metric`) through
a separate observer principal. Set `ELCAP_OBSERVER_AZURE_CLIENT_ID`,
`ELCAP_OBSERVER_AZURE_CLIENT_SECRET`, and
`ELCAP_OBSERVER_AZURE_TENANT_ID`; scanner credentials and ambient Azure CLI
sessions are ignored. The query ends one hour behind real time to avoid the
freshest ingestion window.

The same command can execute the four bounded roles directly through the
OpenAI Responses API:

```bash
OPENAI_API_KEY=... UV_CACHE_DIR=/tmp/elcapitan-uv-cache \
  uv run elcapitan prepare-review ... \
  --runtime openai --model YOUR_EXPLICIT_MODEL
```

The adapter requests strict JSON-schema output, disables response storage, and
records runtime/model/usage provenance. Workflow transitions, candidate
generation, Terraform verification, policy, and approval remain deterministic
product code; the model never receives an apply capability.

See [the product architecture](docs/product-architecture.md) for the system
boundary and first PR-only vertical slice. The retired capability probe is
preserved on the `archive/claude-code-probe-2026-08-25` branch for reference.
