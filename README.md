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
exactly one complete-file replacement keyed by the linked repository-relative
path.

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

See [the product architecture](docs/product-architecture.md) for the system
boundary and first PR-only vertical slice. The retired capability probe is
preserved on the `archive/claude-code-probe-2026-08-25` branch for reference.
