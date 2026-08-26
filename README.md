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

See [the product architecture](docs/product-architecture.md) for the system
boundary and first PR-only vertical slice. The retired capability probe is
preserved on the `archive/claude-code-probe-2026-08-25` branch for reference.
