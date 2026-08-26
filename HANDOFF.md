# El Capitan — product handoff

El Capitan is a vulnerability-remediation platform, not an agent capability
probe. Start with `README.md` and `docs/product-architecture.md`.

## Product rules

- Hermes is not a runtime dependency. Model workers implement the
  provider-neutral `AgentRuntime` contract.
- Agents produce typed recommendations and artifacts. Deterministic workflow
  code owns state transitions, credentials, approvals, execution, and audit.
- Production changes require an approved plan, verification contract, and
  prepared rollback. The current vertical slice stops at PR creation.
- Scanner and validator identities are scoped and read-only. Ambient cloud
  profiles are ignored.
- Evidence is immutable and content-addressed. Workflow events are append-only.
- One asset may have only one active remediation case per tenant.

## Current implementation

The product currently supports OCSF and ASFF intake, exact-asset correlation,
transparent priority scoring, SQLite-backed cases/findings/records, explicit
workflow gates, and read-only validation for its first Azure and AWS rules.

Run the complete suite with:

```bash
UV_CACHE_DIR=/tmp/elcapitan-uv-cache uv run pytest -q
```

The retired Claude/Hermes capability probe is preserved on
`archive/claude-code-probe-2026-08-25`. Eiger is a separate active repository
and must never be modified as part of El Capitan maintenance.
