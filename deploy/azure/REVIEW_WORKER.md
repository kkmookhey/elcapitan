# Operational review worker

`Dockerfile.review` builds a manual Azure Container Apps Job that advances one
durable, validated case to `awaiting_approval`. It has no ingress, no schedule,
no mutation route, and no Azure role beyond Reader on the target resource group.

The job requires four Azure secret references:

- `database-url`: the durable El Capitan PostgreSQL DSN
- `promotion-token`: the case-specific, evidence-bound promotion token
- `openai-api-key`: maker and window-review provider credential
- `anthropic-api-key`: SRE and rollback-review provider credential

Secret values must be injected by an authorized operator or secret manager; they
must not be committed, supplied as container arguments, or printed in deployment
logs. The non-secret configuration is:

```text
image: ca7b25e7d425acr.azurecr.io/elcapitan-demo:20260827-review.25
trigger: Manual
retry limit: 0
timeout: 1800 seconds
planner identity: elcapitan-review-planner
planner Azure role: Reader on eiger-rg only
models: OpenAI gpt-5.4-mini; Anthropic claude-sonnet-5
repository: /review-inputs/eiger/repository
state: /review-inputs/eiger/target-state.json
service context: /review-inputs/eiger/service-context.json
usage: /review-inputs/eiger/usage.json
```

Terraform executes with `refresh=false` and an ephemeral sanitized state file.
The plan is accepted only if JSON inspection proves exactly one in-place change:
`azurerm_storage_account.corpus.public_network_access_enabled` from `true` to
`false`. The binary plan and state are deleted before the container exits. The
worker is resumable from any completed preapproval stage and stops before approval
or execution.

If the rollback checker rejects with concrete `required_changes`, the durable case
records an immutable feedback decision, clears only the superseded plan projection,
and allows one checker-to-maker rework. The revised maker task is evidence-bound to
that feedback. A second rejection is terminal, preventing unbounded agent loops.

The service-context document may include a strict `window_policy` object for a
customer or laboratory maintenance policy. Unknown fields and invalid timezone,
duration, weekday, hour, candidate, or sample constraints fail closed. When it
is absent, the worker retains the conservative weekday midnight default.
An explicit `fixed_start_delay_minutes` is available for approved emergency or
disposable-lab policies; it is bounded to 1–1440 minutes and remains visible in
the immutable candidate evidence and human review package.
