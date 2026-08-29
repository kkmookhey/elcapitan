# Agent-run budgets and circuit breakers

El Capitan bounds model-backed work per remediation case at the
provider-neutral `AgentRuntime` boundary. The same boundary is active for
recorded local results, so replay and failure behavior can be tested without
provider keys or network calls.

## Default policy

Each case starts with these central limits:

| Limit | Default | Behavior at the limit |
|---|---:|---|
| Runtime/model calls | 42 per case | Stop before another dispatch |
| Attempts | 3 per case, role, output contract, and evidence package | Stop that role/package |
| Elapsed run time | 3,600 seconds from the first recorded invocation | Stop at the next dispatch boundary |
| Equivalent failures | 2 with the same deterministic failure signature | Open the role/package circuit |

These are ceilings, not retry targets. A non-correctable provider failure is
returned immediately. The isolated review worker may correct eligible
structured-output or token-limit failures, but still makes no more than three
total attempts for that role/package. Decision-specific semantic and citation
correction remains capped at two retries. Preapproval remains capped at 14
state advances. Provider and subprocess timeouts, Terraform safeguards, and
the 100-page ARM pagination bound remain independently enforced.

Elapsed time is checked before dispatch. It does not interrupt an in-flight
provider request; the provider timeout owns that narrower bound.

## Durable binding and records

Replay identity is derived from the case, role, objective/output contract and
constraints, plus a SHA-256 package hash over the immutable input-record and
evidence IDs. Generated task IDs are deliberately excluded. A successful
result for the same binding is reconstructed from the durable outcome record,
with the current task ID, and the runtime is not called again.

Every dispatch writes an `AgentInvocation.v1` record with `started` status
before calling the runtime. Completion writes one
`AgentInvocationOutcome.v1`, including a hashed reference to the typed result
evidence on success, or a minimized failure class and hashed signature on
failure. Complete model output remains in the existing case artifact boundary
rather than being copied into the product database. Raw exception text is not
persisted. If a process stops after the start record and before its outcome,
reload fails closed rather than assuming that the call never happened.

Exhaustion, an incomplete prior invocation, or an open circuit writes one
`AgentRunTerminal.v1` with `status: needs_human`, the reason, current counts,
policy snapshot, and package binding. Preapproval then moves the case to
`blocked` and binds `agent_run_terminal_id` to the immutable case event. It
never restarts the role from attempt one.

## Overrides and operator recovery

The `prepare-review` and `prepare-review-worker` commands expose:

```text
--agent-max-model-calls
--agent-max-attempts-per-package
--agent-max-elapsed-seconds
--agent-failure-threshold
--agent-override-terminal-record RECORD_ID
```

Positive limit overrides must be chosen before dispatch. Recovering a blocked
case requires both an explicit case resume through the workflow authority and,
when reusing the same package, the exact terminal-record override. Raising a
limit alone does not erase the old terminal record. Each subsequent invocation
captures the active policy and override IDs for audit. Supplying changed input
or evidence creates a new package binding; it does not rewrite earlier records.

Terminal overrides are a deliberate human action, not an automatic retry
mechanism. They do not relax provider timeouts, stage retry caps, evidence
validation, model-egress authorization, approval, or execution policy.

## Limitations

- The first implementation uses the existing immutable product-record store;
  it is not a replacement workflow or queue.
- Elapsed limits are dispatch-boundary checks rather than active cancellation.
- A crash-ambiguous invocation is treated as consumed and needs human review.
- Failure equivalence is exact after whitespace normalization and hashing; two
  differently worded failures may consume attempts without sharing a circuit.
- Budgets govern preapproval agent work. Deterministic validation, Terraform
  subprocess checks, scheduling, execution, and ARM pagination retain their
  own existing bounds.
