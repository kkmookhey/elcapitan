# Why deterministic gates own El Capitan's transitions

Cloud remediation combines two different kinds of work. Interpreting evidence,
proposing a change, and anticipating operational risk benefit from specialized
reasoning. Deciding whether evidence is admissible, whether a case may advance,
and whether a side effect is authorized require repeatable rules. El Capitan
keeps those jobs separate.

## Models produce artifacts, not authority

An optional model worker receives a bounded evidence package and must return a
versioned typed artifact: a complete-file remediation proposal, SRE review,
window assessment, rollback review, or release audit. Local code constrains the
input, validates the schema and citations, limits output and time, and records
runtime provenance. A malformed, unsupported, uncited, or unavailable result
does not become workflow state.

The model never receives deployment credentials. It cannot approve its own
work, schedule a job, weaken a policy, skip a stage, or call an action
connector. Recorded results can replace live runtimes entirely for testing and
review.

## Gates decide transitions

Deterministic code owns the state machine and evaluates exact predicates:

- Does the current live observation match the finding's provider, resource,
  control, and evidence contract?
- Is one Terraform resource linked without ambiguity, and did format,
  validation, and no-refresh plan checks pass in an isolated copy?
- Are the SRE, change-window, rollback, and verification records complete and
  mutually consistent?
- Does the human decision reference the current review-package hash?
- Is the scheduled job within its window, leased by one worker, and backed by
  a proven connector, checkpoint, monitor, and rollback path?

These checks are replayable and testable. Missing or stale evidence fails
closed; it cannot be converted into confidence by persuasive prose.

## Bounded work is part of correctness

Every runtime dispatch is bound to a case, role, task contract, and immutable
evidence-package hash. A completed replay returns the durable result without a
new call. Attempts, model-call count, elapsed time, and equivalent failure
signatures have explicit limits. Repeated failures open a circuit and write an
operator-visible needs-human record instead of silently restarting.

That distinction matters operationally. A retry loop that eventually produces
something is not reliable automation if nobody can explain how many attempts
occurred, what changed, or why it stopped.

## The result

El Capitan uses reasoning where ambiguity is real, but places authorization in
small deterministic boundaries that can be inspected independently. The
machine-readable capability matrix makes the same separation visible at the
control level: validation, remediation planning, live execution, and evidence
grade are separate facts.

This technical preview does not claim unattended production remediation,
complete cloud coverage, or a production identity experience. Its narrower
claim is auditable: a reviewer can follow one finding through minimized
evidence, bounded proposals, deterministic gates, package-bound human authority,
and—only for explicitly proven connectors—a monitored action or rollback.
