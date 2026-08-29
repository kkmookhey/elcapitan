# v0.1 launch demo and screenshot runbook

This runbook prepares launch media without expanding product claims. Recording,
publication, and any live-lab segment require their own authorization. Never use
customer data, a customer identity, Eiger, or a production resource.

## Seven-minute recording

| Time | Segment | Proof to show |
|---:|---|---|
| 0:00–0:45 | Trust boundary | README architecture diagram; validation, planning, and execution are separate |
| 0:45–1:45 | Offline import | Import a sanitized OCSF/ASFF export and reconcile exact outcome counts |
| 1:45–2:45 | Authorized lab validation | One bounded read-only validation; show identity scope and normalized evidence, not raw cloud JSON |
| 2:45–3:40 | Evidence inspection | Resource/control identity, observation time, provenance, availability, and evidence grade |
| 3:40–5:05 | Package review | Exact source diff, plan gates, SRE review, window, rollback, and package hash |
| 5:05–5:45 | Human boundary | Typed package-specific decision; explain that approval is not generic execution authority |
| 5:45–6:45 | Synthetic rollback | Separate labeled scenario triggers health failure, restores the checkpoint, and proves recovery |
| 6:45–7:00 | Limitations | Technical-preview limits and capability/evidence matrix |

The live-lab segment must stop unless the subscription, resource, read-only
identity, role scope, and sanitized output contract are explicitly approved.
Use a recorded or contract fixture if those prerequisites are absent, and label
it accurately rather than implying live proof.

## Screenshot set

Capture from a clean local quickstart at 1440×900 or larger:

1. `shadow-fleet.png` — synthetic fleet overview with source type and exact
   finding accounting visible.
2. `capability-boundaries.png` — one control showing separate validation,
   planning, execution, and evidence-grade labels.
3. `evidence-timeline.png` — minimized evidence and immutable timeline without
   tokens, raw provider responses, host paths, or identifiers.
4. `package-review.png` — synthetic review package with exact diff, rollback,
   and package-bound confirmation.
5. `synthetic-rollback.png` — clearly labeled rollback and recovered health.

Before committing any image, inspect every pixel for access tokens, cookies,
connection strings, personal browser chrome, account/subscription/resource
identifiers, private URLs, customer names, and local filesystem paths. Prefer a
fresh browser profile and the checked-in synthetic tenant. Optimize the final
PNG files and record the commit that produced them.

## Current capture status

The written sequence is ready. Actual screenshots and the recording remain
pending because this session had no connected browser surface, and the live-lab
segment is outside the current no-cloud objective. Do not replace either with a
fabricated image or an unlabeled synthetic claim.
