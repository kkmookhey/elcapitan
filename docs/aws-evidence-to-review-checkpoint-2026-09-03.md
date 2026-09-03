# AWS evidence-to-review checkpoint — 2026-09-03

This checkpoint extends the existing AWS validation and prioritization surface
to one complete, reviewable remediation path without adding mutation authority.
It is deliberately limited to AWS. GCP is out of scope.

## Capability boundary

- 37 AWS controls retain deterministic validation: 7 S3, 8 RDS DB-instance,
  20 EC2 security-group, and 2 EBS volume controls.
- Every imported finding is normalized and correlated to an exact cloud
  resource. Contextual risk remains transparent: severity, asset criticality,
  exposure, reachability, exploit signals, runtime dependency, and
  compensating controls are independent inputs rather than an opaque score.
- The 36 validation-only controls stop at a confirmed, cleared, unavailable, or
  unsupported result plus priority. They do not silently acquire planning or
  execution capability.
- `s3_bucket_object_versioning` is the only AWS control admitted to remediation
  planning and canonical human-review packaging.
- No AWS control has deployment or live-execution authority.

## S3 versioning path

The contract-tested path is:

1. ingest a Prowler OCSF finding and preserve its raw evidence;
2. normalize and prioritize its exact bucket ARN;
3. re-read the bounded S3 versioning evidence and confirm the finding
   deterministically;
4. resolve exactly one `aws_s3_bucket_versioning` resource from authoritative
   Terraform source and state;
5. materialize only `status = "Enabled"` in the linked resource block;
6. run Terraform in an isolated copy and inspect an ephemeral targeted plan;
7. reject every plan except one in-place change from `Disabled` or `Suspended`
   to `Enabled` at `versioning_configuration[0].status`;
8. perform the existing independent SRE, usage-window, and rollback reviews;
9. mechanically check record ownership, exact plan scope, evidence chain,
   reviewer decisions, model diversity, and a future window; and
10. issue `HumanReviewPackage.v1` in `awaiting_approval` with
    `execution_status: not_started`.

The source repository is not edited. Terraform state and the plan artifact are
not persisted in product records. The durable package contains the linked
resource address, state digest, source/change digests, exact finding/rule scope,
validation result, review records, policy decision, and immutable evidence
references.

## Identity boundary

The planning process accepts only a complete dedicated AWS session through:

```text
ELCAP_PLANNER_AWS_ACCESS_KEY_ID
ELCAP_PLANNER_AWS_SECRET_ACCESS_KEY
ELCAP_PLANNER_AWS_SESSION_TOKEN
```

It uses an isolated home and credential-file paths. Ambient profiles, ambient
roles, scanner variables, and Azure planner identity are excluded from the
Terraform subprocess. A missing planner field fails before Terraform runs.

## Proof and remaining work

Automated coverage proves exact state linking, deterministic source
materialization, credential isolation, nested plan-diff inspection, rejection
of an accompanying MFA Delete change, and the full canonical package lifecycle.
The proof uses recorded cloud/state/runtime fixtures and makes no AWS request.

A real AWS pilot still requires owner-authorized, non-production scope; a
dedicated read-only scanner identity; authoritative IaC and sanitized state; a
separate least-privilege short-lived planner session; service context; usage
telemetry; and approved independent reviewer routes. Live AWS measurement and
any execution design are separate future checkpoints.
