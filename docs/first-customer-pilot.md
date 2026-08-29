# First customer pilot profile

The first customer engagement should prove evidence quality and prioritization
before it proves autonomous mutation. Start with a dedicated read-only shadow
deployment and one non-production cloud boundary.

## Ideal environment

- One Azure subscription or AWS account that is explicitly non-production and
  has no regulated or customer data.
- 20–100 current scanner findings, preferably Prowler OCSF or AWS Security
  Finding Format, plus the unchanged source export for chain of custody.
- At least five resources with a useful mixture of true findings, stale
  findings, unsupported controls, shared services, and differing criticality.
- Two or more findings covered by deterministic El Capitan validators. Use
  `elcapitan capabilities` as the authoritative support matrix. The current
  Azure scope spans selected Storage, SQL Server, Key Vault, subnet, App
  Service/Functions, Container Registry, and Azure OpenAI controls. Most are
  validation-only; only the capability output may be used to infer planning or
  execution authority. The current AWS pilot includes S3 object versioning
  validation and planning but no AWS mutation authority.
- A read-only Terraform repository snapshot and sanitized state JSON for a
  small subset of validated resources. No secrets, provider credentials,
  access keys, connection strings, or data-plane content.
- Named service owner, environment, business criticality, dependencies,
  maintenance policy, rollback expectations, and observable health signals for
  the resources selected for planning.
- At least seven days of hourly usage or request metrics, with timestamps and
  timezone, or a separately scoped metrics-observer identity.

## Identity separation

Use distinct identities; do not grant one identity all capabilities.

1. **Scanner:** Reader/SecurityAudit only on the pilot subscription, resource
   group, account, or explicitly listed resources.
2. **Metrics observer:** read-only access only to the approved metrics and log
   namespaces.
3. **IaC planner:** read-only repository/state access and cloud Reader only when
   Terraform refresh requires it.
4. **Executor:** not present during the shadow run. Add it only for a later,
   separately approved non-production action pilot, scoped to exact resource
   operations and exact resource IDs or tags.

Prefer workload identity or short-lived federation. Do not provide personal
administrator sessions, subscription Owner, account Administrator, or key-list
permissions.

## Data and model boundary

- Deploy a customer-specific database and tenant identifier; do not mix pilot
  data with the public demo.
- Put SSO or an identity-aware proxy in front of external ingress and centralize
  access/audit logs.
- Agree retention, encryption, region, deletion, incident contact, and evidence
  export requirements before upload.
- The shadow plane sends no customer evidence to model providers. Promotion to
  maker/checker review requires a separate, explicit evidence manifest and
  customer authorization naming the model providers and bounded fields.
- Exclude secrets, personal data, payload bodies, source data, and broad log
  content. Provide derived usage counts and named health signals instead.

## Pilot sequence and acceptance

1. Ingest 5–10 findings and verify tenant, account, resource ID, rule mapping,
   risk factors, and synthetic/real labels manually.
2. Validate one supported finding live and compare El Capitan evidence with the
   cloud console or scanner.
3. Validate the remaining eligible batch, capped at 100 cases.
4. Review false-positive closure, unavailable evidence, unsupported coverage,
   and portfolio ordering with the customer owner.
5. Promote one confirmed, low-impact case into the isolated planning plane only
   after the repository, state, service context, usage data, and model-egress
   authorization are approved.
6. Stop at the human package. The pilot passes when every claim traces to an
   immutable evidence record, unsupported or unavailable data fails closed, the
   Terraform diff is exact, reviewers are phase-correct, and no action identity
   exists in the shadow service.

Only after those checks pass should a separate action pilot be proposed. Use a
disposable or canary resource, an exact-scope executor, a checkpointed change,
mandatory post-change vulnerability validation, health monitoring, automatic
rollback, and an originator handoff certificate.
