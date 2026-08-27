# Customer shadow-run guide

The customer shadow fleet is the first real-environment entry point for El
Capitan. It answers four questions before any remediation authority exists:

1. Which scanner findings are still true in live cloud configuration?
2. Which controls does El Capitan understand deterministically?
3. What is the transparent risk order across the customer portfolio?
4. Which validated cases are ready to enter the separately controlled
   planning and human-review plane?

## Hard boundary

`serve-shadow` exposes finding intake, fleet inventory, connector readiness,
case evidence, single-case validation, and bounded batch validation. It has no
approval, schedule, deployment, rollback, or model endpoint. Its policy object
cannot be constructed with any of those action permissions enabled. Do not
attach an executor identity, Contributor role, model API key, or customer
write credential to this service.

The first customer run should use a dedicated deployment and database. Do not
reuse the public synthetic lifecycle demo's `/data` volume.

## Supported live validation

Support is explicit and fails closed:

| Provider | Rule | Live validation | Live execution |
|---|---|---:|---:|
| AWS | `s3_bucket_object_versioning` | yes | no |
| Azure | `storage_account_public_network_access_disabled` | yes | separately gated |
| Azure | `storage_blob_public_access_level_is_disabled` | yes | separately gated |
| Azure | `storage_blob_versioning_is_enabled` | yes | no |

An unknown provider rejects the entire intake batch before persistence. An
unknown rule may be retained in the portfolio for coverage reporting, but the
validator makes no cloud request and does not infer its status.

## Identity contract

Use a dedicated read-only scanner identity. Ambient AWS and Azure CLI sessions
are not eligible. Supply exactly the connector-specific variables:

```text
ELCAP_SCANNER_AWS_ACCESS_KEY_ID
ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY
ELCAP_SCANNER_AWS_SESSION_TOKEN

ELCAP_SCANNER_AZURE_CLIENT_ID
ELCAP_SCANNER_AZURE_CLIENT_SECRET
ELCAP_SCANNER_AZURE_TENANT_ID
```

AWS should use a short-lived session and least-privilege read actions for the
resource types being validated. Azure should use a service principal or
workload identity with Reader limited to the in-scope subscriptions or
resource groups. Keep the scanner identity distinct from the observer used for
historical metrics and from any future execution worker.

Before ingestion, verify local prerequisites without making a cloud request:

```bash
uv run elcapitan connector-preflight --provider azure
uv run elcapitan connector-preflight --provider aws
uv run elcapitan capabilities
```

## Safe run sequence

1. Create a customer-specific tenant identifier that contains no secret or
   personal data.
2. Export findings from the scanner. Keep the source export unchanged for
   chain-of-custody purposes.
3. Start `serve-shadow` with a fresh 24+ character access token and a dedicated
   work directory.
4. Import a small representative batch first. Confirm provider, account,
   resource identifier, rule mapping, risk factors, and supported/unsupported
   counts in the case drill-down.
5. Confirm connector readiness. If it is offline, resolve the missing binary or
   named environment variables; do not substitute a broader credential.
6. Validate one non-production or low-risk case, inspect its evidence record,
   then use **Validate eligible** for batches of at most 100 cases.
7. Export or review the resulting prioritized fleet. Cases in `validated` are
   candidates for the existing `prepare-review` workflow; cases in
   `closed_no_action` are stale or already resolved, and `blocked` cases require
   evidence or control support.

Batch validation resolves every case's tenant ownership, state, rule support,
and connector readiness before the first cloud request. It remains possible
for a cloud read to fail after preflight; that failure is retained as restricted
evidence and the affected case fails closed.

## Data handling

Finding documents and captured configuration evidence remain on the service's
local durable volume. The shadow service sends nothing to OpenAI, Anthropic,
Gemini, or any other model provider. `/healthz` is anonymous for the hosting
platform; all dashboard assets and case APIs require the access token. Browser
sessions use an HttpOnly, Secure, SameSite=Strict cookie, and cross-origin
writes are rejected.

For a real customer, put Entra ID, an identity-aware proxy, or equivalent SSO
in front of the app, encrypt the durable store with customer-managed controls,
define retention, centralize audit logs, and replace SQLite with PostgreSQL
before horizontal scaling.

## Promotion to human review

Promotion is deliberately a separate deployment boundary. The planning worker
requires a read-only customer IaC checkout or repository snapshot, optional
Terraform state JSON for computed resource mapping, explicit service ownership
and health signals, and historical usage samples. Run `prepare-review` only for
a confirmed case. It works in an isolated copy, never runs `terraform apply`,
and stops at `awaiting_approval` after Terraform checks, SRE review, window
selection, and independent rollback review all pass.

Do not give the shadow web service those repository, model, observer, or
execution credentials. That separation is an intentional product control, not
a temporary UI omission.
