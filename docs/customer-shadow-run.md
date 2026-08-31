# Customer shadow-run guide

For environment selection and the CTO access request, start with the
[first customer pilot profile](first-customer-pilot.md).

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
reuse the public synthetic lifecycle demo's `/data` volume or cloud identity.

## Supported live validation

Support is explicit and fails closed:

Definitions are installed through the
[control-pack architecture](control-packs.md); the fleet workflow remains
provider-neutral while each service retains its exact evidence semantics.

| Provider | Rule | Live validation | Live execution |
|---|---|---:|---:|
| AWS | `s3_bucket_object_versioning` | yes | no |
| AWS | `s3_bucket_kms_encryption` | yes | no |
| AWS | `s3_bucket_server_access_logging_enabled` | yes | no |
| AWS | `s3_bucket_event_notifications_enabled` | yes | no |
| AWS | `s3_bucket_lifecycle_enabled` | yes | no |
| AWS | `s3_bucket_object_lock` | yes | no |
| AWS | `s3_bucket_no_mfa_delete` | yes | no |
| AWS | `rds_instance_backup_enabled` | yes | no |
| AWS | `rds_instance_copy_tags_to_snapshots` | yes | no |
| AWS | `rds_instance_enhanced_monitoring_enabled` | yes | no |
| AWS | `rds_instance_iam_authentication_enabled` | yes | no |
| AWS | `rds_instance_inside_vpc` | yes | no |
| AWS | `rds_instance_integration_cloudwatch_logs` | yes | no |
| AWS | `rds_instance_minor_version_upgrade_enabled` | yes | no |
| AWS | `rds_instance_storage_encrypted` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_all_ports` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434` | yes | no |
| AWS | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23` | yes | no |
| AWS | `ec2_securitygroup_allow_wide_open_public_ipv4` | yes | no |
| AWS | `ec2_securitygroup_default_restrict_traffic` | yes | no |
| AWS | `ec2_securitygroup_from_launch_wizard` | yes | no |
| AWS | `ec2_securitygroup_with_many_ingress_egress_rules` | yes | no |
| Azure | `storage_account_public_network_access_disabled` | yes | separately gated |
| Azure | `storage_blob_public_access_level_is_disabled` | yes | separately gated |
| Azure | `storage_blob_versioning_is_enabled` | yes | no |
| Azure | `sqlserver_tde_encrypted_with_cmk` | yes | no |

The SQL control reads the server encryption protector, every page of the
database inventory, and the TDE state of every user database. The immutable
`master` database is excluded to match Azure and current Prowler semantics.
Incomplete, denied, malformed, or out-of-scope reads block validation rather
than producing a partial result.

The seven S3 controls reuse one bounded bucket-state capture. The six new
controls are contract tested; only object versioning currently carries an
E2E-measured evidence grade and remediation-planning capability. No AWS control
has live-execution capability.

The eight RDS controls use one `DescribeDBInstances` call scoped to the exact
DB-instance ARN and its ARN-derived region. They are contract tested and
validation-only. The response must contain exactly that one instance; denied,
missing, multiple, mismatched, paginated, DocumentDB, and malformed responses
remain unavailable evidence rather than inferred configuration.

The twenty EC2 security-group controls use one exact-ID group read plus one
group-filtered attachment read capped after the first result. They validate
public port and CIDR exposure, default and Launch Wizard groups, and excessive
permission-entry counts. Prowler's unused-group exclusion and duplicate
all-port/specific-port suppression remain explicit. Both reads are required;
denied, absent, mismatched, partial-empty, and malformed responses fail closed.

An unknown provider rejects the entire intake batch before persistence. An
unknown rule may be retained in the portfolio for coverage reporting, but the
validator makes no cloud request and does not infer its status.

Several controls on one resource correlate into one case. When such a case
contains both supported and unsupported controls, live validation evaluates
the supported subset and records every unsupported sibling explicitly. One or
more live-confirmed controls may advance the case to validated; promotion is
bound only to the exact confirmed finding and evidence set. A case containing
no supported control is rejected before any cloud request, and a case with no
confirmation plus unavailable or unsupported evidence remains blocked.

## Identity contract

Use a dedicated read-only scanner identity. Ambient AWS and Azure CLI sessions
are not eligible. Azure Container Apps should use a user-assigned managed
identity and supply its client ID:

```text
ELCAP_SCANNER_AZURE_MANAGED_IDENTITY_CLIENT_ID
```

The platform-provided `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` complete that
credential-free flow. The validator requests an ARM token from the local
identity endpoint and calls only read operations. For local development or a
non-Azure host, the explicit service-principal fallback is:

```text
ELCAP_SCANNER_AWS_ACCESS_KEY_ID
ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY
ELCAP_SCANNER_AWS_SESSION_TOKEN

ELCAP_SCANNER_AZURE_CLIENT_ID
ELCAP_SCANNER_AZURE_CLIENT_SECRET
ELCAP_SCANNER_AZURE_TENANT_ID
```

AWS should use a short-lived session and least-privilege read actions for the
resource types being validated. Azure should use a managed identity with Reader
limited to the in-scope resource groups; never mix the managed-identity and
service-principal variables. Keep the scanner identity distinct from the
observer used for historical metrics and from any future execution worker.

Before ingestion, verify local prerequisites without making a cloud request:

```bash
uv run elcapitan connector-preflight --provider azure
uv run elcapitan connector-preflight --provider aws
uv run elcapitan capabilities
```

## Safe run sequence

Before any upload or connector access, run the same intake and prioritization
policy entirely locally:

```bash
uv run elcapitan shadow-offline-report /path/to/prowler.ocsf.json \
  --tenant CUSTOMER-OFFLINE \
  --workdir /private/tmp/elcapitan-customer-shadow/work \
  --json-output /private/tmp/elcapitan-customer-shadow/portfolio.json \
  --markdown-output /private/tmp/elcapitan-customer-shadow/summary.md
```

The command starts with an empty local shadow store, accepts only explicit
Prowler `FAIL` records, and writes both outputs with mode `0600`. It makes no
cloud or model request. The JSON contains every resource case and deterministic
risk factor; the Markdown summary highlights intake accounting, control
coverage, and the bounded live-validation candidates. Its ordering is labeled
scanner-evidence provisional until customer asset criticality, ownership,
dependencies, exploitability, and business impact are supplied.

1. Create a customer-specific tenant identifier that contains no secret or
   personal data.
2. Export findings from the scanner. Keep the source export unchanged for
   chain-of-custody purposes.
3. Start `serve-shadow` with a fresh 24+ character access token, a dedicated
   work directory, and `ELCAPITAN_DATABASE_URL` set to a TLS-required PostgreSQL
   connection string.
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

Prowler exports may contain `PASS`, `FAIL`, and `MANUAL` records together.
El Capitan treats only an explicit `status_code == "FAIL"` as an actionable
finding. It reports and skips `PASS` and `MANUAL`; it never infers the result
from OCSF `status` or `severity`. `status` is commonly `New` for every check,
and a passing control retains that control's configured severity. Missing or
unknown Prowler outcomes reject the batch before durable writes.

Prowler 5.x may also reuse `finding_info.uid` for the same check on different
resources. Intake therefore binds Prowler idempotency to the producer UID,
rule ID, and resource UID together. The original UID remains preserved in the
normalized evidence record; replaying one check/resource observation remains
idempotent without collapsing distinct resources.

## Data handling

When `ELCAPITAN_DATABASE_URL` is present, cases, events, findings, product
records, and immutable evidence blobs are stored in PostgreSQL. Evidence is
rehydrated into the container's private working directory at startup and every
blob is checked against its persisted SHA-256 digest. Reusing an artifact path
with different content fails closed. SQLite and local files remain the local,
single-node fallback when the database variable is absent.

The shadow service sends nothing to OpenAI, Anthropic, Gemini, or any other
model provider. `/healthz` is anonymous for the hosting platform and performs
a real database query; all dashboard assets and case APIs require the access
token. Browser sessions use an HttpOnly, Secure, SameSite=Strict cookie, and
cross-origin writes are rejected.

The Azure reference deployment uses a VNet-integrated Container Apps
environment and PostgreSQL Flexible Server with public network access disabled,
TLS required, seven-day backups, and a database-scoped application credential.
The checked-in `deploy/azure/shadow-app.yaml` deliberately defaults to internal
ingress. Enable HTTPS-only external ingress only after database health,
anonymous denial, and authenticated UI/API checks pass.

The guarded lab bootstrap is split into explicit phases under `deploy/azure`.
`bootstrap-shadow-database.sh` creates or rotates one non-privileged login and
an application-owned schema through a temporary no-ingress job, deletes that
job and its secrets, and reseals the server administrator. The scoped password
is handed to `create-customer-shadow-app.sh` through macOS Keychain and removed
after the internal app is created. `repair-customer-shadow-database.sh` is the
fail-closed recovery path when a scoped password or immutable image must be
rebound; it deliberately retains the Keychain handoff until health is proven.
All three scripts pin the El Capitan lab subscription and refuse an unconfirmed
operation. The bootstrap, create, and repair scripts also require
`ELCAPITAN_LAB_IMAGE` to name an immutable image digest in the pinned lab ACR.
The create script additionally requires `ELCAPITAN_LAB_SCANNER_ID` and
`ELCAPITAN_LAB_SCANNER_CLIENT_ID`; it accepts only the dedicated
`elcapitan-<slug>-scanner` identity in the pinned resource group and attaches it
separately from the image-pull identity. They are reference automation, not
authorization to use a customer subscription.

For a real customer, put Entra ID, an identity-aware proxy, or equivalent SSO
in front of the app, use customer-controlled encryption and retention, and
centralize audit logs. The access-token boundary is appropriate for this
non-production demo, not the final customer authentication design.

## Promotion to human review

Promotion is deliberately a separate deployment boundary. The planning worker
requires a read-only customer IaC checkout or repository snapshot, optional
Terraform state JSON for computed resource mapping, explicit service ownership
and health signals, and historical usage samples. Run `prepare-review` only for
a confirmed case. It works in an isolated copy, never runs `terraform apply`,
and stops at `awaiting_approval` after Terraform checks, SRE review, window
selection, and independent rollback review all pass.

Export the current evidence-minimized handoff first:

```bash
uv run elcapitan promotion-manifest \
  --tenant TENANT --case CASE-... --db /path/to/product.db
```

Pass its `promotion_token` to `prepare-review --promotion-token`. The token is
derived from the exact case, confirmed finding set, target resource,
validation record, and validation evidence references. It is not a bearer
credential and grants no cloud access; it is a tamper/TOCTOU guard. A changed
or incomplete validation boundary is rejected before model dispatch or
Terraform work.

Do not give the shadow web service those repository, model, observer, or
execution credentials. That separation is an intentional product control, not
a temporary UI omission.
