# Changelog

All notable changes to El Capitan are recorded here. Dates use ISO 8601.

## [Unreleased]

### Added

- Evidence-minimized Layer 2 promotion for mixed resource cases. A promotion
  now binds only findings that are both live-confirmed and deterministically
  planning-capable, records every excluded sibling, and passes that exact
  finding scope into remediation planning. The Azure trial now exposes six
  preparation candidates; no plan or review package is claimed until
  authoritative IaC, service context, telemetry, and human routes are supplied.
- Lifecycle count language that distinguishes 21 validated resource cases
  from 23 checked cases and 93 confirmed findings from 95 supported findings.
- Owner-authorized Azure test validation through a temporary, isolated
  Reader-scoped scanner identity: 23 resource cases checked, 93 of 95
  supported findings confirmed, and two kind-mismatched OpenAI findings kept
  unavailable. The live pass also added canonical File Service child-to-parent
  collection and explicit absent-policy semantics for container soft delete,
  without adding any shadow approval or mutation route.
- Screenshot-led readability improvements across the lifecycle, queue,
  connector panel, and case-evidence drawer, with unrun validation shown as
  “Not run” and completed validation counted by resource case.
- Evidence-to-outcome shadow workspace that exposes scanner source and input
  format, normalized resource cases, validation state, transparent priority,
  and current outcome, followed by a visibly separate and locked remediation
  lifecycle from plan preparation through monitoring. Fleet summaries include
  source, format, priority, outcome, and downstream capability counts without
  adding approval, scheduling, or execution authority to shadow mode.
- Exact-resource asset-context manifests for shadow intake, including no-write
  match/gap preview, per-resource deterministic priority signals, immutable row
  digests and provenance, explicit synthetic business labels, and customer
  result views for owner, environment, criticality, and observed exposure.
  Resource drill-downs identify the score-driving observation and show every
  grouped finding's independent score instead of implying that scores add.
- Guided Shadow Trial onboarding with safe-sample and scanner-export entry
  paths, a fail-closed no-write intake preview, and plain-language validation
  outcomes that retain the existing read-only evidence boundary. Supported
  controls are distinguished from connector-ready checks, grouped scanner
  observations identify their resource count, and unavailable batch actions
  remain disabled.
- Two validation-only AWS EBS volume controls for encryption and owned-snapshot
  presence, using exact-resource `DescribeVolumes` and bounded
  `DescribeSnapshots` reads.
- Twenty validation-only AWS EC2 security-group controls for public port and
  CIDR exposure, default and Launch Wizard groups, and excessive rule counts,
  using exact-group and bounded attachment reads.
- Eight validation-only AWS RDS DB-instance controls for backups, snapshot tag
  copying, enhanced monitoring, IAM database authentication, VPC placement,
  CloudWatch Logs exports, automatic minor upgrades, and storage encryption,
  using one exact-ARN `DescribeDBInstances` read.
- Six validation-only AWS S3 controls for KMS encryption, server access
  logging, event notifications, lifecycle configuration, Object Lock, and MFA
  Delete, using the existing bounded bucket-state collector.
- Release governance, CI security gates, and guarded artifact provenance.
- Registry-generated capability/evidence matrix and explicit browser labels for
  source type, live outcome, validation, planning, execution, and evidence grade.
- Local-only Docker Compose quickstart with PostgreSQL and a timed synthetic
  acceptance journey that receives no cloud or model credentials.
- Clean-checkout release-candidate rehearsal with distribution checksums,
  CycloneDX container SBOM, and BuildKit provenance inspection.

## [0.1.0] - Unreleased

### Added

- Evidence-bound intake for Prowler OCSF and AWS Security Hub ASFF exports.
- Explicit AWS and Azure deterministic live-validation capability registry.
- Separate read-only shadow and human-review services.
- Typed immutable evidence, package-bound approval, durable scheduling, bounded
  action connectors, deterministic verification, and rollback evidence.
- Synthetic local lifecycle and cloud-free contract-test fixtures.

### Security

- Shadow mode contains no approval, scheduling, model, or mutation route.
- Missing, stale, malformed, unauthorized, and unsupported evidence fails
  closed.

### Known limitations

- This is not an autonomous remediation service or a multi-tenant hosted SaaS.
- Most registered controls validate only; consult `elcapitan capabilities` for
  separate planning and execution flags.
- Public release remains blocked on the gates in
  `docs/release-readiness.md`, including license/name approval and Git-history
  remediation.

[Unreleased]: https://github.com/kkmookhey/elcapitan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kkmookhey/elcapitan/releases/tag/v0.1.0
