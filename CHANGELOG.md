# Changelog

All notable changes to El Capitan are recorded here. Dates use ISO 8601.

## [Unreleased]

### Added

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
