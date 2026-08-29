# Changelog

All notable changes to El Capitan are recorded here. Dates use ISO 8601.

## [Unreleased]

### Added

- Release governance, CI security gates, and guarded artifact provenance.

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
