# Support policy

El Capitan is a technical preview, not a managed service. There is no uptime,
response-time, or remediation-success SLA.

Use GitHub issues for reproducible bugs, documentation defects, and bounded
feature proposals that contain no secrets or customer data. Use the private
path in [SECURITY.md](SECURITY.md) for vulnerabilities. Operational incidents
in a customer environment remain the operator's responsibility; disconnect
identities and stop the service before sharing sanitized diagnostics.

Support covers the latest published minor release on Python 3.12 and the
versioned OCI image for `linux/amd64` and `linux/arm64`. Source builds from
unreleased commits, modified images, broad cloud roles, and unlisted controls
are best effort. `elcapitan capabilities` is the authority for validation,
planning, and execution coverage.
