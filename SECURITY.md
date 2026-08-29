# Security policy

## Supported version

Until a public `v0.1.0` release is approved, only the current `main` branch is
supported. After release, security fixes will target the latest published minor
line; older technical-preview builds may require upgrade.

## Reporting a vulnerability

Do not open a public issue with exploit details, credentials, customer data, or
private endpoints. Use GitHub's private vulnerability reporting for this
repository. Include the affected commit or artifact digest, reproduction steps,
impact, and any known mitigations. If private reporting is unavailable, open a
public issue containing no sensitive detail and request a private contact.

Maintainers should acknowledge a report within three business days, provide an
initial severity assessment within seven business days, and coordinate a fix
and disclosure timeline with the reporter. These are response targets, not a
service-level agreement.

## Security boundary

The supported default is self-hosted read-only shadow mode. Shadow mode has no
approval, scheduling, model, or cloud-mutation route. Review mode has no model
or cloud-mutation route. Approval records alone never create execution
authority. See [the threat model](docs/threat-model.md) and
[public-release blueprint](docs/public-release-v0.1.md).

Never submit real credentials, Terraform state, customer exports, private
deployment values, model traces, or personal data in an issue or pull request.
