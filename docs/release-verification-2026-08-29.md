# v0.1 UI and release-gate verification — 2026-08-29

This record covers the local, cloud-free acceptance slice based on commit
`3bb4fd63577707eacb4459b6e5ecfba0ed3edeb7` and the changes committed with
this document. It is evidence for review, not authorization to tag or publish.

## Results

| Check | Result |
|---|---|
| Python suite | 542 passed in 29.57 seconds under the locked Python 3.12 environment |
| PostgreSQL quickstart | Passed in 10 seconds with synthetic input and no cloud/model credentials |
| Authenticated UI contract | Login, hardened session cookie, fleet HTML/JS/CSS, intake, capability labels, and read-only boundary passed |
| Write-boundary checks | Cross-origin intake returned 403; the shadow execution route returned 404 |
| Accessibility contract | Dialog names/descriptions, table caption/column scopes, polite status announcements, explicit button types, visible keyboard focus, and reduced-motion behavior are checked in tests |
| Runtime identity | OCI process ran as UID 10001 |
| Terraform path | Pinned Terraform 1.16.0 completed the synthetic verified-review path |
| Container scan | Trivy 0.70.0 reported zero fixed high/critical findings in the local Linux arm64 public runtime image |
| Complete-history prevention scan | Gitleaks 8.30.1 scanned 181 commits and reported zero current-rule findings even with an empty ignore directory |
| Release invariants | Release-tree, generated capability matrix, locked dependency export, compile, narrow Ruff, Docker build check, workflow YAML parsing, and immutable action-reference checks passed |

The prior runtime failed the container gate because its Debian/OpenSSL packages
and Terraform Go binary had fixed high/critical vulnerabilities. The revised
image uses a refreshed digest-pinned Python base and rebuilds the exact
Terraform 1.16.0 source commit with digest-pinned Go 1.26.6. Docker verifies the
source archive checksum before the build. No vulnerability waiver was added.
Every workflow action is commit-pinned, and the manual release job now repeats
the high/critical runtime scan before registry login and publication.

The complete-history result does not adjudicate the 22 legacy fingerprints in
`.gitleaksignore`. A newer detector no longer reproducing an old match is not
proof that the historical value was harmless or revoked. Security-owner review,
rotation where necessary, and an explicit history decision remain release
gates. No historical secret value was printed or copied during this run.

## Remaining visual and external proof

No in-app browser surface was connected, so rendered keyboard navigation,
responsive layout, dialog interaction, and sanitized screenshots remain
unverified. The browser artifacts must not be fabricated or substituted with
HTTP assertions. Remote GitHub CI/container evidence is also required for the
committed slice.

The repository is private on a GitHub plan that returned HTTP 403 for protected
environments and repository rulesets. The guarded release workflow must retain
its `release` environment requirement; an owner must enable that protection by
upgrading the plan or, only when separately authorized for publication, making
the repository public and configuring required reviewers.

No Azure/AWS/GCP call, model call, customer-data access, release tag, package
publication, repository-visibility change, or Eiger operation occurred.
