# v0.1.0 release readiness

This is the fail-closed release record. `implemented` means the mechanism exists;
`verified` requires recorded run evidence; `blocked` means the release must not
be tagged or published.

## Local gates

| Gate | Status | Evidence or next proof |
|---|---|---|
| Full Python suite | verified | 533 tests passed at commit `6bedd5f`; rerun for the final candidate |
| Wheel and source distribution | implemented | CI builds and `scripts/check_distributions.py` inspects contents and metadata |
| Syntax/static checks | implemented | CI compile check and narrow Ruff error rules; repository-wide Ruff formatting remains migration debt |
| Dependency review | implemented | GitHub dependency review rejects moderate-or-higher vulnerabilities on pull requests |
| Secret scanning | blocked | CI prevents new leaks, but 22 historical findings are baselined pending credential adjudication, rotation, and history cleaning |
| Container scan | implemented | CI builds the runtime image and Trivy rejects fixed high/critical vulnerabilities |
| Governance policies | implemented | Security, contributing, conduct, support, versioning, and changelog files exist |
| Threat model | implemented | `docs/threat-model.md` covers the required trust and failure boundaries |
| Lifecycle operations | implemented | `docs/operations.md` covers upgrade, backup, restore, retention, deletion, and uninstall |
| Capability/evidence matrix | verified | Registry generates checked-in JSON/Markdown; CI rejects drift; CLI reports the same 36-control contract |
| Docker Compose quickstart | pending | Add PostgreSQL quickstart and clean-machine acceptance test |
| UI release labels | implemented | Fleet API/browser separate synthetic/real input, live outcomes, validation/planning/execution, and evidence grade; clean-machine UI acceptance remains |
| Local RC rehearsal | pending | Run from a clean checkout with no cloud/model credentials |

## External authorization gates

| Gate | Status | Required authority/evidence |
|---|---|---|
| License selection | blocked | Legal/business owner selects and approves `LICENSE`; none is inferred by this repository |
| Project-name approval | blocked | Business/legal owner records approval for the El Capitan name |
| Historical secret response | blocked | Authorized owner adjudicates the 22 fingerprints, rotates any live material, and approves history rewrite if required |
| Protected release environment | pending | Repository owner configures `release` reviewers before enabling the workflow |
| OCI/distribution publication | blocked | Run guarded release workflow only after all release gates pass |
| Customer shadow pilot | blocked | Requires an authorized non-production boundary, customer agreement, identities, data handling, and read-only access |
| Public launch materials | blocked | Publication and consent are external writes and remain unapproved |

The release workflow is manual-only. It runs only on a tag, requires the exact
`RELEASE APPROVED` input, uses the protected `release` environment, and then
rechecks the license, changelog date, tag/version match, tests, distribution,
checksums, SBOM, provenance, and signed attestations before pushing the
multi-architecture GHCR image. Its existence is not release approval.

## Historical-secret response

The `.gitleaksignore` file is a prevention baseline, not an assertion that the
old matches are safe. Before public release, an authorized security owner must:

1. Review matches without copying secret values into tickets or logs.
2. Identify the owning environment and decide whether each value was a secret,
   private endpoint, customer identifier, or detector false positive.
3. Revoke or rotate every potentially live credential first.
4. Obtain explicit approval before rewriting shared Git history.
5. Remove resolved fingerprints from the baseline, clone afresh, and require a
   zero-finding complete-history scan.
6. Audit wheel, sdist, OCI filesystem/SBOM, fixtures, and launch material for
   customer names, credentials, private endpoints, and unsanitized identifiers.

## Release evidence bundle

The final evidence bundle must contain the commit and tag, exact tool versions,
test and clean-machine logs, generated capability matrix, wheel/sdist and image
digests, `SHA256SUMS`, CycloneDX SBOM, GitHub provenance/SBOM attestations,
container scan result, secret audit adjudication, license/name approvals, threat
model review, and dated changelog/release notes. Verification instructions must
use immutable digests and `gh attestation verify`.
