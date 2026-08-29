# v0.1.0 release readiness

This is the fail-closed release record. `implemented` means the mechanism exists;
`verified` requires recorded run evidence; `blocked` means the release must not
be tagged or published.

## Local gates

| Gate | Status | Evidence or next proof |
|---|---|---|
| Full Python suite | verified | 542 tests passed in the dated UI/release-gate verification; 538 passed independently in the clean-clone rehearsal at `44dd79e` |
| Wheel and source distribution | verified | The post-E2E slice and clean-clone rehearsal both built wheel and source distributions successfully; rehearsal artifacts were inspected and checksummed at `44dd79e` |
| Syntax/static checks | verified | Clean-clone compile and narrow Ruff error checks passed at `44dd79e`; repository-wide Ruff formatting remains migration debt |
| Dependency review | implemented | GitHub dependency review rejects moderate-or-higher vulnerabilities on pull requests |
| Secret scanning | blocked | CI prevents new leaks. Gitleaks 8.30.1 found zero current-rule matches across 181 commits without the baseline, but 22 legacy fingerprints remain pending credential adjudication, rotation where necessary, and an explicit history decision |
| Container scan | verified | The dated verification rebuilt Terraform 1.16.0 with patched Go; Trivy found zero fixed high/critical findings locally on Linux arm64 and remotely on Linux amd64 in [CI run 33270941312](https://github.com/kkmookhey/elcapitan/actions/runs/33270941312) |
| Reproducible container inputs | verified | Python, Go, Terraform source, and PostgreSQL inputs are digest/checksum pinned; runtime Python dependencies are version/hash locked and CI checks export drift |
| Governance policies | implemented | Security, contributing, conduct, support, versioning, and changelog files exist |
| Threat model | implemented | `docs/threat-model.md` covers the required trust and failure boundaries |
| Lifecycle operations | implemented | `docs/operations.md` covers upgrade, backup, restore, retention, deletion, and uninstall |
| Capability/evidence matrix | verified | Registry generates checked-in JSON/Markdown; CI rejects drift; CLI reports the same 36-control contract |
| Docker Compose quickstart | verified | The dated verification reached the authenticated synthetic PostgreSQL result plus UI/cookie/write-boundary assertions in 10 seconds; independent new-host evidence remains |
| UI release labels | verified at HTTP/contract level | Fleet API/browser separate synthetic/real input, live outcomes, validation/planning/execution, and evidence grade; semantic accessibility checks pass, while rendered browser acceptance and screenshots remain pending |
| Local RC rehearsal | verified | [Dated evidence](release-rehearsal-2026-08-28.md) records the clean-clone suite/build, secret prevention scan, PostgreSQL quickstart, checksums, 370-component CycloneDX SBOM, OCI digest, and provenance at `44dd79e` |
| Authorized Azure hosted E2E | verified | [Dated evidence](azure-e2e-2026-08-29.md) records fresh PostgreSQL isolation, authenticated intake, managed-identity validation, scanner mutation denial, both Storage success/rollback lifecycles, restoration, and cleanup at candidate source `57cfcb5` |

## External authorization gates

| Gate | Status | Required authority/evidence |
|---|---|---|
| License selection | blocked | Legal/business owner selects and approves `LICENSE`; none is inferred by this repository |
| Project-name approval | blocked | Business/legal owner records approval for the El Capitan name |
| Historical secret response | blocked | Authorized owner adjudicates the 22 fingerprints, rotates any live material, and approves history rewrite if required |
| Protected release environment | blocked | GitHub returned HTTP 403 because protected environments/rulesets are unavailable for this private repository on its current plan; an owner must upgrade or separately authorize public visibility, then configure `release` reviewers |
| Remote CI | verified | [Run 33270941312](https://github.com/kkmookhey/elcapitan/actions/runs/33270941312) passed test/package, complete-history secret scan, high/critical container scan, and the expanded PostgreSQL/UI quickstart at `0cfbaf3` |
| OCI/distribution publication | blocked | Run guarded release workflow only after all release gates pass |
| Customer shadow pilot | blocked | Requires an authorized non-production boundary, customer agreement, identities, data handling, and read-only access |
| Public launch materials | blocked | Architecture/trust-boundary README, article drafts, release notes, and capture runbook exist; real screenshots, authorized live-lab recording, consent, and publication remain external gates |

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

The current cloud-free UI/runtime evidence is recorded in
[`release-verification-2026-08-29.md`](release-verification-2026-08-29.md).
