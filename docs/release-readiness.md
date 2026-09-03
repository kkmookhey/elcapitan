# v0.1.0 release readiness

This is the fail-closed release record. `implemented` means the mechanism exists;
`verified` requires recorded run evidence; `blocked` means the release must not
be tagged or published.

## Local gates

| Gate | Status | Evidence or next proof |
|---|---|---|
| Full Python suite | verified | 725 tests passed at the AWS S3 evidence-to-review checkpoint; 538 passed independently in the clean-clone release rehearsal at `44dd79e` |
| Wheel and source distribution | verified | The post-E2E slice and clean-clone rehearsal both built wheel and source distributions successfully; rehearsal artifacts were inspected and checksummed at `44dd79e` |
| Syntax/static checks | verified | Clean-clone compile and narrow Ruff error checks passed at `44dd79e`; repository-wide Ruff formatting remains migration debt |
| Dependency review | implemented | GitHub dependency review rejects moderate-or-higher vulnerabilities on pull requests |
| Secret scanning | verified | CI prevents new leaks. All 22 historical fingerprints have sanitized dispositions, `.gitleaksignore` is empty, and a fresh redacted all-ref scan passed on 2026-09-03 under three exact-field false-positive rules. GitHub Support confirmed affected PR cleanup that day; independent checks found zero pull requests, zero advertised pull refs, and no access to the first rewritten commit |
| Container scan | verified | Public-setup CI surfaced fixed-high `CVE-2026-84304` in Terraform 1.16.0's embedded gRPC-Go. Runtime, CI, and release pins now use upstream Terraform 1.16.1, whose official source embeds patched gRPC-Go 1.83.1; a rebuilt Linux arm64 image passed fresh Trivy 0.70.0 high/critical scanning locally |
| Reproducible container inputs | verified | Python, Go, Terraform source, and PostgreSQL inputs are digest/checksum pinned; runtime Python dependencies are version/hash locked and CI checks export drift |
| Governance policies | implemented | Security, contributing, conduct, support, versioning, and changelog files exist |
| Threat model | implemented | `docs/threat-model.md` covers the required trust and failure boundaries |
| Lifecycle operations | implemented | `docs/operations.md` covers upgrade, backup, restore, retention, deletion, and uninstall |
| Capability/evidence matrix | verified | Registry generates checked-in JSON/Markdown; CI rejects drift; CLI reports the same 72-control contract |
| Docker Compose quickstart | verified | The dated verification reached the authenticated synthetic PostgreSQL result plus UI/cookie/write-boundary assertions in 10 seconds; independent new-host evidence remains |
| UI release labels | verified | Fleet API/browser separate synthetic/real input, live outcomes, validation/planning/execution, and evidence grade; semantic accessibility checks pass; [manual Chromium acceptance](manual-browser-acceptance-2026-08-30.md) verified the rendered fleet, review, lifecycle, dialog, and focus states after correcting the defects it exposed |
| Local RC rehearsal | verified | [Dated evidence](release-rehearsal-2026-08-28.md) records the clean-clone suite/build, secret prevention scan, PostgreSQL quickstart, checksums, 370-component CycloneDX SBOM, OCI digest, and provenance at `44dd79e` |
| Authorized Azure hosted E2E | verified | [Dated evidence](azure-e2e-2026-08-29.md) records fresh PostgreSQL isolation, authenticated intake, managed-identity validation, scanner mutation denial, both Storage success/rollback lifecycles, restoration, and cleanup at candidate source `57cfcb5` |

## External authorization gates

| Gate | Status | Required authority/evidence |
|---|---|---|
| License selection | verified | Transilience, Inc. approved Apache-2.0; the canonical license, package metadata, notice, and [dated owner record](owner-decisions-2026-08-30.md) are checked in |
| Project-name approval | verified | Transilience, Inc. approved retaining El Capitan after the collision risk was surfaced; the [dated record](owner-decisions-2026-08-30.md) is a business decision, not a trademark opinion |
| Historical secret response | verified | The [sanitized review](historical-secret-review-2026-08-30.md) records all 22 dispositions, completed Eiger credential cleanup, three narrowly constrained false-positive rules, an empty baseline, and a zero-finding isolated all-ref scan |
| Protected release environment | verified | The repository is public. The `release` environment requires reviewer `kkmookhey`, has self-review prevention disabled as approved, and has no branch-policy restriction; this setup does not authorize a tag or workflow run |
| Remote CI | verified | Post-rewrite [run 33358160306](https://github.com/kkmookhey/elcapitan/actions/runs/33358160306) passed the 549-test/package job, complete-history secret scan, high/critical container scan, and expanded PostgreSQL/UI quickstart at `6ea9663` |
| OCI/distribution publication | blocked | Run guarded release workflow only after all release gates pass |
| Customer shadow pilot | blocked | Requires an authorized non-production boundary, customer agreement, identities, data handling, and read-only access |
| Public launch materials | blocked | Architecture/trust-boundary README, article drafts, release notes, and capture runbook exist; manual browser acceptance passed, while sanitized viewport-only launch screenshots, authorized live-lab recording, consent, and publication remain external gates |

The release workflow is manual-only. It runs only on a tag, requires the exact
`RELEASE APPROVED` input and the SHA-256 of the committed
`RELEASE_APPROVAL.json`, uses the protected `release` environment, and then
rechecks the license, changelog date, tag/version match, tests, distribution,
checksums, SBOM, provenance, and signed attestations before pushing the
multi-architecture GHCR image. Its existence is not release approval.

Copy `docs/release-approval-record.example.json` to `RELEASE_APPROVAL.json`
only after every named owner has made the recorded decision. Replace every
placeholder, commit the completed record before creating the tag, and calculate
the workflow input from that exact checkout:

```console
sha256sum RELEASE_APPROVAL.json
uv run python scripts/check_release_tree.py --release --tag v0.1.0 \
  --approval-sha256 <64-character digest>
```

The final check rejects a mismatched digest, pending or missing decisions, a
license mismatch, any remaining historical-secret baseline, an incomplete
credential response, or a `release` environment without required reviewers.
Do not commit the example as if it were an approval or infer owner decisions
from technical test results.

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
container scan result, the committed `RELEASE_APPROVAL.json` and its SHA-256,
secret audit adjudication, license/name approvals, threat model review, and
dated changelog/release notes. Verification instructions must use immutable
digests and `gh attestation verify`.

The current cloud-free UI/runtime evidence is recorded in
[`release-verification-2026-08-29.md`](release-verification-2026-08-29.md).
