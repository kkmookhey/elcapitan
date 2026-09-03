# Public-release owner decisions — 2026-08-30

This record preserves explicit owner decisions for the `v0.1.0` release gate.
It is not the final publication authorization. GitHub confirmed the required
server-side cleanup on 2026-09-03, but the protected `release` environment and
the exact release approval remain separate gates, so `RELEASE_APPROVAL.json`
must not yet be created.

## License

- SPDX identifier: `Apache-2.0`
- Decision: approved
- Copyright holder: Transilience, Inc.
- Approved by: Transilience, Inc.
- Approved at: 2026-08-30
- Evidence reference: this committed decision record

The repository must include the unmodified Apache License 2.0 text, declare
`Apache-2.0` in package metadata, and retain the Transilience, Inc. notice.

## Project name

- Public name: El Capitan
- Decision: approved by the business owner
- Approved by: Transilience, Inc.
- Approved at: 2026-08-30
- Evidence reference: this committed decision record

The owner elected to retain El Capitan after being advised that a preliminary
public search found existing prominent software and computing uses, including
Apple's OS X El Capitan name. This records a business-owner decision, not a
legal opinion, trademark registration, or guarantee of non-infringement.

## Historical review boundary

The owner authorized read-only review of exact Eiger-named blobs referenced by
the El Capitan `.gitleaksignore`. Eiger is public. The authorization does not
extend to Anna-named blobs, commit-wide diffs, unrelated source, customer data,
cloud access, secret-value disclosure, or modification of the separate Eiger
repository.

No historical secret value may be printed or committed. An Anna-named baseline
entry remains owner-reviewed outside this process or unresolved; it cannot be
waived by the final release record.

After reviewing a redacted occurrence listing, the owner confirmed that the
Eiger-named files belonged to El Capitan's retired Azure capability probe, not
to the Eiger application. The owner approved purging the two Trap-2 Terraform
state paths from all Git history, force-pushing rewritten `main` and archive
branches, closing/deleting and recreating the seven affected Dependabot
branches, removing the 11 resolved Eiger fingerprints, correcting the durable
record, and rerunning scans and CI. Anna and the other ten fingerprints remain
explicitly excluded from that authorization.

## Subsequent test-Azure review decision — 2026-08-31

The owner confirmed that Eiger is a public vulnerable-by-design application and
that its Azure environment was an El Capitan test capability created during
prior Codex sessions. The owner authorized read-only, complete-history review
of the remaining Eiger and El Capitan test-Azure material, requested a
sanitized disposition list before changes, and approved the proposed cleanup
only if no named private-customer data was present. The authorization did
not include the Anna entry, cloud access, or modification of the separate Eiger
repository.

The review found no named private-customer identifier, domain, tenant,
subscription, resource identifier, export file, or finding payload in
the current tree or reachable history. All reachable Azure subscription and
service identifiers mapped to the documented El Capitan/Eiger lab or synthetic
contract fixtures. The owner then approved removing the ten ACR image-reference
fingerprints, adding a narrowly constrained exact-field false-positive rule,
updating the durable records, and verifying the result without another history
rewrite. The Anna fingerprint remains unresolved and cannot be waived.

## Anna exact-line review decision — 2026-08-31

The owner subsequently authorized exact-line, read-only review of the remaining
Anna fingerprint. The reviewed Markdown table row recorded model-run session
metadata. Gitleaks treated the ordinary phrase `API calls` as a key indicator
and captured a model-response termination-status pair. The captured text was
not a credential, customer value, or cloud response.

The owner authorized clearing the release blocks. The Anna fingerprint was
removed from the baseline under a rule constrained to the exact retired path
and exact detector match. The resulting empty-baseline, all-ref scan is
the required durable technical evidence; GitHub Support cleanup of retained PR
refs remains a separate publication prerequisite.

## Repository visibility and release reviewer decision — 2026-08-31

The owner authorized changing the repository's visibility to public after
GitHub confirms removal of the retained pull-request refs and cached views. The
repository must remain private while Support ticket `#4715479` is open.

After that confirmation and visibility change, the protected `release`
environment must require reviewer `kkmookhey`. Because that reviewer is also
the workflow initiator, self-review prevention must remain disabled unless a
different required reviewer is separately approved. This decision authorizes
the visibility and environment configuration steps; it does not authorize a
tag, release workflow run, package/image publication, or public launch.

## Conditional visibility authorization became actionable — 2026-09-03

GitHub Support confirmed deletion and cleanup under ticket `#4715479`, and
independent read-only checks found no pull requests, advertised pull-request
refs, or accessible copy of the first rewritten commit. The condition attached
to the 2026-08-31 visibility decision is therefore satisfied. The owner
confirmed that the remaining authorized repository-visibility and protected-
environment setup may proceed.

The authority remains limited to making this repository public and configuring
the `release` environment with required reviewer `kkmookhey` and self-review
prevention disabled. It still does not authorize creating a tag, running the
release workflow, publishing a package or image, or announcing a public launch.

## Authorized repository setup completed — 2026-09-03

After the pre-publication suite, distribution, release-tree, generated-matrix,
locked-dependency, static, and redacted complete-history secret gates passed,
the repository was changed to public. The `release` environment was then
created with required reviewer `kkmookhey`, self-review prevention disabled,
and no deployment branch-policy restriction. Read-only verification confirmed
those settings.

There was no tag, release workflow run, package or image publication, or launch
announcement. Those actions still require a separate exact final decision and
the committed digest-bound approval record.
