# Historical-secret review — 2026-08-30

This is a sanitized, fail-closed review record for the `v0.1.0` release. It
contains no credential value, value hash, customer identifier, or cloud
response. It is not authorization to publish.

## Baseline inventory

The original `.gitleaksignore` contained 22 legacy fingerprints across 14
reachable commits and five removed paths:

- 21 `generic-api-key` detections;
- one `hashicorp-tf-password` detection;
- ten YAML occurrences, five Terraform-state occurrences, five backup-state
  occurrences, one Terraform source occurrence, and one Markdown occurrence;
- 17 distinct historical source lines.

Eleven Eiger fingerprints were resolved by the review and cleanup below. The
checked-in baseline now retains the other 11 unresolved fingerprints. No
referenced path remains tracked in the current tree.

## Authorized Eiger-only review

The owner authorized exact-line, read-only review of Eiger-named entries only.
The review used explicit path filtering, did not enumerate commit trees, did
not print values, and did not access or modify the separate Eiger repository or
any cloud resource.

The 11 Eiger fingerprints occurred across three commits and three removed
paths. They reduced to:

- two distinct Azure Storage account keys generated for the temporary Trap-2
  account, appearing four times directly and six times inside connection
  strings across an applied state and its identical destroy-time backup; and
- one detector false positive: a 12-character Container App secret-name
  identifier assigned to `password_secret_name`. The actual ACR password was
  a Terraform resource reference, not a source literal. Its legacy fingerprint
  was removed and a fail-closed Gitleaks rule now allows only that exact field
  shape at that exact retired source path.

These files belonged to El Capitan's retired Azure capability-probe environment,
which ran the public Eiger Docker image; they were not Eiger application
credentials. The recorded destroy commit left the Trap-2 Terraform state with
zero resources, and a later commit removed the retired environment.

The owner approved removing the two generated state paths from every reachable
Git ref, force-pushing the rewritten `main` and archive branches, rebuilding
the affected Dependabot branches from clean history, removing all 11 resolved
Eiger fingerprints, and rerunning complete-history scanning and CI. The
authorization explicitly excluded Anna and the other ten entries.

## Rewrite verification

`git-filter-repo --sensitive-data-removal` rewrote 119 of 211 locally fetched
commits and reported `0fb075fc9eab9d3b5ba2a32b1b181e3d20b4b121` as the first
changed commit. Eight pull-request head refs (`1` through `8`) were affected;
seven were open Dependabot updates and one was already closed. No tag was
affected and Git LFS was not in use.

The isolated rewritten mirror contained zero reachable objects at either
approved state path. An all-ref Gitleaks scan passed with the retained
11-entry baseline and the exact-field false-positive rule. The same scan with
no baseline reported exactly the 11 entries that remain unresolved. GitHub's
read-only pull-request refs and cached views require the separately documented
server-side cleanup step before public visibility.

Post-rewrite CI run `33358160306` passed the 549-test/package job,
complete-history branch scan, high/critical container scan, and PostgreSQL/UI
quickstart at sanitized commit `6ea9663`.

## Excluded Anna entry

One baseline entry names Anna. The owner explicitly denied source review. It
remains unresolved and cannot be removed from the baseline or waived. The
Anna owner must separately classify and disposition it without disclosing the
value to this project, then provide a sanitized durable attestation.

## Remaining baseline

The other ten fingerprints are outside the Eiger-only authorization and remain
unresolved. Together with the excluded Anna entry, they are the 11 entries
still present in `.gitleaksignore`. Ten lines in the original overall baseline
contain an explicit synthetic marker, but marker text alone is insufficient
proof that every associated value was non-sensitive.

## Required completion evidence

Historical-secret response is complete only after all 22 original fingerprints
have a sanitized disposition, every potential credential is rotated or proven
destroyed, the baseline is reduced to zero, and a complete-history scan passes
without an ignore file. The Eiger rewrite is approved and completed; no rewrite
or source review is authorized for Anna or the other ten entries.
