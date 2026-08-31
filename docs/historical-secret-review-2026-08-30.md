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

Eleven Eiger fingerprints were resolved by the review and cleanup below. A
later owner-authorized review classified the ten Azure deployment-template
fingerprints as detector false positives. A final owner-authorized exact-line
review classified the Anna fingerprint as a detector false positive. The
checked-in baseline is now empty.

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

## Authorized Azure deployment-template review — 2026-08-31

The owner subsequently authorized read-only, complete-history review of the
remaining Eiger and El Capitan test-Azure material, followed by cleanup after a
sanitized occurrence list was approved. The authorization did not include the
Anna entry, cloud access, secret disclosure, or modification of the separate
Eiger repository.

The ten remaining non-Anna fingerprints were `generic-api-key` detections on
ten historical revisions of the `image` field in
`deploy/azure/shadow-app.yaml`. Each value was a syntactically valid ACR image
reference to the El Capitan demo repository with one of ten dated shadow-build
tags. The field contained a registry host, repository, and tag only. Registry
authentication was configured separately through a managed identity, and the
manifest's two application credentials were secret references without values.
The image references therefore contained no key, password, token, connection
string, or credential material and required no rotation or history rewrite.

The ten fingerprints were removed from `.gitleaksignore`. A fail-closed rule
allows only the exact manifest path, exact `image` field, credential-free ACR
reference shape, exact demo repository, exact build date, and the ten reviewed
tag suffixes. It does not allow another field, repository, date, tag, URL
userinfo, or future detection. An isolated all-ref scan without an ignore file
then reported only the excluded Anna entry.

The same review found no named private-customer identifier, domain, tenant,
subscription, resource identifier, export file, or finding payload in the
current tree, reachable paths, commit messages, or reachable blob history.
Every Azure subscription identifier and service host in reachable history
mapped to the documented El Capitan/Eiger lab or a synthetic contract fixture.
Only the previously documented aggregate coverage count derived from the
private export remains; it contains no customer-specific identifier or finding
data.

## Authorized Anna exact-line review — 2026-08-31

The owner explicitly authorized exact-line, read-only review of the remaining
Anna fingerprint. The `generic-api-key` rule matched a Markdown observation
table row labeled `Session`: after the ordinary phrase `API calls`, the row
recorded a backticked model-response termination-status pair. The captured text
was run metadata, not an API key, session credential, token, password, customer
value, or cloud response.

The fingerprint was removed from `.gitleaksignore`. A fail-closed rule allows
only the exact retired path and the detector's exact matched phrase containing
the termination status. Negative tests reject another field, status, count
prefix, assignment, or free-form line.

## Remaining baseline

`.gitleaksignore` contains zero fingerprints. An isolated all-ref scan without
an ignore file reports zero findings under the three exact-field
false-positive rules.

## Required completion evidence

Historical-secret response is complete only after all 22 original fingerprints
have a sanitized disposition, every potential credential is rotated or proven
destroyed, the baseline is reduced to zero, and a complete-history scan passes
without an ignore file. All 22 fingerprints now have sanitized dispositions,
the two generated credentials belonged to a destroyed test resource and were
purged through the completed Eiger rewrite, the baseline is zero, and the
complete-history scan passes without an ignore file. GitHub Support ticket
`#4715479` was opened on 2026-08-31 to remove the retained refs and cached views
for pull requests `#1` through `#8`. The ticket remains open, and the repository
must remain private until GitHub confirms that server-side cleanup.
