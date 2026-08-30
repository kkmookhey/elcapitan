# Historical-secret review — 2026-08-30

This is a sanitized, fail-closed review record for the `v0.1.0` release. It
contains no credential value, value hash, source path, customer identifier, or
cloud response. It is not authorization to publish or rewrite history.

## Baseline inventory

The checked-in `.gitleaksignore` contains 22 legacy fingerprints across 14
reachable commits and five removed paths:

- 21 `generic-api-key` detections;
- one `hashicorp-tf-password` detection;
- ten YAML occurrences, five Terraform-state occurrences, five backup-state
  occurrences, one Terraform source occurrence, and one Markdown occurrence;
- 17 distinct historical source lines.

No referenced path remains tracked in the current tree. That does not make a
historical credential safe because Git history remains downloadable.

## Authorized Eiger-only review

The owner authorized exact-line, read-only review of Eiger-named entries only.
The review used explicit path filtering, did not enumerate commit trees, did
not print values, and did not access or modify the separate Eiger repository or
any cloud resource.

The 11 Eiger fingerprints occur across three commits and three removed paths.
They reduce to the following potential credential material:

- two distinct probable Azure Storage account keys for one account, appearing
  four times directly and six times inside connection strings; and
- one VM or administrative password embedded in Terraform source.

None of those lines contains an explicit synthetic or placeholder marker. The
storage keys and password must therefore be treated as compromised. Before
release, the Eiger owner must either rotate the credentials or prove that the
corresponding resources were destroyed, then provide a sanitized durable
attestation. El Capitan will not test the values or mutate Eiger resources.

## Excluded Anna entry

One baseline entry names Anna. The owner explicitly denied source review. It
remains unresolved and cannot be removed from the baseline or waived. The
Anna owner must separately classify and disposition it without disclosing the
value to this project, then provide a sanitized durable attestation.

## Remaining baseline

The other ten fingerprints are outside the Eiger-only authorization and remain
unresolved. Ten lines in the overall baseline contain an explicit synthetic
marker, but marker text alone is insufficient proof that every associated
value was non-sensitive.

## Required completion evidence

Historical-secret response is complete only after all 22 fingerprints have a
sanitized disposition, every potential credential is rotated or proven
destroyed, the owner explicitly chooses whether history rewrite is required,
the baseline is reduced to zero, and a complete-history scan passes without an
ignore file. History rewrite is destructive and requires separate explicit
approval after credential response is complete.
