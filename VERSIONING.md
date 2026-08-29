# Versioning policy

El Capitan uses semantic versioning after `v0.1.0`. While the major version is
zero, a minor release may change technical-preview interfaces; patch releases
contain compatible fixes and documentation corrections.

The CLI's typed JSON records and schemas are the stable integration surface.
Breaking schema or command behavior requires a minor-version increment,
migration notes, and an explicit changelog entry. Capability additions may be
minor releases; corrections that only make an existing control fail closed may
be patches when they preserve the declared contract.

Git tags, Python package versions, OCI tags, changelog headings, and release
notes must use the same `X.Y.Z` value. Images and attestations are additionally
identified by immutable digest. No mutable `latest` tag is part of the v0.1
contract.
