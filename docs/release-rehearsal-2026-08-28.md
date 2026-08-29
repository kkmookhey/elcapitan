# v0.1.0 local release-candidate rehearsal — 2026-08-28

The clean-clone rehearsal passed for commit
`4fb9dbd72e8f733286873fe879dcb82176b586ee` on an Apple Silicon macOS host.
This is local candidate evidence, not authorization to tag or publish a
release.

## Results

| Check | Result |
|---|---|
| Release-tree, generated-matrix, compile, and narrow Ruff checks | passed |
| Python suite | 538 passed in 33.34 seconds under CPython 3.12.13 |
| Wheel | `bd9a97aab523f69892347cb939f7bf2029e1b55ba9df0f3f9040ab58e8f1caee` |
| Source distribution | `0f64a14af25e8d6c31226511a05977b0ee6b9851e0b2ff7717969a63b66b2abb` |
| Distribution inspection | passed for wheel and source distribution |
| Complete-history Gitleaks prevention scan | passed with the checked-in historical baseline |
| PostgreSQL quickstart | authenticated synthetic acceptance passed in 10 seconds |
| OCI image digest | `sha256:25ddcf4ff8ec70fde52b9e36ab6fefb6e7f76f0f5eb7524d6d32244e32661ae2` |
| CycloneDX container SBOM | valid, 370 components |
| BuildKit provenance | present in local OCI build metadata |
| Total rehearsal time | 51 seconds |

The Gitleaks result does not adjudicate the 22 historical fingerprints in
`.gitleaksignore`. Credential ownership review, rotation where necessary, and
approved history cleaning remain mandatory before a public release.

## Boundary

The script cloned the candidate locally, required a clean checkout, cleared the
application environment, and ran Python dependency resolution from the local
offline `uv` cache. It used only the checked-in synthetic fixture and local
PostgreSQL. It used no cloud-provider credentials or APIs, no model runtime,
and no customer data. Docker base images and runtime dependencies are
digest/hash pinned; Docker may consult their public registries when a local
build cache is not populated.

The evidence-producing tools were Git 2.50.1, uv 0.11.14, Docker client/server
29.4.3, Buildx 0.33.0-desktop.1, docker-sbom 0.6.0 with Syft 0.43.0, and
Gitleaks 8.30.1.

## Reproduction and retained evidence

Run:

```bash
./scripts/rehearse_release_candidate.sh
```

The command fails closed per stage and writes detailed logs, checksums, SBOM,
OCI metadata, tool versions, and a machine-readable summary beneath the ignored
`release/rehearsal-<commit>/` directory. Those host-local files are not public
attestations. The guarded release workflow must regenerate and attest artifacts
for the approved tag after every external release gate is satisfied.
