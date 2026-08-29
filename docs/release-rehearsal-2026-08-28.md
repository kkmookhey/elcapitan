# v0.1.0 local release-candidate rehearsal — 2026-08-28

The clean-clone rehearsal passed for commit
`44dd79e84d621ad2ea7a873dc6b33eef2d58de60` on an Apple Silicon macOS host.
This is local candidate evidence, not authorization to tag or publish a
release.

## Results

| Check | Result |
|---|---|
| Release-tree, generated-matrix, compile, and narrow Ruff checks | passed |
| Python suite | 538 passed in 30.83 seconds under CPython 3.12.13 |
| Wheel | `e62a8db0317206133ca792a345cc551de4bc2592224a98839b60247051686e63` |
| Source distribution | `0293f00bb8e5db93de074d1d7fbf399593268290c0fe15836e41e535f488974e` |
| Distribution inspection | passed for wheel and source distribution |
| Complete-history Gitleaks prevention scan | passed with the checked-in historical baseline |
| PostgreSQL quickstart | authenticated synthetic acceptance passed in 14 seconds |
| OCI image digest | `sha256:c764072191bbd5b1080ac7c3aa5e76e6c4c2efa40e9da59a6ecf46061c2011fc` |
| CycloneDX container SBOM | valid, 370 components |
| BuildKit provenance | present in local OCI build metadata |
| Total rehearsal time | 52 seconds |

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
