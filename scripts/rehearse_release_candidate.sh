#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/elcapitan-rc.XXXXXX")
checkout="$temporary/checkout"
cache="${UV_CACHE_DIR:-$(uv cache dir)}"
commit=$(git -C "$repository" rev-parse HEAD)
short=$(printf '%s' "$commit" | cut -c1-12)
evidence="$repository/release/rehearsal-$short"
image="elcapitan:rc-$short"
started=$(date +%s)

cleanup() {
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$evidence"
git clone --quiet --local --no-hardlinks "$repository" "$checkout"
test -z "$(git -C "$checkout" status --porcelain)"

{
  printf 'commit: %s\n' "$commit"
  git --version
  uv --version
  python3 --version
  docker version --format 'docker client: {{.Client.Version}}; server: {{.Server.Version}}'
  docker buildx version
  docker sbom version
  gitleaks version
} >"$evidence/tool-versions.txt"

clean_env() {
  env -i \
    PATH="$PATH" \
    UV_CACHE_DIR="$cache" \
    UV_NO_CONFIG=1 \
    UV_OFFLINE=1 \
    "$@"
}

if ! (
  cd "$checkout"
  clean_env uv sync --locked --dev
  clean_env uv run python scripts/check_release_tree.py
  clean_env uv run python scripts/generate_capability_matrix.py --check
  clean_env uv run python -m compileall -q src tests scripts
  clean_env uv run ruff check --select E9,F63,F7,F82 src tests scripts
  clean_env uv run pytest -q
) >"$evidence/python-verification.log" 2>&1; then
  cat "$evidence/python-verification.log"
  exit 1
fi
cat "$evidence/python-verification.log"

if ! (
  cd "$checkout"
  clean_env uv build --out-dir dist
  clean_env uv run python scripts/check_distributions.py dist
  cd dist
  shasum -a 256 elcapitan-*.whl elcapitan-*.tar.gz >"$evidence/SHA256SUMS"
) >"$evidence/distribution-build.log" 2>&1; then
  cat "$evidence/distribution-build.log"
  exit 1
fi
cat "$evidence/distribution-build.log"

if ! (
  cd "$checkout"
  gitleaks detect --source . --no-banner --redact
  ./scripts/accept_quickstart.sh
) >"$evidence/security-and-quickstart.log" 2>&1; then
  cat "$evidence/security-and-quickstart.log"
  exit 1
fi
cat "$evidence/security-and-quickstart.log"

if ! (
  cd "$checkout"
  docker buildx build \
    --load \
    --network=none \
    --provenance=mode=max \
    --metadata-file "$evidence/oci-build-metadata.json" \
    --tag "$image" \
    .
  docker sbom --quiet --format cyclonedx-json \
    --output "$evidence/container-sbom.cdx.json" "$image"
) >"$evidence/container-build.log" 2>&1; then
  cat "$evidence/container-build.log"
  exit 1
fi
cat "$evidence/container-build.log"

clean_env python3 - "$evidence" "$commit" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
commit = sys.argv[2]
sbom = json.loads((root / "container-sbom.cdx.json").read_text())
metadata = json.loads((root / "oci-build-metadata.json").read_text())
if not str(sbom.get("bomFormat", "")).lower() == "cyclonedx":
    raise SystemExit("container SBOM is not CycloneDX")
if not metadata.get("containerimage.digest", "").startswith("sha256:"):
    raise SystemExit("OCI build metadata has no image digest")
provenance = metadata.get("buildx.build.provenance")
if not provenance:
    raise SystemExit("OCI build metadata has no provenance statement")
summary = {
    "commit": commit,
    "container_digest": metadata["containerimage.digest"],
    "cyclonedx_components": len(sbom.get("components", [])),
    "provenance_present": True,
}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY

elapsed_note="release candidate rehearsal passed for $commit"
elapsed=$(($(date +%s) - started))
printf '%s\n' "$elapsed_note"
printf 'elapsed: %ss\n' "$elapsed"
printf 'evidence: %s\n' "$evidence"
