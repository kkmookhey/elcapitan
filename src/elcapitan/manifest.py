"""The immutable input manifest.

Hashing concatenated file bytes is ambiguous — no filenames, no length
boundaries, so distinct file sets can collide. It also omitted real inputs:
the prompt, repository commit, runtime image, dependency lock, profile config
and environment adapter all change the experiment.
"""
from pathlib import Path

from .hashing import sha256_file, sha256_record
from .paths import safe_resolve

def build_manifest(run_dir, *, files: list[str], repository_commit: str,
                   runtime_image_id: str, runtime_lock_sha256: str,
                   profile_config_sha256: str,
                   environment_adapter_sha256: str) -> dict:
    run_dir = Path(run_dir)
    entries = []
    for rel in sorted(files):
        # Containment lives here, not in the caller. Today's harness passes
        # literals, but the Global Constraint ("resolve, prove
        # is_relative_to(run_dir), reject symlinks") is an invariant of the
        # manifest, and a future caller must not be able to hash a file from
        # outside the run directory into a bundle that never carries it.
        path = safe_resolve(run_dir, rel)
        entries.append({"path": rel,
                        "size": path.stat().st_size,
                        "sha256": sha256_file(path)})
    return {
        "files": entries,
        "repository_commit": repository_commit,
        "runtime_image_id": runtime_image_id,
        "runtime_lock_sha256": runtime_lock_sha256,
        "profile_config_sha256": profile_config_sha256,
        "environment_adapter_sha256": environment_adapter_sha256,
    }

def bundle_hash(manifest: dict) -> str:
    return sha256_record(manifest)
