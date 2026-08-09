"""The immutable input manifest.

Hashing concatenated file bytes is ambiguous — no filenames, no length
boundaries, so distinct file sets can collide. It also omitted real inputs:
the prompt, repository commit, runtime image, dependency lock, profile config
and environment adapter all change the experiment.
"""
from pathlib import Path

from .hashing import sha256_file, sha256_record

def build_manifest(run_dir, *, files: list[str], repository_commit: str,
                   runtime_image_id: str, runtime_lock_sha256: str,
                   profile_config_sha256: str,
                   environment_adapter_sha256: str) -> dict:
    run_dir = Path(run_dir)
    entries = [
        {"path": rel,
         "size": (run_dir / rel).stat().st_size,
         "sha256": sha256_file(run_dir / rel)}
        for rel in sorted(files)
    ]
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
