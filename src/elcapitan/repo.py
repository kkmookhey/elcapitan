"""Independent post-run repository diagnostics.

The read-only bind mount is the enforcement. This recomputes state from the
repository after the container exits and compares it with state captured
before — never with a value supplied by the caller.
"""
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

@dataclass(frozen=True)
class RepoState:
    commit: str
    dirty_files: list[str] = field(default_factory=list)

def _git(path, *args) -> str:
    result = subprocess.run(["git", "-C", str(path), *args],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout

def capture_repo_state(path) -> RepoState:
    path = Path(path)
    try:
        commit = _git(path, "rev-parse", "HEAD").strip()
    except ValueError as exc:
        raise ValueError(f"repository has no commits (unborn branch): {path}") from exc
    porcelain = _git(path, "status", "--porcelain", "--untracked-files=all")
    return RepoState(commit=commit,
                     dirty_files=sorted(porcelain.splitlines()))

def assert_unchanged(path, before: RepoState) -> list[str]:
    """Return failures. Empty list means the repository is untouched."""
    after = capture_repo_state(path)
    failures: list[str] = []

    if after.commit != before.commit:
        failures.append(
            f"canonical repository commit changed: {before.commit[:8]} -> {after.commit[:8]}")

    appeared = set(after.dirty_files) - set(before.dirty_files)
    for entry in sorted(appeared):
        failures.append(f"canonical repository modified during run: {entry.strip()}")

    return failures
