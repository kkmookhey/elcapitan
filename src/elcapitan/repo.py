"""Independent post-run repository diagnostics.

The read-only bind mount is the enforcement. This recomputes state from the
repository after the container exits and compares it with state captured
before — never with a value supplied by the caller.
"""
import subprocess
from dataclasses import dataclass
from pathlib import Path

# git's wording for "HEAD exists but points nowhere yet"
_UNBORN_MARKERS = ("unknown revision", "ambiguous argument 'HEAD'",
                   "does not have any commits")

@dataclass(frozen=True)
class RepoState:
    commit: str
    # A tuple, not a list: frozen=True blocks attribute reassignment but not
    # in-place mutation, and this baseline is what tamper detection diffs
    # against. A mutated baseline yields false negatives — real tampering that
    # goes unreported. Records are immutable.
    dirty_files: tuple[str, ...] = ()

def _git(path, *args) -> str:
    try:
        result = subprocess.run(["git", "-C", str(path), *args],
                                capture_output=True, text=True)
    except OSError as exc:
        # subprocess.run raises FileNotFoundError (an OSError) when `git` is
        # not on PATH — an exception type callers do not expect from this
        # module, and one that escaped the validator's `except ValueError`
        # entirely. Everything that can go wrong here leaves as ValueError.
        raise ValueError(f"git could not be executed (is it on PATH?): {exc}") from exc
    if result.returncode != 0:
        raise ValueError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout

def capture_repo_state(path) -> RepoState:
    path = Path(path)
    try:
        commit = _git(path, "rev-parse", "HEAD").strip()
    except ValueError as exc:
        # Only claim "unborn branch" when git actually said so. A missing path
        # or a directory that is not a repository at all must not be reported
        # as "no commits" — asserting a specific wrong cause is worse than a
        # generic one, because it sends the reader somewhere else entirely.
        detail = str(exc)
        if any(marker in detail for marker in _UNBORN_MARKERS):
            raise ValueError(f"repository has no commits (unborn branch): {path}") from exc
        raise ValueError(f"not a usable git repository: {path} — {detail}") from exc
    porcelain = _git(path, "status", "--porcelain", "--untracked-files=all")
    return RepoState(commit=commit,
                     dirty_files=tuple(sorted(porcelain.splitlines())))

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
