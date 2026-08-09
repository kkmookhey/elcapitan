"""Containment for agent-supplied paths.

evidence-index.json is written by the agent. Any path it contains is untrusted
input to a host-side validator running with the operator's privileges.

Error contract: every failure to produce a contained path — an unsafe relative
path, a symlinked component, a resolved path outside the root, and also a root
that does not exist or cannot be traversed — raises PathEscape and nothing
else. Callers are guards inside a validator that "returns structured failures
rather than raising", so a single exception type is what lets them convert
every outcome into a failure string without enumerating OS errors. Before this
was uniform, safe_resolve could raise FileNotFoundError (missing root) or
OSError (ELOOP) straight through call sites that caught only PathEscape.
"""
from pathlib import Path

class PathEscape(Exception):
    """A supplied path is absolute, traverses upward, crosses a symlink,
    resolves outside the root, or the root itself cannot be resolved."""

def safe_resolve(root, relative: str) -> Path:
    try:
        root = Path(root).resolve(strict=True)
    except OSError as exc:
        # FileNotFoundError is an OSError. A missing/unreadable root is not a
        # caller bug to crash on: it is one more way this path is not
        # provably contained, and it must reach the caller as PathEscape.
        raise PathEscape(f"root directory does not resolve: {root!r} ({exc})") from exc

    if relative.startswith("/") or ".." in Path(relative).parts:
        raise PathEscape(f"unsafe path: {relative!r}")

    try:
        candidate = root
        for part in Path(relative).parts:
            candidate = candidate / part
            # Guard 1, symlinks. Independent of guard 2: it is the only thing
            # that rejects a symlink pointing back *inside* the root, where
            # the resolved path is perfectly relative_to(root).
            if candidate.is_symlink():
                raise PathEscape(f"symlink in evidence path: {candidate}")

        resolved = candidate.resolve()
    except OSError as exc:
        raise PathEscape(f"path could not be resolved: {relative!r} ({exc})") from exc

    # Guard 2, containment. Independent of guard 1: symlink detection is a
    # separate syscall from resolution, so a link created in that window (or
    # one lstat fails to observe) still has to fail here.
    if not resolved.is_relative_to(root):
        raise PathEscape(f"path escapes run directory: {relative!r}")
    return resolved
