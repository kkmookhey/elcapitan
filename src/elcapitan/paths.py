"""Containment for agent-supplied paths.

evidence-index.json is written by the agent. Any path it contains is untrusted
input to a host-side validator running with the operator's privileges.
"""
from pathlib import Path

class PathEscape(Exception):
    """A supplied path is absolute, traverses upward, or crosses a symlink."""

def safe_resolve(root, relative: str) -> Path:
    root = Path(root).resolve(strict=True)
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise PathEscape(f"unsafe path: {relative!r}")

    candidate = root
    for part in Path(relative).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise PathEscape(f"symlink in evidence path: {candidate}")

    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise PathEscape(f"path escapes run directory: {relative!r}")
    return resolved
