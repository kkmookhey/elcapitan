# src/elcapitan/toolsem.py
"""Per-tool exit-code semantics.

A generic 'non-zero means failure' rule would mis-score the probe: a
successful `terraform plan -detailed-exitcode` that contains changes exits 2,
and that is the expected outcome of every remediation this system generates.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class ExitVerdict:
    ok: bool
    meaning: str

def _terraform(argv: list[str], code: int) -> ExitVerdict:
    sub = argv[0] if argv else ""
    if sub == "plan" and "-detailed-exitcode" in argv:
        return {
            0: ExitVerdict(True, "plan succeeded, no changes"),
            2: ExitVerdict(True, "plan succeeded, changes present"),
        }.get(code, ExitVerdict(False, f"terraform plan error (exit {code})"))
    return ExitVerdict(code == 0, f"terraform {sub} exit {code}")

def _cdk(argv: list[str], code: int) -> ExitVerdict:
    if argv and argv[0] == "diff" and "--fail" in argv:
        if code == 0:
            return ExitVerdict(True, "cdk diff: no differences")
        if code == 1:
            return ExitVerdict(True, "cdk diff: differences present")
        return ExitVerdict(False, f"cdk diff error (exit {code})")
    return ExitVerdict(code == 0, f"cdk exit {code}")

def _trivy(argv: list[str], code: int) -> ExitVerdict:
    if "--exit-code" in argv:
        try:
            configured = int(argv[argv.index("--exit-code") + 1])
        except (IndexError, ValueError):
            configured = None
        if code == 0:
            return ExitVerdict(True, "trivy: no findings")
        if configured is not None and code == configured:
            return ExitVerdict(True, "trivy: findings present")
    return ExitVerdict(code == 0, f"trivy exit {code}")

_HANDLERS = {"terraform": _terraform, "cdk": _cdk, "trivy": _trivy}

def interpret_exit(tool: str, argv: list[str], code: int) -> ExitVerdict:
    handler = _HANDLERS.get(tool)
    if handler is None:
        return ExitVerdict(code == 0, f"generic semantics: exit {code}")
    return handler(argv, code)
