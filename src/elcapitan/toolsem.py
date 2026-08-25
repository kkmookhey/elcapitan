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
    ambiguous: bool = False    # exit code cannot distinguish success from tool failure

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
            return ExitVerdict(True,
                               "cdk diff: differences present OR cdk error — "
                               "exit 1 cannot distinguish them",
                               ambiguous=True)
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
            if configured == 1:
                return ExitVerdict(True,
                                   "trivy: findings present OR trivy error — "
                                   "exit 1 cannot distinguish them",
                                   ambiguous=True)
            return ExitVerdict(True, "trivy: findings present")
    return ExitVerdict(code == 0, f"trivy exit {code}")

_HANDLERS = {"terraform": _terraform, "cdk": _cdk, "trivy": _trivy}

def _without_tool_name(tool: str, argv: list[str]) -> list[str]:
    """argv with a leading repeat of the tool name removed.

    A CommandRecord's argv has two conventions in the wild and an agent picks
    between them freely:

        ["terraform", "plan", "-detailed-exitcode"]   tool included
        ["plan", "-detailed-exitcode"]                tool excluded

    The handlers read argv[0] as the SUBCOMMAND. Under the first convention
    that made `sub` equal "terraform", the -detailed-exitcode branch never
    matched, and a plan exiting 2 — which means CHANGES PRESENT, the expected
    outcome of every remediation this system generates — was scored as a
    failure reading "terraform terraform exit 2".

    That cost six trials and about $13 in the first real batch. Identical work
    scoring differently because of a recording convention is an experimental
    confound, not a formatting nit.
    """
    return argv[1:] if argv and argv[0] == tool else argv


def interpret_exit(tool: str, argv: list[str], code: int) -> ExitVerdict:
    handler = _HANDLERS.get(tool)
    if handler is None:
        return ExitVerdict(code == 0, f"generic semantics: exit {code}")
    return handler(_without_tool_name(tool, argv), code)
