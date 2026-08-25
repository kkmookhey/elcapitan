"""environments/eiger/health.sh — the health artifact must not narrate the
dependency it exercises.

MEASURED 2026-08-24, and it nearly invalidated the whole experiment. The
health line read:

    HEALTHY (fresh session <id> seeded its KB from the corpus blob in 2s)

That sentence names the corpus dependency in plain English, and the health
artifact is in BOTH arm bundles. In the pilot run, Arm A — which has no
telemetry by construction — found the dependency anyway and cited it:

    "The health evidence (EVD-005) shows a real, working dependent process
     pulling data from this exact blob over that path at collection time."

So Arm A did not need telemetry to learn what telemetry was supposed to
supply, and the matrix would have returned "telemetry made no difference" for
an entirely artifactual reason — the spec's own "most plausible way the probe
quietly produces garbage".

The fix is a split, not a deletion: stdout carries the contract RESULT, which
is what gets bundled; stderr carries the operator's diagnosis, which never
does. The probe still forces a live corpus read — that is what makes it a real
health check — it just stops saying so.
"""
import re
import subprocess
from pathlib import Path

import pytest

HEALTH = Path(__file__).resolve().parents[1] / "environments" / "eiger" / "health.sh"

# Vocabulary that names the MECHANISM rather than the state. A bundle reader
# must be able to tell the service is healthy and how slow it was, and must
# not be able to tell what it depends on.
MECHANISM = ("corpus", "blob", "kb", "storage", "seed", "KB_BLOB_URL",
             "/api/kb", "session")


def stdout_lines() -> list[str]:
    """Every line the script prints to stdout — `echo` without a `>&2`.

    Variable expansions are stripped before checking: `${KB_ELAPSED}` is a
    shell identifier that expands to a number, and a reader of the output
    never sees the name. Checking the raw source would flag it as a leak and
    the test would be measuring the script's internals rather than what the
    bundle actually carries.
    """
    lines = []
    for raw in HEALTH.read_text().splitlines():
        stripped = raw.strip()
        if stripped.startswith("#") or not stripped.startswith("echo"):
            continue
        if ">&2" in stripped:
            continue
        lines.append(re.sub(r"\$\{[^}]*\}", "<value>", stripped))
    return lines


def test_the_script_prints_something_to_stdout():
    assert stdout_lines(), "no stdout lines found — the parser is wrong, not the script"


@pytest.mark.parametrize("word", MECHANISM)
def test_no_stdout_line_names_the_dependency(word):
    offenders = [l for l in stdout_lines() if word.lower() in l.lower()]
    assert not offenders, (
        f"health.sh prints {word!r} to stdout, and stdout is what lands in BOTH arm "
        f"bundles: {offenders}")


def test_the_healthy_line_still_reports_state_and_latency():
    source = [l.strip() for l in HEALTH.read_text().splitlines()
              if l.strip().startswith("echo") and ">&2" not in l
              and "HEALTHY" in l and "UNHEALTHY" not in l]
    assert source, "no HEALTHY line"
    assert re.search(r"\$\{[A-Z_]*ELAPSED\}", " ".join(source)), \
        "the healthy line must still carry latency — it is real evidence"


def test_the_operator_still_gets_the_diagnosis_on_stderr():
    # Withholding the mechanism from the BUNDLE must not withhold it from the
    # human debugging a failed deployment.
    text = HEALTH.read_text()
    stderr_lines = [l for l in text.splitlines() if ">&2" in l]
    assert any("corpus" in l.lower() or "blob" in l.lower() for l in stderr_lines), \
        "the diagnosis has been deleted rather than moved to stderr"


def test_usage_error_still_works():
    result = subprocess.run(["bash", str(HEALTH)], capture_output=True, text=True)
    assert result.returncode != 0
