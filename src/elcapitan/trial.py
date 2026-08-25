"""The middle of a trial: everything between the engineer exiting and the
challenger starting.

`bin/run-trial.sh` ran engineer → validate. The collector and the challenger
both existed and nothing invoked them, so no trial had ever produced a bundle
or a verdict. This is the missing middle.

It lives in Python rather than shell because it reads the engineer's
artifacts, projects them, queries two clouds under two different identities
and assembles one immutable snapshot. Shell is the right tool for ordering
those steps and the wrong tool for any of them.

## What it refuses to do

**It does not hand the engineer's reasoning to the challenger.** The proposal
is projected through `collector.project_proposal` on the way in, every time.
The withholding is the measurement instrument — a raw proposal here would
quietly turn the experiment into a test of whether one model agrees with
another's confident summary.

**It does not read the telemetry window the trial actually occupied.**
MEASURED: a storage operation at 21:47:44 landed in the 21:48 bucket and first
became visible ~60 seconds later. A window ending when the engineer exited
misses the engineer's own last actions, and Arm B comes back quieter than the
trial really was — which looks exactly like "telemetry showed nothing".
"""
import json
import subprocess
from datetime import datetime, timedelta, UTC
from pathlib import Path

from .collector import project_proposal
from .hashing import canonical_json

# MEASURED 2026-08-24 against the live deployment: load generated at 21:47:44
# appeared in the 21:48 bucket, first visible at 21:48:47 — about 60s of
# ingestion lag, plus bucketing into the following minute. 150s is that,
# doubled and rounded, because being early is silent and being late costs
# nothing but wall-clock.
INGESTION_LAG_SECONDS = 150

# The window also opens BEFORE the trial. The engineer's first cloud reads
# happen within seconds of the container starting, and a window that opens
# exactly at the recorded start time can miss them to clock skew alone.
WINDOW_LEAD_SECONDS = 120

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
_HEALTH_TIMEOUT = 120


def read_engineer_artifacts(run_dir) -> tuple[bytes, bytes, bytes]:
    """(projected proposal, patch, verification) from what the engineer left.

    The proposal is projected here rather than by the caller so that no path
    into a bundle can skip it. `verification` carries commands and exit codes
    and NOT `output`: console text quoted back is where an engineer's
    narrative reappears after the narrative fields have been removed.
    """
    run_dir = Path(run_dir)
    proposal_path = run_dir / "proposal.json"
    if not proposal_path.is_file():
        raise ValueError(
            f"the engineer left no proposal.json in {run_dir} — there is nothing "
            f"for a challenger to judge, and a trial that reached this point "
            f"without one did not fail loudly enough earlier")
    raw = proposal_path.read_bytes()
    projected = project_proposal(raw)

    # Concatenated in sorted order so the same patch set always hashes the
    # same. A patch directory is legitimately absent for a proposal whose
    # resolution_type is false_positive or risk_accepted.
    patch_dir = run_dir / "patch"
    patch = b""
    if patch_dir.is_dir():
        for path in sorted(patch_dir.iterdir()):
            if path.is_file():
                patch += path.read_bytes()

    try:
        commands = (json.loads(raw).get("verification") or {}).get("commands_run") or []
    except (json.JSONDecodeError, AttributeError, TypeError):
        # The projection already recorded that the proposal was unparseable;
        # this half simply has nothing to contribute.
        commands = []
    return projected, patch, canonical_json(commands)


def telemetry_window(started_at: str, finished_at: str) -> tuple[str, str]:
    """The window the collector should ask about, widened at both ends.

    Widened at the END by the measured ingestion lag: telemetry that has not
    landed is indistinguishable from telemetry that says nothing happened, and
    the second reading is the one that silently turns the experiment into
    A-versus-A.

    Widened at the START because the engineer's first cloud reads happen
    within seconds of container start, and clock skew between the host writing
    the timestamp and Azure bucketing the metric is enough to lose them.
    """
    start = datetime.strptime(started_at, _RFC3339) - timedelta(seconds=WINDOW_LEAD_SECONDS)
    end = datetime.strptime(finished_at, _RFC3339) + timedelta(seconds=INGESTION_LAG_SECONDS)
    return start.strftime(_RFC3339), end.strftime(_RFC3339)


def wait_for_ingestion(sleep=None) -> None:
    """Block for the measured lag before collecting.

    Widening the window is necessary and not sufficient: asking at 21:48:10
    about a window ending 21:50:14 still returns zeros for the minutes that
    have not landed. The collector's populated-check would then correctly
    report `unpopulated`, and the trial would be scoring-invalid for a reason
    that was only ever impatience.
    """
    import time

    (sleep or time.sleep)(INGESTION_LAG_SECONDS)


def probe_health(command) -> bytes:
    """The health contract's stdout, as evidence. Never raises.

    STDOUT ONLY, deliberately. stdout is the contract result; stderr is the
    operator's diagnosis and it names the corpus dependency in plain English.
    Capturing stderr would put that leak straight back into both arm bundles,
    which is the defect this project has already fixed once.

    A service that is DOWN is the most interesting evidence a trial can carry,
    so a non-zero exit is recorded rather than raised. A health script that
    cannot run at all is recorded as UNKNOWN — distinguishable from both
    HEALTHY and UNHEALTHY, because "we did not look" is not "we looked and it
    was fine".
    """
    try:
        result = subprocess.run(list(command), capture_output=True,
                                timeout=_HEALTH_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return (f"UNKNOWN: the health contract could not be run ({exc}). This is "
                f"not evidence that the service is healthy.").encode()
    out = result.stdout.strip()
    if not out:
        return (f"UNKNOWN: the health contract exited {result.returncode} and "
                f"printed nothing to stdout.").encode()
    return out


def now_rfc3339() -> str:
    return datetime.now(UTC).strftime(_RFC3339)
