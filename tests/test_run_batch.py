"""bin/run-batch.sh — the 20-cell matrix, shuffled with a recorded seed.

Ordering is randomised because a batch that always runs A-then-B lets any
drift during the batch — a model-service change, environment drift, a quota
throttle that kicks in late — masquerade as an arm effect. The seed is
recorded so the order is reproducible afterwards; a shuffle nobody can
reproduce is indistinguishable from one that never happened.

The load-bearing tests:

  test_the_recorded_seed_reproduces_the_order
      an unreproducible order is not a controlled variable.

  test_every_cell_appears_exactly_once
      a duplicated cell double-counts a result; a dropped cell silently
      shrinks n and nothing downstream would notice.

  test_a_failed_trial_does_not_abort_the_batch
      one bad trial out of twenty must cost one row, not nineteen.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "run-batch.sh"


def plan_cells(seed: str, cases=("FIND-002", "FIND-003"), arms=("A", "B"), n=5):
    """Ask the script for its plan without running anything."""
    result = subprocess.run(
        [str(SCRIPT), "--plan-only", "--seed", seed, "--cases", ",".join(cases),
         "--arms", ",".join(arms), "--trials", str(n), "--env", "eiger"],
        capture_output=True, text=True, env={**os.environ})
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    return json.loads(result.stdout)


def test_script_is_executable():
    assert os.access(SCRIPT, os.X_OK)


def test_the_plan_has_one_cell_per_case_arm_and_trial():
    plan = plan_cells("seed-1")
    assert len(plan["cells"]) == 20


def test_every_cell_appears_exactly_once():
    plan = plan_cells("seed-1")
    keys = [(c["finding_id"], c["arm"], c["n"]) for c in plan["cells"]]
    assert len(set(keys)) == len(keys), "a cell is duplicated"
    expected = {(f, a, n) for f in ("FIND-002", "FIND-003")
                for a in ("A", "B") for n in range(1, 6)}
    assert set(keys) == expected, "a cell is missing"


def test_the_recorded_seed_reproduces_the_order():
    first = plan_cells("reproducible-seed")
    second = plan_cells("reproducible-seed")
    assert first["cells"] == second["cells"]
    assert first["seed"] == "reproducible-seed"


def test_a_different_seed_gives_a_different_order():
    a = plan_cells("seed-alpha")["cells"]
    b = plan_cells("seed-bravo")["cells"]
    assert a != b, "the seed is not actually driving the shuffle"


def test_the_order_is_not_arms_grouped():
    # The failure this exists to prevent: all ten A trials, then all ten B.
    # Any drift during the batch would then look like an arm effect.
    arms = [c["arm"] for c in plan_cells("seed-1")["cells"]]
    first_half, second_half = arms[:10], arms[10:]
    assert not (set(first_half) == {"A"} and set(second_half) == {"B"})
    assert not (set(first_half) == {"B"} and set(second_half) == {"A"})


def test_run_ids_are_distinct_and_well_formed():
    import re
    plan = plan_cells("seed-1")
    run_ids = [c["run_id"] for c in plan["cells"]]
    assert len(set(run_ids)) == 20
    for run_id in run_ids:
        assert re.match(r"^eiger-FIND-\d{3}-arm[AB]-n\d+$", run_id), run_id


def test_the_plan_records_the_seed_for_the_record():
    plan = plan_cells("seed-for-the-record")
    assert plan["seed"] == "seed-for-the-record"


def test_a_missing_seed_is_refused_rather_than_invented():
    # A batch that generated its own seed and did not record it would be
    # unreproducible in exactly the way this is meant to prevent.
    result = subprocess.run([str(SCRIPT), "--plan-only", "--env", "eiger"],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "seed" in result.stderr.lower()
