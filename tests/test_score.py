"""elcapitan.score — the matrix, and why a verdict-only matrix would lie.

Two scorers, because one of them is not enough.

**The primary matrix** is catch rate and false-reject rate per arm. It is what
the project exists to produce and it is two numbers per cell.

**The assertion-level matrix** exists because verdict-only scoring counts
"correctly rejected for entirely the wrong reason" as a success. A challenger
that rejects TRAP-1 because it dislikes Terraform scores identically to one
that rejects it because telemetry showed a live dependency — and those are
completely different capabilities, only one of which is worth shipping.

The load-bearing tests here:

  test_a_right_answer_for_the_wrong_reason_is_visible
      the whole reason the second matrix exists.

  test_stub_trials_are_excluded
      a dry run has no agent in it. If stub rows reach the matrix the numbers
      are fiction, and they would look entirely reasonable.

  test_ground_truth_is_read_only_at_scoring_time
      the ground truth lives outside every agent-visible path and is applied
      after artifacts are finalised. A scorer that could be pointed at a
      run_dir would let a trial influence its own grade.
"""
import json
from pathlib import Path

import pytest

from elcapitan.score import (
    ASSERTIONS,
    Outcome,
    assertion_matrix,
    primary_matrix,
    score_trial,
)

GROUND_TRUTH = {
    "FIND-002": {"correct_verdict": "REJECT", "case": "TRAP-1",
                 "required_evidence": ["telemetry:dependency_edges"]},
    "FIND-003": {"correct_verdict": "APPROVE", "case": "CONTROL",
                 "required_evidence": []},
}


def trial(finding_id="FIND-002", arm="B", n=1, decision="REJECT",
          cited=("EVD-006",), stub=False, scoring_valid=True,
          assertions=None):
    return {
        "run_id": f"eiger-{finding_id}-arm{arm}-n{n}",
        "finding_id": finding_id, "arm": arm, "n": n,
        "stub": stub, "scoring_valid": scoring_valid,
        "verdict": {"decision": decision, "evidence_cited": list(cited),
                    "objections": ["it severs the corpus read"]},
        "assertions": assertions or {},
    }


# --- the primary matrix -----------------------------------------------------

def test_a_correct_reject_on_the_trap_is_a_catch():
    outcome = score_trial(trial(), ground_truth=GROUND_TRUTH)
    assert outcome.correct is True
    assert outcome.kind == "catch"


def test_a_missed_trap_is_a_miss():
    outcome = score_trial(trial(decision="APPROVE"), ground_truth=GROUND_TRUTH)
    assert outcome.correct is False and outcome.kind == "miss"


def test_rejecting_the_control_is_a_false_reject():
    # The failure the control exists to catch. A reject-everything challenger
    # passes every trap and is commercially worthless.
    outcome = score_trial(trial(finding_id="FIND-003", decision="REJECT"),
                          ground_truth=GROUND_TRUTH)
    assert outcome.correct is False and outcome.kind == "false_reject"


def test_approving_the_control_is_correct():
    outcome = score_trial(trial(finding_id="FIND-003", decision="APPROVE"),
                          ground_truth=GROUND_TRUTH)
    assert outcome.correct is True and outcome.kind == "correct_approve"


def test_needs_more_evidence_is_neither_catch_nor_miss():
    # It is a real answer, and collapsing it into either column would
    # overstate the challenger in one direction or the other.
    outcome = score_trial(trial(decision="NEEDS_MORE_EVIDENCE"),
                          ground_truth=GROUND_TRUTH)
    assert outcome.kind == "abstained"
    assert outcome.correct is None


def test_the_primary_matrix_counts_per_case_and_arm():
    trials = ([trial(arm="A", n=i, decision="APPROVE") for i in range(1, 6)]
              + [trial(arm="B", n=i, decision="REJECT") for i in range(1, 6)])
    matrix = primary_matrix(trials, ground_truth=GROUND_TRUTH)
    assert matrix["TRAP-1"]["A"]["catch"] == 0
    assert matrix["TRAP-1"]["A"]["miss"] == 5
    assert matrix["TRAP-1"]["B"]["catch"] == 5


def test_stub_trials_are_excluded():
    trials = [trial(stub=True) for _ in range(5)]
    matrix = primary_matrix(trials, ground_truth=GROUND_TRUTH)
    assert matrix["TRAP-1"]["B"]["catch"] == 0
    assert matrix["TRAP-1"]["B"]["excluded"] == 5


def test_scoring_invalid_trials_are_excluded_not_counted_as_misses():
    # An Arm B trial whose telemetry never landed did not test the
    # hypothesis. Counting it as a miss would report the collector's bad day
    # as evidence about telemetry.
    trials = [trial(scoring_valid=False, decision="APPROVE") for _ in range(3)]
    matrix = primary_matrix(trials, ground_truth=GROUND_TRUTH)
    assert matrix["TRAP-1"]["B"]["miss"] == 0
    assert matrix["TRAP-1"]["B"]["excluded"] == 3


def test_an_unknown_finding_is_refused_not_silently_dropped():
    with pytest.raises(ValueError) as exc:
        score_trial(trial(finding_id="FIND-999"), ground_truth=GROUND_TRUTH)
    assert "FIND-999" in str(exc.value)


# --- the assertion-level matrix ---------------------------------------------

def test_the_nine_assertions_are_all_scored():
    assert len(ASSERTIONS) == 9
    for name in ("finding_confirmation", "iac_ownership", "source_linking",
                 "resolution_type", "toolchain_verification",
                 "dependency_identification", "final_verdict", "evidence_use",
                 "calibration"):
        assert name in ASSERTIONS


def test_a_right_answer_for_the_wrong_reason_is_visible():
    # THE reason this matrix exists. Both trials reject TRAP-1 and both score
    # a catch in the primary matrix. Only one of them identified the
    # dependency, and that is the capability worth shipping.
    grounded = trial(cited=("EVD-006", "EVD-008"),
                     assertions={"dependency_identification": True,
                                 "evidence_use": True})
    lucky = trial(cited=(), assertions={"dependency_identification": False,
                                        "evidence_use": False})
    assert score_trial(grounded, ground_truth=GROUND_TRUTH).kind == "catch"
    assert score_trial(lucky, ground_truth=GROUND_TRUTH).kind == "catch"

    matrix = assertion_matrix([grounded, lucky], ground_truth=GROUND_TRUTH)
    assert matrix["dependency_identification"]["B"]["true"] == 1
    assert matrix["dependency_identification"]["B"]["false"] == 1


def test_an_unscored_assertion_is_unknown_not_false():
    # Absent is not failed. Recording a missing judgement as a failure would
    # invent evidence against the challenger.
    matrix = assertion_matrix([trial(assertions={})], ground_truth=GROUND_TRUTH)
    assert matrix["final_verdict"]["B"]["unknown"] == 1
    assert matrix["final_verdict"]["B"]["false"] == 0


def test_the_assertion_matrix_also_excludes_stubs():
    matrix = assertion_matrix([trial(stub=True, assertions={"evidence_use": True})],
                              ground_truth=GROUND_TRUTH)
    assert matrix["evidence_use"]["B"]["true"] == 0


# --- ground truth stays out of band -----------------------------------------

def test_ground_truth_is_read_only_at_scoring_time(tmp_path):
    from elcapitan.score import load_ground_truth

    inside = tmp_path / "runs" / "r" / "ground-truth.json"
    inside.parent.mkdir(parents=True)
    inside.write_text(json.dumps(GROUND_TRUTH))
    with pytest.raises(ValueError) as exc:
        load_ground_truth(inside, workspace=tmp_path)
    assert "workspace" in str(exc.value).lower()


def test_ground_truth_outside_the_workspace_loads(tmp_path):
    from elcapitan.score import load_ground_truth

    outside = tmp_path.parent / f"gt-{tmp_path.name}.json"
    outside.write_text(json.dumps(GROUND_TRUTH))
    try:
        assert load_ground_truth(outside, workspace=tmp_path) == GROUND_TRUTH
    finally:
        outside.unlink()


# --- honest reporting -------------------------------------------------------

def test_the_report_refuses_to_state_a_percentage():
    from elcapitan.score import render_matrix

    trials = [trial(arm="B", n=i) for i in range(1, 6)]
    text = render_matrix(primary_matrix(trials, ground_truth=GROUND_TRUTH),
                         assertion_matrix(trials, ground_truth=GROUND_TRUTH))
    assert "%" not in text, (
        "n=5 separates 'never' from 'often'; it is not a rate estimate, and a "
        "percentage in this table would be quoted as one")
    assert "5/5" in text or "5 of 5" in text
