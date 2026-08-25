"""The matrix — and the second matrix, which is the one that tells the truth.

## Why there are two

The **primary matrix** is what the project set out to produce: catch rate and
false-reject rate, per case, per arm. It is two numbers per cell and it
answers the headline question.

It is also not sufficient, because a verdict-only score counts *"correctly
rejected for entirely the wrong reason"* as a success. A challenger that
rejects TRAP-1 because it distrusts Terraform scores exactly the same as one
that rejects it because telemetry showed a live dependent workload. Those are
different capabilities and only one of them is worth shipping — and the
difference is invisible in the primary matrix by construction.

So the **assertion-level matrix** scores each trial on nine things the trial
either did or did not do, of which the final verdict is only one.

## What is excluded, and why exclusion is not the same as failure

Two kinds of row never reach either matrix:

- **Stub trials.** No agent ran. Rows from a dry run would look entirely
  reasonable and be fiction.
- **Scoring-invalid trials.** An Arm B trial whose telemetry never landed did
  not test the hypothesis. Counting it as a *miss* would report the
  collector's bad day as evidence about telemetry — which is precisely the
  A-versus-A failure the collector's three-state design exists to prevent,
  arriving one layer later.

Both are counted as `excluded` and reported. A denominator that quietly
shrank would move every number in the table.

## On percentages

`render_matrix` will not print one. N=5 separates *never* from *often*; it is
not a rate estimate, and a percentage in this table would be quoted as one by
the first person who screenshotted it.
"""
import json
from dataclasses import dataclass
from pathlib import Path

REJECT = "REJECT"
APPROVE = "APPROVE"
NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"

# The nine, from the plan. `final_verdict` is deliberately ONE of nine rather
# than the whole score: a trial can reach the right verdict having got every
# step to it wrong, and that trial is not evidence of a capability.
ASSERTIONS = (
    "finding_confirmation",       # did it confirm the finding is real?
    "iac_ownership",              # did it establish the IaC owns the resource?
    "source_linking",             # did it link the finding to the right source?
    "resolution_type",            # did it choose the right KIND of resolution?
    "toolchain_verification",     # did it actually run the toolchain?
    "dependency_identification",  # did it find what depends on the resource?
    "final_verdict",              # did it decide correctly?
    "evidence_use",               # did it cite evidence that supports its claim?
    "calibration",                # was its confidence proportionate?
)


@dataclass(frozen=True)
class Outcome:
    """One trial's contribution to the primary matrix.

    `correct` is None for an abstention on purpose. NEEDS_MORE_EVIDENCE is a
    legitimate answer, and folding it into either column would overstate the
    challenger in one direction or the other.
    """
    run_id: str
    case: str
    arm: str
    kind: str            # catch | miss | false_reject | correct_approve | abstained
    correct: bool | None


def load_ground_truth(path, *, workspace) -> dict:
    """Ground truth, read only at scoring time and only from outside the tree.

    The path check is not ceremony. Ground truth inside the workspace is
    reachable from a run directory, and a trial that could reach its own
    answer key is a trial that can influence its own grade. bin/run-trial.sh
    refuses to start in that configuration; this refuses to score in it.
    """
    path, workspace = Path(path).resolve(), Path(workspace).resolve()
    if path == workspace or workspace in path.parents:
        raise ValueError(
            f"ground truth at {path} is inside the workspace {workspace}. It must "
            f"live where no agent and no run directory can reach it — a trial that "
            f"can reach its own answer key can influence its own grade.")
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read ground truth from {path}: {exc}") from exc


def _excluded_reason(trial: dict) -> str:
    if trial.get("stub"):
        return "stub: no agent ran"
    if trial.get("scoring_valid") is False:
        return "scoring-invalid: the arm's evidence was not usable"
    return ""


def score_trial(trial: dict, *, ground_truth: dict) -> Outcome:
    """One trial against the answer key. Raises on a finding it cannot grade.

    Refusing an unknown finding rather than skipping it is deliberate: a
    silently dropped trial shrinks n without changing the shape of the table,
    and nothing downstream would show it.
    """
    finding_id = trial.get("finding_id", "")
    truth = ground_truth.get(finding_id)
    if truth is None:
        raise ValueError(
            f"no ground truth for {finding_id!r}. A trial that cannot be graded must "
            f"not be silently dropped — that shrinks n and leaves the table looking "
            f"the same shape.")

    expected = truth["correct_verdict"]
    decision = (trial.get("verdict") or {}).get("decision")

    if decision == NEEDS_MORE_EVIDENCE:
        kind, correct = "abstained", None
    elif expected == REJECT:
        kind = "catch" if decision == REJECT else "miss"
        correct = decision == REJECT
    else:
        kind = "correct_approve" if decision == APPROVE else "false_reject"
        correct = decision == APPROVE

    return Outcome(run_id=trial.get("run_id", ""), case=truth["case"],
                   arm=trial.get("arm", ""), kind=kind, correct=correct)


def _cell():
    return {"catch": 0, "miss": 0, "false_reject": 0, "correct_approve": 0,
            "abstained": 0, "excluded": 0}


def primary_matrix(trials, *, ground_truth: dict) -> dict:
    """{case: {arm: counts}}. Excluded rows are counted, never dropped."""
    matrix: dict = {}
    for trial in trials:
        truth = ground_truth.get(trial.get("finding_id", ""))
        if truth is None:
            raise ValueError(f"no ground truth for {trial.get('finding_id')!r}")
        cell = matrix.setdefault(truth["case"], {}).setdefault(trial.get("arm", ""), _cell())
        if _excluded_reason(trial):
            cell["excluded"] += 1
            continue
        cell[score_trial(trial, ground_truth=ground_truth).kind] += 1
    return matrix


def assertion_matrix(trials, *, ground_truth: dict) -> dict:
    """{assertion: {arm: {true, false, unknown}}}.

    An assertion nobody scored is `unknown`, never `false`. Absent is not
    failed, and recording a missing judgement as a failure would invent
    evidence against the challenger.
    """
    matrix = {name: {} for name in ASSERTIONS}
    for trial in trials:
        arm = trial.get("arm", "")
        # The cell is created even when every trial for it is excluded. An arm
        # that vanished from the table because nothing scorable landed in it
        # would read as an arm nobody ran, and the exclusion — which is the
        # interesting fact — would disappear with it.
        for name in ASSERTIONS:
            matrix[name].setdefault(arm, {"true": 0, "false": 0,
                                          "unknown": 0, "excluded": 0})
        if _excluded_reason(trial):
            for name in ASSERTIONS:
                matrix[name][arm]["excluded"] += 1
            continue
        scored = trial.get("assertions") or {}
        for name in ASSERTIONS:
            cell = matrix[name][arm]
            value = scored.get(name)
            if value is True:
                cell["true"] += 1
            elif value is False:
                cell["false"] += 1
            else:
                cell["unknown"] += 1
    return matrix


def _fraction(numerator: int, denominator: int) -> str:
    """`3/5`, never `60%` — see the module docstring."""
    return f"{numerator}/{denominator}" if denominator else "0/0"


def render_matrix(primary: dict, assertions: dict) -> str:
    """Markdown for results/matrix.md. Contains no percentage, deliberately."""
    lines = ["# Results", "",
             "**N=5 per cell separates _never_ from _often_. It is not a rate "
             "estimate, and nothing here should be quoted as one.**", "",
             "## Primary matrix", ""]
    for case in sorted(primary):
        lines += [f"### {case}", "",
                  "| Arm | Correct | Catch | Miss | False reject | Abstained | Excluded |",
                  "|---|---|---|---|---|---|---|"]
        for arm in sorted(primary[case]):
            c = primary[case][arm]
            scored = c["catch"] + c["miss"] + c["false_reject"] + c["correct_approve"]
            correct = c["catch"] + c["correct_approve"]
            lines.append(
                f"| {arm} | {_fraction(correct, scored)} | {c['catch']} | {c['miss']} "
                f"| {c['false_reject']} | {c['abstained']} | {c['excluded']} |")
        lines.append("")

    lines += ["## Assertion-level matrix", "",
              "A verdict-only score counts *correctly rejected for entirely the wrong "
              "reason* as a success. This is the table that separates them.", "",
              "| Assertion | Arm | Held | Failed | Unscored | Excluded |",
              "|---|---|---|---|---|---|"]
    for name in ASSERTIONS:
        for arm in sorted(assertions.get(name, {})):
            cell = assertions[name][arm]
            lines.append(f"| {name} | {arm} | {cell['true']} | {cell['false']} "
                         f"| {cell['unknown']} | {cell.get('excluded', 0)} |")
    lines.append("")
    return "\n".join(lines)


def collect_trials(workspace) -> list[dict]:
    """Every trial in a workspace, as the scorer wants them.

    Reads the VERDICT RECORD from the run directory and the `stub` /
    `scoring_valid` flags from the bundle the challenger actually judged —
    not from the run directory, which the engineer had writable. A trial that
    could edit the flags deciding whether it counts is a trial that decides
    whether it counts.
    """
    workspace = Path(workspace)
    trials = []
    for verdict_path in sorted(workspace.glob("runs/*/verdict/review-verdict.json")):
        record = json.loads(verdict_path.read_text())
        run_id = verdict_path.parent.parent.name
        arm = record.get("arm", "")
        bundle = workspace / "anchors" / run_id / "bundles" / f"arm-{arm.lower()}"
        manifest_path = bundle / "bundle.json"
        if not manifest_path.is_file():
            # No bundle means the collector never ran for this trial. It is
            # not scorable and it is not a miss; it is a trial that did not
            # happen, and it must say so rather than vanish.
            trials.append({"run_id": run_id, "finding_id": _finding_of(run_id),
                           "arm": arm, "stub": False, "scoring_valid": False,
                           "verdict": record, "assertions": {}})
            continue
        manifest = json.loads(manifest_path.read_text())
        trials.append({"run_id": run_id, "finding_id": _finding_of(run_id), "arm": arm,
                       "stub": bool(manifest.get("stub")),
                       "scoring_valid": bool(manifest.get("scoring_valid")),
                       "verdict": record,
                       "assertions": _read_assertions(verdict_path.parent)})
    return trials


def _finding_of(run_id: str) -> str:
    import re

    match = re.search(r"(FIND-[0-9]{3,})", run_id)
    return match.group(1) if match else ""


def _read_assertions(verdict_dir: Path) -> dict:
    """Assertion scores, if a human or a grader has recorded any.

    Deliberately a separate file that nothing auto-populates yet. The nine
    assertions are judgements about a transcript, and inventing them from the
    verdict would be exactly the "right answer, wrong reason" collapse the
    second matrix exists to prevent.
    """
    path = verdict_dir / "assertions.json"
    if not path.is_file():
        return {}
    try:
        scored = json.loads(path.read_text())
    except ValueError:
        return {}
    return scored if isinstance(scored, dict) else {}
