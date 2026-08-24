"""The challenger's decision, and the trial's immutable record of it.

Two records, each guarding a different way the experiment can lie.

**A verdict can be schema-valid and still be contaminated.** The dangerous
shape is a verdict that reads as evidence-grounded — cites `EVD-004`, objects
at length, sounds careful — when `EVD-004` was never in the bundle it was
given. An Arm A verdict citing a telemetry artifact it could not see is an Arm
A result carrying Arm B information, and nothing in the text shows it. So
`validate_verdict_against_bundle` checks citations against what the bundle
actually contained; the schema constrains shape and cannot do this.

**Dissent is retained, never averaged.** `member_positions` come from the raw
MoA trace, not the aggregator's summary — the aggregator's account of what the
reference models thought is the aggregator's opinion, not theirs. A position
that cannot be parsed keeps its raw text and is marked `parsed: False`;
dropping it would manufacture consensus out of silence, and an empty trace is
recorded as `extraction_incomplete`, not as unanimity.

**Records are immutable, and tuples are how.** `frozen=True` blocks attribute
reassignment but not in-place mutation, so a list field stays mutable and — the
part that actually bit, three separate times in Stages 0-1 — a record that
stores the caller's list *aliases* it. The caller appends later and the record
changes underneath whatever already read it. Every sequence field is coerced
to a tuple in `__post_init__`, so the aliasing cannot happen at all.
"""
import json
import re
from dataclasses import dataclass

APPROVE = "APPROVE"
REJECT = "REJECT"
NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
DECISIONS = (APPROVE, REJECT, NEEDS_MORE_EVIDENCE)

# run ids are <env>-<finding>-arm<A|B>-n<N>; the arm and n in the id and in the
# record are two spellings of one fact and must not be able to disagree.
RUN_ID = re.compile(r"^(?P<env>.+)-(?P<finding>FIND-[0-9]{3,})-arm(?P<arm>[AB])-n(?P<n>[0-9]+)$")


@dataclass(frozen=True)
class MemberPosition:
    """One MoA reference model's position, structured if it could be.

    `parsed=False` means the raw text is all there is. It is not a failure to
    record — it is the honest form of "this model said something we could not
    turn into a comparable judgement", and it is strictly better than either
    dropping the position or guessing at it.
    """
    model: str
    decision: str
    objections: tuple[str, ...]
    evidence_cited: tuple[str, ...]
    confidence: float | None
    raw_text: str = ""
    parsed: bool = True

    def __post_init__(self):
        object.__setattr__(self, "objections", tuple(self.objections))
        object.__setattr__(self, "evidence_cited", tuple(self.evidence_cited))
        if self.parsed and self.decision not in DECISIONS:
            raise ValueError(
                f"a parsed position must carry one of {DECISIONS}; got "
                f"{self.decision!r}. An unrecognised decision belongs in raw_text "
                f"with parsed=False — coercing it would fabricate a comparable "
                f"judgement out of one that was never made.")


@dataclass(frozen=True)
class ReviewVerdict:
    verdict_id: str
    schema_version: int
    created_at: str
    run_id: str
    arm: str
    decision: str
    objections: tuple[str, ...]
    evidence_cited: tuple[str, ...]
    member_positions: tuple[MemberPosition, ...]
    dissent: bool
    extraction_incomplete: bool
    raw_trace_sha256: str

    def __post_init__(self):
        if self.decision not in DECISIONS:
            raise ValueError(f"unknown decision {self.decision!r}; expected one of "
                             f"{DECISIONS}")
        for name in ("objections", "evidence_cited", "member_positions"):
            object.__setattr__(self, name, tuple(getattr(self, name)))


@dataclass(frozen=True)
class TrialResult:
    """One trial, with everything needed to run it again.

    The reproducibility block is not optional and not partially fillable. An
    experiment reproduced from model names alone is not reproduced: the model
    version, the MoA composition and the scanner builds all move, and a
    results table whose provenance is missing is a table nobody can defend.
    """
    run_id: str
    env: str
    finding_id: str
    arm: str
    n: int
    started_at: str
    completed_at: str
    verdict: ReviewVerdict
    usage: dict
    scoring_valid: bool
    input_bundle_hash: str
    repository_commit: str
    runtime_image_id: str
    model: str
    model_version: str
    moa_preset: str
    moa_fanout: str
    hermes_version: str
    scanner_versions: dict

    def __post_init__(self):
        match = RUN_ID.match(self.run_id)
        if not match:
            raise ValueError(f"run_id {self.run_id!r} is not "
                             f"<env>-<finding>-arm<A|B>-n<N>")
        # The run id is the directory name a trial's artifacts live under. A
        # result whose arm or n disagrees with it is filed against the wrong
        # cell of the matrix, and the matrix is the whole output.
        if match.group("arm") != self.arm:
            raise ValueError(
                f"run_id says arm{match.group('arm')} but the record says arm "
                f"{self.arm!r} — a result filed under the wrong arm contaminates "
                f"the matrix silently")
        if int(match.group("n")) != self.n:
            raise ValueError(f"run_id says n{match.group('n')} but the record says "
                             f"n={self.n}")
        if match.group("finding") != self.finding_id:
            raise ValueError(f"run_id says {match.group('finding')} but the record "
                             f"says {self.finding_id!r}")


def _position_from(entry: dict) -> MemberPosition:
    """One trace entry -> a position. Never raises, never drops.

    Anything that cannot be turned into a comparable judgement comes back with
    `parsed=False` and its text intact.
    """
    model = str(entry.get("model") or "unknown")
    content = entry.get("content")
    raw = content if isinstance(content, str) else json.dumps(content, sort_keys=True)

    def unparsed() -> MemberPosition:
        return MemberPosition(model=model, decision="", objections=(),
                              evidence_cited=(), confidence=None,
                              raw_text=raw, parsed=False)

    if not isinstance(content, str):
        return unparsed()
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, RecursionError):
        return unparsed()
    if not isinstance(document, dict):
        return unparsed()
    if document.get("decision") not in DECISIONS:
        return unparsed()

    objections = document.get("objections") or []
    cited = document.get("evidence_cited") or []
    confidence = document.get("confidence")
    if (not isinstance(objections, list) or not isinstance(cited, list)
            or not all(isinstance(x, str) for x in objections + cited)
            or not (confidence is None or isinstance(confidence, (int, float)))):
        return unparsed()
    return MemberPosition(model=model, decision=document["decision"],
                          objections=tuple(objections), evidence_cited=tuple(cited),
                          confidence=confidence, raw_text=raw, parsed=True)


def parse_member_positions(trace) -> tuple[tuple[MemberPosition, ...], bool]:
    """(positions, extraction_incomplete) from the raw MoA trace.

    An EMPTY trace returns `extraction_incomplete=True`, not agreement. No
    positions is not consensus — it is the absence of evidence about
    consensus, and recording it as unanimity is the averaging failure in its
    purest form.
    """
    if not trace:
        return (), True
    positions = tuple(_position_from(entry if isinstance(entry, dict) else {})
                      for entry in trace)
    return positions, any(not p.parsed for p in positions)


def validate_verdict_against_bundle(verdict: ReviewVerdict,
                                    *, bundle_evidence_ids) -> list[str]:
    """Structured failures, never an exception. Empty list means clean.

    This is the check the schema cannot do: whether the verdict cites evidence
    that was actually in the bundle it judged. An Arm A verdict citing a
    telemetry artifact is Arm B information in an Arm A result, and the two
    arms have stopped being independent without anything looking wrong.
    """
    failures = []
    present = set(bundle_evidence_ids)

    for cited in verdict.evidence_cited:
        if cited not in present:
            failures.append(
                f"verdict {verdict.verdict_id} cites {cited}, which is not in the "
                f"arm {verdict.arm} bundle it judged — a citation to evidence the "
                f"challenger was never given means the arms are not independent")

    for pos in verdict.member_positions:
        if not pos.parsed:
            # No structured citations to check. Reporting a failure for raw
            # text would be inventing one.
            continue
        for cited in pos.evidence_cited:
            if cited not in present:
                failures.append(
                    f"member position from {pos.model} cites {cited}, which is not "
                    f"in the arm {verdict.arm} bundle — reference-model citations "
                    f"cross arms as easily as the aggregator's, and nobody reads them")

    unparsed = [p for p in verdict.member_positions if not p.parsed]
    if unparsed and not verdict.extraction_incomplete:
        failures.append(
            f"extraction_incomplete is false but {len(unparsed)} member position(s) "
            f"could not be parsed ({', '.join(p.model for p in unparsed)}) — a "
            f"verdict that hides unread positions reports agreement it does not have")

    # dissent=False is a positive claim: they agreed. With a position nobody
    # could read, that claim is unknowable — and "unknown" recorded as
    # "agreed" is exactly the averaging this design refuses. A single
    # unparsed position is exempt: there is nothing for it to dissent from.
    if (verdict.extraction_incomplete and not verdict.dissent
            and len(verdict.member_positions) > 1 and unparsed):
        failures.append(
            f"dissent is false while extraction_incomplete is true and "
            f"{len(verdict.member_positions)} positions were taken — whether the "
            f"members agreed cannot be known when one of them could not be read, "
            f"and unknown must not be recorded as agreement")

    decisions = {p.decision for p in verdict.member_positions if p.parsed}
    if len(decisions) > 1 and not verdict.dissent:
        failures.append(
            f"member positions disagree ({', '.join(sorted(decisions))}) but dissent "
            f"is false — dissent is retained, never averaged")

    return failures


def position_to_dict(position: MemberPosition) -> dict:
    return {"model": position.model, "decision": position.decision,
            "objections": list(position.objections),
            "evidence_cited": list(position.evidence_cited),
            "confidence": position.confidence, "raw_text": position.raw_text,
            "parsed": position.parsed}


def verdict_to_dict(verdict: ReviewVerdict) -> dict:
    return {"verdict_id": verdict.verdict_id, "schema_version": verdict.schema_version,
            "created_at": verdict.created_at, "run_id": verdict.run_id,
            "arm": verdict.arm, "decision": verdict.decision,
            "objections": list(verdict.objections),
            "evidence_cited": list(verdict.evidence_cited),
            "member_positions": [position_to_dict(p) for p in verdict.member_positions],
            "dissent": verdict.dissent,
            "extraction_incomplete": verdict.extraction_incomplete,
            "raw_trace_sha256": verdict.raw_trace_sha256}


def result_to_dict(result: TrialResult) -> dict:
    return {"run_id": result.run_id, "env": result.env,
            "finding_id": result.finding_id, "arm": result.arm, "n": result.n,
            "started_at": result.started_at, "completed_at": result.completed_at,
            "verdict": verdict_to_dict(result.verdict), "usage": dict(result.usage),
            "scoring_valid": result.scoring_valid,
            "input_bundle_hash": result.input_bundle_hash,
            "repository_commit": result.repository_commit,
            "runtime_image_id": result.runtime_image_id,
            "model": result.model, "model_version": result.model_version,
            "moa_preset": result.moa_preset, "moa_fanout": result.moa_fanout,
            "hermes_version": result.hermes_version,
            "scanner_versions": dict(result.scanner_versions)}
