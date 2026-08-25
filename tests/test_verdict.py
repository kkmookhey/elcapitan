"""elcapitan.verdict — the challenger's decision, and the trial's record of it.

Two records, and both exist to stop a specific way the experiment lies to you.

`ReviewVerdict` is the challenger's output. Its dangerous failure is a verdict
that *sounds* evidence-grounded: cites EVD-004, objects at length, reads
convincingly — and EVD-004 was never in the bundle it was given. Arm A citing
a telemetry artifact it could not see would be an Arm A result contaminated by
Arm B, and nothing about the text would show it. So citations are checked
against the bundle, not trusted.

`TrialResult` is the reproducibility record. Its dangerous failure is quieter:
a results table nobody can reproduce because the model version, MoA
composition or scanner build were never written down. Model names alone do not
identify a run.

The load-bearing tests here:

  test_a_verdict_citing_evidence_absent_from_its_bundle_is_rejected
      the contamination check, and the only one that can catch an arm reading
      across.

  test_an_unparseable_member_position_keeps_its_raw_text
      the spec is explicit that dissent is retained, never averaged, and that
      positions come from the raw MoA trace rather than the aggregator's
      summary. A parser that dropped what it could not read would silently
      manufacture consensus.

  test_records_are_immutable
      lists in a frozen dataclass are still mutable in place. This defect
      appeared THREE times in Stages 0-1.
"""
import json
import re

import pytest

from elcapitan.records import validate_doc
from elcapitan.verdict import (
    APPROVE,
    DECISIONS,
    NEEDS_MORE_EVIDENCE,
    REJECT,
    MemberPosition,
    ReviewVerdict,
    TrialResult,
    parse_member_positions,
    verdict_to_dict,
    result_to_dict,
    validate_verdict_against_bundle,
)

NOW = "2026-08-24T23:30:00Z"
BUNDLE_EVIDENCE = ("EVD-001", "EVD-002", "EVD-003", "EVD-004", "EVD-005")


def position(model="claude-sonnet-5", decision=REJECT, confidence=0.8,
             evidence_cited=("EVD-001",), objections=("breaks the corpus read",)):
    return MemberPosition(model=model, decision=decision, objections=tuple(objections),
                          evidence_cited=tuple(evidence_cited), confidence=confidence,
                          raw_text="", parsed=True)


def verdict(decision=REJECT, evidence_cited=("EVD-001",), positions=None,
            dissent=False, extraction_incomplete=False, objections=("it breaks prod",)):
    return ReviewVerdict(
        verdict_id="VERD-001", schema_version=1, created_at=NOW,
        run_id="eiger-FIND-002-armA-n1", arm="A", decision=decision,
        objections=tuple(objections), evidence_cited=tuple(evidence_cited),
        member_positions=tuple(positions if positions is not None else [position()]),
        dissent=dissent, extraction_incomplete=extraction_incomplete,
        raw_trace_sha256="a" * 64)


# --- the decision itself ----------------------------------------------------

def test_the_three_decisions_are_the_only_ones():
    assert set(DECISIONS) == {APPROVE, REJECT, NEEDS_MORE_EVIDENCE}


def test_an_unknown_decision_is_refused_by_name():
    with pytest.raises(ValueError) as exc:
        verdict(decision="LOOKS_FINE")
    assert "LOOKS_FINE" in str(exc.value)


@pytest.mark.parametrize("decision", [APPROVE, REJECT, NEEDS_MORE_EVIDENCE])
def test_every_valid_decision_validates(decision):
    doc = verdict_to_dict(verdict(decision=decision,
                                  positions=[position(decision=decision)]))
    assert validate_doc("review-verdict", doc) == []


# --- the contamination check ------------------------------------------------

def test_a_verdict_citing_evidence_absent_from_its_bundle_is_rejected():
    # The failure this exists for: an Arm A verdict citing a telemetry
    # artifact it was never given. The text would read as evidence-grounded
    # and the arms would silently stop being independent.
    failures = validate_verdict_against_bundle(
        verdict(evidence_cited=("EVD-001", "EVD-099")),
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert len(failures) == 1
    assert "EVD-099" in failures[0]


def test_a_verdict_citing_only_present_evidence_passes():
    assert validate_verdict_against_bundle(
        verdict(evidence_cited=("EVD-001", "EVD-003")),
        bundle_evidence_ids=BUNDLE_EVIDENCE) == []


def test_a_member_position_citing_absent_evidence_is_caught_too():
    # A reference model's citations are as capable of crossing arms as the
    # aggregator's, and they are the ones nobody reads.
    failures = validate_verdict_against_bundle(
        verdict(positions=[position(evidence_cited=("EVD-404",))]),
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert any("EVD-404" in f for f in failures)


def test_an_unparsed_position_is_not_checked_for_citations():
    # It has no structured citations to check — only raw text. Reporting a
    # citation failure for it would be inventing one.
    raw = MemberPosition(model="m", decision="", objections=(), evidence_cited=(),
                         confidence=None, raw_text="I think EVD-404 matters",
                         parsed=False)
    assert validate_verdict_against_bundle(
        verdict(positions=[raw], extraction_incomplete=True),
        bundle_evidence_ids=BUNDLE_EVIDENCE) == []


# --- member positions: never silently dropped -------------------------------

def test_an_unparseable_member_position_keeps_its_raw_text():
    trace = [
        {"model": "claude-sonnet-5", "content": json.dumps(
            {"decision": "REJECT", "objections": ["severs the corpus"],
             "evidence_cited": ["EVD-001"], "confidence": 0.9})},
        {"model": "some-other-model", "content": "Honestly it depends on the workload."},
    ]
    positions, incomplete = parse_member_positions(trace)
    assert len(positions) == 2, "a position that cannot be parsed must not vanish"
    assert incomplete is True
    unparsed = [p for p in positions if not p.parsed]
    assert len(unparsed) == 1
    assert unparsed[0].raw_text == "Honestly it depends on the workload."
    assert unparsed[0].model == "some-other-model"


def test_a_fully_parseable_trace_is_not_marked_incomplete():
    trace = [{"model": "m1", "content": json.dumps(
        {"decision": "APPROVE", "objections": [], "evidence_cited": ["EVD-002"],
         "confidence": 0.6})}]
    positions, incomplete = parse_member_positions(trace)
    assert incomplete is False
    assert positions[0].parsed is True and positions[0].decision == APPROVE


def test_a_position_with_an_unknown_decision_is_unparsed_not_coerced():
    # Coercing "probably reject" to REJECT would fabricate a comparable
    # judgement out of one that was never made.
    trace = [{"model": "m1", "content": json.dumps({"decision": "probably reject"})}]
    positions, incomplete = parse_member_positions(trace)
    assert incomplete is True and positions[0].parsed is False
    assert "probably reject" in positions[0].raw_text


def test_an_empty_trace_is_incomplete_not_unanimous():
    # No positions is not agreement. A verdict claiming consensus from an
    # empty trace is the averaging failure in its purest form.
    positions, incomplete = parse_member_positions([])
    assert positions == ()
    assert incomplete is True


# --- dissent is retained, not averaged --------------------------------------

def test_disagreeing_positions_with_dissent_false_is_a_validation_failure():
    failures = validate_verdict_against_bundle(
        verdict(decision=REJECT, dissent=False,
                positions=[position(model="m1", decision=REJECT),
                           position(model="m2", decision=APPROVE)]),
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert any("dissent" in f.lower() for f in failures)


def test_disagreeing_positions_with_dissent_true_is_fine():
    assert validate_verdict_against_bundle(
        verdict(decision=REJECT, dissent=True,
                positions=[position(model="m1", decision=REJECT),
                           position(model="m2", decision=APPROVE)]),
        bundle_evidence_ids=BUNDLE_EVIDENCE) == []


def test_an_unparsed_position_alone_does_not_manufacture_agreement():
    # Two positions, one unreadable: whether they agreed is unknown, and
    # unknown must not be recorded as consensus.
    raw = MemberPosition(model="m2", decision="", objections=(), evidence_cited=(),
                         confidence=None, raw_text="unclear", parsed=False)
    failures = validate_verdict_against_bundle(
        verdict(dissent=False, extraction_incomplete=True,
                positions=[position(model="m1"), raw]),
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert any("extraction_incomplete" in f for f in failures)


def test_extraction_incomplete_must_be_true_when_a_position_is_unparsed():
    raw = MemberPosition(model="m2", decision="", objections=(), evidence_cited=(),
                         confidence=None, raw_text="unclear", parsed=False)
    failures = validate_verdict_against_bundle(
        verdict(extraction_incomplete=False, positions=[raw]),
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert any("extraction_incomplete" in f for f in failures)


# --- the reproducibility block ----------------------------------------------

REPRO = dict(input_bundle_hash="b" * 64, repository_commit="c" * 40,
             runtime_image_id="sha256:" + "d" * 64, model="claude-sonnet-5",
             model_version="20260501", moa_preset="balanced-3", moa_fanout="1",
             hermes_version="0.20.0",
             scanner_versions={"prowler": "5.37.1", "terraform": "1.15.8"})


def trial_result(**kw) -> TrialResult:
    params = dict(
        run_id="eiger-FIND-002-armA-n1", env="eiger", finding_id="FIND-002",
        arm="A", n=1, started_at=NOW, completed_at=NOW,
        verdict=verdict(), usage={"input_tokens": 1000, "output_tokens": 200,
                                  "cost_usd": 1.42, "provider": "anthropic"},
        scoring_valid=True, **REPRO)
    params.update(kw)
    return TrialResult(**params)


@pytest.mark.parametrize("field", sorted(REPRO))
def test_the_reproducibility_block_is_required(field):
    doc = result_to_dict(trial_result())
    assert doc[field], f"{field} missing — an experiment is not reproducible from names"
    del doc[field]
    assert validate_doc("trial-result", doc) != []


def test_the_engineers_usage_is_carried():
    doc = result_to_dict(trial_result())
    assert doc["usage"]["cost_usd"] == 1.42
    assert validate_doc("trial-result", doc) == []


def test_arm_and_n_are_carried():
    doc = result_to_dict(trial_result(run_id="eiger-FIND-002-armB-n5",
                                      arm="B", n=5))
    assert doc["arm"] == "B" and doc["n"] == 5


def test_a_trial_result_validates_against_its_schema():
    assert validate_doc("trial-result", result_to_dict(trial_result())) == []


def test_an_empty_scanner_versions_map_is_refused():
    doc = result_to_dict(trial_result(scanner_versions={}))
    assert validate_doc("trial-result", doc) != []


def test_the_run_id_must_agree_with_arm_and_n():
    # A result filed under the wrong run id contaminates the matrix silently.
    with pytest.raises(ValueError) as exc:
        trial_result(run_id="eiger-FIND-002-armB-n1", arm="A", n=1)
    assert "armB" in str(exc.value) or "arm" in str(exc.value)


# --- immutability: the defect that appeared three times ---------------------

@pytest.mark.parametrize("record,field", [
    ("verdict", "objections"), ("verdict", "evidence_cited"),
    ("verdict", "member_positions"), ("position", "objections"),
    ("position", "evidence_cited"),
])
def test_records_are_immutable(record, field):
    obj = verdict() if record == "verdict" else position()
    value = getattr(obj, field)
    assert isinstance(value, tuple), f"{record}.{field} is {type(value).__name__}, not a tuple"
    with pytest.raises((AttributeError, TypeError)):
        value.append("mutated")


def test_a_verdict_cannot_be_reassigned():
    v = verdict()
    with pytest.raises(AttributeError):
        v.decision = APPROVE


def test_a_trial_result_cannot_be_reassigned():
    r = trial_result()
    with pytest.raises(AttributeError):
        r.arm = "B"


def test_lists_passed_in_are_stored_as_tuples():
    # The three-times defect in its real form: a caller passes a list, the
    # dataclass stores the SAME list object, and the caller mutates it later.
    objections = ["first"]
    v = ReviewVerdict(verdict_id="VERD-001", schema_version=1, created_at=NOW,
                      run_id="eiger-FIND-002-armA-n1", arm="A", decision=REJECT,
                      objections=objections, evidence_cited=["EVD-001"],
                      member_positions=[position()], dissent=False,
                      extraction_incomplete=False, raw_trace_sha256="a" * 64)
    objections.append("added after the fact")
    assert v.objections == ("first",), "the record aliased the caller's list"
    assert isinstance(v.evidence_cited, tuple)
    assert isinstance(v.member_positions, tuple)


def test_a_position_whose_content_is_not_text_is_kept_as_raw_json():
    # Hermes' trace is not guaranteed to hand back a string — a provider that
    # returns structured content would otherwise hit a branch no test covered,
    # and a position would vanish from the trace with nothing to show for it.
    trace = [{"model": "m1", "content": {"decision": "REJECT", "why": "corpus"}}]
    positions, incomplete = parse_member_positions(trace)
    assert len(positions) == 1 and positions[0].parsed is False
    assert incomplete is True
    assert "REJECT" in positions[0].raw_text, "the content must survive verbatim"


def test_a_position_with_malformed_objections_is_unparsed_not_partially_kept():
    # Half-parsed is worse than unparsed: it looks comparable and is not.
    trace = [{"model": "m1", "content": json.dumps(
        {"decision": "REJECT", "objections": [{"text": "nested"}],
         "evidence_cited": ["EVD-001"], "confidence": 0.5})}]
    positions, incomplete = parse_member_positions(trace)
    assert positions[0].parsed is False and incomplete is True


def test_a_trace_entry_that_is_not_an_object_still_yields_a_position():
    positions, incomplete = parse_member_positions(["just a string", 42])
    assert len(positions) == 2 and incomplete is True
    assert all(not p.parsed for p in positions)


# --- assembly: the challenger's output becomes a record ---------------------
#
# The challenger writes /work/out/verdict.json — decision, objections,
# citations. Everything else in a ReviewVerdict is DERIVED here, host-side,
# from the raw MoA trace: the member positions, whether they dissented,
# whether extraction was complete. None of it is taken from the challenger's
# own account of its members, because the aggregator's summary of what the
# reference models thought is the aggregator's opinion, not theirs.

from elcapitan.verdict import assemble_verdict


def trace_entry(model, decision, cited=("EVD-001",)):
    return {"model": model, "content": json.dumps(
        {"decision": decision, "objections": [], "evidence_cited": list(cited),
         "confidence": 0.7})}


def test_member_positions_survive_into_the_verdict():
    v, failures = assemble_verdict(
        verdict_doc={"decision": "REJECT", "objections": ["breaks the corpus read"],
                     "evidence_cited": ["EVD-001"]},
        raw_trace=[trace_entry("m1", REJECT), trace_entry("m2", REJECT)],
        run_id="eiger-FIND-002-armB-n1", arm="B", verdict_id="VERD-001", now=NOW,
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert failures == []
    assert len(v.member_positions) == 2
    assert [p.model for p in v.member_positions] == ["m1", "m2"]
    assert v.decision == REJECT


def test_dissent_is_derived_from_the_trace_not_from_the_aggregator():
    v, _ = assemble_verdict(
        verdict_doc={"decision": REJECT, "objections": [], "evidence_cited": [],
                     "dissent": False},   # the aggregator says they agreed
        raw_trace=[trace_entry("m1", REJECT), trace_entry("m2", APPROVE)],
        run_id="eiger-FIND-002-armB-n1", arm="B", verdict_id="VERD-001", now=NOW,
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert v.dissent is True, "the trace disagreed; the aggregator's claim is not evidence"


def test_extraction_incomplete_is_derived_from_the_trace():
    v, _ = assemble_verdict(
        verdict_doc={"decision": REJECT, "objections": [], "evidence_cited": []},
        raw_trace=[trace_entry("m1", REJECT), {"model": "m2", "content": "hmm"}],
        run_id="eiger-FIND-002-armB-n1", arm="B", verdict_id="VERD-001", now=NOW,
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert v.extraction_incomplete is True
    assert v.dissent is True, "one member unreadable means agreement is unknown"


def test_assembly_reports_a_citation_the_bundle_never_held():
    _, failures = assemble_verdict(
        verdict_doc={"decision": REJECT, "objections": ["see EVD-099"],
                     "evidence_cited": ["EVD-099"]},
        raw_trace=[trace_entry("m1", REJECT)],
        run_id="eiger-FIND-002-armA-n1", arm="A", verdict_id="VERD-001", now=NOW,
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert any("EVD-099" in f for f in failures)


def test_an_unknown_decision_from_the_challenger_is_a_failure_not_a_crash():
    # The challenger is a model. It can return something outside the enum, and
    # a trial must record that rather than die assembling its own record.
    v, failures = assemble_verdict(
        verdict_doc={"decision": "probably fine", "objections": [],
                     "evidence_cited": []},
        raw_trace=[trace_entry("m1", REJECT)],
        run_id="eiger-FIND-002-armA-n1", arm="A", verdict_id="VERD-001", now=NOW,
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert v.decision == NEEDS_MORE_EVIDENCE
    assert any("probably fine" in f for f in failures)


def test_the_raw_trace_is_hashed_into_the_verdict():
    v, _ = assemble_verdict(
        verdict_doc={"decision": REJECT, "objections": [], "evidence_cited": []},
        raw_trace=[trace_entry("m1", REJECT)],
        run_id="eiger-FIND-002-armB-n1", arm="B", verdict_id="VERD-001", now=NOW,
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert re.match(r"^[0-9a-f]{64}$", v.raw_trace_sha256)


def test_an_assembled_verdict_validates_against_its_schema():
    v, _ = assemble_verdict(
        verdict_doc={"decision": APPROVE, "objections": [], "evidence_cited": ["EVD-002"]},
        raw_trace=[trace_entry("m1", APPROVE, cited=("EVD-002",))],
        run_id="eiger-FIND-002-armB-n1", arm="B", verdict_id="VERD-001", now=NOW,
        bundle_evidence_ids=BUNDLE_EVIDENCE)
    assert validate_doc("review-verdict", verdict_to_dict(v)) == []


def test_an_empty_trace_assembles_but_is_flagged():
    # Flagged for an ENSEMBLE, which was asked for positions and produced
    # none. A single-model challenger is covered separately: it was never
    # asked, so its empty trace is not an extraction failure.
    v, failures = assemble_verdict(
        verdict_doc={"decision": APPROVE, "objections": [], "evidence_cited": []},
        raw_trace=[], run_id="eiger-FIND-002-armB-n1", arm="B",
        verdict_id="VERD-001", now=NOW, bundle_evidence_ids=BUNDLE_EVIDENCE,
        composition="moa")
    assert v.member_positions == () and v.extraction_incomplete is True
    assert v.dissent is False, "no members is not disagreement either"


# --- single-model is a CHOICE, and the record has to say so -----------------
#
# The spec describes an MoA challenger and makes dissent a product
# requirement. In practice nothing produces an MoA trace, so every verdict so
# far reads `member_positions: []`, `extraction_incomplete: true` — which
# says "we tried to parse positions and could not". That is not what happened.
# No ensemble was ever run.
#
# The plan's own words: "MoA composition is held constant across arms.
# Single-model vs ensemble is a legitimate follow-up experiment, not this
# one." So running single-model is defensible. Silently reporting it as a
# parsing failure is not.

def test_a_single_model_challenger_says_so(): 
    v, _ = assemble_verdict(
        verdict_doc={"decision": REJECT, "objections": [], "evidence_cited": []},
        raw_trace=[], run_id="eiger-FIND-002-armB-n1", arm="B",
        verdict_id="VERD-001", now=NOW, bundle_evidence_ids=BUNDLE_EVIDENCE,
        composition="single-model")
    assert v.challenger_composition == "single-model"
    # And the absence of positions is then NOT an extraction failure.
    assert v.extraction_incomplete is False
    assert v.member_positions == ()


def test_an_moa_challenger_with_an_empty_trace_is_still_incomplete():
    # The distinction that matters: an ensemble that produced no readable
    # positions IS an extraction failure, and must keep saying so.
    v, _ = assemble_verdict(
        verdict_doc={"decision": REJECT, "objections": [], "evidence_cited": []},
        raw_trace=[], run_id="eiger-FIND-002-armB-n1", arm="B",
        verdict_id="VERD-001", now=NOW, bundle_evidence_ids=BUNDLE_EVIDENCE,
        composition="moa")
    assert v.extraction_incomplete is True


def test_the_composition_reaches_the_record():
    v, _ = assemble_verdict(
        verdict_doc={"decision": APPROVE, "objections": [], "evidence_cited": []},
        raw_trace=[], run_id="eiger-FIND-002-armB-n1", arm="B",
        verdict_id="VERD-001", now=NOW, bundle_evidence_ids=BUNDLE_EVIDENCE,
        composition="single-model")
    assert verdict_to_dict(v)["challenger_composition"] == "single-model"
    assert validate_doc("review-verdict", verdict_to_dict(v)) == []
