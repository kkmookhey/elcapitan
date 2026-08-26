import pytest

from elcapitan.priority import (
    PriorityPolicy, PrioritySignals, assess_priority,
)


def signals(**overrides):
    values = dict(
        severity="high", asset_criticality=0.8, exploit_probability=0.6,
        internet_exposed=True, reachable=True, known_exploited=False,
        active_exploitation=False, runtime_dependency=True,
        compensating_control_strength=0.25, evidence_ids=("EVD-001",),
    )
    values.update(overrides)
    return PrioritySignals(**values)


def test_default_policy_produces_explainable_bounded_priority():
    assessment = assess_priority("RISK-001", signals())
    assert assessment.score == 83.0
    assert assessment.urgency == "urgent"
    assert "asset is internet exposed" in assessment.factors
    assert assessment.evidence_ids == ("EVD-001",)


def test_compensating_controls_reduce_priority_transparently():
    without = assess_priority(
        "RISK-001", signals(compensating_control_strength=0))
    with_controls = assess_priority(
        "RISK-002", signals(compensating_control_strength=1))
    assert without.score - with_controls.score == 20


def test_customer_policy_can_change_weights_without_changing_code():
    policy = PriorityPolicy(internet_exposed_weight=40)
    assessment = assess_priority("RISK-001", signals(), policy=policy)
    assert assessment.score == 100


def test_invalid_signal_ranges_are_refused():
    with pytest.raises(ValueError, match="asset_criticality"):
        signals(asset_criticality=1.1)


def test_thresholds_must_be_ordered():
    with pytest.raises(ValueError, match="thresholds"):
        PriorityPolicy(normal_threshold=70, high_threshold=60)
