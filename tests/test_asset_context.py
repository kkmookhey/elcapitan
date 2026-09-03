import pytest

from elcapitan.asset_context import asset_key, parse_asset_contexts
from elcapitan.intake import IntakeContext


RESOURCE = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/"
    "resourceGroups/Test/providers/Microsoft.Storage/storageAccounts/example")


def row(**overrides):
    document = {
        "resource_uid": RESOURCE,
        "environment": "production",
        "owner": "payments-platform",
        "asset_criticality": .9,
        "internet_exposed": True,
        "reachable": True,
        "runtime_dependency": True,
        "compensating_control_strength": .2,
        "service_ids": ["payments"],
        "context_source": "trial-asset-inventory",
        "observed_at": "2026-09-01T20:00:00Z",
        "evidence_references": ["azure-config:storage/publicNetworkAccess"],
        "synthetic_business_context": True,
    }
    document.update(overrides)
    return document


def test_asset_context_is_exactly_keyed_and_preserves_provenance():
    parsed = parse_asset_contexts([row()])
    context = parsed[asset_key(RESOURCE.upper())]

    assert context.owner == "payments-platform"
    assert context.synthetic_business_context is True
    assert context.evidence_references == (
        "azure-config:storage/publicNetworkAccess",)
    assert len(context.context_digest) == 64
    intake = context.intake_context(
        IntakeContext(exploit_probability=.4, known_exploited=True))
    assert intake.asset_criticality == .9
    assert intake.exploit_probability == .4
    assert intake.known_exploited is True
    assert intake.internet_exposed is True
    assert intake.service_ids == ("payments",)


def test_asset_context_rejects_duplicate_normalized_arm_ids():
    with pytest.raises(ValueError, match="duplicate resource_uid"):
        parse_asset_contexts([row(), row(resource_uid=RESOURCE.upper())])


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"environment": "customer-facing"}, "environment"),
        ({"asset_criticality": 2}, "between 0 and 1"),
        ({"internet_exposed": "true"}, "boolean or null"),
        ({"owner": ""}, "owner is required"),
        ({"criticality": .8}, "unknown field"),
        ({"evidence_references": []}, "must not be empty"),
    ],
)
def test_asset_context_rejects_ambiguous_or_invalid_values(overrides, message):
    with pytest.raises(ValueError, match=message):
        parse_asset_contexts([row(**overrides)])
