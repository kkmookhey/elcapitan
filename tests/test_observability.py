import json
import os

import pytest
import fake_az

from elcapitan.observability import (
    UsageAnalysisError, UsageSample, WindowPolicy, candidate_windows,
    capture_azure_monitor_usage, load_usage_samples,
)


def test_usage_profiles_produce_ranked_future_policy_candidates():
    samples = (
        UsageSample("2026-08-17T02:00:00Z", 5, 0, 40),
        UsageSample("2026-08-24T02:00:00Z", 7, 0, 50),
        UsageSample("2026-08-17T03:00:00Z", 50, 2, 100),
        UsageSample("2026-08-24T03:00:00Z", 40, 1, 90),
    )
    candidates = candidate_windows(
        samples,
        policy=WindowPolicy(
            timezone="UTC", notice_hours=24, allowed_weekdays=(0,),
            allowed_start_hours=(2, 3), minimum_profile_samples=2),
        now="2026-08-26T12:00:00Z",
    )
    assert [item.candidate_id for item in candidates] == ["CAND-001", "CAND-002"]
    assert candidates[0].average_requests == 6
    assert candidates[0].starts_at == "2026-08-31T02:00:00Z"
    assert candidates[0].ends_at == "2026-08-31T03:00:00Z"


def test_usage_loader_requires_timezone_and_nonnegative_values(tmp_path):
    path = tmp_path / "usage.json"
    path.write_text(json.dumps({"samples": [{
        "timestamp": "2026-08-26T01:00:00", "requests": 1,
    }]}))
    with pytest.raises(UsageAnalysisError, match="timezone"):
        load_usage_samples(path)
    with pytest.raises(UsageAnalysisError, match="requests"):
        UsageSample("2026-08-26T01:00:00Z", -1)


def test_policy_refuses_telemetry_without_an_allowed_profile():
    with pytest.raises(UsageAnalysisError, match="no samples"):
        candidate_windows(
            (UsageSample("2026-08-24T02:00:00Z", 1),),
            policy=WindowPolicy(allowed_weekdays=(1,)),
            now="2026-08-26T12:00:00Z",
        )


def test_azure_monitor_usage_uses_only_the_observer_identity(tmp_path):
    bin_dir = fake_az.install(tmp_path / "bin")
    host_env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        **fake_az.observer_credentials(),
        **fake_az.scanner_credentials(),
        "AZURE_CLIENT_SECRET": "ambient-secret-must-not-be-used",
    }
    samples = capture_azure_monitor_usage(
        fake_az.RESOURCE_UID, start="2026-08-01T00:00:00Z",
        end="2026-08-25T00:00:00Z", host_env=host_env)
    assert len(samples) == 15
    assert sum(sample.requests for sample in samples) == 1
    calls = fake_az.calls(bin_dir)
    assert [call["operation"] for call in calls] == [
        "login", "monitor metrics list",
    ]
    assert all(not any(name.startswith("ELCAP_SCANNER") for name in call["env"])
               for call in calls)
    assert all("AZURE_CONFIG_DIR" in call["env"] for call in calls)
