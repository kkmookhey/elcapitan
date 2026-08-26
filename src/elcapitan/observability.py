"""Deterministic usage analysis for safe change-window candidates."""
from __future__ import annotations

import json
import math
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import mean
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .constants import observer_env_map


class UsageAnalysisError(ValueError):
    pass


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise UsageAnalysisError("timestamp must be non-empty RFC3339 text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageAnalysisError(f"invalid RFC3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise UsageAnalysisError(f"timestamp must include a timezone: {value!r}")
    return parsed


def utc_text(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class UsageSample:
    timestamp: str
    requests: float
    errors: float = 0
    p95_latency_ms: float = 0

    def __post_init__(self) -> None:
        parse_timestamp(self.timestamp)
        for name in ("requests", "errors", "p95_latency_ms"):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value < 0):
                raise UsageAnalysisError(f"{name} must be a non-negative number")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class WindowPolicy:
    timezone: str = "UTC"
    duration_minutes: int = 60
    notice_hours: int = 24
    allowed_weekdays: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6)
    allowed_start_hours: tuple[int, ...] = tuple(range(24))
    candidate_count: int = 3
    minimum_profile_samples: int = 2

    def __post_init__(self) -> None:
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise UsageAnalysisError(f"unknown timezone: {self.timezone}") from exc
        integer_fields = {
            "duration_minutes": self.duration_minutes, "notice_hours": self.notice_hours,
            "candidate_count": self.candidate_count,
            "minimum_profile_samples": self.minimum_profile_samples,
        }
        if any(isinstance(value, bool) or not isinstance(value, int)
               for value in integer_fields.values()):
            raise UsageAnalysisError("window policy counts and durations must be integers")
        if self.duration_minutes <= 0 or self.notice_hours < 0:
            raise UsageAnalysisError("window duration must be positive and notice non-negative")
        if not 1 <= self.candidate_count <= 10:
            raise UsageAnalysisError("candidate_count must be between 1 and 10")
        if self.minimum_profile_samples < 1:
            raise UsageAnalysisError("minimum_profile_samples must be positive")
        if not self.allowed_weekdays or any(
                isinstance(day, bool) or not isinstance(day, int) or day not in range(7)
                for day in self.allowed_weekdays):
            raise UsageAnalysisError("allowed_weekdays must contain values from 0 through 6")
        if not self.allowed_start_hours or any(
                isinstance(hour, bool) or not isinstance(hour, int) or hour not in range(24)
                for hour in self.allowed_start_hours):
            raise UsageAnalysisError("allowed_start_hours must contain values from 0 through 23")
        object.__setattr__(self, "allowed_weekdays", tuple(dict.fromkeys(self.allowed_weekdays)))
        object.__setattr__(self, "allowed_start_hours", tuple(dict.fromkeys(self.allowed_start_hours)))

    def to_dict(self) -> dict:
        value = asdict(self)
        value["allowed_weekdays"] = list(self.allowed_weekdays)
        value["allowed_start_hours"] = list(self.allowed_start_hours)
        return value


@dataclass(frozen=True)
class WindowCandidate:
    candidate_id: str
    starts_at: str
    ends_at: str
    timezone: str
    local_start: str
    historical_samples: int
    average_requests: float
    average_errors: float
    average_p95_latency_ms: float
    rank: int

    def to_dict(self) -> dict:
        return asdict(self)


def load_usage_samples(path) -> tuple[UsageSample, ...]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = document.get("samples") if isinstance(document, dict) else document
    if not isinstance(rows, list) or not rows:
        raise UsageAnalysisError("usage input must contain a non-empty samples array")
    samples = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise UsageAnalysisError(f"usage sample {index} must be an object")
        try:
            samples.append(UsageSample(
                timestamp=row["timestamp"], requests=row["requests"],
                errors=row.get("errors", 0),
                p95_latency_ms=row.get("p95_latency_ms", 0),
            ))
        except KeyError as exc:
            raise UsageAnalysisError(f"usage sample {index} is missing {exc.args[0]}") from exc
    return tuple(samples)


def candidate_windows(samples: tuple[UsageSample, ...], *, policy: WindowPolicy,
                      now: str) -> tuple[WindowCandidate, ...]:
    if not samples:
        raise UsageAnalysisError("at least one usage sample is required")
    zone = ZoneInfo(policy.timezone)
    profiles: dict[tuple[int, int], list[UsageSample]] = {}
    for sample in samples:
        local = parse_timestamp(sample.timestamp).astimezone(zone)
        key = (local.weekday(), local.hour)
        if key[0] in policy.allowed_weekdays and key[1] in policy.allowed_start_hours:
            profiles.setdefault(key, []).append(sample)
    eligible = [
        (key, values) for key, values in profiles.items()
        if len(values) >= policy.minimum_profile_samples
    ]
    if not eligible:
        raise UsageAnalysisError("telemetry has no samples in an allowed change-window profile")

    ranked = sorted(
        eligible,
        key=lambda item: (
            mean(sample.requests for sample in item[1]),
            mean(sample.errors for sample in item[1]),
            mean(sample.p95_latency_ms for sample in item[1]),
            item[0],
        ),
    )
    earliest = parse_timestamp(now).astimezone(zone) + timedelta(hours=policy.notice_hours)
    candidates = []
    for rank, ((weekday, hour), values) in enumerate(ranked, start=1):
        days = (weekday - earliest.weekday()) % 7
        start = earliest.replace(hour=hour, minute=0, second=0, microsecond=0) + timedelta(days=days)
        if start < earliest:
            start += timedelta(days=7)
        end = start + timedelta(minutes=policy.duration_minutes)
        candidates.append(WindowCandidate(
            candidate_id=f"CAND-{len(candidates) + 1:03d}",
            starts_at=utc_text(start), ends_at=utc_text(end), timezone=policy.timezone,
            local_start=start.isoformat(), historical_samples=len(values),
            average_requests=round(mean(sample.requests for sample in values), 3),
            average_errors=round(mean(sample.errors for sample in values), 3),
            average_p95_latency_ms=round(
                mean(sample.p95_latency_ms for sample in values), 3),
            rank=rank,
        ))
        if len(candidates) == policy.candidate_count:
            break
    return tuple(candidates)


def _observer_environment(host_env, *, provider: str) -> dict[str, str]:
    mapping = observer_env_map(provider)
    missing = sorted(name for name in mapping if not host_env.get(name))
    if missing:
        raise UsageAnalysisError(
            f"observability credentials for provider {provider!r} are not set: "
            + ", ".join(missing))
    environment = {target: host_env[source] for source, target in mapping.items()}
    environment["PATH"] = host_env.get("PATH", os.defpath)
    return environment


def capture_azure_monitor_usage(resource_uid: str, *, start: str, end: str,
                                host_env, metric: str = "Transactions",
                                interval: str = "PT1H",
                                timeout_seconds: float = 120) -> tuple[UsageSample, ...]:
    """Read Azure Monitor request counts with a dedicated observer identity."""
    if not resource_uid.startswith("/subscriptions/"):
        raise UsageAnalysisError("Azure Monitor resource must be an ARM resource id")
    start_at, end_at = parse_timestamp(start), parse_timestamp(end)
    if start_at >= end_at:
        raise UsageAnalysisError("Azure Monitor start must be earlier than end")
    if not metric or not interval or timeout_seconds <= 0:
        raise UsageAnalysisError("Azure Monitor metric, interval, and timeout are required")
    environment = _observer_environment(host_env, provider="azure")
    with tempfile.TemporaryDirectory(prefix="elcap-observer-az-") as config_dir:
        environment["AZURE_CONFIG_DIR"] = config_dir
        commands = (
            (
                "sign in the observer principal",
                ("az", "login", "--service-principal", "--username",
                 environment["AZURE_CLIENT_ID"], "--password",
                 environment["AZURE_CLIENT_SECRET"], "--tenant",
                 environment["AZURE_TENANT_ID"], "--output", "json",
                 "--only-show-errors"),
            ),
            (
                "read Azure Monitor metrics",
                ("az", "monitor", "metrics", "list", "--resource", resource_uid,
                 "--metric", metric, "--aggregation", "Total", "--interval", interval,
                 "--start-time", utc_text(start_at), "--end-time", utc_text(end_at),
                 "--output", "json", "--only-show-errors"),
            ),
        )
        outputs = []
        for label, argv in commands:
            try:
                completed = subprocess.run(
                    argv, env=environment, capture_output=True, text=True,
                    check=False, timeout=timeout_seconds)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise UsageAnalysisError(f"could not {label}: {exc}") from exc
            if completed.returncode != 0:
                detail = completed.stderr.strip() or completed.stdout.strip()
                raise UsageAnalysisError(
                    f"could not {label}: exited {completed.returncode}: {detail}")
            outputs.append(completed.stdout)
    try:
        document = json.loads(outputs[-1])
    except (json.JSONDecodeError, RecursionError) as exc:
        raise UsageAnalysisError(f"Azure Monitor returned invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("value"), list):
        raise UsageAnalysisError("Azure Monitor response has no value array")
    totals: dict[str, float] = {}
    for metric_value in document["value"]:
        if not isinstance(metric_value, dict):
            continue
        for series in metric_value.get("timeseries", ()):
            if not isinstance(series, dict):
                continue
            for point in series.get("data", ()):
                if not isinstance(point, dict) or "timeStamp" not in point:
                    continue
                total = point.get("total")
                if total is None:
                    continue
                if (isinstance(total, bool) or not isinstance(total, (int, float))
                        or not math.isfinite(total) or total < 0):
                    raise UsageAnalysisError("Azure Monitor returned an invalid Total value")
                timestamp = utc_text(parse_timestamp(point["timeStamp"]))
                totals[timestamp] = totals.get(timestamp, 0) + total
    if not totals:
        raise UsageAnalysisError("Azure Monitor returned no populated metric points")
    return tuple(
        UsageSample(timestamp=timestamp, requests=total)
        for timestamp, total in sorted(totals.items())
    )
