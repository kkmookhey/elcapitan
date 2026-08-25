"""Normalise a scanner's OCSF finding without discarding provenance.

The intake contract is 'one OCSF finding', not 'the Prowler JSON'. Prowler
emits the OCSF Detection Finding class; so do other sources. Normalisation
must therefore preserve enough to identify, re-fetch and audit the original.

The raw event is written as evidence *inside the trial run directory*
(`run_dir`), not a shared findings directory: the harness copies the run
directory verbatim into each trial bundle, so `raw_event.artifact_path`
must resolve there or a later validator cannot re-fetch/audit the original.
"""
from .evidence import Collector, write_evidence
from .hashing import canonical_json


# OCSF severity_id -> name (OCSF 1.1, Security Finding class). Security Hub
# sends the id and no `severity` string; Prowler sends the string. Both are
# legal OCSF, and an intake that read only one of them would silently report
# every finding from the other producer as severity-less — which reaches the
# challenger's context, where it looks like the scanner had no opinion.
OCSF_SEVERITY = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
                 4: "High", 5: "Critical", 6: "Fatal"}


def _severity(raw: dict) -> str:
    severity = raw.get("severity")
    if isinstance(severity, str) and severity:
        return severity
    severity_id = raw.get("severity_id")
    if isinstance(severity_id, bool) or not isinstance(severity_id, int):
        return ""
    # An id outside the table is reported as itself rather than as "Unknown":
    # a new OCSF severity is a fact about the producer, and mapping it to
    # Unknown would hide that a scanner is speaking a newer dialect.
    return OCSF_SEVERITY.get(severity_id, f"severity_id={severity_id}")


def _observed_at(raw: dict) -> str:
    """RFC3339, from whichever of OCSF's two time fields the producer sent.

    `time_dt` is the string form and `time` is epoch milliseconds. Prowler
    sends the first, Security Hub the second, and both are legal. Reading only
    time_dt drops the timestamp for every Security Hub finding — and
    observed_at is provenance, which is the part of a record that has to
    survive for the result to mean anything later.
    """
    time_dt = raw.get("time_dt")
    if isinstance(time_dt, str) and time_dt:
        return time_dt
    epoch = raw.get("time")
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)):
        return ""
    from datetime import datetime, UTC
    # OCSF `time` is milliseconds. Seconds would put it in 1970; the guard is
    # a sanity bound, not a parse.
    seconds = epoch / 1000 if epoch > 1e11 else epoch
    try:
        return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def cloud_target(raw: dict) -> tuple[str, str, str]:
    """(provider, resource_uid, region) for the raw OCSF finding's primary
    resource — the same three values normalise_ocsf writes into the record.

    One definition, two importers. bin/run-trial.sh needs this target *before*
    the run directory exists, so it can capture the pre-trial cloud state (and
    fail on a bad credential or an unsupported provider) without burning the
    trial id; normalise_ocsf needs the same three fields for the record it
    writes. Two independently-typed copies would let a rename on one side
    silently strand the other — the failure mode constants.py exists to stop.

    region is coerced to str. An OCSF event with an explicit `"cloud":
    {"region": null}` is legal JSON and yields `.get("region", "")` -> None,
    not "" — the default only applies when the key is absent, not when it is
    present and null. That None used to reach cloud.CloudState.region and
    from there `to_dict`, which wrote a literal `"region": null` to
    cloud-state-before.json. Nothing at capture time rejected it, so the
    trial ran and burned its immutable id; only at validation time did
    `from_dict`'s `isinstance(region, str)` check reject the anchor — the
    failure landed at the end of the trial instead of at its pre-flight
    check, where every other bad-input case in this path is caught. Coercing
    here closes it at the source for both importers at once.
    """
    cloud = raw.get("cloud") or {}
    resources = raw.get("resources") or [{}]
    primary = resources[0] if isinstance(resources[0], dict) else {}
    region = cloud.get("region", "")
    if not isinstance(region, str):
        region = "" if region is None else str(region)
    # Lower-cased because this string keys constants.SCANNER_ENV_MAPS and the
    # cloud-capture dispatch. Prowler writes "aws", Security Hub writes "AWS",
    # and an unnormalised "AWS" surfaces as "no scanner credential map for
    # provider \'AWS\'" — a confusing way to say "wrong case".
    provider = cloud.get("provider", "")
    return (provider.lower() if isinstance(provider, str) else "",
            primary.get("uid", ""), region)


def normalise_ocsf(raw: dict, *, run_dir, finding_id: str,
                   collector: Collector, now: str) -> dict:
    if "class_uid" not in raw:
        raise ValueError("input is not an OCSF finding: missing class_uid")

    metadata = raw.get("metadata", {})
    product = metadata.get("product", {})
    cloud = raw.get("cloud", {})
    resources = raw.get("resources") or [{}]
    primary = resources[0]
    provider, resource_uid, region = cloud_target(raw)

    raw_ref = write_evidence(
        run_dir, "EVD-001", "scanner_raw_event",
        canonical_json(raw), collector,
        command_id="CMD-000", now=now,
    )

    return {
        "finding_id": finding_id,
        "ocsf": {
            "version": metadata.get("version", ""),
            "class_uid": raw["class_uid"],
            "original_uid": raw.get("finding_info", {}).get("uid", ""),
            "title": raw.get("finding_info", {}).get("title", ""),
        },
        "provenance": {
            "product": product.get("name", ""),
            "product_version": product.get("version", ""),
            "provider": provider,
            "account": cloud.get("account", {}).get("uid", ""),
            "region": region,
            "observed_at": _observed_at(raw),
        },
        "resource": {
            "uid": resource_uid,
            "type": primary.get("type", ""),
        },
        "severity": _severity(raw),
        "raw_event": raw_ref.to_dict(),
        "vendor_extensions": dict(raw.get("unmapped", {})),
    }
