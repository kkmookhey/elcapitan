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


def normalise_ocsf(raw: dict, *, run_dir, finding_id: str,
                   collector: Collector, now: str) -> dict:
    if "class_uid" not in raw:
        raise ValueError("input is not an OCSF finding: missing class_uid")

    metadata = raw.get("metadata", {})
    product = metadata.get("product", {})
    cloud = raw.get("cloud", {})
    resources = raw.get("resources") or [{}]
    primary = resources[0]

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
            "provider": cloud.get("provider", ""),
            "account": cloud.get("account", {}).get("uid", ""),
            "region": cloud.get("region", ""),
            "observed_at": raw.get("time_dt", ""),
        },
        "resource": {
            "uid": primary.get("uid", ""),
            "type": primary.get("type", ""),
        },
        "severity": raw.get("severity", ""),
        "raw_event": raw_ref.to_dict(),
        "vendor_extensions": dict(raw.get("unmapped", {})),
    }
