"""ASFF -> OCSF, for AWS Security Hub findings.

## Read this before trusting the output

**Security Hub does not emit OCSF.** Its native format is ASFF
(`SchemaVersion: 2018-10-08`); the OCSF form comes from Amazon Security Lake,
a separate and substantially more expensive service. The plan's Task 6 asked
for "Security Hub's OCSF export", and no such thing exists at the Security Hub
layer.

So **this mapping is ours, not AWS's.** It is written against a real finding
captured live from account 331145994818 on 2026-08-25
(`tests/fixtures/securityhub-asff-real.json`), and every converted document
carries `unmapped.converted_by = "elcapitan.asff"` so that a record read six
months from now cannot be mistaken for something AWS produced. If a result
ever turns on a Security Hub finding, the conversion is a thing to check, not
a thing to assume.

## What the real finding taught, that a shaped one could not

A first pass at this gate used a document built to the shape Security Lake
emits. It found three real dialect gaps — provider case, `severity_id` vs
`severity`, `time` vs `time_dt` — all of which were fixed in `finding.py`.

It could not have found the fourth, because nobody writing a fixture by hand
writes this:

    "Resources": [{"Id": "AWS::::Account:331145994818", "Type": "AwsAccount"}]

**That is not an ARN.** Security Hub reports account-level controls against a
pseudo-identifier that no ARN parser accepts. `elcapitan.cloud` cannot
re-query it, which means a trial over an account-scoped finding cannot be
verified and must fail at pre-flight rather than produce an unverifiable run.
The uid is carried through verbatim precisely so that failure happens loudly
and for the right reason, instead of being normalised into something that
looks queryable.
"""
import json

# ASFF severity labels -> the OCSF severity strings finding.py already
# understands. Security Hub also sends a Normalized 0-100 integer, which is
# deliberately not used: the label is what a human sees in the console, and
# two representations of one fact invite them to disagree.
_SEVERITY = {
    "INFORMATIONAL": "Informational",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}

# OCSF Compliance Finding, class_uid 2003 in OCSF 1.1. Security Hub's control
# findings are compliance findings, not detection findings, and mapping them
# to the detection class would put them in the wrong table for anyone who
# later reads these records as OCSF.
_CLASS_UID = 2003
_CLASS_NAME = "Compliance Finding"


def asff_to_ocsf(finding: dict) -> dict:
    """One ASFF finding as an OCSF document `normalise_ocsf` accepts.

    Raises ValueError on anything that is not ASFF. Silently converting a
    document that was already OCSF would double-wrap it, and the result would
    validate while meaning something different.
    """
    if not isinstance(finding, dict) or "SchemaVersion" not in finding:
        raise ValueError(
            "not an ASFF finding: no SchemaVersion. Security Hub findings carry "
            "SchemaVersion 2018-10-08; a document without one is either already "
            "OCSF or is not a finding at all, and converting it would produce "
            "something that validates and means the wrong thing.")

    resources = finding.get("Resources") or [{}]
    primary = resources[0] if isinstance(resources[0], dict) else {}
    compliance = finding.get("Compliance") or {}
    severity = finding.get("Severity") or {}
    product = finding.get("ProductName") or "Security Hub"

    return {
        "class_uid": _CLASS_UID,
        "class_name": _CLASS_NAME,
        "category_uid": 2,
        "activity_id": 1,
        "severity": _SEVERITY.get(str(severity.get("Label", "")).upper(), ""),
        # ASFF timestamps are already RFC3339 strings, so time_dt is the right
        # field and no epoch conversion is involved.
        "time_dt": finding.get("UpdatedAt") or finding.get("CreatedAt") or "",
        "metadata": {
            "version": "1.1.0",
            "product": {"name": product, "vendor_name": "AWS",
                        "version": finding.get("SchemaVersion", "")},
            # The control id is the ONLY thing identifying which check ran.
            # Prowler puts this in event_code; without it a Security Hub
            # finding is "something failed on this account".
            "event_code": compliance.get("SecurityControlId")
                          or finding.get("GeneratorId", ""),
        },
        "cloud": {
            "provider": "AWS",   # finding.cloud_target lower-cases it
            "region": finding.get("Region", ""),
            "account": {"uid": finding.get("AwsAccountId", ""),
                        "type": "AWS Account"},
        },
        "resources": [{
            # VERBATIM. See the module docstring: an account-scoped control
            # reports "AWS::::Account:<id>", which is not an ARN, and
            # normalising it into something ARN-shaped would turn an honest
            # "this cannot be re-queried" into a query against the wrong
            # thing.
            "uid": primary.get("Id", ""),
            "type": primary.get("Type", ""),
            "region": primary.get("Region", finding.get("Region", "")),
            "cloud_partition": primary.get("Partition", "aws"),
        }],
        "finding_info": {
            "uid": finding.get("Id", ""),
            "title": finding.get("Title", ""),
            "desc": finding.get("Description", ""),
        },
        "compliance": {
            "status": compliance.get("Status", ""),
            "control": compliance.get("SecurityControlId", ""),
            "standards": [s.get("StandardsId", "") for s
                          in (compliance.get("AssociatedStandards") or [])
                          if isinstance(s, dict)],
        },
        "unmapped": {
            # The honesty marker. This document looks like OCSF and was not
            # produced by anything at AWS.
            "converted_by": "elcapitan.asff",
            "source_format": "ASFF",
            "source_schema_version": finding.get("SchemaVersion", ""),
            "generator_id": finding.get("GeneratorId", ""),
            "record_state": finding.get("RecordState", ""),
            "product_arn": finding.get("ProductArn", ""),
            "remediation": json.dumps(finding.get("Remediation") or {},
                                      sort_keys=True),
        },
    }
