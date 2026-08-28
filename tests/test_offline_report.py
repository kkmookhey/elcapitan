import json
import stat
from pathlib import Path

from elcapitan.offline_report import write_offline_report


FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"


def test_offline_report_uses_shadow_intake_and_restricted_outputs(tmp_path):
    finding = json.loads(FIXTURE.read_text())
    source = tmp_path / "export.json"
    source.write_text(json.dumps([finding]))
    json_output = tmp_path / "report.json"
    markdown_output = tmp_path / "report.md"

    report = write_offline_report(
        input_path=source, tenant_id="CUSTOMER-OFFLINE",
        workdir=tmp_path / "work", json_output=json_output,
        markdown_output=markdown_output,
    )

    assert report["intake"]["accepted_failures"] == 1
    assert report["coverage"]["supported_findings"] == 1
    assert report["safety_boundary"]["cloud_requests"] is False
    assert report["priority"]["classification"] == "scanner_evidence_provisional"
    assert stat.S_IMODE(json_output.stat().st_mode) == 0o600
    assert stat.S_IMODE(markdown_output.stat().st_mode) == 0o600
    assert "Storage account has 'Public Network Access' disabled" in (
        markdown_output.read_text())


def test_offline_report_refuses_to_overwrite_outputs(tmp_path):
    finding = json.loads(FIXTURE.read_text())
    source = tmp_path / "export.json"
    source.write_text(json.dumps([finding]))
    output = tmp_path / "report.json"
    output.write_text("keep")

    try:
        write_offline_report(
            input_path=source, tenant_id="CUSTOMER-OFFLINE",
            workdir=tmp_path / "work", json_output=output,
            markdown_output=tmp_path / "report.md",
        )
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing output should not be overwritten")
    assert output.read_text() == "keep"
