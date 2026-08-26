import json
import os
from pathlib import Path

import fake_az

from elcapitan.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-azure-sample.json"


def test_cli_ingests_a_finding_and_prints_the_prioritized_case(tmp_path, capsys):
    args = [
        "intake", str(FIXTURE), "--tenant", "TEN-001",
        "--db", str(tmp_path / "product.db"),
        "--artifacts", str(tmp_path / "artifacts"),
        "--asset-criticality", "0.8", "--reachable",
    ]
    assert main(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output) == 1
    assert output[0]["case"]["state"] == "prioritized"
    assert output[0]["case_created"] is True
    assert output[0]["case"]["priority"]["score"] == 66

    assert main(args) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay[0]["duplicate"] is True
    assert replay[0]["case_id"] == output[0]["case_id"]


def test_cli_validates_case_with_scoped_read_only_cloud_identity(
        tmp_path, capsys, monkeypatch):
    db = tmp_path / "product.db"
    artifacts = tmp_path / "artifacts"
    assert main([
        "intake", str(FIXTURE), "--tenant", "TEN-001",
        "--db", str(db), "--artifacts", str(artifacts),
    ]) == 0
    ingested = json.loads(capsys.readouterr().out)[0]

    bin_dir = fake_az.install(tmp_path / "bin")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    for name, value in fake_az.scanner_credentials().items():
        monkeypatch.setenv(name, value)
    assert main([
        "validate", "--case", ingested["case_id"],
        "--db", str(db), "--artifacts", str(artifacts),
    ]) == 0
    validated = json.loads(capsys.readouterr().out)
    assert validated["case"]["state"] == "validated"
    assert validated["findings"][0]["status"] == "confirmed"
    assert validated["record"]["body"]["evidence"][0]["collector"]["identity"] == (
        "read-only-scanner")
