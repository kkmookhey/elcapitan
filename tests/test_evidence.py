import os

import pytest
from elcapitan.evidence import Collector, write_evidence, verify_evidence
from elcapitan.paths import PathEscape

C = Collector(tool="az", version="2.64.0", identity="anna-scanner")
NOW = "2026-08-08T12:00:00Z"

def test_round_trip_verifies(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "api", b'{"ok":true}', C, now=NOW)
    assert verify_evidence(tmp_path, ref) is True

def test_detects_tampering(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "api", b'{"ok":true}', C, now=NOW)
    (tmp_path / ref.artifact_path).write_bytes(b'{"ok":false}')
    assert verify_evidence(tmp_path, ref) is False

def test_missing_artifact_is_false_not_an_exception(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "api", b"x", C, now=NOW)
    (tmp_path / ref.artifact_path).unlink()
    assert verify_evidence(tmp_path, ref) is False

def test_escaping_artifact_path_is_false_not_an_exception(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "api", b"x", C, now=NOW)
    escaped = type(ref)(**{**ref.to_dict(), "artifact_path": "../escape",
                           "collector": C})
    assert verify_evidence(tmp_path, escaped) is False

def test_evidence_id_must_match_the_required_pattern(tmp_path):
    with pytest.raises(ValueError, match="evidence_id"):
        write_evidence(tmp_path, "../oops", "api", b"x", C, now=NOW)

def test_duplicate_evidence_id_is_rejected_atomically(tmp_path):
    write_evidence(tmp_path, "EVD-001", "api", b"x", C, now=NOW)
    with pytest.raises(FileExistsError):
        write_evidence(tmp_path, "EVD-001", "api", b"y", C, now=NOW)

def test_now_must_be_supplied(tmp_path):
    with pytest.raises(ValueError, match="now"):
        write_evidence(tmp_path, "EVD-001", "api", b"x", C)

@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses permission bits")
def test_unreadable_artifact_is_false_not_an_exception(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "api", b"x", C, now=NOW)
    artifact = tmp_path / ref.artifact_path
    artifact.chmod(0o000)
    try:
        assert verify_evidence(tmp_path, ref) is False
    finally:
        artifact.chmod(0o644)
