import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .hashing import sha256_bytes, sha256_file
from .paths import PathEscape, safe_resolve

EVIDENCE_DIR = "evidence"
EVIDENCE_ID = re.compile(r"^EVD-[0-9]{3,}$")

@dataclass(frozen=True)
class Collector:
    tool: str
    version: str
    identity: str

@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    type: str
    artifact_path: str
    sha256: str
    collected_at: str
    sensitivity: str
    command_id: str
    collector: Collector

    def to_dict(self) -> dict:
        return asdict(self)

def write_evidence(run_dir, evidence_id, type, payload: bytes, collector: Collector,
                   *, sensitivity: str = "internal", command_id: str = "",
                   now: str | None = None) -> EvidenceRef:
    if not EVIDENCE_ID.match(evidence_id):
        raise ValueError(f"evidence_id must match {EVIDENCE_ID.pattern}: {evidence_id!r}")
    if now is None:
        raise ValueError("now must be supplied explicitly so trials are reproducible")

    run_dir = Path(run_dir)
    (run_dir / EVIDENCE_DIR).mkdir(parents=True, exist_ok=True)
    relative = f"{EVIDENCE_DIR}/{evidence_id}.bin"
    # Exclusive creation: no exists()-then-write race, and duplicates fail loudly.
    with (run_dir / relative).open("xb") as handle:
        handle.write(payload)

    return EvidenceRef(evidence_id=evidence_id, type=type, artifact_path=relative,
                       sha256=sha256_bytes(payload), collected_at=now,
                       sensitivity=sensitivity, command_id=command_id,
                       collector=collector)

def verify_evidence(run_dir, ref: EvidenceRef) -> bool:
    """False on tamper, absence, or containment violation — never raises."""
    try:
        path = safe_resolve(run_dir, ref.artifact_path)
    except (PathEscape, FileNotFoundError, OSError):
        return False
    if not path.is_file():
        return False
    return sha256_file(path) == ref.sha256
