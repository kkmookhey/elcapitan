# El Capitan Probe Substrate & Anna Shakedown — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic host-side substrate — immutable records, evidence hashing, artifact validation, and isolation-enforcing ephemeral containers — then prove it end-to-end by running one real Anna finding through an engineer container and emitting a schema-valid, hash-verified `RemediationProposal`.

**Architecture:** Everything deterministic runs on the host in Python; the agent runs inside a fresh, ephemeral container per stage. The host harness is the only component that launches containers, injects secrets, and reads ground truth. Records are written once and never mutated; every evidence claim is an artifact reference with a SHA-256 that the validator independently re-verifies.

**Tech Stack:** Python 3.12 · pytest · `jsonschema` · Docker · bash · Hermes Agent (pinned by digest) · Prowler (OCSF output)

**Covers:** Spec Stages 0 and 1. Stage 2 (Eiger environment) and Stages 3–5 (challenger, arms, scored trials) are separate plans that consume the interfaces defined here.

## Global Constraints

Copied verbatim from the spec. Every task's requirements implicitly include these.

- **Pin exactly.** Hermes exact version, git tag, **OCI image digest**, and dependency lockfile hash. Never a range like `>=0.20.x` — "a range permits behavior changes between trials."
- **Ground truth lives outside every agent-mounted directory.** "Ground-truth leakage would make the entire experiment invalid."
- **Canonical repository is mounted read-only at a pinned commit.** Never written, never pushed.
- **Only the arm's secrets enter a container.** "No mount containing credentials for the other arm."
- **No cloud mutation.** No `terraform apply`, no write-capable cloud calls, ever.
- **Records are immutable.** Corrections create `package_version: N+1` with `supersedes`; version 1 is never mutated.
- **Evidence is an artifact reference with a `sha256`**, never an unconstrained string.
- **Exit codes are tool-specific.** `terraform plan -detailed-exitcode` returns `2` for a valid plan *containing changes*. "A generic 'non-zero means failure' validator would score valid remediation plans incorrectly."
- **The host-side validator is the final authority** — it runs after the container exits, independently of any in-container gate.
- **Anna is exploratory.** Results are labelled exploratory and excluded from any scored matrix. **No telemetry is collected from Anna in this plan** (see spec Appendix B).

---

## File Structure

```
elcapitan/
├── pyproject.toml                          Python project + pinned deps
├── runtime.lock.json                       Hermes version, image digest, scanner versions
├── docker/Dockerfile                       derived image: Hermes + scanners + toolchains
├── bin/
│   ├── run-trial.sh                        harness entry point (engineer stage)
│   ├── agent-run.sh                        runtime shim — the only place Hermes is invoked
│   └── validate-trial-artifacts.sh         validator entry point
├── schemas/
│   ├── evidence-ref.schema.json
│   ├── finding-record.schema.json
│   └── remediation-proposal.schema.json
├── src/elcapitan/
│   ├── hashing.py                          canonical JSON + SHA-256 primitives
│   ├── evidence.py                         EvidenceRef, write_evidence, verify_evidence
│   ├── finding.py                          FindingRecord, normalise_ocsf (provenance-preserving)
│   ├── toolsem.py                          per-tool exit-code semantics
│   ├── proposal.py                         RemediationProposal record
│   ├── validate.py                         deterministic artifact validator
│   └── container.py                        ephemeral container spec + launcher
├── environments/anna/env.yaml              Anna adapter: identities, repo pin, classification
└── tests/
    ├── test_runtime_lock.py   test_hashing.py    test_evidence.py
    ├── test_finding.py        test_toolsem.py    test_proposal.py
    ├── test_validate.py       test_container.py  test_shim.py
    └── fixtures/
```

**Responsibility boundaries.** `hashing` knows nothing about domain types. `evidence`/`finding`/`proposal` are record types with no I/O beyond their own artifact writes. `toolsem` is a pure function table. `validate` consumes all of the above and performs no mutation. `container` builds an argv and never interprets records. `run-trial.sh` is the only thing that sequences them.

---

### Task 1: Project scaffold and pinned runtime manifest

**Files:**
- Create: `pyproject.toml`, `src/elcapitan/__init__.py`, `runtime.lock.json`, `docker/Dockerfile`
- Test: `tests/test_runtime_lock.py`

**Interfaces:**
- Consumes: nothing
- Produces: `runtime.lock.json` with keys `hermes_version`, `hermes_git_tag`, `image_digest`, `python_lock_sha256`, `scanner_versions` — read by Task 8 (`agent-run.sh`) and Task 9 (trial metadata)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_runtime_lock.py
import json
from pathlib import Path

LOCK = Path(__file__).resolve().parents[1] / "runtime.lock.json"
FLOATING = (">=", "<=", ">", "<", "^", "~", "*", "latest", ":main")

def test_runtime_lock_exists():
    assert LOCK.is_file(), "runtime.lock.json must exist at repo root"

def test_runtime_lock_has_required_keys():
    lock = json.loads(LOCK.read_text())
    for key in ("hermes_version", "hermes_git_tag", "image_digest",
                "python_lock_sha256", "scanner_versions"):
        assert key in lock, f"missing required key: {key}"

def test_image_is_pinned_by_digest():
    lock = json.loads(LOCK.read_text())
    assert lock["image_digest"].startswith("sha256:"), \
        "image must be pinned by digest, not tag"
    assert len(lock["image_digest"]) == 71  # 'sha256:' + 64 hex

def test_no_floating_version_specifiers():
    raw = LOCK.read_text()
    for token in FLOATING:
        assert token not in raw, \
            f"floating specifier {token!r} in runtime.lock.json — a range permits behaviour change between trials"

def test_scanner_versions_are_exact():
    lock = json.loads(LOCK.read_text())
    assert lock["scanner_versions"], "at least one scanner must be pinned"
    for tool, version in lock["scanner_versions"].items():
        assert version[0].isdigit(), f"{tool} version {version!r} must be exact"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_runtime_lock.py -v`
Expected: FAIL — `assert LOCK.is_file()` → `runtime.lock.json must exist at repo root`

- [ ] **Step 3: Resolve the real pinned values**

Do not guess these. Resolve each one and record the actual output.

```bash
# Find the current Hermes release tag and the official image reference.
# The docs index is at https://hermes-agent.nousresearch.com/docs/user-guide/docker
gh release list --repo NousResearch/hermes-agent --limit 5

# Pull the exact tag, then read back its immutable digest:
docker pull <image-ref>:<exact-version>
docker inspect --format='{{index .RepoDigests 0}}' <image-ref>:<exact-version>

# Scanner versions (run inside the pulled image or locally):
prowler --version
trivy --version
```

- [ ] **Step 4: Write the scaffold files**

```toml
# pyproject.toml
[project]
name = "elcapitan"
version = "0.1.0"
requires-python = "==3.12.*"
dependencies = ["jsonschema==4.23.0", "PyYAML==6.0.2"]

[project.optional-dependencies]
dev = ["pytest==8.3.3"]

[build-system]
requires = ["setuptools==75.1.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]
```

```json
// runtime.lock.json — replace every <...> with the value resolved in Step 3
{
  "hermes_version": "<exact version, e.g. 0.20.0>",
  "hermes_git_tag": "<exact tag, e.g. v0.20.0>",
  "image_digest": "sha256:<64 hex chars>",
  "image_ref": "<registry/org/image>",
  "python_lock_sha256": "<sha256 of pyproject.toml, filled in Step 5>",
  "scanner_versions": {
    "prowler": "<exact>",
    "trivy": "<exact>"
  }
}
```

```dockerfile
# docker/Dockerfile
ARG BASE_DIGEST
FROM <image-ref>@${BASE_DIGEST}

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl jq unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Toolchains and scanners are pinned by the versions in runtime.lock.json.
# Install Azure CLI, Terraform, Node/CDK, Prowler and Trivy at those exact
# versions here. Every version string in this file must also appear in
# runtime.lock.json — test_no_floating_version_specifiers guards the lock,
# and Task 9 records the built image digest per trial.

USER hermes
WORKDIR /workspace
```

`src/elcapitan/__init__.py` is empty.

- [ ] **Step 5: Fill in the dependency lock hash**

```bash
python3 -c "import hashlib,pathlib,json; \
p=pathlib.Path('runtime.lock.json'); d=json.loads(p.read_text()); \
d['python_lock_sha256']=hashlib.sha256(pathlib.Path('pyproject.toml').read_bytes()).hexdigest(); \
p.write_text(json.dumps(d,indent=2)+'\n')"
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pip install -e '.[dev]' && pytest tests/test_runtime_lock.py -v`
Expected: 5 passed

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml runtime.lock.json docker/Dockerfile src/elcapitan/__init__.py tests/test_runtime_lock.py
git commit -m "feat(substrate): scaffold and digest-pinned runtime manifest"
```

---

### Task 2: Hashing primitives and evidence artifacts

**Files:**
- Create: `src/elcapitan/hashing.py`, `src/elcapitan/evidence.py`, `schemas/evidence-ref.schema.json`
- Test: `tests/test_hashing.py`, `tests/test_evidence.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `sha256_bytes(data: bytes) -> str`, `sha256_file(path: Path) -> str`
  - `canonical_json(obj) -> bytes`, `sha256_record(obj) -> str`
  - `EvidenceRef` frozen dataclass with fields `evidence_id, type, artifact_path, sha256, collected_at, sensitivity, command_id, collector`
  - `write_evidence(run_dir, evidence_id, type, payload, collector, *, sensitivity="internal", command_id="", now=None) -> EvidenceRef`
  - `verify_evidence(run_dir: Path, ref: EvidenceRef) -> bool`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_hashing.py
from elcapitan.hashing import sha256_bytes, sha256_file, canonical_json, sha256_record

EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_sha256_bytes_known_vector():
    assert sha256_bytes(b"") == EMPTY

def test_sha256_file_matches_bytes(tmp_path):
    p = tmp_path / "a.json"
    p.write_bytes(b'{"x":1}')
    assert sha256_file(p) == sha256_bytes(b'{"x":1}')

def test_canonical_json_is_key_order_independent():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

def test_canonical_json_has_no_incidental_whitespace():
    assert canonical_json({"a": 1, "b": 2}) == b'{"a":1,"b":2}'

def test_sha256_record_stable_across_key_order():
    assert sha256_record({"b": 1, "a": 2}) == sha256_record({"a": 2, "b": 1})

def test_sha256_record_changes_on_value_change():
    assert sha256_record({"a": 1}) != sha256_record({"a": 2})
```

```python
# tests/test_evidence.py
import json
import pytest
from elcapitan.evidence import Collector, EvidenceRef, write_evidence, verify_evidence

COLLECTOR = Collector(tool="az", version="2.64.0", identity="anna-scanner-reader")
NOW = "2026-08-08T12:00:00Z"

def test_write_evidence_persists_artifact(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "azure_api_response",
                         b'{"ok":true}', COLLECTOR, command_id="CMD-001", now=NOW)
    assert (tmp_path / ref.artifact_path).read_bytes() == b'{"ok":true}'

def test_write_evidence_records_hash_of_payload(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "azure_api_response",
                         b'{"ok":true}', COLLECTOR, now=NOW)
    assert verify_evidence(tmp_path, ref) is True

def test_verify_evidence_detects_tampering(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "azure_api_response",
                         b'{"ok":true}', COLLECTOR, now=NOW)
    (tmp_path / ref.artifact_path).write_bytes(b'{"ok":false}')
    assert verify_evidence(tmp_path, ref) is False

def test_verify_evidence_false_when_artifact_missing(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "t", b"x", COLLECTOR, now=NOW)
    (tmp_path / ref.artifact_path).unlink()
    assert verify_evidence(tmp_path, ref) is False

def test_evidence_ref_is_immutable(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "t", b"x", COLLECTOR, now=NOW)
    with pytest.raises(Exception):
        ref.sha256 = "0" * 64

def test_artifact_path_is_relative_and_contained(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "t", b"x", COLLECTOR, now=NOW)
    assert not ref.artifact_path.startswith("/")
    assert ".." not in ref.artifact_path

def test_evidence_id_must_be_unique(tmp_path):
    write_evidence(tmp_path, "EVD-001", "t", b"x", COLLECTOR, now=NOW)
    with pytest.raises(ValueError, match="already exists"):
        write_evidence(tmp_path, "EVD-001", "t", b"y", COLLECTOR, now=NOW)

def test_to_dict_round_trips_through_json(tmp_path):
    ref = write_evidence(tmp_path, "EVD-001", "t", b"x", COLLECTOR, now=NOW)
    assert json.loads(json.dumps(ref.to_dict()))["collector"]["identity"] == "anna-scanner-reader"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hashing.py tests/test_evidence.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'elcapitan.hashing'`

- [ ] **Step 3: Implement hashing**

```python
# src/elcapitan/hashing.py
"""Content-addressing primitives. No domain knowledge lives here."""
import hashlib
import json
from pathlib import Path
from typing import Any

_CHUNK = 65536

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()

def canonical_json(obj: Any) -> bytes:
    """Deterministic encoding: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def sha256_record(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj))
```

- [ ] **Step 4: Implement evidence**

```python
# src/elcapitan/evidence.py
"""Evidence is an artifact reference with a verifiable hash — never a string."""
from dataclasses import asdict, dataclass
from pathlib import Path

from .hashing import sha256_bytes, sha256_file

EVIDENCE_DIR = "evidence"

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
    if now is None:
        raise ValueError("now must be supplied explicitly so trials are reproducible")
    run_dir = Path(run_dir)
    target = run_dir / EVIDENCE_DIR / f"{evidence_id}.bin"
    if target.exists():
        raise ValueError(f"evidence_id {evidence_id} already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return EvidenceRef(
        evidence_id=evidence_id,
        type=type,
        artifact_path=f"{EVIDENCE_DIR}/{evidence_id}.bin",
        sha256=sha256_bytes(payload),
        collected_at=now,
        sensitivity=sensitivity,
        command_id=command_id,
        collector=collector,
    )

def verify_evidence(run_dir, ref: EvidenceRef) -> bool:
    path = Path(run_dir) / ref.artifact_path
    if not path.is_file():
        return False
    return sha256_file(path) == ref.sha256
```

- [ ] **Step 5: Write the evidence JSON Schema**

```json
// schemas/evidence-ref.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "EvidenceRef",
  "type": "object",
  "required": ["evidence_id", "type", "artifact_path", "sha256",
               "collected_at", "sensitivity", "command_id", "collector"],
  "additionalProperties": false,
  "properties": {
    "evidence_id":   { "type": "string", "pattern": "^EVD-[0-9]{3,}$" },
    "type":          { "type": "string", "minLength": 1 },
    "artifact_path": { "type": "string", "pattern": "^[^/][^\\s]*$" },
    "sha256":        { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "collected_at":  { "type": "string", "format": "date-time" },
    "sensitivity":   { "enum": ["public", "internal", "confidential", "restricted"] },
    "command_id":    { "type": "string" },
    "collector": {
      "type": "object",
      "required": ["tool", "version", "identity"],
      "additionalProperties": false,
      "properties": {
        "tool":     { "type": "string", "minLength": 1 },
        "version":  { "type": "string", "minLength": 1 },
        "identity": { "type": "string", "minLength": 1 }
      }
    }
  }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_hashing.py tests/test_evidence.py -v`
Expected: 14 passed

- [ ] **Step 7: Commit**

```bash
git add src/elcapitan/hashing.py src/elcapitan/evidence.py schemas/evidence-ref.schema.json tests/test_hashing.py tests/test_evidence.py
git commit -m "feat(records): hashed evidence artifacts with tamper detection"
```

---

### Task 3: OCSF finding normalisation with provenance

**Files:**
- Create: `src/elcapitan/finding.py`, `schemas/finding-record.schema.json`
- Test: `tests/test_finding.py`, `tests/fixtures/prowler-ocsf-sample.json`

**Interfaces:**
- Consumes: `evidence.write_evidence`, `evidence.Collector` (Task 2)
- Produces: `normalise_ocsf(raw: dict, *, run_dir, finding_id, collector, now) -> dict` returning a FindingRecord dict with keys `finding_id, ocsf, provenance, resource, raw_event, vendor_extensions`

**Why this shape:** the spec requires that normalisation *not discard* — raw event retained as evidence, product-specific extensions namespaced.

- [ ] **Step 1: Write the fixture**

```json
// tests/fixtures/prowler-ocsf-sample.json
{
  "metadata": {
    "version": "1.3.0",
    "product": { "name": "Prowler", "version": "5.2.1", "vendor_name": "Prowler" },
    "event_code": "s3_bucket_public_access"
  },
  "class_uid": 2004,
  "finding_info": { "uid": "prowler-aws-s3-123", "title": "S3 bucket allows public access" },
  "cloud": { "provider": "aws", "account": { "uid": "111122223333" }, "region": "us-east-1" },
  "resources": [{ "uid": "arn:aws:s3:::anna-assets", "type": "AwsS3Bucket" }],
  "time_dt": "2026-08-08T11:00:00Z",
  "severity": "High",
  "unmapped": { "prowler_check_id": "s3_bucket_public_access", "compliance": ["CIS-2.1"] }
}
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_finding.py
import json
from pathlib import Path
import pytest
from elcapitan.evidence import Collector, verify_evidence, EvidenceRef
from elcapitan.finding import normalise_ocsf

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-sample.json"
COLLECTOR = Collector(tool="prowler", version="5.2.1", identity="anna-scanner-reader")
NOW = "2026-08-08T12:00:00Z"

@pytest.fixture
def record(tmp_path):
    raw = json.loads(FIXTURE.read_text())
    return normalise_ocsf(raw, run_dir=tmp_path, finding_id="FIND-001",
                          collector=COLLECTOR, now=NOW), tmp_path

def test_preserves_ocsf_version_and_class_uid(record):
    rec, _ = record
    assert rec["ocsf"]["version"] == "1.3.0"
    assert rec["ocsf"]["class_uid"] == 2004

def test_preserves_original_finding_uid(record):
    rec, _ = record
    assert rec["ocsf"]["original_uid"] == "prowler-aws-s3-123"

def test_preserves_scanner_product_and_version(record):
    rec, _ = record
    assert rec["provenance"]["product"] == "Prowler"
    assert rec["provenance"]["product_version"] == "5.2.1"

def test_preserves_cloud_account_and_region(record):
    rec, _ = record
    assert rec["provenance"]["provider"] == "aws"
    assert rec["provenance"]["account"] == "111122223333"
    assert rec["provenance"]["region"] == "us-east-1"

def test_preserves_resource_uid_and_type(record):
    rec, _ = record
    assert rec["resource"]["uid"] == "arn:aws:s3:::anna-assets"
    assert rec["resource"]["type"] == "AwsS3Bucket"

def test_preserves_observation_timestamp(record):
    rec, _ = record
    assert rec["provenance"]["observed_at"] == "2026-08-08T11:00:00Z"

def test_raw_event_retained_as_verifiable_evidence(record):
    rec, run_dir = record
    ref = EvidenceRef(**{**rec["raw_event"],
                         "collector": Collector(**rec["raw_event"]["collector"])})
    assert verify_evidence(run_dir, ref) is True

def test_vendor_specific_fields_namespaced_not_discarded(record):
    rec, _ = record
    assert rec["vendor_extensions"]["prowler_check_id"] == "s3_bucket_public_access"
    assert rec["vendor_extensions"]["compliance"] == ["CIS-2.1"]

def test_rejects_input_without_class_uid(tmp_path):
    with pytest.raises(ValueError, match="class_uid"):
        normalise_ocsf({"metadata": {}}, run_dir=tmp_path, finding_id="FIND-001",
                       collector=COLLECTOR, now=NOW)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_finding.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'elcapitan.finding'`

- [ ] **Step 4: Implement**

```python
# src/elcapitan/finding.py
"""Normalise a scanner's OCSF finding without discarding provenance.

The intake contract is 'one OCSF finding', not 'the Prowler JSON'. Prowler
emits the OCSF Detection Finding class; so do other sources. Normalisation
must therefore preserve enough to identify, re-fetch and audit the original.
"""
from pathlib import Path

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
        run_dir, f"EVD-{finding_id.split('-')[-1]}", "scanner_raw_event",
        canonical_json(raw), collector,
        sensitivity="internal", command_id="CMD-SCAN", now=now,
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
```

- [ ] **Step 5: Write the JSON Schema**

```json
// schemas/finding-record.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "FindingRecord",
  "type": "object",
  "required": ["finding_id", "ocsf", "provenance", "resource", "severity",
               "raw_event", "vendor_extensions"],
  "additionalProperties": false,
  "properties": {
    "finding_id": { "type": "string", "pattern": "^FIND-[0-9]{3,}$" },
    "ocsf": {
      "type": "object",
      "required": ["version", "class_uid", "original_uid", "title"],
      "additionalProperties": false,
      "properties": {
        "version":      { "type": "string", "minLength": 1 },
        "class_uid":    { "type": "integer" },
        "original_uid": { "type": "string", "minLength": 1 },
        "title":        { "type": "string" }
      }
    },
    "provenance": {
      "type": "object",
      "required": ["product", "product_version", "provider", "account",
                   "region", "observed_at"],
      "additionalProperties": false,
      "properties": {
        "product":         { "type": "string", "minLength": 1 },
        "product_version": { "type": "string", "minLength": 1 },
        "provider":        { "type": "string", "minLength": 1 },
        "account":         { "type": "string", "minLength": 1 },
        "region":          { "type": "string" },
        "observed_at":     { "type": "string" }
      }
    },
    "resource": {
      "type": "object",
      "required": ["uid", "type"],
      "additionalProperties": false,
      "properties": {
        "uid":  { "type": "string", "minLength": 1 },
        "type": { "type": "string" }
      }
    },
    "severity":          { "type": "string" },
    "raw_event":         { "$ref": "evidence-ref.schema.json" },
    "vendor_extensions": { "type": "object" }
  }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_finding.py -v`
Expected: 9 passed

- [ ] **Step 7: Commit**

```bash
git add src/elcapitan/finding.py schemas/finding-record.schema.json tests/test_finding.py tests/fixtures/prowler-ocsf-sample.json
git commit -m "feat(records): provenance-preserving OCSF finding normalisation"
```

---

### Task 4: Per-tool exit-code semantics

**Files:**
- Create: `src/elcapitan/toolsem.py`
- Test: `tests/test_toolsem.py`

**Interfaces:**
- Consumes: nothing
- Produces: `ExitVerdict(ok: bool, meaning: str)` frozen dataclass; `interpret_exit(tool: str, argv: list[str], code: int) -> ExitVerdict`

**Why this is its own unit:** the spec is explicit that a generic "non-zero means failure" validator would score valid remediation plans incorrectly. `terraform plan -detailed-exitcode` returns `2` for a *successful* plan that contains changes — which is the expected outcome for every remediation the probe generates.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_toolsem.py
import pytest
from elcapitan.toolsem import interpret_exit

def test_terraform_plan_detailed_exitcode_2_is_success_with_changes():
    v = interpret_exit("terraform", ["plan", "-detailed-exitcode"], 2)
    assert v.ok is True
    assert "changes" in v.meaning

def test_terraform_plan_detailed_exitcode_0_is_success_no_changes():
    v = interpret_exit("terraform", ["plan", "-detailed-exitcode"], 0)
    assert v.ok is True
    assert "no changes" in v.meaning

def test_terraform_plan_detailed_exitcode_1_is_error():
    assert interpret_exit("terraform", ["plan", "-detailed-exitcode"], 1).ok is False

def test_terraform_plan_without_detailed_exitcode_2_is_error():
    # Without the flag, 2 carries no special meaning and is a failure.
    assert interpret_exit("terraform", ["plan"], 2).ok is False

def test_terraform_validate_zero_is_success():
    assert interpret_exit("terraform", ["validate"], 0).ok is True

def test_terraform_validate_nonzero_is_error():
    assert interpret_exit("terraform", ["validate"], 1).ok is False

def test_cdk_diff_without_fail_flag_zero_is_success():
    assert interpret_exit("cdk", ["diff"], 0).ok is True

def test_cdk_diff_with_fail_flag_one_means_differences_present():
    v = interpret_exit("cdk", ["diff", "--fail"], 1)
    assert v.ok is True
    assert "differences" in v.meaning

def test_trivy_with_exit_code_flag_reports_findings_not_failure():
    v = interpret_exit("trivy", ["config", ".", "--exit-code", "1"], 1)
    assert v.ok is True
    assert "findings" in v.meaning

def test_trivy_without_exit_code_flag_nonzero_is_error():
    assert interpret_exit("trivy", ["config", "."], 1).ok is False

def test_unknown_tool_falls_back_to_zero_is_success():
    assert interpret_exit("jq", ["."], 0).ok is True
    assert interpret_exit("jq", ["."], 1).ok is False

def test_unknown_tool_verdict_states_the_fallback():
    assert "generic" in interpret_exit("jq", ["."], 1).meaning
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_toolsem.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'elcapitan.toolsem'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/toolsem.py
"""Per-tool exit-code semantics.

A generic 'non-zero means failure' rule would mis-score the probe: a
successful `terraform plan -detailed-exitcode` that contains changes exits 2,
and that is the expected outcome of every remediation this system generates.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class ExitVerdict:
    ok: bool
    meaning: str

def _terraform(argv: list[str], code: int) -> ExitVerdict:
    sub = argv[0] if argv else ""
    if sub == "plan" and "-detailed-exitcode" in argv:
        return {
            0: ExitVerdict(True, "plan succeeded, no changes"),
            2: ExitVerdict(True, "plan succeeded, changes present"),
        }.get(code, ExitVerdict(False, f"terraform plan error (exit {code})"))
    return ExitVerdict(code == 0, f"terraform {sub} exit {code}")

def _cdk(argv: list[str], code: int) -> ExitVerdict:
    if argv and argv[0] == "diff" and "--fail" in argv:
        if code == 0:
            return ExitVerdict(True, "cdk diff: no differences")
        if code == 1:
            return ExitVerdict(True, "cdk diff: differences present")
        return ExitVerdict(False, f"cdk diff error (exit {code})")
    return ExitVerdict(code == 0, f"cdk exit {code}")

def _trivy(argv: list[str], code: int) -> ExitVerdict:
    if "--exit-code" in argv:
        try:
            configured = int(argv[argv.index("--exit-code") + 1])
        except (IndexError, ValueError):
            configured = None
        if code == 0:
            return ExitVerdict(True, "trivy: no findings")
        if configured is not None and code == configured:
            return ExitVerdict(True, "trivy: findings present")
    return ExitVerdict(code == 0, f"trivy exit {code}")

_HANDLERS = {"terraform": _terraform, "cdk": _cdk, "trivy": _trivy}

def interpret_exit(tool: str, argv: list[str], code: int) -> ExitVerdict:
    handler = _HANDLERS.get(tool)
    if handler is None:
        return ExitVerdict(code == 0, f"generic semantics: exit {code}")
    return handler(argv, code)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_toolsem.py -v`
Expected: 12 passed

- [ ] **Step 5: Commit**

```bash
git add src/elcapitan/toolsem.py tests/test_toolsem.py
git commit -m "feat(validate): per-tool exit-code semantics"
```

---

### Task 5: RemediationProposal record and schema

**Files:**
- Create: `src/elcapitan/proposal.py`, `schemas/remediation-proposal.schema.json`
- Test: `tests/test_proposal.py`

**Interfaces:**
- Consumes: `evidence.EvidenceRef` (Task 2), `finding` record shape (Task 3)
- Produces: `RESOLUTION_TYPES` tuple; `TERMINAL_STATUSES` tuple; `load_schema(name: str) -> dict`; `validate_proposal(doc: dict) -> list[str]` returning human-readable errors (empty list = valid)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_proposal.py
import copy
import pytest
from elcapitan.proposal import RESOLUTION_TYPES, TERMINAL_STATUSES, validate_proposal

VALID = {
    "proposal_id": "PROP-001",
    "schema_version": 1,
    "created_at": "2026-08-08T12:00:00Z",
    "finding_id": "FIND-001",
    "input_bundle_hash": "a" * 64,
    "validation": {"confirmed": True, "evidence": ["EVD-001"], "confidence": 0.9},
    "linking": {
        "iac_managed": False, "system_detected": "aws-cdk",
        "method": "grepped bucket name in aws/infra/cdk/*.ts",
        "confidence": 0.4, "evidence": ["EVD-002"], "files": [],
    },
    "root_cause": "bucket created at runtime by the application",
    "resolution_type": "runtime_change",
    "remediation": {"objective": "stop creating the bucket publicly",
                    "approach": "set ACL at creation in app code",
                    "patch_file": None},
    "verification": {"commands_run": [], "output": [], "passed": None},
    "production_impact": {"expected": "none", "dependencies": [],
                          "unknowns": [], "risk": "low"},
    "context": {"severity": "High", "asset_id": "arn:aws:s3:::anna-assets",
                "owner": "", "exploitability": ""},
    "status": "READY_FOR_REVIEW",
}

def test_valid_proposal_has_no_errors():
    assert validate_proposal(VALID) == []

def test_missing_required_field_is_reported():
    doc = copy.deepcopy(VALID); del doc["linking"]
    assert any("linking" in e for e in validate_proposal(doc))

def test_unknown_resolution_type_is_rejected():
    doc = copy.deepcopy(VALID); doc["resolution_type"] = "just_fix_it"
    assert validate_proposal(doc) != []

def test_all_five_resolution_types_are_accepted():
    for rt in RESOLUTION_TYPES:
        doc = copy.deepcopy(VALID); doc["resolution_type"] = rt
        if rt == "patch":
            doc["remediation"]["patch_file"] = "patch/change.diff"
        assert validate_proposal(doc) == [], f"{rt} should be valid"

def test_resolution_types_are_exactly_the_five_from_the_spec():
    assert set(RESOLUTION_TYPES) == {
        "patch", "runtime_change", "risk_accepted", "false_positive", "needs_design"}

def test_needs_human_context_is_a_terminal_status():
    assert "NEEDS_HUMAN_CONTEXT" in TERMINAL_STATUSES
    doc = copy.deepcopy(VALID); doc["status"] = "NEEDS_HUMAN_CONTEXT"
    assert validate_proposal(doc) == []

def test_linking_method_may_not_be_empty():
    doc = copy.deepcopy(VALID); doc["linking"]["method"] = ""
    assert validate_proposal(doc) != []

def test_input_bundle_hash_must_be_sha256():
    doc = copy.deepcopy(VALID); doc["input_bundle_hash"] = "not-a-hash"
    assert validate_proposal(doc) != []

def test_confidence_outside_zero_to_one_is_rejected():
    doc = copy.deepcopy(VALID); doc["linking"]["confidence"] = 1.5
    assert validate_proposal(doc) != []

def test_additional_properties_are_rejected():
    doc = copy.deepcopy(VALID); doc["surprise"] = True
    assert validate_proposal(doc) != []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_proposal.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'elcapitan.proposal'`

- [ ] **Step 3: Write the schema**

```json
// schemas/remediation-proposal.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "RemediationProposal",
  "type": "object",
  "additionalProperties": false,
  "required": ["proposal_id", "schema_version", "created_at", "finding_id",
               "input_bundle_hash", "validation", "linking", "root_cause",
               "resolution_type", "remediation", "verification",
               "production_impact", "context", "status"],
  "properties": {
    "proposal_id":       { "type": "string", "pattern": "^PROP-[0-9]{3,}$" },
    "schema_version":    { "type": "integer", "minimum": 1 },
    "created_at":        { "type": "string", "minLength": 1 },
    "finding_id":        { "type": "string", "pattern": "^FIND-[0-9]{3,}$" },
    "input_bundle_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "validation": {
      "type": "object", "additionalProperties": false,
      "required": ["confirmed", "evidence", "confidence"],
      "properties": {
        "confirmed":  { "type": "boolean" },
        "evidence":   { "type": "array", "items": { "type": "string" } },
        "confidence": { "type": "number", "minimum": 0, "maximum": 1 }
      }
    },
    "linking": {
      "type": "object", "additionalProperties": false,
      "required": ["iac_managed", "system_detected", "method",
                   "confidence", "evidence", "files"],
      "properties": {
        "iac_managed":     { "type": "boolean" },
        "system_detected": { "type": "string" },
        "method":          { "type": "string", "minLength": 1 },
        "confidence":      { "type": "number", "minimum": 0, "maximum": 1 },
        "evidence":        { "type": "array", "items": { "type": "string" } },
        "files":           { "type": "array", "items": { "type": "string" } }
      }
    },
    "root_cause":      { "type": "string" },
    "resolution_type": { "enum": ["patch", "runtime_change", "risk_accepted",
                                  "false_positive", "needs_design"] },
    "remediation": {
      "type": "object", "additionalProperties": false,
      "required": ["objective", "approach", "patch_file"],
      "properties": {
        "objective":  { "type": "string" },
        "approach":   { "type": "string" },
        "patch_file": { "type": ["string", "null"] }
      }
    },
    "verification": {
      "type": "object", "additionalProperties": false,
      "required": ["commands_run", "output", "passed"],
      "properties": {
        "commands_run": { "type": "array" },
        "output":       { "type": "array" },
        "passed":       { "type": ["boolean", "null"] }
      }
    },
    "production_impact": {
      "type": "object", "additionalProperties": false,
      "required": ["expected", "dependencies", "unknowns", "risk"],
      "properties": {
        "expected":     { "type": "string" },
        "dependencies": { "type": "array", "items": { "type": "string" } },
        "unknowns":     { "type": "array", "items": { "type": "string" } },
        "risk":         { "type": "string" }
      }
    },
    "context": {
      "type": "object", "additionalProperties": false,
      "required": ["severity", "asset_id", "owner", "exploitability"],
      "properties": {
        "severity":       { "type": "string" },
        "asset_id":       { "type": "string" },
        "owner":          { "type": "string" },
        "exploitability": { "type": "string" }
      }
    },
    "status": { "enum": ["READY_FOR_REVIEW", "NEEDS_HUMAN_CONTEXT"] }
  }
}
```

- [ ] **Step 4: Implement**

```python
# src/elcapitan/proposal.py
"""RemediationProposal — record type #2. Written once, never mutated."""
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"

RESOLUTION_TYPES = ("patch", "runtime_change", "risk_accepted",
                    "false_positive", "needs_design")
TERMINAL_STATUSES = ("READY_FOR_REVIEW", "NEEDS_HUMAN_CONTEXT")

@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text())

def validate_proposal(doc: dict) -> list[str]:
    """Return human-readable errors. Empty list means valid."""
    validator = Draft202012Validator(load_schema("remediation-proposal"))
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    ]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_proposal.py -v`
Expected: 10 passed

- [ ] **Step 6: Commit**

```bash
git add src/elcapitan/proposal.py schemas/remediation-proposal.schema.json tests/test_proposal.py
git commit -m "feat(records): RemediationProposal record and schema"
```

---

### Task 6: Deterministic artifact validator

**Files:**
- Create: `src/elcapitan/validate.py`, `bin/validate-trial-artifacts.sh`
- Test: `tests/test_validate.py`

**Interfaces:**
- Consumes: `proposal.validate_proposal`, `evidence.verify_evidence`, `toolsem.interpret_exit`, `hashing.sha256_record`
- Produces: `ValidationResult(passed: bool, failures: list[str])`; `validate_run(run_dir: Path, *, canonical_digest: str) -> ValidationResult`

**This is the final authority.** Hermes' `/goal` completion contracts are LLM-judged and its quality gates run inside the container; this runs on the host after the container exits and overrides both.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_validate.py
import json
from pathlib import Path
import pytest
from elcapitan.evidence import Collector, write_evidence
from elcapitan.validate import validate_run

COLLECTOR = Collector(tool="prowler", version="5.2.1", identity="anna-scanner-reader")
NOW = "2026-08-08T12:00:00Z"
DIGEST = "b" * 64

def build_run(tmp_path, *, proposal_overrides=None, mutate_evidence=False,
              transcript="ran: aws s3api get-bucket-acl\n"):
    run = tmp_path / "runs" / "R1"
    (run / "inputs").mkdir(parents=True)
    ref = write_evidence(run, "EVD-001", "scanner_raw_event", b'{"x":1}',
                         COLLECTOR, command_id="CMD-SCAN", now=NOW)
    if mutate_evidence:
        (run / ref.artifact_path).write_bytes(b'{"x":2}')
    proposal = {
        "proposal_id": "PROP-001", "schema_version": 1, "created_at": NOW,
        "finding_id": "FIND-001", "input_bundle_hash": "a" * 64,
        "validation": {"confirmed": True, "evidence": ["EVD-001"], "confidence": 0.9},
        "linking": {"iac_managed": False, "system_detected": "aws-cdk",
                    "method": "grep", "confidence": 0.4,
                    "evidence": ["EVD-001"], "files": []},
        "root_cause": "runtime creation", "resolution_type": "runtime_change",
        "remediation": {"objective": "o", "approach": "a", "patch_file": None},
        "verification": {"commands_run": [], "output": [], "passed": None},
        "production_impact": {"expected": "", "dependencies": [],
                              "unknowns": [], "risk": "low"},
        "context": {"severity": "High", "asset_id": "arn", "owner": "",
                    "exploitability": ""},
        "status": "READY_FOR_REVIEW",
    }
    proposal.update(proposal_overrides or {})
    (run / "proposal.json").write_text(json.dumps(proposal))
    (run / "evidence-index.json").write_text(json.dumps([ref.to_dict()]))
    (run / "inputs" / "bundle.sha256").write_text("a" * 64)
    (run / "transcript.log").write_text(transcript)
    (run / "canonical.digest").write_text(DIGEST)
    return run

def test_well_formed_run_passes(tmp_path):
    assert validate_run(build_run(tmp_path), canonical_digest=DIGEST).passed is True

def test_schema_violation_fails(tmp_path):
    run = build_run(tmp_path, proposal_overrides={"resolution_type": "nope"})
    assert validate_run(run, canonical_digest=DIGEST).passed is False

def test_tampered_evidence_fails(tmp_path):
    r = validate_run(build_run(tmp_path, mutate_evidence=True), canonical_digest=DIGEST)
    assert r.passed is False
    assert any("hash mismatch" in f for f in r.failures)

def test_unresolvable_evidence_reference_fails(tmp_path):
    run = build_run(tmp_path, proposal_overrides={
        "validation": {"confirmed": True, "evidence": ["EVD-999"], "confidence": 0.9}})
    r = validate_run(run, canonical_digest=DIGEST)
    assert any("EVD-999" in f for f in r.failures)

def test_patch_resolution_without_patch_file_fails(tmp_path):
    run = build_run(tmp_path, proposal_overrides={
        "resolution_type": "patch",
        "remediation": {"objective": "o", "approach": "a", "patch_file": None}})
    r = validate_run(run, canonical_digest=DIGEST)
    assert any("patch_file" in f for f in r.failures)

def test_false_positive_with_patch_and_no_justification_fails(tmp_path):
    run = build_run(tmp_path, proposal_overrides={
        "resolution_type": "false_positive",
        "remediation": {"objective": "", "approach": "", "patch_file": "patch/x.diff"}})
    r = validate_run(run, canonical_digest=DIGEST)
    assert any("false_positive" in f for f in r.failures)

def test_input_bundle_hash_mismatch_fails(tmp_path):
    run = build_run(tmp_path)
    (run / "inputs" / "bundle.sha256").write_text("c" * 64)
    r = validate_run(run, canonical_digest=DIGEST)
    assert any("input_bundle_hash" in f for f in r.failures)

def test_canonical_repo_digest_change_fails(tmp_path):
    r = validate_run(build_run(tmp_path), canonical_digest="d" * 64)
    assert r.passed is False
    assert any("canonical" in f for f in r.failures)

def test_cloud_mutation_in_transcript_fails(tmp_path):
    run = build_run(tmp_path, transcript="ran: terraform apply -auto-approve\n")
    r = validate_run(run, canonical_digest=DIGEST)
    assert any("mutation" in f for f in r.failures)

def test_terraform_plan_exit_2_is_not_a_failure(tmp_path):
    run = build_run(tmp_path, proposal_overrides={
        "verification": {
            "commands_run": [{"tool": "terraform",
                              "argv": ["plan", "-detailed-exitcode"], "exit_code": 2}],
            "output": [], "passed": True}})
    assert validate_run(run, canonical_digest=DIGEST).passed is True

def test_terraform_plan_exit_1_is_a_failure(tmp_path):
    run = build_run(tmp_path, proposal_overrides={
        "verification": {
            "commands_run": [{"tool": "terraform",
                              "argv": ["plan", "-detailed-exitcode"], "exit_code": 1}],
            "output": [], "passed": True}})
    r = validate_run(run, canonical_digest=DIGEST)
    assert any("terraform" in f for f in r.failures)

def test_ground_truth_present_in_run_dir_fails(tmp_path):
    run = build_run(tmp_path)
    (run / "ground-truth.json").write_text("{}")
    r = validate_run(run, canonical_digest=DIGEST)
    assert any("ground truth" in f.lower() for f in r.failures)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_validate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'elcapitan.validate'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/validate.py
"""Host-side deterministic validator — the final authority on a trial.

Hermes completion contracts are LLM-judged and its quality gates run inside
the container. This runs on the host after the container exits and overrides
both. If this fails, the trial does not count.
"""
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .evidence import Collector, EvidenceRef, verify_evidence
from .proposal import validate_proposal
from .toolsem import interpret_exit

MUTATION_PATTERNS = (
    r"\bterraform\s+apply\b", r"\bterraform\s+destroy\b", r"\bterraform\s+import\b",
    r"\bcdk\s+deploy\b", r"\bcdk\s+destroy\b",
    r"\baz\s+\S+\s+(create|update|delete|set)\b",
    r"\baws\s+\S+\s+(create|put|delete|update)\S*\b",
    r"\bgit\s+push\b",
)
GROUND_TRUTH_MARKERS = ("ground-truth", "ground_truth", "groundtruth")

@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    failures: list[str]

def _load_evidence_index(run_dir: Path) -> dict[str, EvidenceRef]:
    raw = json.loads((run_dir / "evidence-index.json").read_text())
    return {
        item["evidence_id"]: EvidenceRef(
            **{**item, "collector": Collector(**item["collector"])})
        for item in raw
    }

def _collect_evidence_ids(doc: dict) -> set[str]:
    found: set[str] = set()
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "evidence" and isinstance(value, list):
                    found.update(v for v in value if isinstance(v, str))
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(doc)
    return found

def validate_run(run_dir, *, canonical_digest: str) -> ValidationResult:
    run_dir = Path(run_dir)
    failures: list[str] = []

    for path in run_dir.rglob("*"):
        if any(marker in path.name.lower() for marker in GROUND_TRUTH_MARKERS):
            failures.append(f"ground truth present inside run dir: {path.name}")

    proposal = json.loads((run_dir / "proposal.json").read_text())
    failures.extend(f"schema: {err}" for err in validate_proposal(proposal))

    index = _load_evidence_index(run_dir)
    for ref in index.values():
        if not verify_evidence(run_dir, ref):
            failures.append(f"evidence hash mismatch or missing artifact: {ref.evidence_id}")
    for evidence_id in _collect_evidence_ids(proposal):
        if evidence_id not in index:
            failures.append(f"unresolvable evidence reference: {evidence_id}")

    resolution = proposal.get("resolution_type")
    patch_file = proposal.get("remediation", {}).get("patch_file")
    if resolution == "patch" and not patch_file:
        failures.append("resolution_type=patch requires remediation.patch_file")
    if resolution == "patch" and patch_file and not (run_dir / patch_file).is_file():
        failures.append(f"declared patch_file does not exist: {patch_file}")
    if resolution == "false_positive" and patch_file:
        justification = proposal.get("root_cause", "")
        if "justif" not in justification.lower():
            failures.append(
                "resolution_type=false_positive carries a patch without explicit justification")

    declared = proposal.get("input_bundle_hash", "")
    actual = (run_dir / "inputs" / "bundle.sha256").read_text().strip()
    if declared != actual:
        failures.append(f"input_bundle_hash {declared[:8]} does not match bundle {actual[:8]}")

    recorded_digest = (run_dir / "canonical.digest").read_text().strip()
    if recorded_digest != canonical_digest:
        failures.append("canonical repository digest changed during the run")

    transcript = (run_dir / "transcript.log").read_text()
    for pattern in MUTATION_PATTERNS:
        if re.search(pattern, transcript):
            failures.append(f"cloud or repository mutation in transcript: /{pattern}/")

    for command in proposal.get("verification", {}).get("commands_run", []):
        verdict = interpret_exit(command.get("tool", ""), command.get("argv", []),
                                 command.get("exit_code", 0))
        if not verdict.ok:
            failures.append(
                f"verification command failed: {command.get('tool')} — {verdict.meaning}")

    return ValidationResult(passed=not failures, failures=failures)
```

- [ ] **Step 4: Write the CLI entry point**

```bash
#!/usr/bin/env bash
# bin/validate-trial-artifacts.sh
set -euo pipefail
RUN_DIR="${1:?usage: validate-trial-artifacts.sh <run-dir> <canonical-digest>}"
CANONICAL_DIGEST="${2:?missing canonical digest}"

python3 - "$RUN_DIR" "$CANONICAL_DIGEST" <<'PY'
import sys
from elcapitan.validate import validate_run

result = validate_run(sys.argv[1], canonical_digest=sys.argv[2])
for failure in result.failures:
    print(f"FAIL: {failure}", file=sys.stderr)
print("PASS" if result.passed else "FAILED")
sys.exit(0 if result.passed else 1)
PY
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `chmod +x bin/validate-trial-artifacts.sh && pytest tests/test_validate.py -v`
Expected: 12 passed

- [ ] **Step 6: Commit**

```bash
git add src/elcapitan/validate.py bin/validate-trial-artifacts.sh tests/test_validate.py
git commit -m "feat(validate): deterministic host-side artifact validator"
```

---

### Task 7: Ephemeral container spec — the isolation boundary

**Files:**
- Create: `src/elcapitan/container.py`
- Test: `tests/test_container.py`

**Interfaces:**
- Consumes: `runtime.lock.json` (Task 1)
- Produces: `Mount(source: str, target: str, read_only: bool)`; `ContainerSpec` frozen dataclass; `engineer_spec(...) -> ContainerSpec`; `challenger_spec(...) -> ContainerSpec`; `ContainerSpec.to_argv() -> list[str]`

**This task is Stage 0's exit gate expressed as tests.** Hermes profiles are explicitly *not* a security boundary — the docs state "a profile does not stop it from accessing folders outside the profile directory." The container is what makes Arm A's inability to reach observability data true rather than merely asserted.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_container.py
import pytest
from elcapitan.container import Mount, engineer_spec, challenger_spec

SCANNER = {"AWS_ACCESS_KEY_ID": "AKIA_SCANNER", "AWS_SECRET_ACCESS_KEY": "s1"}
OBSERVER = {"AWS_ACCESS_KEY_ID": "AKIA_OBSERVER", "AWS_SECRET_ACCESS_KEY": "s2"}
DIGEST = "sha256:" + "e" * 64

def eng(**kw):
    return engineer_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                         canonical_repo="/w/repos/anna", hermes_home="/tmp/h1",
                         secrets=SCANNER, **kw)

def test_canonical_repo_is_mounted_read_only():
    mount = next(m for m in eng().mounts if m.target.endswith("/canonical"))
    assert mount.read_only is True

def test_run_dir_is_writable():
    mount = next(m for m in eng().mounts if m.target.endswith("/run"))
    assert mount.read_only is False

def test_hermes_home_is_fresh_per_container():
    a = engineer_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                      canonical_repo="/w/repos/anna", hermes_home="/tmp/h1",
                      secrets=SCANNER)
    b = engineer_spec(image_digest=DIGEST, run_dir="/w/runs/R2",
                      canonical_repo="/w/repos/anna", hermes_home="/tmp/h2",
                      secrets=SCANNER)
    assert a.hermes_home != b.hermes_home

def test_image_is_referenced_by_digest_not_tag():
    assert "@sha256:" in eng().to_argv()[-2] or eng().image.startswith("sha256:")
    assert ":latest" not in " ".join(eng().to_argv())

def test_container_is_removed_on_exit():
    assert "--rm" in eng().to_argv()

def test_no_docker_socket_is_mounted():
    assert all("docker.sock" not in m.source for m in eng().mounts)

def test_ground_truth_path_is_rejected():
    with pytest.raises(ValueError, match="ground truth"):
        engineer_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                      canonical_repo="/w/repos/anna", hermes_home="/tmp/h1",
                      secrets=SCANNER,
                      extra_mounts=[Mount("/w/ground-truth", "/gt", True)])

# --- the experimental control ---

def test_arm_a_challenger_has_no_observer_credential():
    spec = challenger_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-a", hermes_home="/tmp/h2",
                           arm="A", scanner_secrets=SCANNER, observer_secrets=OBSERVER)
    assert spec.env["AWS_ACCESS_KEY_ID"] == "AKIA_SCANNER"
    assert "AKIA_OBSERVER" not in " ".join(spec.to_argv())

def test_arm_b_challenger_has_observer_credential():
    spec = challenger_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-b", hermes_home="/tmp/h2",
                           arm="B", scanner_secrets=SCANNER, observer_secrets=OBSERVER)
    assert spec.env["ELCAP_OBSERVER_AWS_ACCESS_KEY_ID"] == "AKIA_OBSERVER"

def test_challenger_bundle_is_mounted_read_only():
    spec = challenger_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-a", hermes_home="/tmp/h2",
                           arm="A", scanner_secrets=SCANNER, observer_secrets=OBSERVER)
    assert next(m for m in spec.mounts if m.target.endswith("/bundle")).read_only is True

def test_challenger_cannot_see_the_canonical_repo():
    spec = challenger_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-a", hermes_home="/tmp/h2",
                           arm="A", scanner_secrets=SCANNER, observer_secrets=OBSERVER)
    assert all("canonical" not in m.target for m in spec.mounts)

def test_unknown_arm_is_rejected():
    with pytest.raises(ValueError, match="arm"):
        challenger_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                        bundle_path="/w/b", hermes_home="/tmp/h2", arm="C",
                        scanner_secrets=SCANNER, observer_secrets=OBSERVER)

def test_network_is_disabled_for_the_challenger():
    # The challenger judges a fixed bundle; it must not fetch anything.
    spec = challenger_spec(image_digest=DIGEST, run_dir="/w/runs/R1",
                           bundle_path="/w/b", hermes_home="/tmp/h2", arm="A",
                           scanner_secrets=SCANNER, observer_secrets=OBSERVER)
    assert spec.network == "none" or "--network=none" in spec.to_argv()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_container.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'elcapitan.container'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/container.py
"""Ephemeral container specs — the experiment's actual isolation boundary.

Hermes profiles isolate config, sessions, skills and memory, but the docs are
explicit that "a profile does not stop it from accessing folders outside the
profile directory", and profiles are not a security boundary. Two profiles in
one long-running container would share an OS user and could read each other's
credentials, which would invalidate the claim that Arm A cannot reach
observability data. Containers make that claim true.
"""
from dataclasses import dataclass, field
from pathlib import PurePosixPath

GROUND_TRUTH_MARKERS = ("ground-truth", "ground_truth", "groundtruth")
VALID_ARMS = ("A", "B")

@dataclass(frozen=True)
class Mount:
    source: str
    target: str
    read_only: bool

    def to_flag(self) -> str:
        suffix = ",readonly" if self.read_only else ""
        return f"--mount=type=bind,source={self.source},target={self.target}{suffix}"

@dataclass(frozen=True)
class ContainerSpec:
    image: str
    mounts: list[Mount]
    env: dict[str, str]
    hermes_home: str
    network: str
    command: list[str] = field(default_factory=list)

    def to_argv(self) -> list[str]:
        argv = ["docker", "run", "--rm", f"--network={self.network}",
                "--user", "hermes", f"--env=HERMES_HOME={self.hermes_home}"]
        argv += [m.to_flag() for m in self.mounts]
        argv += [f"--env={k}={v}" for k, v in sorted(self.env.items())]
        argv += [self.image, *self.command]
        return argv

def _reject_ground_truth(mounts: list[Mount]) -> None:
    for mount in mounts:
        haystack = f"{mount.source} {mount.target}".lower()
        if any(marker in haystack for marker in GROUND_TRUTH_MARKERS):
            raise ValueError(
                f"refusing to mount ground truth into an agent container: {mount.source}")

def _image(image_digest: str) -> str:
    if not image_digest.startswith("sha256:"):
        raise ValueError("image must be pinned by digest")
    return f"elcapitan-lab@{image_digest}"

def engineer_spec(*, image_digest, run_dir, canonical_repo, hermes_home,
                  secrets: dict[str, str], extra_mounts: list[Mount] | None = None,
                  command: list[str] | None = None) -> ContainerSpec:
    mounts = [
        Mount(str(canonical_repo), "/work/canonical", True),
        Mount(str(run_dir), "/work/run", False),
        Mount(str(hermes_home), "/opt/data", False),
        *(extra_mounts or []),
    ]
    _reject_ground_truth(mounts)
    return ContainerSpec(image=_image(image_digest), mounts=mounts,
                         env=dict(secrets), hermes_home="/opt/data",
                         network="bridge", command=command or [])

def challenger_spec(*, image_digest, run_dir, bundle_path, hermes_home, arm,
                    scanner_secrets: dict[str, str], observer_secrets: dict[str, str],
                    command: list[str] | None = None) -> ContainerSpec:
    if arm not in VALID_ARMS:
        raise ValueError(f"unknown arm {arm!r}; expected one of {VALID_ARMS}")
    mounts = [
        Mount(str(bundle_path), "/work/bundle", True),
        Mount(str(PurePosixPath(run_dir) / "verdict"), "/work/out", False),
        Mount(str(hermes_home), "/opt/data", False),
    ]
    _reject_ground_truth(mounts)
    env = dict(scanner_secrets)
    if arm == "B":
        env.update({f"ELCAP_OBSERVER_{k}": v for k, v in observer_secrets.items()})
    # The challenger judges a fixed bundle. It fetches nothing.
    return ContainerSpec(image=_image(image_digest), mounts=mounts, env=env,
                         hermes_home="/opt/data", network="none",
                         command=command or [])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_container.py -v`
Expected: 13 passed

- [ ] **Step 5: Commit**

```bash
git add src/elcapitan/container.py tests/test_container.py
git commit -m "feat(isolation): ephemeral container specs enforce the arm boundary"
```

---

### Task 8: Runtime shim with a deterministic stub mode

**Files:**
- Create: `bin/agent-run.sh`, `src/elcapitan/shim.py`
- Test: `tests/test_shim.py`

**Interfaces:**
- Consumes: `container.ContainerSpec` (Task 7), `runtime.lock.json` (Task 1)
- Produces: `run_agent(spec, prompt_path, *, stub=None) -> AgentResult(exit_code: int, transcript: str)`

**Why a stub mode:** every test above this point must run without an LLM call, or the suite becomes slow, expensive, and non-deterministic — which would defeat the point of a deterministic harness. `stub` accepts a callable returning a canned transcript, used by every test; production passes `stub=None` and Hermes actually runs.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_shim.py
from pathlib import Path
import pytest
from elcapitan.container import engineer_spec
from elcapitan.shim import run_agent

DIGEST = "sha256:" + "f" * 64

def spec(tmp_path):
    return engineer_spec(image_digest=DIGEST, run_dir=str(tmp_path),
                         canonical_repo=str(tmp_path), hermes_home=str(tmp_path),
                         secrets={"K": "V"})

def test_stub_mode_returns_canned_transcript(tmp_path):
    prompt = tmp_path / "p.md"; prompt.write_text("do the thing")
    result = run_agent(spec(tmp_path), prompt,
                       stub=lambda argv, text: (0, f"STUB saw: {text}"))
    assert result.exit_code == 0
    assert "do the thing" in result.transcript

def test_stub_receives_the_full_docker_argv(tmp_path):
    prompt = tmp_path / "p.md"; prompt.write_text("x")
    seen = {}
    def stub(argv, text):
        seen["argv"] = argv
        return 0, ""
    run_agent(spec(tmp_path), prompt, stub=stub)
    assert seen["argv"][0] == "docker"
    assert "--rm" in seen["argv"]

def test_transcript_is_written_to_the_run_directory(tmp_path):
    prompt = tmp_path / "p.md"; prompt.write_text("x")
    run_agent(spec(tmp_path), prompt, stub=lambda a, t: (0, "hello"))
    assert (tmp_path / "transcript.log").read_text() == "hello"

def test_nonzero_exit_is_propagated(tmp_path):
    prompt = tmp_path / "p.md"; prompt.write_text("x")
    assert run_agent(spec(tmp_path), prompt,
                     stub=lambda a, t: (3, "boom")).exit_code == 3

def test_missing_prompt_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_agent(spec(tmp_path), tmp_path / "nope.md", stub=lambda a, t: (0, ""))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_shim.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'elcapitan.shim'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/shim.py
"""The only place an agent runtime is invoked.

If Hermes proves unsuitable, this file is the entire loss — records,
validator, container specs, adapters and scoring all survive unchanged.
"""
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .container import ContainerSpec

StubFn = Callable[[list[str], str], tuple[int, str]]

@dataclass(frozen=True)
class AgentResult:
    exit_code: int
    transcript: str

def run_agent(spec: ContainerSpec, prompt_path, *, stub: StubFn | None = None) -> AgentResult:
    prompt_path = Path(prompt_path)
    prompt_text = prompt_path.read_text()  # raises FileNotFoundError by design
    argv = spec.to_argv() + ["hermes", "--prompt-file", "/work/run/prompt.md"]

    if stub is not None:
        exit_code, transcript = stub(argv, prompt_text)
    else:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False)
        exit_code, transcript = completed.returncode, completed.stdout + completed.stderr

    run_dir = next(Path(m.source) for m in spec.mounts if m.target == "/work/run")
    (run_dir / "transcript.log").write_text(transcript)
    return AgentResult(exit_code=exit_code, transcript=transcript)
```

- [ ] **Step 4: Write the shell entry point**

```bash
#!/usr/bin/env bash
# bin/agent-run.sh — thin wrapper so the harness never calls Hermes directly.
set -euo pipefail
RUN_DIR="${1:?usage: agent-run.sh <run-dir> <prompt-file> <role> <arm>}"
PROMPT="${2:?missing prompt file}"
ROLE="${3:?missing role: engineer|challenger}"
ARM="${4:-A}"

python3 - "$RUN_DIR" "$PROMPT" "$ROLE" "$ARM" <<'PY'
import json, sys, os
from pathlib import Path
from elcapitan.container import engineer_spec, challenger_spec
from elcapitan.shim import run_agent

run_dir, prompt, role, arm = sys.argv[1:5]
lock = json.loads(Path("runtime.lock.json").read_text())
digest = lock["image_digest"]
scanner = {k: os.environ[k] for k in os.environ if k.startswith("ELCAP_SCANNER_")}
observer = {k: os.environ[k] for k in os.environ if k.startswith("ELCAP_OBSERVER_")}

if role == "engineer":
    spec = engineer_spec(image_digest=digest, run_dir=run_dir,
                         canonical_repo=os.environ["ELCAP_CANONICAL_REPO"],
                         hermes_home=os.environ["ELCAP_HERMES_HOME"], secrets=scanner)
else:
    spec = challenger_spec(image_digest=digest, run_dir=run_dir,
                           bundle_path=os.environ["ELCAP_BUNDLE"],
                           hermes_home=os.environ["ELCAP_HERMES_HOME"], arm=arm,
                           scanner_secrets=scanner, observer_secrets=observer)

result = run_agent(spec, prompt)
sys.exit(result.exit_code)
PY
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `chmod +x bin/agent-run.sh && pytest tests/test_shim.py -v`
Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
git add src/elcapitan/shim.py bin/agent-run.sh tests/test_shim.py
git commit -m "feat(shim): runtime shim with deterministic stub mode"
```

---

### Task 9: Trial harness — engineer stage

**Files:**
- Create: `bin/run-trial.sh`, `prompts/engineer.md`
- Test: `tests/test_run_trial.py`

**Interfaces:**
- Consumes: everything from Tasks 1–8
- Produces: a populated `runs/<run-id>/` containing `inputs/bundle.sha256`, `evidence/`, `evidence-index.json`, `proposal.json`, `transcript.log`, `canonical.digest`

- [ ] **Step 1: Write the engineer prompt**

The contract states *what must be established*, never how. No IaC system, cloud, or scanner is named — detecting the toolchain is a capability under measurement.

```markdown
<!-- prompts/engineer.md -->
You are a remediation engineer. You have been given one security finding in
OCSF form at `/work/run/inputs/finding.json`, and a source repository mounted
read-only at `/work/canonical`.

Establish each of the following, and cite evidence for every claim. Evidence
means the command you ran and its raw output, written to `/work/run/evidence/`.

1. Confirm the finding against the live environment. Cite the API call and its
   raw output.
2. Establish whether the affected resource is managed by infrastructure-as-code
   at all. State the method you used and your confidence. "Not managed by IaC"
   is a legitimate and important conclusion, not a failure.
3. If it is managed, locate the exact source construct. Cite file and line, and
   state the method by which you established the link.
4. Determine the root cause.
5. Choose exactly one resolution type: patch, runtime_change, risk_accepted,
   false_positive, or needs_design. If and only if you choose `patch`, apply it
   to the scratch working copy at `/work/run/patch/` — never to
   `/work/canonical`.
6. Verify your work using whatever the repository's own toolchain provides.
   Record every command, its argv, and its exit code.
7. State the production impact, the dependencies you identified, and what
   remains unknown.
8. Write `/work/run/proposal.json` conforming to the RemediationProposal schema.

Hard rules:
- Never mutate any cloud resource. You hold read-only credentials.
- Never write to `/work/canonical`. Never push. Never open a pull request.
- If required business or ownership knowledge is unavailable, set
  `status: NEEDS_HUMAN_CONTEXT`. That is a successful outcome, not a failure.
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_run_trial.py
import json, os, subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]

def test_run_trial_script_exists_and_is_executable():
    script = ROOT / "bin" / "run-trial.sh"
    assert script.is_file()
    assert os.access(script, os.X_OK)

def test_run_trial_refuses_without_required_env(tmp_path):
    result = subprocess.run([str(ROOT / "bin" / "run-trial.sh"), "anna", "FIND-001", "A", "1"],
                            capture_output=True, text=True, env={"PATH": os.environ["PATH"]})
    assert result.returncode != 0
    assert "ELCAP_" in result.stderr

def test_run_trial_stub_mode_produces_a_validating_run(tmp_path):
    env = {**os.environ,
           "ELCAP_STUB": "1",
           "ELCAP_WORKSPACE": str(tmp_path),
           "ELCAP_CANONICAL_REPO": str(tmp_path / "repo"),
           "ELCAP_GROUND_TRUTH_DIR": str(tmp_path / "gt")}
    (tmp_path / "repo").mkdir(); (tmp_path / "gt").mkdir()
    subprocess.run(["git", "init", "-q", str(tmp_path / "repo")], check=True)
    result = subprocess.run([str(ROOT / "bin" / "run-trial.sh"), "anna", "FIND-001", "A", "1"],
                            capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stderr
    runs = list((tmp_path / "runs").iterdir())
    assert len(runs) == 1
    assert (runs[0] / "proposal.json").is_file()
    assert (runs[0] / "inputs" / "bundle.sha256").is_file()

def test_ground_truth_dir_is_never_inside_the_workspace_runs_tree(tmp_path):
    env = {**os.environ, "ELCAP_STUB": "1", "ELCAP_WORKSPACE": str(tmp_path),
           "ELCAP_CANONICAL_REPO": str(tmp_path / "repo"),
           "ELCAP_GROUND_TRUTH_DIR": str(tmp_path / "runs" / "gt")}
    (tmp_path / "repo").mkdir(); (tmp_path / "runs" / "gt").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(tmp_path / "repo")], check=True)
    result = subprocess.run([str(ROOT / "bin" / "run-trial.sh"), "anna", "FIND-001", "A", "1"],
                            capture_output=True, text=True, env=env)
    assert result.returncode != 0
    assert "ground truth" in result.stderr.lower()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_run_trial.py -v`
Expected: FAIL — `bin/run-trial.sh` does not exist

- [ ] **Step 4: Implement the harness**

```bash
#!/usr/bin/env bash
# bin/run-trial.sh — the deterministic orchestrator.
#
# Hermes offers delegate_task background fan-out. It is deliberately NOT used
# for scored trials: agentic orchestration would add a second experimental
# variable. This script stays dumb on purpose.
set -euo pipefail

ENV_NAME="${1:?usage: run-trial.sh <env> <finding-id> <arm> <n>}"
FINDING_ID="${2:?missing finding id}"
ARM="${3:?missing arm (A|B)}"
TRIAL_N="${4:?missing trial number}"

: "${ELCAP_WORKSPACE:?ELCAP_WORKSPACE must be set}"
: "${ELCAP_CANONICAL_REPO:?ELCAP_CANONICAL_REPO must be set}"
: "${ELCAP_GROUND_TRUTH_DIR:?ELCAP_GROUND_TRUTH_DIR must be set}"

# Ground truth must live outside every agent-mounted path. Leakage would
# invalidate the entire experiment, so this is checked before anything runs.
case "$(cd "$ELCAP_GROUND_TRUTH_DIR" && pwd -P)" in
  "$(cd "$ELCAP_WORKSPACE" && pwd -P)"/runs*)
    echo "refusing to start: ground truth directory is inside the runs tree" >&2
    exit 2 ;;
esac

RUN_ID="${ENV_NAME}-${FINDING_ID}-arm${ARM}-n${TRIAL_N}"
RUN_DIR="${ELCAP_WORKSPACE}/runs/${RUN_ID}"
[ -e "$RUN_DIR" ] && { echo "run ${RUN_ID} already exists — trials are immutable" >&2; exit 3; }
mkdir -p "$RUN_DIR"/{inputs,evidence,patch,verdict}

# Fresh HERMES_HOME per trial: self-authored skills must not carry across.
HERMES_HOME="$(mktemp -d)"
export ELCAP_HERMES_HOME="$HERMES_HOME"
trap 'rm -rf "$HERMES_HOME"' EXIT

# Pin and record the canonical repository commit, then prove it unchanged later.
COMMIT="$(git -C "$ELCAP_CANONICAL_REPO" rev-parse HEAD)"
CANONICAL_DIGEST="$(git -C "$ELCAP_CANONICAL_REPO" rev-parse HEAD^{tree})"
echo "$CANONICAL_DIGEST" > "$RUN_DIR/canonical.digest"

# Build and hash the immutable input bundle.
cp "${ELCAP_WORKSPACE}/findings/${FINDING_ID}.json" "$RUN_DIR/inputs/finding.json"
cp "$(dirname "$0")/../prompts/engineer.md" "$RUN_DIR/prompt.md"
python3 -c "
import sys; from pathlib import Path
from elcapitan.hashing import sha256_bytes
parts = sorted(Path(sys.argv[1], 'inputs').glob('*'))
payload = b''.join(p.read_bytes() for p in parts)
Path(sys.argv[1], 'inputs', 'bundle.sha256').write_text(sha256_bytes(payload))
" "$RUN_DIR"

if [ "${ELCAP_STUB:-0}" = "1" ]; then
  python3 "$(dirname "$0")/../tests/stub_engineer.py" "$RUN_DIR" "$FINDING_ID"
else
  "$(dirname "$0")/agent-run.sh" "$RUN_DIR" "$RUN_DIR/prompt.md" engineer "$ARM"
fi

"$(dirname "$0")/validate-trial-artifacts.sh" "$RUN_DIR" "$CANONICAL_DIGEST"
echo "run ${RUN_ID} complete at commit ${COMMIT}"
```

- [ ] **Step 5: Write the stub engineer**

```python
# tests/stub_engineer.py
"""Emits a minimal valid run so the harness is testable without an LLM."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from elcapitan.evidence import Collector, write_evidence  # noqa: E402

run_dir, finding_id = Path(sys.argv[1]), sys.argv[2]
now = "2026-08-08T12:00:00Z"
collector = Collector(tool="stub", version="0", identity="stub-reader")
ref = write_evidence(run_dir, "EVD-001", "stub_response", b'{"stub":true}',
                     collector, command_id="CMD-001", now=now)

(run_dir / "evidence-index.json").write_text(json.dumps([ref.to_dict()]))
(run_dir / "transcript.log").write_text("stub engineer: no commands run\n")
(run_dir / "proposal.json").write_text(json.dumps({
    "proposal_id": "PROP-001", "schema_version": 1, "created_at": now,
    "finding_id": finding_id,
    "input_bundle_hash": (run_dir / "inputs" / "bundle.sha256").read_text().strip(),
    "validation": {"confirmed": True, "evidence": ["EVD-001"], "confidence": 0.5},
    "linking": {"iac_managed": False, "system_detected": "unknown",
                "method": "stub", "confidence": 0.0, "evidence": ["EVD-001"],
                "files": []},
    "root_cause": "stub", "resolution_type": "needs_design",
    "remediation": {"objective": "", "approach": "", "patch_file": None},
    "verification": {"commands_run": [], "output": [], "passed": None},
    "production_impact": {"expected": "", "dependencies": [], "unknowns": [],
                          "risk": ""},
    "context": {"severity": "", "asset_id": "", "owner": "", "exploitability": ""},
    "status": "NEEDS_HUMAN_CONTEXT",
}))
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `chmod +x bin/run-trial.sh && pytest tests/test_run_trial.py -v`
Expected: 4 passed

- [ ] **Step 7: Run the whole suite**

Run: `pytest -v`
Expected: all tests pass (~70)

- [ ] **Step 8: Commit**

```bash
git add bin/run-trial.sh prompts/engineer.md tests/test_run_trial.py tests/stub_engineer.py
git commit -m "feat(harness): deterministic engineer-stage trial runner"
```

---

### Task 10: Anna adapter and the Stage 1 shakedown

**Files:**
- Create: `environments/anna/env.yaml`, `environments/anna/README.md`
- Modify: none

**Interfaces:**
- Consumes: the full harness (Tasks 1–9)
- Produces: `runs/anna-FIND-001-armA-n1/` — the first real, validated run

**Human prerequisite.** Steps 1–2 need KK's AWS access to create a read-only identity. They cannot be automated.

- [ ] **Step 1: Create the read-only scanner identity**

```bash
aws iam create-user --user-name elcapitan-anna-scanner
aws iam attach-user-policy --user-name elcapitan-anna-scanner \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-user-policy --user-name elcapitan-anna-scanner \
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
aws iam create-access-key --user-name elcapitan-anna-scanner
```

Export as `ELCAP_SCANNER_AWS_ACCESS_KEY_ID` / `ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY`.
**No observability identity is created** — Anna collects no telemetry in this plan.

- [ ] **Step 2: Write the environment adapter**

```yaml
# environments/anna/env.yaml
name: anna
classification: exploratory        # NOT part of any scored matrix
cloud: aws
repository:
  path: ../../Anna/ni-sales-agent
  iac_root: aws/infra/cdk
  pin: HEAD                        # replaced with an exact SHA at Step 3
identities:
  scanner: ELCAP_SCANNER_          # env prefix
  observer: null                   # telemetry deliberately out of scope
telemetry:
  enabled: false
  reason: >
    MoA fans a bundle out to multiple model providers and Anna's CloudWatch
    logs may contain prospect PII. Hermes' moa.privacy_filter covers API keys,
    JWTs, emails and phone numbers, not business data. Redaction must precede
    model ingestion; until a prerequisite from spec Appendix B is chosen,
    Anna contributes no telemetry.
health_contract: null              # not required: no remediation is applied
ground_truth: null                 # none exists; results are human-adjudicated
```

- [ ] **Step 3: Pin the repository commit**

```bash
COMMIT=$(git -C ../Anna/ni-sales-agent rev-parse HEAD)
sed -i '' "s|pin: HEAD|pin: ${COMMIT}|" environments/anna/env.yaml
echo "pinned Anna at ${COMMIT}"
```

- [ ] **Step 4: Scan and normalise one finding**

```bash
mkdir -p "$ELCAP_WORKSPACE/findings"

AWS_ACCESS_KEY_ID="$ELCAP_SCANNER_AWS_ACCESS_KEY_ID" \
AWS_SECRET_ACCESS_KEY="$ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY" \
prowler aws --output-formats json-ocsf \
            --output-directory "$ELCAP_WORKSPACE/scans/anna"

# Pick one FAIL finding whose resource is plausibly present in the CDK stack.
jq '[.[] | select(.status_code=="FAIL")][0]' \
   "$ELCAP_WORKSPACE"/scans/anna/*.ocsf.json > /tmp/raw-finding.json

python3 -c "
import json, sys
from pathlib import Path
from elcapitan.evidence import Collector
from elcapitan.finding import normalise_ocsf
raw = json.loads(Path('/tmp/raw-finding.json').read_text())
run = Path(sys.argv[1]) / 'findings'
rec = normalise_ocsf(raw, run_dir=run, finding_id='FIND-001',
                     collector=Collector('prowler', sys.argv[2], 'elcapitan-anna-scanner'),
                     now=sys.argv[3])
(run / 'FIND-001.json').write_text(json.dumps(rec, indent=2))
print(rec['ocsf']['title'])
" "$ELCAP_WORKSPACE" "$(prowler --version | head -1)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

- [ ] **Step 5: Run the real engineer trial**

```bash
export ELCAP_CANONICAL_REPO="$PWD/../Anna/ni-sales-agent"
export ELCAP_GROUND_TRUTH_DIR="$HOME/.elcapitan-ground-truth"   # outside the workspace
mkdir -p "$ELCAP_GROUND_TRUTH_DIR"

./bin/run-trial.sh anna FIND-001 A 1
```

- [ ] **Step 6: Verify the Stage 1 exit conditions**

```bash
RUN="$ELCAP_WORKSPACE/runs/anna-FIND-001-armA-n1"

# Scanner output normalised, and a source location proposed:
jq '{iac_managed: .linking.iac_managed,
     system: .linking.system_detected,
     method: .linking.method,
     files: .linking.files,
     resolution: .resolution_type}' "$RUN/proposal.json"

# Validator passes independently of anything the agent claimed:
./bin/validate-trial-artifacts.sh "$RUN" "$(cat "$RUN/canonical.digest")"

# Canonical repo genuinely untouched:
git -C "$ELCAP_CANONICAL_REPO" status --porcelain | tee /dev/stderr | wc -l   # expect 0
```

All four must hold: scanner output normalised · one finding linked to a plausible CDK
source location · a change generated in scratch space · artifact validator passes.

- [ ] **Step 7: Record the prediction outcome**

The spec puts a prediction on record: *the agent greps the resource name in `*.ts`
rather than resolving ARN → physical name → CFN logical ID → `cdk.out/tree.json`
construct path → source.* Read `linking.method` verbatim and write down which
happened. Do not smooth the result — if the prediction was wrong, that is the more
interesting outcome.

```bash
jq -r '.linking.method' "$RUN/proposal.json" > environments/anna/OBSERVATIONS.md
```

- [ ] **Step 8: Commit**

```bash
git add environments/anna/
git commit -m "feat(anna): exploratory adapter and Stage 1 shakedown results

Results labelled exploratory: Anna changes cloud, IaC language and
environment-reality simultaneously and has no constructed ground truth, so
it cannot demonstrate generalisation. Telemetry deliberately not collected."
```

---

## Self-Review

**Spec coverage (Stages 0–1).**

| Spec requirement | Task |
|---|---|
| Exact image digest recorded | 1 |
| Evidence as hashed artifact references | 2 |
| OCSF provenance preserved, raw retained, vendor fields namespaced | 3 |
| Per-tool exit semantics (`-detailed-exitcode` = 2 is success) | 4 |
| Five resolution types; `NEEDS_HUMAN_CONTEXT` terminal | 5 |
| Host-side validator is final authority (9 checks) | 6 |
| Arm A cannot access the observer credential | 7 |
| Ground truth absent from both containers | 7, 9 |
| Canonical repo demonstrably read-only | 7, 9, 10 |
| Fresh `HERMES_HOME` per trial (no skill carry-over) | 9 |
| Input bundle built and hashed | 9 |
| Contract names no IaC system, cloud, or scanner | 9 |
| Anna labelled exploratory; no telemetry | 10 |
| Linking-method prediction recorded verbatim | 10 |

**Deferred to later plans, by design:** challenger container invocation, evidence
collector and paired A/B bundle derivation, MoA member positions, ReviewVerdict and
TrialResult records, randomised arm ordering, assertion-level scoring, and everything
in Stage 2 (Eiger Terraform, traps, load generator).

**Placeholder scan:** the only `<...>` placeholders are in Task 1 Step 4, where Step 3
gives the exact commands to resolve each value — deliberate, because guessing a
registry path or version would violate the pinning constraint.

**Type consistency:** `EvidenceRef` fields are identical in Tasks 2, 3, 6 and the
schema. `Collector` is reconstructed the same way in `validate._load_evidence_index`
and `test_finding`. `interpret_exit(tool, argv, code)` has one signature across Tasks 4
and 6. `engineer_spec` / `challenger_spec` keyword arguments match between Tasks 7, 8
and 9.
