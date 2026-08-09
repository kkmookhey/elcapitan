# El Capitan Probe Substrate & Anna Shakedown — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic host-side substrate — immutable records, contained evidence, real integrity checks, and isolation-enforcing ephemeral containers — then prove it end-to-end by running one real Anna finding through an engineer container and emitting a schema-valid, hash-verified `RemediationProposal`.

**Architecture:** Everything deterministic runs on the host in Python. The agent runs in a fresh, ephemeral container per stage, seeded from a sanitised baseline Hermes home. The host harness is the only component that launches containers, holds secrets, and reads ground truth. Records are written once; every evidence claim is a contained artifact reference whose hash the validator independently re-verifies.

**Tech Stack:** Python 3.12 · pytest · `jsonschema` + `referencing` · `uv` (dependency lock) · Docker · bash · Hermes Agent (pinned by built-image ID) · Prowler (OCSF output)

**Covers:** Spec Stages 0 and 1. Stage 2 (Eiger) and Stages 3–5 (challenger, arms, scored trials) are separate plans consuming these interfaces.

**Revision note:** this supersedes a first draft whose self-review claimed a passing suite it had not run. Five tests in that draft could not pass, and four "enforcement" mechanisms were assurance in name only. Task 0 now exists because several values in the previous draft were invented rather than resolved.

## Global Constraints

- **Pin exactly.** Base image digest **and** built-image ID are distinct identities and both are recorded. Dependency locking is a real resolver lock (`uv.lock`), not a hash of `pyproject.toml` — transitive dependencies must not float.
- **Ground truth lives outside every agent-mounted path.** Leakage invalidates the experiment.
- **Secret values never enter an argv, a `ContainerSpec` field that gets serialised, or a test string.** Specs carry variable *names*; values travel only in a narrowly scoped subprocess environment.
- **The challenger holds no cloud credentials.** It judges a fixed offline bundle with `--network=none`. The *evidence collector* holds the observer credential and builds Arm A/B bundles.
- **Canonical repository is mounted read-only.** The mount is the enforcement; post-run git checks are independent diagnostics, recomputed from the repository, never compared against a caller-supplied copy of the recorded value.
- **Transcript mutation-scanning is a diagnostic signal, not a control.** Credential scope and read-only mounts are the controls. Do not describe regexes as enforcement.
- **Exit codes are tool-specific.** `terraform plan -detailed-exitcode` returns `2` for a valid plan *containing changes*. A missing exit code is an error, never a default success.
- **Evidence paths are contained.** Resolve, prove `is_relative_to(run_dir)`, reject symlinks, create exclusively.
- **The host-side validator is the final authority**, and it returns structured failures rather than raising on malformed input.
- **Anna is exploratory.** No telemetry, no scored matrix, temporary role credentials only.

---

## File Structure

```
elcapitan/
├── pyproject.toml  uv.lock                 real resolver lock
├── runtime.lock.json                       base + derived image identities, tool versions
├── docker/Dockerfile                       derived image (executable, no placeholders)
├── baseline-home/                          sanitised Hermes home: config.yaml, SOUL.md, .env.template
├── bin/
│   ├── spike-image.sh                      Task 0 — proves image + invocation
│   ├── run-trial.sh                        harness entry point (engineer stage)
│   ├── agent-run.sh                        runtime shim — the only place Hermes is invoked
│   └── validate-trial-artifacts.sh
├── schemas/                                evidence-ref · command-record · finding-record · remediation-proposal
├── src/elcapitan/
│   ├── hashing.py      canonical JSON + SHA-256
│   ├── paths.py        containment + symlink rejection
│   ├── evidence.py     EvidenceRef, write_evidence, verify_evidence
│   ├── finding.py      normalise_ocsf (raw artifact packaged into the run)
│   ├── manifest.py     canonical input manifest + bundle hash
│   ├── toolsem.py      per-tool exit semantics
│   ├── records.py      schema loading, registry, FormatChecker, validators
│   ├── repo.py         real canonical-repository integrity checks
│   ├── validate.py     host-side validator
│   ├── container.py    ephemeral container specs (names-only secrets, hardening)
│   └── shim.py         the only Hermes invocation
├── environments/anna/env.yaml
└── tests/
```

---

### Task 0: Spike — prove the pinned image and the invocation

**Files:**
- Create: `bin/spike-image.sh`, `docs/spike-findings.md`
- Test: none — this task's deliverable *is* evidence

**Interfaces:**
- Consumes: nothing
- Produces: `docs/spike-findings.md` recording six facts that Tasks 1, 2 and 10 read directly: the resolved base image reference and digest; the exact working non-interactive invocation; whether tool transcript and usage metadata can be captured together; the minimum `/opt/data` contents required to start; whether `--user` breaks s6 init; and the observed exit-code behaviour.

**Why this is Task 0.** The previous draft invented `hermes --prompt-file`, which does not exist, and applied an upstream digest to a derived image, which cannot resolve. Neither error was discoverable from documentation alone. Nothing downstream may be written as if these answers are known.

**Known constraints going in** (from the Hermes CLI and Docker references, already verified):

- There is **no `--prompt-file`**. Non-interactive forms are `hermes chat -q "..."` and `hermes -z "..."`; input may also arrive on stdin.
- `-z` emits *only* the final response — no tool output. `chat -q` retains the interaction including tool calls. **The probe needs the tool transcript, so `-q` is the starting hypothesis.**
- `--usage-file <path>` writes a JSON cost/token report but is documented as working **with `-z` only**. This conflicts with needing `-q`. The spike must determine whether usage metadata can be obtained under `-q`, or whether token accounting comes from elsewhere.
- Useful flags: `-m/--model`, `--provider`, `-t/--toolsets` (terminal tools must be explicitly enabled), `--ignore-user-config` (determinism), `--yolo` (bypasses approval prompts — required for headless, and a deliberate reduction of a defence layer that must be recorded).
- The image runs **s6-overlay as PID 1** and drops to the `hermes` user (UID 10000) itself. **`--user` is not recommended** and may bypass init.
- `/opt/data` must contain `.env`, `config.yaml`, and `SOUL.md`. The setup wizard creates these interactively — so a baseline home must be prepared once and copied per trial (Task 2).

- [ ] **Step 1: Resolve the base image identity**

```bash
gh release list --repo NousResearch/hermes-agent --limit 5
docker pull nousresearch/hermes-agent:<exact-version-from-above>
docker image inspect nousresearch/hermes-agent:<exact-version> \
  --format '{{index .RepoDigests 0}}{{"\n"}}{{.Id}}'
```

Record both the `repo@sha256:...` digest and the local image ID.

- [ ] **Step 2: Create a throwaway Hermes home interactively**

```bash
mkdir -p /tmp/spike-home
docker run -it --rm -v /tmp/spike-home:/opt/data \
  nousresearch/hermes-agent:<exact-version> setup
ls -la /tmp/spike-home        # expect .env, config.yaml, SOUL.md
```

- [ ] **Step 3: Prove the non-interactive invocation**

Try each and record verbatim what happens — stdout, stderr, exit code, and whether tool calls appear.

```bash
cd /tmp && mkdir -p spike-run && echo "List the files in /work/run and write the count to /work/run/out.txt" > spike-run/prompt.md

# Hypothesis A — query mode, prompt as positional argument
docker run --rm -v /tmp/spike-home:/opt/data -v /tmp/spike-run:/work/run \
  nousresearch/hermes-agent:<exact-version> \
  chat -q "$(cat /tmp/spike-run/prompt.md)" -t terminal --yolo --ignore-user-config
echo "exit=$?"

# Hypothesis B — prompt on stdin
docker run --rm -i -v /tmp/spike-home:/opt/data -v /tmp/spike-run:/work/run \
  nousresearch/hermes-agent:<exact-version> \
  chat -q -t terminal --yolo --ignore-user-config < /tmp/spike-run/prompt.md
echo "exit=$?"

# Hypothesis C — scripting mode, to see what -z omits by comparison
docker run --rm -v /tmp/spike-home:/opt/data -v /tmp/spike-run:/work/run \
  nousresearch/hermes-agent:<exact-version> \
  -z "$(cat /tmp/spike-run/prompt.md)" --usage-file /work/run/usage.json
echo "exit=$?"
```

- [ ] **Step 4: Test the `--user` hypothesis**

```bash
docker run --rm --user hermes -v /tmp/spike-home:/opt/data \
  nousresearch/hermes-agent:<exact-version> chat -q "say ok"
```

Record whether s6 init completes or the container fails. If it fails, **`--user` must not appear in any container spec.**

- [ ] **Step 5: Record findings**

Write `docs/spike-findings.md` answering exactly six questions, with the commands and their real output pasted in:

```markdown
1. base_image_ref / base_image_digest =
2. Working invocation (verbatim argv) =
3. Tool transcript captured? How? Usage metadata alongside? =
4. Minimum /opt/data contents to start =
5. Does --user break s6 init? =
6. Exit code on success / on model error / on tool failure =
```

- [ ] **Step 6: Commit**

```bash
git add bin/spike-image.sh docs/spike-findings.md
git commit -m "spike: prove pinned Hermes image and non-interactive invocation"
```

**Gate:** do not start Task 1 until all six questions have real answers. If the tool transcript cannot be recovered from `-q`, stop and raise it — the probe's evidence requirements depend on it, and a design change is cheaper now than after Task 10.

---

### Task 1: Runtime manifest with distinct image identities and a real lock

**Files:**
- Create: `pyproject.toml`, `uv.lock`, `runtime.lock.json`, `docker/Dockerfile`, `src/elcapitan/__init__.py`
- Test: `tests/test_runtime_lock.py`

**Interfaces:**
- Consumes: `docs/spike-findings.md` (Task 0)
- Produces: `runtime.lock.json` with `base_image_ref`, `base_image_digest`, `runtime_image_ref`, `runtime_image_id`, `dockerfile_sha256`, `uv_lock_sha256`, `tool_versions` — read by Tasks 6, 9, 10

- [ ] **Step 1: Write the failing test**

```python
# tests/test_runtime_lock.py
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "runtime.lock.json"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
BARE = re.compile(r"^[0-9a-f]{64}$")

def test_required_keys_present():
    lock = json.loads(LOCK.read_text())
    for key in ("base_image_ref", "base_image_digest", "runtime_image_ref",
                "runtime_image_id", "dockerfile_sha256", "uv_lock_sha256",
                "tool_versions"):
        assert key in lock, f"missing {key}"

def test_base_and_runtime_identities_are_distinct():
    lock = json.loads(LOCK.read_text())
    assert lock["base_image_ref"] != lock["runtime_image_ref"], \
        "derived image must have its own repository identity"
    assert lock["base_image_digest"] != lock["runtime_image_id"], \
        "a digest from the base image cannot identify the derived image"

def test_both_image_identities_are_sha256():
    lock = json.loads(LOCK.read_text())
    assert SHA256.match(lock["base_image_digest"])
    assert SHA256.match(lock["runtime_image_id"])

def test_dockerfile_hash_matches_the_file_on_disk():
    import hashlib
    lock = json.loads(LOCK.read_text())
    actual = hashlib.sha256((ROOT / "docker" / "Dockerfile").read_bytes()).hexdigest()
    assert lock["dockerfile_sha256"] == actual, "Dockerfile changed without re-pinning"

def test_uv_lock_exists_and_hash_matches():
    import hashlib
    lock = json.loads(LOCK.read_text())
    uv_lock = ROOT / "uv.lock"
    assert uv_lock.is_file(), "a real resolver lock is required; a pyproject hash is not a lock"
    assert lock["uv_lock_sha256"] == hashlib.sha256(uv_lock.read_bytes()).hexdigest()

def test_dockerfile_contains_no_unresolved_placeholders():
    text = (ROOT / "docker" / "Dockerfile").read_text()
    assert "<" not in text and ">" not in text, "Dockerfile still contains template placeholders"

def test_dockerfile_pins_every_tool_it_installs():
    lock = json.loads(LOCK.read_text())
    text = (ROOT / "docker" / "Dockerfile").read_text()
    assert lock["tool_versions"], "at least one tool must be pinned"
    for tool, version in lock["tool_versions"].items():
        assert version[0].isdigit(), f"{tool} version {version!r} must be exact"
        assert version in text, f"{tool}=={version} must appear in the Dockerfile"

def test_no_floating_specifiers_anywhere():
    for token in (">=", "<=", "^", "~", ":latest", ":main"):
        assert token not in LOCK.read_text(), f"floating specifier {token!r}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_runtime_lock.py -v`
Expected: FAIL — `runtime.lock.json` does not exist

- [ ] **Step 3: Write the project files and generate a real lock**

```toml
# pyproject.toml
[project]
name = "elcapitan"
version = "0.1.0"
requires-python = "==3.12.*"
dependencies = ["jsonschema==4.23.0", "referencing==0.35.1", "PyYAML==6.0.2"]

[dependency-groups]
dev = ["pytest==8.3.3"]

[build-system]
requires = ["setuptools==75.1.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]
```

```bash
uv lock            # produces uv.lock with fully resolved transitive dependencies
uv sync --group dev
```

- [ ] **Step 4: Write an executable Dockerfile**

Substitute the base reference and digest recorded in Task 0. Every version below must also appear in `runtime.lock.json.tool_versions`; the test enforces both directions.

```dockerfile
# docker/Dockerfile
FROM nousresearch/hermes-agent@sha256:BASE_DIGEST_FROM_TASK_0

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      git=1:2.45.2-1 curl=8.9.1-2 jq=1.7.1-3 unzip=6.0-28 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Terraform
RUN curl -fsSL -o /tmp/tf.zip \
      https://releases.hashicorp.com/terraform/1.9.8/terraform_1.9.8_linux_amd64.zip \
 && unzip -d /usr/local/bin /tmp/tf.zip && rm /tmp/tf.zip

# Trivy
RUN curl -fsSL -o /tmp/trivy.deb \
      https://github.com/aquasecurity/trivy/releases/download/v0.56.2/trivy_0.56.2_Linux-64bit.deb \
 && dpkg -i /tmp/trivy.deb && rm /tmp/trivy.deb

# Prowler and the AWS/Azure CLIs, pinned
RUN python3 -m pip install --no-cache-dir \
      prowler==5.2.1 awscli==1.34.24 azure-cli==2.64.0

# No USER directive: s6-overlay is PID 1 and drops to the hermes user itself.
# Task 0 Step 4 confirms whether forcing --user breaks init.
WORKDIR /work
```

- [ ] **Step 5: Build the derived image and record its identity**

```bash
BASE_DIGEST=$(jq -r .base_image_digest runtime.lock.json 2>/dev/null || echo "sha256:...")
docker build -t elcapitan-lab:0.1.0 -f docker/Dockerfile .
RUNTIME_ID=$(docker image inspect elcapitan-lab:0.1.0 --format '{{.Id}}')

python3 - <<PY
import hashlib, json, pathlib, subprocess
def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
runtime_id = subprocess.check_output(
    ["docker","image","inspect","elcapitan-lab:0.1.0","--format","{{.Id}}"], text=True).strip()
pathlib.Path("runtime.lock.json").write_text(json.dumps({
  "base_image_ref": "nousresearch/hermes-agent",
  "base_image_digest": "sha256:BASE_DIGEST_FROM_TASK_0",
  "runtime_image_ref": "elcapitan-lab:0.1.0",
  "runtime_image_id": runtime_id,
  "dockerfile_sha256": sha("docker/Dockerfile"),
  "uv_lock_sha256": sha("uv.lock"),
  "tool_versions": {"terraform":"1.9.8","trivy":"0.56.2","prowler":"5.2.1",
                    "awscli":"1.34.24","azure-cli":"2.64.0"}
}, indent=2) + "\n")
PY
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_runtime_lock.py -v`
Expected: 8 passed

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock runtime.lock.json docker/Dockerfile src/elcapitan/__init__.py tests/test_runtime_lock.py
git commit -m "feat(substrate): distinct base/derived image identities and real dependency lock"
```

---

### Task 2: Sanitised baseline Hermes home

**Files:**
- Create: `baseline-home/config.yaml`, `baseline-home/SOUL.md`, `baseline-home/.env.template`, `src/elcapitan/home.py`
- Test: `tests/test_home.py`

**Interfaces:**
- Consumes: `docs/spike-findings.md` Q4 (Task 0)
- Produces: `seed_hermes_home(dest: Path, *, model: str, provider: str) -> Path` — copies the baseline into a fresh directory and writes a `.env` containing **no secrets**; secret values arrive as container environment variables at run time.

**Why:** a fresh empty `HERMES_HOME` has no model, provider, approval policy, or skills, so Hermes cannot start. The previous draft's `mktemp -d` would have failed at the first real run.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_home.py
import pytest
from pathlib import Path
from elcapitan.home import seed_hermes_home, BASELINE_FILES

def test_seeds_all_required_baseline_files(tmp_path):
    home = seed_hermes_home(tmp_path / "h1", model="m", provider="p")
    for name in BASELINE_FILES:
        assert (home / name).is_file(), f"{name} missing — Hermes will not start"

def test_env_contains_no_secret_values(tmp_path):
    home = seed_hermes_home(tmp_path / "h1", model="m", provider="p")
    text = (home / ".env").read_text()
    for marker in ("AKIA", "sk-", "PRIVATE KEY", "SECRET_ACCESS_KEY="):
        assert marker not in text, f"baseline .env must not carry secrets ({marker})"

def test_two_seeds_are_independent_directories(tmp_path):
    a = seed_hermes_home(tmp_path / "a", model="m", provider="p")
    b = seed_hermes_home(tmp_path / "b", model="m", provider="p")
    assert a != b
    (a / "skills").mkdir(exist_ok=True)
    (a / "skills" / "learned.md").write_text("x")
    assert not (b / "skills" / "learned.md").exists(), \
        "self-authored skills must not carry between trials"

def test_model_and_provider_are_written_into_config(tmp_path):
    home = seed_hermes_home(tmp_path / "h1", model="claude-opus-5", provider="anthropic")
    config = (home / "config.yaml").read_text()
    assert "claude-opus-5" in config and "anthropic" in config

def test_refuses_to_overwrite_an_existing_home(tmp_path):
    seed_hermes_home(tmp_path / "h1", model="m", provider="p")
    with pytest.raises(FileExistsError):
        seed_hermes_home(tmp_path / "h1", model="m", provider="p")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_home.py -v`
Expected: FAIL — `No module named 'elcapitan.home'`

- [ ] **Step 3: Write the baseline files**

```yaml
# baseline-home/config.yaml — deterministic; model/provider substituted at seed time
model: "__MODEL__"
provider: "__PROVIDER__"
temperature: 0
terminal:
  backend: local          # the container IS the sandbox for this probe
approvals:
  mode: manual            # headless runs pass --yolo explicitly; see spike findings Q2
memory:
  enabled: false          # scored trials must not accumulate cross-run state
skills:
  auto_create: false      # self-authoring is measured separately, not during scored trials
```

```markdown
<!-- baseline-home/SOUL.md -->
You are a remediation engineer operating inside an isolated, ephemeral container.
You hold read-only credentials. You never mutate cloud resources, never write to
`/work/canonical`, and never push to any remote.
```

```bash
# baseline-home/.env.template — names only. Values are injected as container env vars.
# AWS_ACCESS_KEY_ID
# AWS_SECRET_ACCESS_KEY
# AWS_SESSION_TOKEN
# ANTHROPIC_API_KEY
```

- [ ] **Step 4: Implement**

```python
# src/elcapitan/home.py
"""Seed a fresh Hermes home per trial.

An empty HERMES_HOME cannot start: the image requires config.yaml, SOUL.md and
.env in /opt/data. Secrets are deliberately absent from the seeded .env — values
arrive as container environment variables so they never touch disk or argv.
"""
import shutil
from pathlib import Path

BASELINE_DIR = Path(__file__).resolve().parents[2] / "baseline-home"
BASELINE_FILES = ("config.yaml", "SOUL.md", ".env")

def seed_hermes_home(dest, *, model: str, provider: str) -> Path:
    dest = Path(dest)
    if dest.exists():
        raise FileExistsError(f"{dest} already exists; trials require a fresh home")
    dest.mkdir(parents=True)

    config = (BASELINE_DIR / "config.yaml").read_text()
    config = config.replace("__MODEL__", model).replace("__PROVIDER__", provider)
    (dest / "config.yaml").write_text(config)

    shutil.copy2(BASELINE_DIR / "SOUL.md", dest / "SOUL.md")
    (dest / ".env").write_text((BASELINE_DIR / ".env.template").read_text())
    return dest
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_home.py -v`
Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
git add baseline-home/ src/elcapitan/home.py tests/test_home.py
git commit -m "feat(runtime): sanitised baseline Hermes home seeded fresh per trial"
```

---

### Task 3: Hashing and contained evidence artifacts

**Files:**
- Create: `src/elcapitan/hashing.py`, `src/elcapitan/paths.py`, `src/elcapitan/evidence.py`, `schemas/evidence-ref.schema.json`
- Test: `tests/test_hashing.py`, `tests/test_paths.py`, `tests/test_evidence.py`

**Interfaces:**
- Produces: `sha256_bytes`, `sha256_file`, `canonical_json`, `sha256_record`; `safe_resolve(root, relative) -> Path`; `EvidenceRef`, `Collector`, `write_evidence(...)`, `verify_evidence(root, ref) -> bool`

**Threat model:** `evidence-index.json` is written by the agent. Its `artifact_path` is untrusted input to a host-side validator.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_hashing.py
from elcapitan.hashing import sha256_bytes, sha256_file, canonical_json, sha256_record
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def test_known_vector(): assert sha256_bytes(b"") == EMPTY
def test_file_matches_bytes(tmp_path):
    p = tmp_path / "a"; p.write_bytes(b'{"x":1}')
    assert sha256_file(p) == sha256_bytes(b'{"x":1}')
def test_canonical_is_key_order_independent():
    assert canonical_json({"b":1,"a":2}) == canonical_json({"a":2,"b":1})
def test_canonical_has_no_whitespace():
    assert canonical_json({"a":1,"b":2}) == b'{"a":1,"b":2}'
def test_record_hash_changes_on_value_change():
    assert sha256_record({"a":1}) != sha256_record({"a":2})
```

```python
# tests/test_paths.py
import pytest
from elcapitan.paths import safe_resolve, PathEscape

def test_accepts_a_contained_relative_path(tmp_path):
    (tmp_path / "evidence").mkdir(); (tmp_path / "evidence" / "a.bin").write_bytes(b"x")
    assert safe_resolve(tmp_path, "evidence/a.bin").is_file()

def test_rejects_parent_traversal(tmp_path):
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "../outside")

def test_rejects_absolute_path(tmp_path):
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "/etc/passwd")

def test_rejects_symlinked_file(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "link").symlink_to("/etc/passwd")
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "evidence/link")

def test_rejects_symlinked_parent_directory(tmp_path):
    outside = tmp_path.parent / "outside"; outside.mkdir(exist_ok=True)
    (tmp_path / "evidence").symlink_to(outside, target_is_directory=True)
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "evidence/anything")

def test_rejects_embedded_traversal_that_still_lands_inside(tmp_path):
    # Normalises back inside, but the intent is suspicious: reject on '..' outright.
    with pytest.raises(PathEscape):
        safe_resolve(tmp_path, "evidence/../evidence/a.bin")
```

```python
# tests/test_evidence.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hashing.py tests/test_paths.py tests/test_evidence.py -v`
Expected: FAIL — modules do not exist

- [ ] **Step 3: Implement hashing and paths**

```python
# src/elcapitan/hashing.py
import hashlib, json
from pathlib import Path
from typing import Any

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def sha256_record(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj))
```

```python
# src/elcapitan/paths.py
"""Containment for agent-supplied paths.

evidence-index.json is written by the agent. Any path it contains is untrusted
input to a host-side validator running with the operator's privileges.
"""
from pathlib import Path

class PathEscape(Exception):
    """A supplied path is absolute, traverses upward, or crosses a symlink."""

def safe_resolve(root, relative: str) -> Path:
    root = Path(root).resolve(strict=True)
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise PathEscape(f"unsafe path: {relative!r}")

    candidate = root
    for part in Path(relative).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise PathEscape(f"symlink in evidence path: {candidate}")

    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise PathEscape(f"path escapes run directory: {relative!r}")
    return resolved
```

- [ ] **Step 4: Implement evidence**

```python
# src/elcapitan/evidence.py
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
    """False on tamper, absence, or containment violation — never raises.

    The hash read is inside the guard too: an artifact can disappear or become
    unreadable between the is_file() check and the open, and a validator
    iterating many refs must mark that one entry invalid rather than abort the
    whole batch. Task 9 depends on this returning structured failures.
    """
    try:
        path = safe_resolve(run_dir, ref.artifact_path)
        if not path.is_file():
            return False
        return sha256_file(path) == ref.sha256
    except (PathEscape, FileNotFoundError, OSError):
        return False
```

- [ ] **Step 5: Write the evidence schema**

```json
// schemas/evidence-ref.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "evidence-ref.schema.json",
  "title": "EvidenceRef",
  "type": "object",
  "additionalProperties": false,
  "required": ["evidence_id","type","artifact_path","sha256","collected_at",
               "sensitivity","command_id","collector"],
  "properties": {
    "evidence_id":   { "type": "string", "pattern": "^EVD-[0-9]{3,}$" },
    "type":          { "type": "string", "minLength": 1 },
    "artifact_path": { "type": "string",
                       "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))[A-Za-z0-9._/-]+$" },
    "sha256":        { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "collected_at":  { "type": "string", "format": "date-time" },
    "sensitivity":   { "enum": ["public","internal","confidential","restricted"] },
    "command_id":    { "type": "string" },
    "collector": {
      "type": "object", "additionalProperties": false,
      "required": ["tool","version","identity"],
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

Run: `pytest tests/test_hashing.py tests/test_paths.py tests/test_evidence.py -v`
Expected: 18 passed

- [ ] **Step 7: Commit**

```bash
git add src/elcapitan/hashing.py src/elcapitan/paths.py src/elcapitan/evidence.py schemas/evidence-ref.schema.json tests/test_hashing.py tests/test_paths.py tests/test_evidence.py
git commit -m "feat(records): contained, exclusively-created evidence artifacts"
```

---

### Task 4: Strict schemas with working `$ref` and format checking

**Files:**
- Create: `src/elcapitan/records.py`, `schemas/command-record.schema.json`, `schemas/finding-record.schema.json`, `schemas/remediation-proposal.schema.json`
- Test: `tests/test_records.py`

**Interfaces:**
- Produces: `load_schema(name) -> dict`; `validator_for(name) -> Draft202012Validator`; `validate_doc(name, doc) -> list[str]`; `RESOLUTION_TYPES`; `TERMINAL_STATUSES`

**Fixes from review:** `FormatChecker` was absent so `format: date-time` was decorative; relative `$ref` never resolved; `commands_run` accepted anything; a confirmed finding could cite no evidence; `READY_FOR_REVIEW` could coexist with empty remediation.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_records.py
import copy, pytest
from elcapitan.records import (RESOLUTION_TYPES, TERMINAL_STATUSES,
                               validate_doc, validator_for)

CMD = {"command_id": "CMD-001", "tool": "terraform",
       "argv": ["plan", "-detailed-exitcode"], "exit_code": 2,
       "started_at": "2026-08-08T12:00:00Z", "completed_at": "2026-08-08T12:00:05Z",
       "stdout_evidence_id": "EVD-002", "stderr_evidence_id": "EVD-003"}

PROPOSAL = {
    "proposal_id": "PROP-001", "schema_version": 1,
    "created_at": "2026-08-08T12:00:00Z", "finding_id": "FIND-001",
    "input_bundle_hash": "a"*64,
    "validation": {"confirmed": True, "evidence": ["EVD-001"], "confidence": 0.9},
    "linking": {"iac_managed": False, "system_detected": "aws-cdk",
                "method": "grep", "confidence": 0.4, "evidence": ["EVD-001"],
                "files": []},
    "root_cause": "runtime creation", "resolution_type": "runtime_change",
    "remediation": {"objective": "o", "approach": "a", "patch_file": None},
    "verification": {"commands_run": [CMD], "output": [], "passed": True},
    "production_impact": {"expected": "none", "dependencies": [], "unknowns": [],
                          "risk": "low"},
    "context": {"severity": "High", "asset_id": "arn", "owner": "",
                "exploitability": ""},
    "status": "READY_FOR_REVIEW",
}

def test_valid_proposal_passes():
    assert validate_doc("remediation-proposal", PROPOSAL) == []

def test_ref_to_evidence_schema_resolves():
    # $ref resolution in `referencing` is LAZY — constructing the validator
    # succeeds even with a broken registry, and a document that never touches
    # the `raw_event` key never dereferences it either (the `properties`
    # keyword only applies to keys actually present). So the document below
    # deliberately includes `raw_event` with an invalid inner value, forcing
    # the $ref to actually resolve during iter_errors. With the registry wired
    # correctly this surfaces the evidence-ref schema's own field errors
    # (proving real resolution, not just "any string got accepted"); with a
    # broken registry, `referencing` raises Unresolvable instead of yielding
    # errors, which fails this test loudly rather than passing vacuously.
    doc = {"finding_id": "FIND-001", "raw_event": {"evidence_id": "not-a-match"}}
    errors = validate_doc("finding-record", doc)
    assert errors, "expected schema errors, not a resolution failure"
    assert any(e.startswith("raw_event") for e in errors), (
        f"expected errors from inside the resolved evidence-ref schema: {errors}")

def test_format_checker_rejects_a_malformed_timestamp():
    doc = copy.deepcopy(PROPOSAL); doc["created_at"] = "not-a-date"
    assert validate_doc("remediation-proposal", doc) != []

def test_command_record_requires_exit_code():
    doc = copy.deepcopy(PROPOSAL); del doc["verification"]["commands_run"][0]["exit_code"]
    assert validate_doc("remediation-proposal", doc) != []

def test_command_record_rejects_arbitrary_shape():
    doc = copy.deepcopy(PROPOSAL); doc["verification"]["commands_run"] = ["terraform plan"]
    assert validate_doc("remediation-proposal", doc) != []

def test_confirmed_finding_must_cite_evidence():
    doc = copy.deepcopy(PROPOSAL); doc["validation"]["evidence"] = []
    assert validate_doc("remediation-proposal", doc) != []

def test_iac_managed_true_requires_linked_files():
    doc = copy.deepcopy(PROPOSAL)
    doc["linking"].update({"iac_managed": True, "files": []})
    assert validate_doc("remediation-proposal", doc) != []

def test_patch_resolution_requires_patch_file():
    doc = copy.deepcopy(PROPOSAL); doc["resolution_type"] = "patch"
    assert validate_doc("remediation-proposal", doc) != []

def test_ready_for_review_requires_non_empty_impact():
    doc = copy.deepcopy(PROPOSAL); doc["production_impact"]["expected"] = ""
    assert validate_doc("remediation-proposal", doc) != []

def test_needs_human_context_may_have_empty_impact():
    doc = copy.deepcopy(PROPOSAL)
    doc["status"] = "NEEDS_HUMAN_CONTEXT"; doc["production_impact"]["expected"] = ""
    assert validate_doc("remediation-proposal", doc) == []

def test_all_five_resolution_types_exist():
    assert set(RESOLUTION_TYPES) == {"patch","runtime_change","risk_accepted",
                                     "false_positive","needs_design"}

def test_both_terminal_statuses_exist():
    assert set(TERMINAL_STATUSES) == {"READY_FOR_REVIEW","NEEDS_HUMAN_CONTEXT"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_records.py -v`
Expected: FAIL — `No module named 'elcapitan.records'`

- [ ] **Step 3: Write the command-record schema**

```json
// schemas/command-record.schema.json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "command-record.schema.json",
  "title": "CommandRecord",
  "type": "object",
  "additionalProperties": false,
  "required": ["command_id","tool","argv","exit_code","started_at",
               "completed_at","stdout_evidence_id","stderr_evidence_id"],
  "properties": {
    "command_id":         { "type": "string", "pattern": "^CMD-[0-9]{3,}$" },
    "tool":               { "type": "string", "minLength": 1 },
    "argv":               { "type": "array", "items": { "type": "string" } },
    "exit_code":          { "type": "integer" },
    "started_at":         { "type": "string", "format": "date-time" },
    "completed_at":       { "type": "string", "format": "date-time" },
    "stdout_evidence_id": { "type": "string", "pattern": "^EVD-[0-9]{3,}$" },
    "stderr_evidence_id": { "type": "string", "pattern": "^EVD-[0-9]{3,}$" }
  }
}
```

- [ ] **Step 4: Write the proposal schema with conditional rules**

Take the base object from the previous draft and add `$id: "remediation-proposal.schema.json"`, replace `verification.commands_run.items` with `{"$ref": "command-record.schema.json"}`, give `verification.output` `{"type":"string"}` items, and append:

```json
"allOf": [
  { "if":   { "properties": { "resolution_type": { "const": "patch" } } },
    "then": { "properties": { "remediation": {
                "properties": { "patch_file": { "type": "string", "minLength": 1 } },
                "required": ["patch_file"] } } } },

  { "if":   { "properties": { "validation": {
                "properties": { "confirmed": { "const": true } } } } },
    "then": { "properties": { "validation": {
                "properties": { "evidence": { "minItems": 1 } } } } } },

  { "if":   { "properties": { "linking": {
                "properties": { "iac_managed": { "const": true } } } } },
    "then": { "properties": { "linking": {
                "properties": { "files": { "minItems": 1 } } } } } },

  { "if":   { "properties": { "status": { "const": "READY_FOR_REVIEW" } } },
    "then": { "properties": { "production_impact": {
                "properties": { "expected": { "minLength": 1 },
                                "risk":     { "minLength": 1 } } } } } }
]
```

The `finding-record.schema.json` from the previous draft is reused unchanged except for adding `"$id": "finding-record.schema.json"`.

- [ ] **Step 5: Implement the loader**

```python
# src/elcapitan/records.py
"""Schema loading with working $ref resolution and real format checking.

jsonschema does not enforce `format` unless a FormatChecker is supplied, and
relative $ref only resolves when the sibling schemas are in a registry.
Both were missing in the first draft, which made the schemas decorative.
"""
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"

RESOLUTION_TYPES = ("patch", "runtime_change", "risk_accepted",
                    "false_positive", "needs_design")
TERMINAL_STATUSES = ("READY_FOR_REVIEW", "NEEDS_HUMAN_CONTEXT")

@lru_cache(maxsize=None)
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text())

@lru_cache(maxsize=None)
def _registry() -> Registry:
    resources = [
        (path.name, Resource.from_contents(json.loads(path.read_text()),
                                           default_specification=DRAFT202012))
        for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
    ]
    return Registry().with_resources(resources)

# jsonschema's built-in "date-time" check is a NO-OP unless the optional
# rfc3339-validator package is installed — supplying FormatChecker() alone
# leaves the format decorative. Adding a dependency is barred by the pinning
# constraint, so register a strict project-owned checker: RFC3339 requires a
# full date, a full time, and an offset. datetime.fromisoformat alone is too
# permissive — it accepts "2026-08-08" and "2026-08-08T12:00:00".
_FORMAT_CHECKER = FormatChecker()

@_FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _is_rfc3339_date_time(instance) -> bool:
    if not isinstance(instance, str):
        return True                      # non-strings are the type keyword's job
    if not re.match(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}", instance):
        return False                     # date-only or missing time component
    parsed = datetime.fromisoformat(instance.replace("Z", "+00:00"))
    return parsed.tzinfo is not None     # RFC3339 requires an offset

@lru_cache(maxsize=None)
def validator_for(name: str) -> Draft202012Validator:
    return Draft202012Validator(load_schema(name), registry=_registry(),
                                format_checker=_FORMAT_CHECKER)

def validate_doc(name: str, doc: dict) -> list[str]:
    """Human-readable errors. Empty list means valid."""
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator_for(name).iter_errors(doc),
                          key=lambda e: list(e.absolute_path))
    ]
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_records.py -v`
Expected: 12 passed

- [ ] **Step 7: Commit**

```bash
git add src/elcapitan/records.py schemas/ tests/test_records.py
git commit -m "feat(records): strict schemas with resolved refs and format checking"
```

---

### Task 5: OCSF normalisation with the raw artifact inside the run

**Files:**
- Create: `src/elcapitan/finding.py`
- Test: `tests/test_finding.py`, `tests/fixtures/prowler-ocsf-sample.json`

**Interfaces:**
- Consumes: `evidence`, `records.validate_doc`
- Produces: `normalise_ocsf(raw, *, run_dir, finding_id, collector, now) -> dict` — writes the raw event **into `run_dir`**, so `raw_event.artifact_path` resolves inside the trial bundle

**Fix from review:** the previous draft wrote the raw artifact to a shared findings directory while the harness copied only the normalised JSON, leaving a dangling reference the validator never checked.

- [ ] **Step 1: Write the fixture** — identical to the previous draft's `tests/fixtures/prowler-ocsf-sample.json` (Prowler OCSF Detection Finding with `metadata`, `class_uid: 2004`, `finding_info`, `cloud`, `resources`, `time_dt`, `severity`, `unmapped`).

- [ ] **Step 2: Write the failing test**

```python
# tests/test_finding.py
import json
from pathlib import Path
import pytest
from elcapitan.evidence import Collector, EvidenceRef, verify_evidence
from elcapitan.finding import normalise_ocsf
from elcapitan.records import validate_doc

FIXTURE = Path(__file__).parent / "fixtures" / "prowler-ocsf-sample.json"
C = Collector(tool="prowler", version="5.2.1", identity="anna-scanner")
NOW = "2026-08-08T12:00:00Z"

@pytest.fixture
def rec(tmp_path):
    raw = json.loads(FIXTURE.read_text())
    return normalise_ocsf(raw, run_dir=tmp_path, finding_id="FIND-001",
                          collector=C, now=NOW), tmp_path

def test_output_validates_against_its_schema(rec):
    record, _ = rec
    assert validate_doc("finding-record", record) == []

def test_provenance_is_fully_preserved(rec):
    record, _ = rec
    p = record["provenance"]
    assert (p["product"], p["product_version"]) == ("Prowler", "5.2.1")
    assert (p["provider"], p["account"], p["region"]) == ("aws", "111122223333", "us-east-1")
    assert p["observed_at"] == "2026-08-08T11:00:00Z"

def test_ocsf_identifiers_preserved(rec):
    record, _ = rec
    assert record["ocsf"]["class_uid"] == 2004
    assert record["ocsf"]["original_uid"] == "prowler-aws-s3-123"
    assert record["ocsf"]["version"] == "1.3.0"

def test_resource_preserved(rec):
    record, _ = rec
    assert record["resource"]["uid"] == "arn:aws:s3:::anna-assets"

def test_raw_artifact_lives_inside_the_run_dir(rec):
    record, run_dir = rec
    assert (run_dir / record["raw_event"]["artifact_path"]).is_file()

def test_raw_artifact_hash_verifies(rec):
    record, run_dir = rec
    ref = EvidenceRef(**{**record["raw_event"],
                         "collector": Collector(**record["raw_event"]["collector"])})
    assert verify_evidence(run_dir, ref) is True

def test_vendor_fields_namespaced_not_discarded(rec):
    record, _ = rec
    assert record["vendor_extensions"]["prowler_check_id"] == "s3_bucket_public_access"

def test_rejects_non_ocsf_input(tmp_path):
    with pytest.raises(ValueError, match="class_uid"):
        normalise_ocsf({"metadata": {}}, run_dir=tmp_path, finding_id="FIND-001",
                       collector=C, now=NOW)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_finding.py -v`
Expected: FAIL — `No module named 'elcapitan.finding'`

- [ ] **Step 4: Implement** — as in the previous draft, with one change: `run_dir` is the *trial* run directory, so the raw artifact is written where `raw_event.artifact_path` will resolve. Use `write_evidence(run_dir, "EVD-001", "scanner_raw_event", canonical_json(raw), collector, command_id="CMD-000", now=now)` and return the same record shape (`finding_id`, `ocsf`, `provenance`, `resource`, `severity`, `raw_event`, `vendor_extensions`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_finding.py -v`
Expected: 8 passed

- [ ] **Step 6: Commit**

```bash
git add src/elcapitan/finding.py tests/test_finding.py tests/fixtures/
git commit -m "feat(records): OCSF normalisation packages its raw artifact into the run"
```

---

### Task 6: Canonical input manifest

**Files:**
- Create: `src/elcapitan/manifest.py`
- Test: `tests/test_manifest.py`

**Interfaces:**
- Produces: `build_manifest(run_dir, *, files, repository_commit, runtime_image_id, runtime_lock_sha256, profile_config_sha256, environment_adapter_sha256) -> dict`; `bundle_hash(manifest) -> str`

**Fix from review:** concatenating file bytes omits filenames and length boundaries, so distinct file sets can collide. It also ignored the prompt, commit, image, lock, adapter and profile config — all of which are real inputs.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_manifest.py
from elcapitan.manifest import build_manifest, bundle_hash

BASE = dict(repository_commit="c"*40, runtime_image_id="sha256:"+"d"*64,
            runtime_lock_sha256="e"*64, profile_config_sha256="f"*64,
            environment_adapter_sha256="0"*64)

def write(tmp_path, name, data):
    p = tmp_path / name; p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data); return name

def test_manifest_lists_path_size_and_hash(tmp_path):
    write(tmp_path, "inputs/finding.json", b'{"a":1}')
    m = build_manifest(tmp_path, files=["inputs/finding.json"], **BASE)
    entry = m["files"][0]
    assert entry["path"] == "inputs/finding.json"
    assert entry["size"] == 7 and len(entry["sha256"]) == 64

def test_boundary_ambiguity_is_resolved(tmp_path):
    # Concatenation would make these two file sets identical.
    a = tmp_path / "a"; a.mkdir()
    write(a, "inputs/x", b"AB"); write(a, "inputs/y", b"C")
    b = tmp_path / "b"; b.mkdir()
    write(b, "inputs/x", b"A"); write(b, "inputs/y", b"BC")
    ma = build_manifest(a, files=["inputs/x", "inputs/y"], **BASE)
    mb = build_manifest(b, files=["inputs/x", "inputs/y"], **BASE)
    assert bundle_hash(ma) != bundle_hash(mb)

def test_hash_changes_when_the_commit_changes(tmp_path):
    write(tmp_path, "inputs/f", b"x")
    m1 = build_manifest(tmp_path, files=["inputs/f"], **BASE)
    m2 = build_manifest(tmp_path, files=["inputs/f"], **{**BASE, "repository_commit": "a"*40})
    assert bundle_hash(m1) != bundle_hash(m2)

def test_hash_changes_when_the_image_changes(tmp_path):
    write(tmp_path, "inputs/f", b"x")
    m1 = build_manifest(tmp_path, files=["inputs/f"], **BASE)
    m2 = build_manifest(tmp_path, files=["inputs/f"],
                        **{**BASE, "runtime_image_id": "sha256:" + "9"*64})
    assert bundle_hash(m1) != bundle_hash(m2)

def test_file_order_does_not_affect_the_hash(tmp_path):
    write(tmp_path, "inputs/x", b"1"); write(tmp_path, "inputs/y", b"2")
    m1 = build_manifest(tmp_path, files=["inputs/x", "inputs/y"], **BASE)
    m2 = build_manifest(tmp_path, files=["inputs/y", "inputs/x"], **BASE)
    assert bundle_hash(m1) == bundle_hash(m2)

def test_prompt_is_a_first_class_input(tmp_path):
    write(tmp_path, "prompt.md", b"do the thing")
    m = build_manifest(tmp_path, files=["prompt.md"], **BASE)
    assert m["files"][0]["path"] == "prompt.md"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_manifest.py -v`
Expected: FAIL — `No module named 'elcapitan.manifest'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/manifest.py
"""The immutable input manifest.

Hashing concatenated file bytes is ambiguous — no filenames, no length
boundaries, so distinct file sets can collide. It also omitted real inputs:
the prompt, repository commit, runtime image, dependency lock, profile config
and environment adapter all change the experiment.
"""
from pathlib import Path

from .hashing import sha256_file, sha256_record
from .paths import safe_resolve

def build_manifest(run_dir, *, files: list[str], repository_commit: str,
                   runtime_image_id: str, runtime_lock_sha256: str,
                   profile_config_sha256: str,
                   environment_adapter_sha256: str) -> dict:
    run_dir = Path(run_dir)
    entries = []
    for rel in sorted(files):
        # Containment lives here, not in the caller. Today's harness passes
        # literals, but the Global Constraint ("resolve, prove
        # is_relative_to(run_dir), reject symlinks") is an invariant of the
        # manifest, and a future caller must not be able to hash a file from
        # outside the run directory into a bundle that never carries it.
        path = safe_resolve(run_dir, rel)
        entries.append({"path": rel,
                        "size": path.stat().st_size,
                        "sha256": sha256_file(path)})
    return {
        "files": entries,
        "repository_commit": repository_commit,
        "runtime_image_id": runtime_image_id,
        "runtime_lock_sha256": runtime_lock_sha256,
        "profile_config_sha256": profile_config_sha256,
        "environment_adapter_sha256": environment_adapter_sha256,
    }

def bundle_hash(manifest: dict) -> str:
    return sha256_record(manifest)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_manifest.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add src/elcapitan/manifest.py tests/test_manifest.py
git commit -m "feat(harness): unambiguous canonical input manifest"
```

---

### Task 7: Real canonical-repository integrity checks

**Files:**
- Create: `src/elcapitan/repo.py`
- Test: `tests/test_repo.py`

**Interfaces:**
- Produces: `RepoState(commit: str, dirty_files: list[str])`; `capture_repo_state(path) -> RepoState`; `assert_unchanged(path, before: RepoState) -> list[str]`

**Fix from review — this was the worst defect.** The previous check recorded `git rev-parse HEAD^{tree}`, which does not change when tracked files are edited and ignores untracked files entirely; the validator then compared that recorded string against a caller-supplied copy of *the same string*. It was a check that could never fail, which is worse than no check because it reads as assurance.

The **read-only mount remains the enforcement.** This is an independent post-run diagnostic.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_repo.py
import subprocess
import pytest
from elcapitan.repo import capture_repo_state, assert_unchanged

def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True)

@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"; r.mkdir()
    git(r, "init", "-q"); git(r, "config", "user.email", "t@t"); git(r, "config", "user.name", "t")
    (r / "main.tf").write_text("resource {}\n")
    git(r, "add", "-A"); git(r, "commit", "-qm", "init")
    return r

def test_clean_repo_reports_no_changes(repo):
    before = capture_repo_state(repo)
    assert assert_unchanged(repo, before) == []

def test_detects_a_tracked_file_edit(repo):
    before = capture_repo_state(repo)
    (repo / "main.tf").write_text("resource { changed = true }\n")
    failures = assert_unchanged(repo, before)
    assert any("main.tf" in f for f in failures)

def test_detects_an_untracked_file(repo):
    before = capture_repo_state(repo)
    (repo / "sneaky.tf").write_text("x\n")
    assert any("sneaky.tf" in f for f in assert_unchanged(repo, before))

def test_detects_a_staged_change(repo):
    before = capture_repo_state(repo)
    (repo / "main.tf").write_text("y\n"); git(repo, "add", "-A")
    assert assert_unchanged(repo, before) != []

def test_detects_a_new_commit(repo):
    before = capture_repo_state(repo)
    (repo / "main.tf").write_text("z\n")
    git(repo, "add", "-A"); git(repo, "commit", "-qm", "sneak")
    assert any("commit" in f.lower() for f in assert_unchanged(repo, before))

def test_tolerates_a_repo_that_was_already_dirty(repo):
    (repo / "preexisting.txt").write_text("was here first\n")
    before = capture_repo_state(repo)
    assert assert_unchanged(repo, before) == []
    (repo / "new.txt").write_text("added during run\n")
    assert any("new.txt" in f for f in assert_unchanged(repo, before))

def test_unborn_branch_raises_a_clear_error(tmp_path):
    r = tmp_path / "empty"; r.mkdir(); git(r, "init", "-q")
    with pytest.raises(ValueError, match="no commits"):
        capture_repo_state(r)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_repo.py -v`
Expected: FAIL — `No module named 'elcapitan.repo'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/repo.py
"""Independent post-run repository diagnostics.

The read-only bind mount is the enforcement. This recomputes state from the
repository after the container exits and compares it with state captured
before — never with a value supplied by the caller.
"""
import subprocess
from dataclasses import dataclass
from pathlib import Path

# git's wording for "HEAD exists but points nowhere yet"
_UNBORN_MARKERS = ("unknown revision", "ambiguous argument 'HEAD'",
                   "does not have any commits")

@dataclass(frozen=True)
class RepoState:
    commit: str
    # A tuple, not a list: frozen=True blocks attribute reassignment but not
    # in-place mutation, and this baseline is what tamper detection diffs
    # against. A mutated baseline yields false negatives — real tampering that
    # goes unreported. Records are immutable.
    dirty_files: tuple[str, ...] = ()

def _git(path, *args) -> str:
    result = subprocess.run(["git", "-C", str(path), *args],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout

def capture_repo_state(path) -> RepoState:
    path = Path(path)
    try:
        commit = _git(path, "rev-parse", "HEAD").strip()
    except ValueError as exc:
        # Only claim "unborn branch" when git actually said so. A missing path
        # or a directory that is not a repository at all must not be reported
        # as "no commits" — asserting a specific wrong cause is worse than a
        # generic one, because it sends the reader somewhere else entirely.
        detail = str(exc)
        if any(marker in detail for marker in _UNBORN_MARKERS):
            raise ValueError(f"repository has no commits (unborn branch): {path}") from exc
        raise ValueError(f"not a usable git repository: {path} — {detail}") from exc
    porcelain = _git(path, "status", "--porcelain", "--untracked-files=all")
    return RepoState(commit=commit,
                     dirty_files=tuple(sorted(porcelain.splitlines())))

def assert_unchanged(path, before: RepoState) -> list[str]:
    """Return failures. Empty list means the repository is untouched."""
    after = capture_repo_state(path)
    failures: list[str] = []

    if after.commit != before.commit:
        failures.append(
            f"canonical repository commit changed: {before.commit[:8]} -> {after.commit[:8]}")

    appeared = set(after.dirty_files) - set(before.dirty_files)
    for entry in sorted(appeared):
        failures.append(f"canonical repository modified during run: {entry.strip()}")

    return failures
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_repo.py -v`
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/elcapitan/repo.py tests/test_repo.py
git commit -m "fix(validate): real canonical-repository integrity checks

Replaces a check that compared a recorded HEAD^{tree} against a
caller-supplied copy of itself and therefore could never fail."
```

---

### Task 8: Per-tool exit semantics

**Files:**
- Create: `src/elcapitan/toolsem.py`
- Test: `tests/test_toolsem.py`

**Interfaces:**
- Produces: `ExitVerdict(ok: bool, meaning: str)`; `interpret_exit(tool, argv, code) -> ExitVerdict`

Implementation is unchanged from the previous draft — `terraform plan -detailed-exitcode` maps `0`/`2` to success and everything else to failure; `cdk diff --fail` treats `1` as "differences present"; `trivy --exit-code N` treats `N` as "findings present"; unknown tools fall back to `code == 0` with `"generic semantics"` in the message. Reuse that module and its twelve tests verbatim, plus one addition:

- [ ] **Step 1: Add the missing-exit-code test**

```python
# tests/test_toolsem.py  (append)
def test_absent_exit_code_is_never_treated_as_success():
    from elcapitan.toolsem import interpret_exit
    with pytest.raises(TypeError):
        interpret_exit("terraform", ["plan"])   # code is required, never defaulted
```

- [ ] **Step 2: Run, implement, run, commit** as in the previous draft.

```bash
git add src/elcapitan/toolsem.py tests/test_toolsem.py
git commit -m "feat(validate): per-tool exit-code semantics"
```

---

### Task 9: Host-side validator with structured failures

**Files:**
- Create: `src/elcapitan/validate.py`, `bin/validate-trial-artifacts.sh`
- Test: `tests/test_validate.py`

**Interfaces:**
- Consumes: `records`, `evidence`, `repo`, `toolsem`, `manifest`
- Produces: `ValidationResult(passed: bool, failures: list[str])`; `validate_run(run_dir, *, canonical_repo, repo_state_before) -> ValidationResult`

**Signature change from review:** the validator now takes the *repository path* and the *pre-run state*, and recomputes. It no longer accepts a digest string from the caller.

- [ ] **Step 1: Write the failing test**

Build on the previous draft's `build_run()` fixture, with these changes: write an `input-manifest.json`, set `input_bundle_hash` from `bundle_hash()`, include a valid `CommandRecord`, and pass a real git repository. Then:

```python
# tests/test_validate.py  (essential assertions)
def test_well_formed_run_passes(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    assert validate_run(run, canonical_repo=repo, repo_state_before=before).passed

def test_schema_violation_fails(tmp_path, repo):
    run, before = build_run(tmp_path, repo, overrides={"resolution_type": "nope"})
    assert not validate_run(run, canonical_repo=repo, repo_state_before=before).passed

def test_tampered_evidence_fails(tmp_path, repo):
    run, before = build_run(tmp_path, repo, mutate_evidence=True)
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("hash mismatch" in f for f in r.failures)

def test_escaping_evidence_path_is_a_structured_failure_not_an_exception(tmp_path, repo):
    run, before = build_run(tmp_path, repo, evidence_path="../escape")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed and any("escape" in f or "containment" in f for f in r.failures)

def test_malformed_json_is_a_structured_failure_not_an_exception(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (run / "proposal.json").write_text("{not json")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert not r.passed and any("proposal.json" in f for f in r.failures)

def test_missing_file_is_a_structured_failure_not_an_exception(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (run / "evidence-index.json").unlink()
    assert not validate_run(run, canonical_repo=repo, repo_state_before=before).passed

def test_finding_record_is_validated_too(tmp_path, repo):
    run, before = build_run(tmp_path, repo, finding_overrides={"ocsf": {}})
    assert not validate_run(run, canonical_repo=repo, repo_state_before=before).passed

def test_bundle_hash_mismatch_fails(tmp_path, repo):
    run, before = build_run(tmp_path, repo, overrides={"input_bundle_hash": "0"*64})
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("input_bundle_hash" in f for f in r.failures)

def test_repository_modification_is_detected(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (repo / "main.tf").write_text("mutated\n")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("canonical repository" in f for f in r.failures)

def test_terraform_plan_exit_2_is_not_a_failure(tmp_path, repo):
    run, before = build_run(tmp_path, repo)  # fixture CommandRecord uses exit_code 2
    assert validate_run(run, canonical_repo=repo, repo_state_before=before).passed

def test_terraform_plan_exit_1_is_a_failure(tmp_path, repo):
    run, before = build_run(tmp_path, repo, command_exit=1)
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("terraform" in f for f in r.failures)

def test_ground_truth_inside_run_dir_fails(tmp_path, repo):
    run, before = build_run(tmp_path, repo)
    (run / "ground-truth.json").write_text("{}")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("ground truth" in f.lower() for f in r.failures)

def test_mutation_in_transcript_is_reported_as_a_diagnostic(tmp_path, repo):
    run, before = build_run(tmp_path, repo, transcript="terraform apply -auto-approve\n")
    r = validate_run(run, canonical_repo=repo, repo_state_before=before)
    assert any("DIAGNOSTIC" in f for f in r.failures)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_validate.py -v`
Expected: FAIL — `No module named 'elcapitan.validate'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/validate.py
"""Host-side deterministic validator — the final authority on a trial.

Every check returns a structured failure. Malformed input, missing files and
path-containment violations must never raise: a trial that crashes the
validator would otherwise be indistinguishable from one that was never run.
"""
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .evidence import Collector, EvidenceRef, verify_evidence
from .manifest import bundle_hash
from .records import validate_doc
from .repo import RepoState, assert_unchanged
from .toolsem import interpret_exit

# Diagnostic only. Credential scope and read-only mounts are the controls;
# this misses SDK calls, REST calls, renamed binaries and untranscribed commands.
MUTATION_PATTERNS = (
    r"\bterraform\s+(apply|destroy|import)\b", r"\bcdk\s+(deploy|destroy)\b",
    r"\baws\s+cloudformation\s+deploy\b", r"\baws\s+s3\s+(cp|sync|rm)\b",
    r"\baz\s+\S+\s+(create|update|delete|set)\b", r"\bgit\s+push\b",
)
GROUND_TRUTH_MARKERS = ("ground-truth", "ground_truth", "groundtruth")

@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    failures: list[str]

def _read_json(path: Path, failures: list[str]) -> dict | None:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        failures.append(f"missing required artifact: {path.name}")
    except json.JSONDecodeError as exc:
        failures.append(f"malformed JSON in {path.name}: {exc}")
    return None

def _evidence_ids(doc) -> set[str]:
    found: set[str] = set()
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("evidence",) and isinstance(value, list):
                    found.update(v for v in value if isinstance(v, str))
                elif key.endswith("_evidence_id") and isinstance(value, str):
                    found.add(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(doc)
    return found

def validate_run(run_dir, *, canonical_repo, repo_state_before: RepoState) -> ValidationResult:
    run_dir = Path(run_dir)
    failures: list[str] = []

    for path in run_dir.rglob("*"):
        if any(m in path.name.lower() for m in GROUND_TRUTH_MARKERS):
            failures.append(f"ground truth present inside run dir: {path.name}")

    proposal = _read_json(run_dir / "proposal.json", failures)
    finding = _read_json(run_dir / "inputs" / "finding.json", failures)
    index_doc = _read_json(run_dir / "evidence-index.json", failures)
    manifest = _read_json(run_dir / "inputs" / "input-manifest.json", failures)

    if proposal is not None:
        failures += [f"proposal: {e}" for e in validate_doc("remediation-proposal", proposal)]
    if finding is not None:
        failures += [f"finding: {e}" for e in validate_doc("finding-record", finding)]

    index: dict[str, EvidenceRef] = {}
    if isinstance(index_doc, list):
        for item in index_doc:
            errors = validate_doc("evidence-ref", item)
            if errors:
                failures += [f"evidence-index: {e}" for e in errors]
                continue
            ref = EvidenceRef(**{**item, "collector": Collector(**item["collector"])})
            index[ref.evidence_id] = ref
            if not verify_evidence(run_dir, ref):
                failures.append(
                    f"evidence hash mismatch, missing artifact, or containment "
                    f"violation: {ref.evidence_id} ({ref.artifact_path})")

    for doc in (proposal, finding):
        if doc:
            for eid in _evidence_ids(doc) - set(index):
                failures.append(f"unresolvable evidence reference: {eid}")

    if proposal and manifest:
        expected = bundle_hash(manifest)
        if proposal.get("input_bundle_hash") != expected:
            failures.append(
                f"input_bundle_hash does not match input-manifest.json ({expected[:8]})")

    if proposal:
        patch_file = proposal.get("remediation", {}).get("patch_file")
        if proposal.get("resolution_type") == "patch" and patch_file:
            if not (run_dir / patch_file).is_file():
                failures.append(f"declared patch_file does not exist: {patch_file}")
        for command in proposal.get("verification", {}).get("commands_run", []):
            verdict = interpret_exit(command["tool"], command["argv"], command["exit_code"])
            if not verdict.ok:
                failures.append(f"verification command failed: "
                                f"{command['tool']} — {verdict.meaning}")

    failures += assert_unchanged(canonical_repo, repo_state_before)

    try:
        transcript = (run_dir / "transcript.log").read_text()
    except FileNotFoundError:
        failures.append("missing required artifact: transcript.log")
        transcript = ""
    for pattern in MUTATION_PATTERNS:
        if re.search(pattern, transcript):
            failures.append(f"DIAGNOSTIC: possible mutation in transcript /{pattern}/")

    return ValidationResult(passed=not failures, failures=failures)
```

- [ ] **Step 4: Write the CLI wrapper** — same shape as the previous draft, taking `<run-dir> <canonical-repo> <repo-state-before.json>` and exiting non-zero on failure.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_validate.py -v`
Expected: 13 passed

- [ ] **Step 6: Commit**

```bash
git add src/elcapitan/validate.py bin/validate-trial-artifacts.sh tests/test_validate.py
git commit -m "feat(validate): structured-failure validator with real integrity checks"
```

---

### Task 10: Container specs — names-only secrets and hardening

**Files:**
- Create: `src/elcapitan/container.py`
- Test: `tests/test_container.py`

**Interfaces:**
- Produces: `Mount`; `ContainerSpec(image, mounts, env_passthrough, host_hermes_home, network, hardening, command)`; `engineer_spec(...)`; `challenger_spec(...)`; `ContainerSpec.to_argv() -> list[str]`

**Three fixes from review.** Secret *values* never enter `to_argv()` — the spec carries names and `--env NAME` passes the value through from the docker client's own environment. `host_hermes_home` is recorded separately from the container mountpoint `/opt/data`, which is what the previous `test_hermes_home_is_fresh_per_container` was actually trying to assert. And the challenger receives **no cloud credentials at all** — it judges an offline bundle, so the observer credential belongs to the evidence collector.

> **Preserved control.** Moving the observer credential to the collector must not delete the Stage 0 gate. The gate becomes: *the collector, not the challenger, is the only component holding the observer credential, and Arm A bundles provably contain no telemetry artifacts.* That test lands in the Stage 3–5 plan; this task asserts the challenger has no credentials at all, which is the stronger half.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_container.py
import pytest
from elcapitan.container import Mount, engineer_spec, challenger_spec

IMAGE = "sha256:" + "e" * 64
NAMES = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY"]

def eng(tmp="/tmp/h1", **kw):
    return engineer_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                         canonical_repo="/w/repos/anna", host_hermes_home=tmp,
                         env_passthrough=NAMES, **kw)

def test_secret_values_never_appear_in_argv():
    argv = " ".join(eng().to_argv())
    assert "AWS_SECRET_ACCESS_KEY" in argv          # the name is fine
    assert "=" not in argv.split("AWS_SECRET_ACCESS_KEY")[1][:1]  # no '=value'

def test_env_flags_are_name_only():
    argv = eng().to_argv()
    idx = argv.index("--env")
    assert argv[idx + 1] in NAMES

def test_spec_stores_no_secret_values():
    spec = eng()
    assert not hasattr(spec, "env_values")
    assert all(isinstance(n, str) for n in spec.env_passthrough)

def test_host_hermes_home_is_distinct_per_container():
    assert eng("/tmp/h1").host_hermes_home != eng("/tmp/h2").host_hermes_home

def test_container_mountpoint_for_hermes_home_is_always_opt_data():
    assert any(m.target == "/opt/data" for m in eng().mounts)

def test_image_referenced_by_built_image_id():
    assert eng().to_argv()[-1] == IMAGE or IMAGE in eng().to_argv()

def test_no_user_flag_is_passed():
    # s6-overlay is PID 1 and drops to the hermes user itself; forcing --user
    # can bypass init. See spike findings Q5.
    assert "--user" not in eng().to_argv()

def test_canonical_repo_is_read_only():
    assert next(m for m in eng().mounts if m.target.endswith("/canonical")).read_only

def test_run_dir_is_writable():
    assert not next(m for m in eng().mounts if m.target.endswith("/run")).read_only

def test_container_is_removed_on_exit():
    assert "--rm" in eng().to_argv()

def test_no_docker_socket_mounted():
    assert all("docker.sock" not in m.source for m in eng().mounts)

def test_ground_truth_mount_is_rejected():
    with pytest.raises(ValueError, match="ground truth"):
        eng(extra_mounts=[Mount("/w/ground-truth", "/gt", True)])

def test_hardening_flags_present():
    argv = eng().to_argv()
    for flag in ("--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--pids-limit", "--memory", "--cpus"):
        assert any(a.startswith(flag) for a in argv), f"missing {flag}"

# --- challenger ---

def ch(arm="A"):
    return challenger_spec(runtime_image_id=IMAGE, run_dir="/w/runs/R1",
                           bundle_path="/w/runs/R1/bundle-a",
                           host_hermes_home="/tmp/h2", arm=arm,
                           env_passthrough=["ANTHROPIC_API_KEY"])

def test_challenger_holds_no_cloud_credentials():
    assert all(not n.startswith("AWS_") and not n.startswith("AZURE_")
               for n in ch().env_passthrough)

def test_challenger_network_is_disabled():
    assert ch().network == "none"

def test_challenger_bundle_is_read_only():
    assert next(m for m in ch().mounts if m.target.endswith("/bundle")).read_only

def test_challenger_cannot_see_the_canonical_repo():
    assert all("canonical" not in m.target for m in ch().mounts)

def test_unknown_arm_rejected():
    with pytest.raises(ValueError, match="arm"):
        ch(arm="C")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_container.py -v`
Expected: FAIL — `No module named 'elcapitan.container'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/container.py
"""Ephemeral container specs — the experiment's isolation boundary.

Hermes profiles isolate config, sessions, skills and memory, but the docs are
explicit that "a profile does not stop it from accessing folders outside the
profile directory", and profiles are not a security boundary. Containers are.

Secret VALUES never appear here. `--env NAME` passes a value through from the
docker client's environment, so nothing sensitive lands in argv, exceptions,
logs, or test strings.
"""
from dataclasses import dataclass, field
from pathlib import PurePosixPath

GROUND_TRUTH_MARKERS = ("ground-truth", "ground_truth", "groundtruth")
VALID_ARMS = ("A", "B")
HARDENING = ("--cap-drop=ALL", "--security-opt=no-new-privileges",
             "--pids-limit=512", "--memory=4g", "--cpus=2")

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
    env_passthrough: list[str]     # NAMES ONLY — never values
    host_hermes_home: str          # host path; the mountpoint is always /opt/data
    network: str
    command: list[str] = field(default_factory=list)
    hardening: tuple[str, ...] = HARDENING

    def to_argv(self) -> list[str]:
        argv = ["docker", "run", "--rm", f"--network={self.network}", *self.hardening]
        # No --user: s6-overlay is PID 1 and drops to the hermes user itself.
        argv += ["--tmpfs", "/tmp:rw,noexec,nosuid,size=256m"]
        argv += [m.to_flag() for m in self.mounts]
        for name in self.env_passthrough:
            argv += ["--env", name]
        argv += [self.image, *self.command]
        return argv

def _reject_ground_truth(mounts: list[Mount]) -> None:
    for mount in mounts:
        haystack = f"{mount.source} {mount.target}".lower()
        if any(marker in haystack for marker in GROUND_TRUTH_MARKERS):
            raise ValueError(f"refusing to mount ground truth into an agent container: "
                             f"{mount.source}")

def engineer_spec(*, runtime_image_id, run_dir, canonical_repo, host_hermes_home,
                  env_passthrough, extra_mounts=None, command=None) -> ContainerSpec:
    mounts = [
        Mount(str(canonical_repo), "/work/canonical", True),
        Mount(str(run_dir), "/work/run", False),
        Mount(str(host_hermes_home), "/opt/data", False),
        *(extra_mounts or []),
    ]
    _reject_ground_truth(mounts)
    return ContainerSpec(image=runtime_image_id, mounts=mounts,
                         env_passthrough=list(env_passthrough),
                         host_hermes_home=str(host_hermes_home),
                         network="bridge", command=command or [])

def challenger_spec(*, runtime_image_id, run_dir, bundle_path, host_hermes_home,
                    arm, env_passthrough, command=None) -> ContainerSpec:
    if arm not in VALID_ARMS:
        raise ValueError(f"unknown arm {arm!r}; expected one of {VALID_ARMS}")
    for name in env_passthrough:
        if name.startswith(("AWS_", "AZURE_", "ARM_")):
            raise ValueError(
                f"challenger must hold no cloud credentials; got {name}. "
                "The evidence collector holds the observer credential.")
    mounts = [
        Mount(str(bundle_path), "/work/bundle", True),
        Mount(str(PurePosixPath(run_dir) / "verdict"), "/work/out", False),
        Mount(str(host_hermes_home), "/opt/data", False),
    ]
    _reject_ground_truth(mounts)
    return ContainerSpec(image=runtime_image_id, mounts=mounts,
                         env_passthrough=list(env_passthrough),
                         host_hermes_home=str(host_hermes_home),
                         network="none", command=command or [])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_container.py -v`
Expected: 19 passed

- [ ] **Step 5: Commit**

```bash
git add src/elcapitan/container.py tests/test_container.py
git commit -m "feat(isolation): names-only secrets, hardening flags, credential-free challenger"
```

---

### Task 11: Runtime shim using the proven invocation

**Files:**
- Create: `src/elcapitan/shim.py`, `bin/agent-run.sh`
- Test: `tests/test_shim.py`

**Interfaces:**
- Consumes: `docs/spike-findings.md` Q2 and Q3 (Task 0), `container.ContainerSpec`
- Produces: `AgentResult(exit_code, transcript)`; `run_agent(spec, prompt_path, *, secret_env, stub=None) -> AgentResult`; `SCANNER_ENV_MAP`, `MODEL_ENV_MAP`

**Fixes from review:** the invocation comes from the spike, not from invention. The prefix bug is gone — an explicit map translates `ELCAP_SCANNER_AWS_ACCESS_KEY_ID` on the host into `AWS_ACCESS_KEY_ID` inside the container, and the observer prefix is never applied twice.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_shim.py
import pytest
from pathlib import Path
from elcapitan.container import engineer_spec
from elcapitan.shim import SCANNER_ENV_MAP, run_agent, resolve_secret_env

IMAGE = "sha256:" + "f" * 64

def spec(tmp_path):
    return engineer_spec(runtime_image_id=IMAGE, run_dir=str(tmp_path),
                         canonical_repo=str(tmp_path), host_hermes_home=str(tmp_path),
                         env_passthrough=list(SCANNER_ENV_MAP.values()))

def test_scanner_prefix_is_translated_to_the_aws_name():
    host = {"ELCAP_SCANNER_AWS_ACCESS_KEY_ID": "AKIA_X",
            "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY": "s",
            "ELCAP_SCANNER_AWS_SESSION_TOKEN": "t"}
    resolved = resolve_secret_env(host, SCANNER_ENV_MAP)
    assert resolved["AWS_ACCESS_KEY_ID"] == "AKIA_X"
    assert not any(k.startswith("ELCAP_") for k in resolved)

def test_missing_required_secret_raises_by_name():
    with pytest.raises(KeyError, match="ELCAP_SCANNER_AWS_ACCESS_KEY_ID"):
        resolve_secret_env({}, SCANNER_ENV_MAP)

def test_stub_receives_argv_and_prompt(tmp_path):
    p = tmp_path / "p.md"; p.write_text("do the thing")
    seen = {}
    def stub(argv, text, env):
        seen.update(argv=argv, text=text, env=env)
        return 0, "ok"
    run_agent(spec(tmp_path), p, secret_env={"AWS_ACCESS_KEY_ID": "v"}, stub=stub)
    assert seen["argv"][0] == "docker" and "do the thing" in seen["text"]

def test_secret_values_are_not_in_argv(tmp_path):
    p = tmp_path / "p.md"; p.write_text("x")
    seen = {}
    run_agent(spec(tmp_path), p, secret_env={"AWS_SECRET_ACCESS_KEY": "SUPERSECRET"},
              stub=lambda a, t, e: (seen.update(argv=a) or (0, "")))
    assert "SUPERSECRET" not in " ".join(seen["argv"])

def test_transcript_written_to_run_dir(tmp_path):
    p = tmp_path / "p.md"; p.write_text("x")
    run_agent(spec(tmp_path), p, secret_env={}, stub=lambda a, t, e: (0, "hello"))
    assert (tmp_path / "transcript.log").read_text() == "hello"

def test_nonzero_exit_propagates(tmp_path):
    p = tmp_path / "p.md"; p.write_text("x")
    assert run_agent(spec(tmp_path), p, secret_env={},
                     stub=lambda a, t, e: (3, "boom")).exit_code == 3

def test_missing_prompt_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_agent(spec(tmp_path), tmp_path / "nope.md", secret_env={},
                  stub=lambda a, t, e: (0, ""))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_shim.py -v`
Expected: FAIL — `No module named 'elcapitan.shim'`

- [ ] **Step 3: Implement**

```python
# src/elcapitan/shim.py
"""The only place an agent runtime is invoked.

The argv below is taken from docs/spike-findings.md Q2 — an empirically proven
invocation. `--prompt-file` does not exist in Hermes; the supported forms are
`hermes chat -q "<prompt>"` (retains tool output) and `hermes -z` (final text
only). The probe needs the tool transcript, so `chat -q` is used.
"""
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .container import ContainerSpec

StubFn = Callable[[list[str], str, dict], tuple[int, str]]

# Host variable -> in-container variable. Prevents the double-prefix bug where
# ELCAP_SCANNER_AWS_ACCESS_KEY_ID was passed through verbatim and AWS tooling,
# which looks for AWS_ACCESS_KEY_ID, never saw a credential.
SCANNER_ENV_MAP = {
    "ELCAP_SCANNER_AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
    "ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
    "ELCAP_SCANNER_AWS_SESSION_TOKEN": "AWS_SESSION_TOKEN",
}
MODEL_ENV_MAP = {"ELCAP_MODEL_API_KEY": "ANTHROPIC_API_KEY"}

@dataclass(frozen=True)
class AgentResult:
    exit_code: int
    transcript: str

def resolve_secret_env(host_env: dict, mapping: dict) -> dict:
    resolved = {}
    for host_name, container_name in mapping.items():
        if host_name not in host_env:
            raise KeyError(f"required secret not set on host: {host_name}")
        resolved[container_name] = host_env[host_name]
    return resolved

def run_agent(spec: ContainerSpec, prompt_path, *, secret_env: dict,
              stub: StubFn | None = None) -> AgentResult:
    prompt_text = Path(prompt_path).read_text()   # FileNotFoundError by design
    argv = spec.to_argv() + [
        "chat", "-q", prompt_text,
        "-t", "terminal", "--yolo", "--ignore-user-config",
    ]

    if stub is not None:
        exit_code, transcript = stub(argv, prompt_text, secret_env)
    else:
        # Secret values reach docker only through this environment, never argv.
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   check=False, env={"PATH": "/usr/bin:/bin",
                                                     **secret_env})
        exit_code = completed.returncode
        transcript = completed.stdout + completed.stderr

    run_dir = next(Path(m.source) for m in spec.mounts if m.target == "/work/run")
    (run_dir / "transcript.log").write_text(transcript)
    return AgentResult(exit_code=exit_code, transcript=transcript)
```

- [ ] **Step 4: Write `bin/agent-run.sh`** — reads `runtime.lock.json` for `runtime_image_id`, seeds a home via `elcapitan.home.seed_hermes_home`, resolves secrets through the maps above, and calls `run_agent`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_shim.py -v`
Expected: 7 passed

- [ ] **Step 6: Commit**

```bash
git add src/elcapitan/shim.py bin/agent-run.sh tests/test_shim.py
git commit -m "feat(shim): proven Hermes invocation with explicit secret name mapping"
```

---

### Task 12: Trial harness and black-box smoke test

**Files:**
- Create: `bin/run-trial.sh`, `prompts/engineer.md`, `tests/stub_engineer.py`, `tests/test_run_trial.py`, `tests/test_smoke_container.py`
- Test: as listed

**Interfaces:**
- Consumes: Tasks 1–11
- Produces: a populated `runs/<run-id>/` and a passing black-box run against the real image

**Fixes from review:** the stub fixture now creates a git repo *with a commit* and a real `findings/FIND-001.json`, both of which the previous draft omitted; and unit-testing generated argv is supplemented by an actual container run.

- [ ] **Step 1: Write the engineer prompt** — reuse the previous draft's `prompts/engineer.md` verbatim. It states obligations without naming any IaC system, cloud, or scanner, and declares `NEEDS_HUMAN_CONTEXT` a successful outcome.

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_run_trial.py
import json, os, subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "run-trial.sh"

def make_workspace(tmp_path):
    """A repo WITH a commit and a finding file — both absent in the first draft."""
    repo = tmp_path / "repo"; repo.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "t@t"],
                 ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    (repo / "main.tf").write_text("resource {}\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"],
                   check=True, capture_output=True)

    findings = tmp_path / "findings"; findings.mkdir()
    (findings / "FIND-001.json").write_text(
        (ROOT / "tests" / "fixtures" / "prowler-ocsf-sample.json").read_text())

    gt = tmp_path / "gt-outside"; gt.mkdir()
    return {"ELCAP_WORKSPACE": str(tmp_path), "ELCAP_CANONICAL_REPO": str(repo),
            "ELCAP_GROUND_TRUTH_DIR": str(gt), "ELCAP_STUB": "1"}

def test_script_is_executable():
    assert os.access(SCRIPT, os.X_OK)

def test_refuses_without_required_env(tmp_path):
    r = subprocess.run([str(SCRIPT), "anna", "FIND-001", "A", "1"],
                       capture_output=True, text=True,
                       env={"PATH": os.environ["PATH"]})
    assert r.returncode != 0 and "ELCAP_" in r.stderr

def test_stub_run_produces_a_validating_trial(tmp_path):
    env = {**os.environ, **make_workspace(tmp_path)}
    r = subprocess.run([str(SCRIPT), "anna", "FIND-001", "A", "1"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    run = tmp_path / "runs" / "anna-FIND-001-armA-n1"
    for name in ("proposal.json", "transcript.log", "evidence-index.json",
                 "inputs/input-manifest.json", "inputs/finding.json"):
        assert (run / name).is_file(), f"{name} missing"

def test_rerunning_the_same_trial_id_is_refused(tmp_path):
    env = {**os.environ, **make_workspace(tmp_path)}
    subprocess.run([str(SCRIPT), "anna", "FIND-001", "A", "1"], env=env,
                   capture_output=True)
    r = subprocess.run([str(SCRIPT), "anna", "FIND-001", "A", "1"], env=env,
                       capture_output=True, text=True)
    assert r.returncode != 0 and "immutable" in r.stderr

def test_ground_truth_inside_runs_tree_is_refused(tmp_path):
    env = {**os.environ, **make_workspace(tmp_path)}
    inside = tmp_path / "runs" / "gt"; inside.mkdir(parents=True)
    env["ELCAP_GROUND_TRUTH_DIR"] = str(inside)
    r = subprocess.run([str(SCRIPT), "anna", "FIND-001", "A", "1"],
                       capture_output=True, text=True, env=env)
    assert r.returncode != 0 and "ground truth" in r.stderr.lower()
```

```python
# tests/test_smoke_container.py
"""Black-box: the real image actually starts and honours the mounts.

Unit-testing generated argv proves nothing about whether the container runs.
"""
import json, os, subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.environ.get("ELCAP_SMOKE") != "1",
                                reason="set ELCAP_SMOKE=1 to run container smoke tests")

def image_id():
    return json.loads((ROOT / "runtime.lock.json").read_text())["runtime_image_id"]

def test_image_starts_and_tools_are_present():
    r = subprocess.run(["docker", "run", "--rm", "--network=none", image_id(),
                        "sh", "-lc", "terraform version && trivy --version && prowler --version"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

def test_read_only_mount_is_actually_read_only(tmp_path):
    (tmp_path / "f.txt").write_text("original")
    r = subprocess.run(["docker", "run", "--rm", "--network=none",
                        f"--mount=type=bind,source={tmp_path},target=/ro,readonly",
                        image_id(), "sh", "-lc", "echo mutated > /ro/f.txt"],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert (tmp_path / "f.txt").read_text() == "original"

def test_network_none_blocks_egress():
    r = subprocess.run(["docker", "run", "--rm", "--network=none", image_id(),
                        "sh", "-lc", "curl -sS --max-time 5 https://example.com"],
                       capture_output=True, text=True)
    assert r.returncode != 0
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_run_trial.py -v`
Expected: FAIL — `bin/run-trial.sh` does not exist

- [ ] **Step 4: Implement the harness**

Same shape as the previous draft with six corrections: seed the Hermes home via `seed_hermes_home` rather than a bare `mktemp -d`; normalise the finding *into the run directory* so `raw_event` resolves; build and hash an `input-manifest.json` rather than concatenating bytes; capture the pre-run repo state to `repo-state-before.json`; pass the repo path and that state to the validator; and refuse an existing run id.

```bash
#!/usr/bin/env bash
# bin/run-trial.sh — the deterministic orchestrator.
# Hermes delegate_task fan-out is deliberately NOT used for scored trials:
# agentic orchestration would add a second experimental variable.
set -euo pipefail

ENV_NAME="${1:?usage: run-trial.sh <env> <finding-id> <arm> <n>}"
FINDING_ID="${2:?missing finding id}"; ARM="${3:?missing arm}"; TRIAL_N="${4:?missing n}"
: "${ELCAP_WORKSPACE:?ELCAP_WORKSPACE must be set}"
: "${ELCAP_CANONICAL_REPO:?ELCAP_CANONICAL_REPO must be set}"
: "${ELCAP_GROUND_TRUTH_DIR:?ELCAP_GROUND_TRUTH_DIR must be set}"

case "$(cd "$ELCAP_GROUND_TRUTH_DIR" && pwd -P)" in
  "$(cd "$ELCAP_WORKSPACE" && pwd -P)"/runs*)
    echo "refusing to start: ground truth directory is inside the runs tree" >&2; exit 2 ;;
esac

RUN_ID="${ENV_NAME}-${FINDING_ID}-arm${ARM}-n${TRIAL_N}"
RUN_DIR="${ELCAP_WORKSPACE}/runs/${RUN_ID}"
[ -e "$RUN_DIR" ] && { echo "run ${RUN_ID} exists — trials are immutable" >&2; exit 3; }
mkdir -p "$RUN_DIR"/{inputs,evidence,patch,verdict}

HOME_DIR="$(mktemp -d)/hermes-home"
trap 'rm -rf "$(dirname "$HOME_DIR")"' EXIT

python3 - "$RUN_DIR" "$FINDING_ID" "$HOME_DIR" <<'PY'
import json, subprocess, sys
from pathlib import Path
from elcapitan.evidence import Collector
from elcapitan.finding import normalise_ocsf
from elcapitan.home import seed_hermes_home
from elcapitan.hashing import sha256_file
from elcapitan.manifest import build_manifest, bundle_hash
from elcapitan.repo import capture_repo_state
import os, datetime

run_dir, finding_id, home_dir = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
repo = os.environ["ELCAP_CANONICAL_REPO"]
lock = json.loads(Path("runtime.lock.json").read_text())
now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

state = capture_repo_state(repo)
(run_dir / "repo-state-before.json").write_text(
    json.dumps({"commit": state.commit, "dirty_files": state.dirty_files}))

raw = json.loads(Path(os.environ["ELCAP_WORKSPACE"], "findings", f"{finding_id}.json").read_text())
record = normalise_ocsf(raw, run_dir=run_dir, finding_id=finding_id,
                        collector=Collector("prowler", lock["tool_versions"]["prowler"],
                                            "elcapitan-anna-scanner"), now=now)
(run_dir / "inputs" / "finding.json").write_text(json.dumps(record, indent=2))
(run_dir / "prompt.md").write_text(Path("prompts/engineer.md").read_text())

home = seed_hermes_home(home_dir, model=os.environ.get("ELCAP_MODEL", "claude-opus-5"),
                        provider=os.environ.get("ELCAP_PROVIDER", "anthropic"))
manifest = build_manifest(
    run_dir, files=["inputs/finding.json", "prompt.md"],
    repository_commit=state.commit, runtime_image_id=lock["runtime_image_id"],
    runtime_lock_sha256=sha256_file("runtime.lock.json"),
    profile_config_sha256=sha256_file(home / "config.yaml"),
    environment_adapter_sha256=sha256_file(
        f"environments/{os.environ.get('ELCAP_ENV','anna')}/env.yaml"))
(run_dir / "inputs" / "input-manifest.json").write_text(json.dumps(manifest, indent=2))
(run_dir / "inputs" / "bundle.sha256").write_text(bundle_hash(manifest))
PY

if [ "${ELCAP_STUB:-0}" = "1" ]; then
  python3 tests/stub_engineer.py "$RUN_DIR" "$FINDING_ID"
else
  ./bin/agent-run.sh "$RUN_DIR" "$RUN_DIR/prompt.md" engineer "$ARM" "$HOME_DIR"
fi

./bin/validate-trial-artifacts.sh "$RUN_DIR" "$ELCAP_CANONICAL_REPO" \
  "$RUN_DIR/repo-state-before.json"
echo "run ${RUN_ID} complete"
```

- [ ] **Step 5: Write `tests/stub_engineer.py`** — emits a valid `proposal.json` (status `NEEDS_HUMAN_CONTEXT`, `resolution_type: needs_design`), an `evidence-index.json` containing the raw-event ref written by normalisation, a `transcript.log`, and `input_bundle_hash` read from `inputs/bundle.sha256`.

- [ ] **Step 6: Run the full suite**

```bash
pytest -v                       # unit + harness
ELCAP_SMOKE=1 pytest tests/test_smoke_container.py -v   # requires the built image
```

Record the real counts. **Do not write a passing count you have not observed** — that error is what produced this revision.

- [ ] **Step 7: Commit**

```bash
git add bin/run-trial.sh prompts/ tests/stub_engineer.py tests/test_run_trial.py tests/test_smoke_container.py
git commit -m "feat(harness): engineer-stage trial runner with black-box container smoke tests"
```

---

### Task 13: Anna adapter and the Stage 1 shakedown

**Files:**
- Create: `environments/anna/env.yaml`, `environments/anna/scanner-policy.json`, `environments/anna/OBSERVATIONS.md`

**Interfaces:**
- Consumes: the full harness
- Produces: the first real, validated run

**Fixes from review:** the repository path was wrong; a long-lived IAM user is replaced by an assumed role with temporary credentials; the finding is chosen deliberately and recorded rather than taken blindly as the first `FAIL`; and the exit condition no longer demands a patch, since `runtime_change`, `needs_design` and `NEEDS_HUMAN_CONTEXT` are all legitimate outcomes the spec explicitly endorses.

- [ ] **Step 1: Create a scoped read-only role**

`SecurityAudit` + `ViewOnlyAccess` is broader than this probe needs and would grant log-reading that contradicts the no-telemetry constraint. Write an explicit policy instead:

```json
// environments/anna/scanner-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "ConfigReadOnly", "Effect": "Allow", "Resource": "*",
      "Action": ["s3:GetBucket*", "s3:ListAllMyBuckets", "s3:GetEncryptionConfiguration",
                 "dynamodb:DescribeTable", "dynamodb:ListTables",
                 "lambda:GetFunction*", "lambda:ListFunctions",
                 "events:DescribeRule", "events:ListRules",
                 "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets",
                 "iam:Get*", "iam:List*", "cloudwatch:DescribeAlarms",
                 "cloudformation:DescribeStacks", "cloudformation:GetTemplate"] },
    { "Sid": "NoDataPlaneOrLogs", "Effect": "Deny", "Resource": "*",
      "Action": ["s3:GetObject", "dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query",
                 "secretsmanager:GetSecretValue", "logs:GetLogEvents",
                 "logs:FilterLogEvents", "logs:StartQuery"] }
  ]
}
```

The explicit `Deny` is what makes "no telemetry" enforced rather than requested — an IAM deny cannot be overridden by any allow.

```bash
aws iam create-role --role-name elcapitan-anna-scanner \
  --assume-role-policy-document file://environments/anna/trust-policy.json
aws iam put-role-policy --role-name elcapitan-anna-scanner \
  --policy-name elcapitan-scanner --policy-document file://environments/anna/scanner-policy.json

# Temporary credentials only — never a long-lived access key.
eval "$(aws sts assume-role --role-arn arn:aws:iam::<acct>:role/elcapitan-anna-scanner \
  --role-session-name elcapitan-shakedown --duration-seconds 3600 \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text \
  | awk '{print "export ELCAP_SCANNER_AWS_ACCESS_KEY_ID="$1"\nexport ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY="$2"\nexport ELCAP_SCANNER_AWS_SESSION_TOKEN="$3}')"
```

- [ ] **Step 2: Write the adapter**

```yaml
# environments/anna/env.yaml
# `repository.path` is relative to the El Capitan repository root.
name: anna
classification: exploratory        # NOT part of any scored matrix
cloud: aws
repository:
  path: ../Anna/ni-sales-agent
  iac_root: aws/infra/cdk
  pin: ""                          # set by Step 3
identities:
  scanner_role_arn: ""             # set by Step 1
  observer: null                   # telemetry deliberately out of scope
telemetry:
  enabled: false
  enforcement: iam_deny            # see scanner-policy.json Sid=NoDataPlaneOrLogs
selected_finding:
  ocsf_uid: ""                     # set deliberately by Step 4, never "first FAIL"
  rationale: ""
health_contract: null              # no remediation is applied
ground_truth: null                 # human-adjudicated
```

- [ ] **Step 3: Pin the repository commit**

```bash
COMMIT=$(git -C ../Anna/ni-sales-agent rev-parse HEAD)
python3 -c "
import sys,yaml,pathlib
p=pathlib.Path('environments/anna/env.yaml'); d=yaml.safe_load(p.read_text())
d['repository']['pin']=sys.argv[1]; p.write_text(yaml.safe_dump(d, sort_keys=False))" "$COMMIT"
```

- [ ] **Step 4: Scan, then choose a finding deliberately**

```bash
prowler aws --output-formats json-ocsf --output-directory "$ELCAP_WORKSPACE/scans/anna"

# Review candidates rather than taking the first failure.
jq -r '.[] | select(.status_code=="FAIL")
       | [.finding_info.uid, .resources[0].type, .resources[0].uid, .severity]
       | @tsv' "$ELCAP_WORKSPACE"/scans/anna/*.ocsf.json | column -t
```

Choose one whose resource plausibly originates in `aws/infra/cdk/ni-sales-agent-stack.ts`
(DynamoDB, Lambda, EventBridge, Secrets Manager, S3, IAM, CloudWatch or Budgets).
Record the UID and the reason in `env.yaml`. **If no candidate qualifies, stop and say so**
— a shakedown against a resource that cannot possibly link proves nothing.

```bash
jq --arg uid "<CHOSEN_UID>" '[.[] | select(.finding_info.uid==$uid)][0]' \
   "$ELCAP_WORKSPACE"/scans/anna/*.ocsf.json > "$ELCAP_WORKSPACE/findings/FIND-001.json"
```

- [ ] **Step 5: Run the real trial**

```bash
export ELCAP_CANONICAL_REPO="$PWD/../Anna/ni-sales-agent"
export ELCAP_GROUND_TRUTH_DIR="$HOME/.elcapitan-ground-truth"   # outside the workspace
export ELCAP_ENV=anna
mkdir -p "$ELCAP_GROUND_TRUTH_DIR"
./bin/run-trial.sh anna FIND-001 A 1
```

- [ ] **Step 6: Verify the Stage 1 exit conditions**

Revised from the previous draft — the fourth condition no longer demands a patch:

1. Scanner output normalised and schema-valid.
2. The finding is linked to a **plausible CDK source location**, or `iac_managed: false` is asserted with evidence.
3. **A valid resolution is produced** — any of the five `resolution_type` values, or `NEEDS_HUMAN_CONTEXT`.
4. The artifact validator passes.
5. The canonical repository is provably untouched.

```bash
RUN="$ELCAP_WORKSPACE/runs/anna-FIND-001-armA-n1"
jq '{iac_managed:.linking.iac_managed, system:.linking.system_detected,
     method:.linking.method, files:.linking.files,
     resolution:.resolution_type, status:.status}' "$RUN/proposal.json"
./bin/validate-trial-artifacts.sh "$RUN" "$ELCAP_CANONICAL_REPO" "$RUN/repo-state-before.json"
git -C "$ELCAP_CANONICAL_REPO" status --porcelain --untracked-files=all | wc -l   # expect 0
```

- [ ] **Step 7: Record the prediction outcome**

The spec puts a prediction on record: *the agent greps the resource name in `*.ts` rather than
resolving ARN → physical name → CFN logical ID → `cdk.out/tree.json` construct path → source.*
Copy `linking.method` verbatim into `OBSERVATIONS.md` and state plainly which happened. If the
prediction was wrong, that is the more interesting result — do not smooth it.

- [ ] **Step 8: Commit**

```bash
git add environments/anna/
git commit -m "feat(anna): scoped-role adapter and Stage 1 shakedown results

Exploratory only: Anna changes cloud, IaC language and environment-reality
simultaneously and has no constructed ground truth, so it cannot demonstrate
generalisation. Telemetry blocked by explicit IAM deny, not merely by intent."
```

---

## Self-Review

**Review findings, and where each is addressed.**

| Finding | Task |
|---|---|
| P0 — digest belongs to the wrong image; no build step | 1 (distinct `base_image_digest` / `runtime_image_id`, explicit build) |
| P0 — `pyproject` hash is not a dependency lock | 1 (`uv.lock` + its hash) |
| P0 — Dockerfile is a template, not executable | 1 (pinned installs; test rejects `<`/`>`) |
| P0 — `--prompt-file` does not exist | 0 (spike), 11 (`chat -q`, proven argv) |
| P0 — empty `HERMES_HOME` cannot start | 2 (baseline home) |
| P0 — `--user` may bypass s6 init | 0 (Q5), 10 (test asserts no `--user`) |
| P0 — secrets in argv | 10 (names-only), 11 (subprocess env) |
| P0 — `ELCAP_SCANNER_` prefix passed through; observer double-prefixed | 11 (`SCANNER_ENV_MAP`) |
| P0 — challenger should hold no credentials | 10 (raises on `AWS_`/`AZURE_`) |
| P0 — repo integrity check compares recorded input to itself | 7 (recompute; tracked, staged, untracked, commit) |
| P1 — evidence path can escape the run directory | 3 (`safe_resolve`, symlink rejection, exclusive create) |
| P1 — raw event outside the trial bundle | 5 (written into `run_dir`) |
| P1 — bundle hash ambiguous and incomplete | 6 (canonical manifest) |
| P1 — schemas permissive; no `FormatChecker`; `$ref` unresolved | 4 (registry, format checker, `CommandRecord`, conditionals) |
| P1 — validator raises instead of reporting | 9 (structured failures throughout) |
| P1 — mutation regex described as enforcement | 9 (`DIAGNOSTIC:` prefix), Global Constraints |
| Five failing tests | 10 (`host_hermes_home`, image position), 12 (repo with a commit, findings file), 2 (model config) |
| Anna path wrong | 13 (`../Anna/ni-sales-agent`, resolution documented) |
| Blind first-`FAIL` selection | 13 (deliberate choice, UID + rationale recorded, stop if none qualify) |
| IAM too broad; long-lived key | 13 (scoped role, explicit `Deny`, `sts assume-role`) |
| Exit condition demands a patch | 13 ("a valid resolution is produced") |
| Container hardening absent | 10 (`--cap-drop=ALL`, `no-new-privileges`, pids/memory/cpu, tmpfs) |
| Argv-only testing insufficient | 12 (`test_smoke_container.py`) |

**Deliberately not resolved here, and why.** Egress from the engineer container remains
unrestricted: it needs the model API and AWS APIs, and an allowlisting proxy is real work
that would delay Stage 1 without changing what Stage 1 measures. This is a **recorded
residual risk** — a prompt-injected repository could exfiltrate the scanner credential.
Two things reduce the blast radius meanwhile: the credential is a time-boxed assumed role
scoped to configuration reads with an explicit data-plane `Deny` (Task 13), and the
challenger has no network at all. An egress proxy belongs in the Stage 2 plan, before
Eiger — which is a deliberately-vulnerable application and therefore a far more likely
injection source than Anna.

**Placeholder scan.** The only unresolved values are in Task 1 Step 4 (`BASE_DIGEST_FROM_TASK_0`)
and Task 13 (`<acct>`, `<CHOSEN_UID>`), each filled by a preceding step that produces it.
Task 0 exists specifically so these are resolved rather than invented.

**Type consistency.** `EvidenceRef`/`Collector` field sets match across Tasks 3, 5, 9 and the
schema. `validate_doc(name, doc)` has one signature (Tasks 4, 5, 9). `interpret_exit(tool, argv, code)`
takes three required arguments everywhere. `ContainerSpec.env_passthrough` is a list of names in
Tasks 10, 11 and 12. `validate_run(run_dir, *, canonical_repo, repo_state_before)` is called
identically in Task 9's tests, Task 12's harness, and Task 13's verification.

**On test counts.** This plan states expected counts per task but makes no claim about a total
suite result, because that claim has not been observed. Task 12 Step 6 requires recording real
numbers.
