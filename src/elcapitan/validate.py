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
        # remediation/verification/commands_run are schema-validated above,
        # but validate_doc() only *reports* shape errors — it does not stop
        # this function from also touching the same malformed data. Every
        # access below is guarded so a wrong-shaped field adds a failure
        # string instead of raising: the schema failure already explains
        # *what's* wrong, so these guards just prevent a second, unguarded
        # pass over the same data from crashing the validator.
        remediation = proposal.get("remediation")
        patch_file = remediation.get("patch_file") if isinstance(remediation, dict) else None
        if proposal.get("resolution_type") == "patch" and isinstance(patch_file, str) and patch_file:
            if not (run_dir / patch_file).is_file():
                failures.append(f"declared patch_file does not exist: {patch_file}")

        verification = proposal.get("verification")
        commands_run = verification.get("commands_run") if isinstance(verification, dict) else None
        for command in commands_run if isinstance(commands_run, list) else []:
            if not isinstance(command, dict):
                failures.append(f"malformed CommandRecord (not an object): {command!r}")
                continue
            try:
                verdict = interpret_exit(command["tool"], command["argv"], command["exit_code"])
            except (KeyError, TypeError) as exc:
                failures.append(f"malformed CommandRecord, cannot interpret exit code: {exc}")
                continue
            if not verdict.ok:
                failures.append(f"verification command failed: "
                                f"{command['tool']} — {verdict.meaning}")
            elif verdict.ambiguous:
                # The exit code cannot distinguish a passing verification from a
                # tool failure. Surfacing it beats scoring a failed run green.
                failures.append(f"AMBIGUOUS: verification cannot be trusted: "
                                f"{command['tool']} — {verdict.meaning}")

    try:
        failures += assert_unchanged(canonical_repo, repo_state_before)
    except ValueError as exc:
        # repo.py raises when the path is missing or is not a repository at
        # all. That must become a structured failure, not a crash: a trial
        # that kills the validator is indistinguishable from one that never
        # ran, and this validator is the final authority on both.
        failures.append(f"canonical repository could not be inspected: {exc}")

    try:
        transcript = (run_dir / "transcript.log").read_text()
    except FileNotFoundError:
        failures.append("missing required artifact: transcript.log")
        transcript = ""
    for pattern in MUTATION_PATTERNS:
        if re.search(pattern, transcript):
            failures.append(f"DIAGNOSTIC: possible mutation in transcript /{pattern}/")

    return ValidationResult(passed=not failures, failures=failures)
