"""Host-side deterministic validator — the final authority on a trial.

Every check returns a structured failure. Malformed input, missing files and
path-containment violations must never raise: a trial that crashes the
validator would otherwise be indistinguishable from one that was never run.
Just as important: a document that parses but has the wrong shape (`null`,
an empty object, a list where an object was expected) must never be treated
as "nothing to check" and silently skipped — an unvalidated run scoring
green is worse than a crash, because a crash is at least visible.
"""
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .evidence import Collector, EvidenceRef, verify_evidence
from .hashing import sha256_file
from .manifest import bundle_hash
from .paths import PathEscape, safe_resolve
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


def _read_json(path: Path, failures: list[str], *, expect: type = dict):
    """Parse JSON and enforce its top-level shape. Returns None on any
    failure (already appended) — the caller can then treat None as "nothing
    further to check here" without re-deriving why.

    `expect` distinguishes documents that must be a JSON object (proposal,
    finding, manifest) from evidence-index.json, which must be an array.
    A value that parses successfully but to the wrong shape (`null`, a list
    where an object was expected, an int, ...) is exactly as unusable as a
    parse error and must be reported the same way, not passed downstream as
    if it were valid.
    """
    try:
        text = path.read_text()
    except FileNotFoundError:
        failures.append(f"missing required artifact: {path.name}")
        return None
    except (OSError, UnicodeDecodeError) as exc:
        # OSError also covers IsADirectoryError/PermissionError: an artifact
        # that exists but can't be read is not "missing", but it must still
        # become a failure string, not an uncaught exception.
        failures.append(f"could not read {path.name}: {exc}")
        return None

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        failures.append(f"malformed JSON in {path.name}: {exc}")
        return None

    if not isinstance(doc, expect):
        kind = "object" if expect is dict else "array"
        failures.append(f"{path.name} is not a JSON {kind}")
        return None
    return doc


def _evidence_ids(doc) -> set[str]:
    found: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            embedded = node.get("evidence_id")
            if isinstance(embedded, str):
                # A nested EvidenceRef-shaped object — e.g. finding.raw_event
                # — cites its own evidence directly via a bare `evidence_id`
                # key (11 chars; does not end with the 12-char
                # `_evidence_id` suffix matched below), so it needs its own
                # check. It must resolve in the index exactly like any other
                # evidence citation.
                found.add(embedded)
            for key, value in node.items():
                if key == "evidence" and isinstance(value, list):
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


def _verify_manifest_files(run_dir: Path, manifest: dict) -> list[str]:
    """Re-derive each declared file's hash and size from the file actually
    on disk. Comparing bundle_hash(manifest) against the proposal's own copy
    of that hash only proves two agent-visible documents agree with each
    other — a self-consistently forged manifest passes that check by
    construction. Only a value recomputed from something neither document
    controls (the file's real bytes) is evidence.
    """
    failures: list[str] = []
    files = manifest.get("files")
    if not isinstance(files, list):
        return ["input-manifest.json 'files' is missing or not a list"]

    for entry in files:
        if not isinstance(entry, dict):
            failures.append(f"input-manifest.json contains a malformed file entry: {entry!r}")
            continue
        rel = entry.get("path")
        if not isinstance(rel, str):
            failures.append(f"input-manifest.json file entry has a non-string path: {entry!r}")
            continue
        try:
            resolved = safe_resolve(run_dir, rel)
        except PathEscape as exc:
            failures.append(
                f"input-manifest.json file entry escapes the run directory: {rel!r} ({exc})")
            continue
        if not resolved.is_file():
            failures.append(f"input-manifest.json references a missing file: {rel!r}")
            continue

        try:
            actual_sha256 = sha256_file(resolved)
            actual_size = resolved.stat().st_size
        except OSError as exc:
            # is_file() above proves existence, not readability, and it is
            # also a TOCTOU window — the file can vanish or become
            # unreadable between that check and this one. Mirror
            # evidence.verify_evidence's guard: mark this entry invalid
            # rather than let the whole batch crash.
            failures.append(
                f"input-manifest.json file entry could not be read for verification: "
                f"{rel!r} ({exc})")
            continue

        if actual_sha256 != entry.get("sha256"):
            failures.append(
                f"input-manifest.json sha256 for {rel!r} does not match the file on disk "
                f"— manifest may have been forged")
        if actual_size != entry.get("size"):
            failures.append(
                f"input-manifest.json size for {rel!r} does not match the file on disk "
                f"({entry.get('size')!r} vs {actual_size})")
    return failures


def _manifest_declared_paths(manifest: dict) -> set[str]:
    files = manifest.get("files")
    if not isinstance(files, list):
        return set()
    return {entry.get("path") for entry in files
            if isinstance(entry, dict) and isinstance(entry.get("path"), str)}


def validate_run(run_dir, *, canonical_repo, repo_state_before: RepoState) -> ValidationResult:
    run_dir = Path(run_dir)
    failures: list[str] = []

    for path in run_dir.rglob("*"):
        if any(m in path.name.lower() for m in GROUND_TRUTH_MARKERS):
            failures.append(f"ground truth present inside run dir: {path.name}")

    proposal = _read_json(run_dir / "proposal.json", failures, expect=dict)
    finding = _read_json(run_dir / "inputs" / "finding.json", failures, expect=dict)
    index_doc = _read_json(run_dir / "evidence-index.json", failures, expect=list)
    manifest = _read_json(run_dir / "inputs" / "input-manifest.json", failures, expect=dict)

    if isinstance(proposal, dict):
        failures += [f"proposal: {e}" for e in validate_doc("remediation-proposal", proposal)]
    if isinstance(finding, dict):
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

    # Manifest integrity: the document itself (shape/emptiness), then every
    # file it claims (re-hashed from disk), then — only once both of those
    # hold — that the proposal's own copy of the hash matches.
    if manifest is None:
        pass  # _read_json already explained why: missing, malformed, or wrong JSON type
    elif not manifest:
        failures.append("input-manifest.json is empty")
    else:
        failures += _verify_manifest_files(run_dir, manifest)

        # _verify_manifest_files only re-checks what the manifest chose to
        # declare — an empty or decoy-only files list re-hashes nothing and
        # still recomputes a self-consistent bundle_hash. Require the one
        # input this validator already has independent, direct knowledge
        # of: it reads inputs/finding.json itself, above. (Evidence-index
        # artifacts are deliberately NOT required here: most of them, e.g.
        # command stdout/stderr, are produced *during* the trial and do not
        # exist yet when the manifest is built, so requiring them would
        # reject every legitimately-produced run; their integrity is
        # already independently covered by verify_evidence() per entry.)
        required_paths = {"inputs/finding.json"}
        declared_paths = _manifest_declared_paths(manifest)
        for path in sorted(required_paths - declared_paths):
            failures.append(f"input-manifest.json does not declare a required input: {path}")

        if isinstance(proposal, dict):
            expected = bundle_hash(manifest)
            if proposal.get("input_bundle_hash") != expected:
                failures.append(
                    f"input_bundle_hash does not match input-manifest.json ({expected[:8]})")

    if isinstance(proposal, dict):
        # remediation/verification/commands_run are schema-validated above,
        # but validate_doc() only *reports* shape errors — it does not stop
        # this function from also touching the same malformed data. Every
        # access below is guarded so a wrong-shaped field adds its own
        # failure string instead of raising or relying solely on the schema
        # failure already recorded.
        resolution_type = proposal.get("resolution_type")

        remediation = proposal.get("remediation")
        if isinstance(remediation, dict):
            patch_file = remediation.get("patch_file")
        else:
            failures.append(f"proposal.remediation is not a JSON object: {remediation!r}")
            patch_file = None

        if resolution_type == "patch" and isinstance(patch_file, str) and patch_file:
            try:
                resolved_patch = safe_resolve(run_dir, patch_file)
            except PathEscape as exc:
                # Path('run_dir') / '/etc/hosts' == Path('/etc/hosts') under
                # pathlib's own semantics for an absolute second operand, so
                # an unguarded join would let a declared patch_file escape
                # the run directory entirely and still resolve to a real
                # file the agent never produced. Route through safe_resolve
                # like every other agent-supplied path.
                failures.append(
                    f"declared patch_file escapes the run directory: {patch_file!r} ({exc})")
            else:
                if not resolved_patch.is_file():
                    failures.append(f"declared patch_file does not exist: {patch_file}")

        if resolution_type == "false_positive" and isinstance(patch_file, str) and patch_file:
            # A false positive needs no fix, so shipping one alongside it is
            # a structural contradiction the schema doesn't close (patch_file
            # is ["string","null"] for every resolution type; the schema's
            # `allOf` only constrains the `patch` case). Check the field
            # itself — a substring match on free-text "justification" would
            # be theatre, not a check.
            failures.append(
                "resolution_type is false_positive but remediation.patch_file is set "
                f"({patch_file!r}); a false positive must not ship a patch")

        verification = proposal.get("verification")
        if isinstance(verification, dict):
            commands_run = verification.get("commands_run")
        else:
            failures.append(f"proposal.verification is not a JSON object: {verification!r}")
            commands_run = None

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
        # errors="replace": a transcript is a captured terminal stream, so
        # raw control/binary bytes are routine, not adversarial. The content
        # is only regex-scanned below, so lossy decoding is harmless and
        # far better than crashing the validator over the most likely
        # malformed artifact in real use.
        transcript = (run_dir / "transcript.log").read_text(errors="replace")
    except FileNotFoundError:
        failures.append("missing required artifact: transcript.log")
        transcript = ""
    except OSError as exc:
        failures.append(f"could not read transcript.log: {exc}")
        transcript = ""
    for pattern in MUTATION_PATTERNS:
        if re.search(pattern, transcript):
            failures.append(f"DIAGNOSTIC: possible mutation in transcript /{pattern}/")

    return ValidationResult(passed=not failures, failures=failures)
