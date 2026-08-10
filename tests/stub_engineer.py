"""A deterministic stand-in for the engineer agent.

Lets bin/run-trial.sh be exercised end to end — manifest, anchors, validator,
Hermes-home lifecycle — without an LLM, an API key, or a container. It is
invoked by run-trial.sh when ELCAP_STUB=1:

    stub_engineer.py <run-dir> <finding-id> <hermes-home>

Deliberate properties:

- **Deterministic.** Every value it writes is either a constant or derived
  from the inputs the harness already pinned. No wall-clock timestamps: two
  stub trials over the same inputs produce byte-identical proposals apart from
  the finding's own provenance.
- **It produces artifacts that actually pass validate_run.** A stub whose
  output the validator rejects would test the harness's error path forever and
  its success path never.
- **It computes `input_bundle_hash` from `inputs/input-manifest.json`, the
  same way a real agent must** — from the bundle it was given, never from an
  anchor. The harness holds the pre-trial anchor outside the run directory and
  the validator compares the two; a stub that read the anchor would make that
  comparison tautological and hide exactly the defect the anchor exists to
  catch.
- **It fails loudly if the Hermes home is not live and freshly seeded.** The
  home is what carries (or fails to carry) state between trials, and
  run-trial.sh deletes it on exit; checking it here pins the sequencing —
  seeded before the agent step, still present during it. In a real trial this
  is the window in which run_agent copies state.db out of that home into the
  run directory, so a home that were already gone by now would silently cost
  the trial its primary evidence record.

The proposal it writes is honest about being a stub: nothing is confirmed,
nothing is detected, nothing is verified, and the status is
NEEDS_HUMAN_CONTEXT — which the prompt declares a successful outcome.
"""
import json
import os
import sys
from pathlib import Path

from elcapitan.hashing import sha256_file
from elcapitan.manifest import bundle_hash

# Fixed, not `datetime.now()`: see "Deterministic" above. RFC3339 with an
# offset, which records.py's date-time checker actually enforces.
STUB_NOW = "2026-01-01T00:00:00Z"

TRANSCRIPT = """\
stub engineer (tests/stub_engineer.py) — no model was invoked.
read: inputs/finding.json
read: inputs/input-manifest.json
read: prompt.md
no toolchain detection performed; no commands executed; nothing verified.
outcome: NEEDS_HUMAN_CONTEXT
"""


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: stub_engineer.py <run-dir> <finding-id> <hermes-home>",
              file=sys.stderr)
        return 2
    run_dir, finding_id, hermes_home = Path(argv[1]), argv[2], Path(argv[3])

    if not (hermes_home / "config.yaml").is_file():
        # Not a cosmetic check. The harness must seed a fresh home before the
        # agent step and keep it alive through it; if that ordering ever
        # inverts, a real trial loses state.db and this stub is the only
        # thing that would notice in a suite with no container.
        print(f"stub_engineer: hermes home {hermes_home} is not seeded — "
              f"the harness must seed it before the agent step and keep it "
              f"until after",
              file=sys.stderr)
        return 4

    manifest = json.loads((run_dir / "inputs" / "input-manifest.json").read_text())
    finding = json.loads((run_dir / "inputs" / "finding.json").read_text())

    # The raw event the harness normalised into the run directory. Carrying it
    # into the index is what makes finding.json's own evidence citation
    # resolvable — the validator walks the finding as well as the proposal.
    raw_event = finding["raw_event"]
    (run_dir / "evidence-index.json").write_text(json.dumps([raw_event], indent=2))
    (run_dir / "transcript.log").write_text(TRANSCRIPT)

    proposal = {
        "proposal_id": "PROP-001",
        "schema_version": 1,
        "created_at": STUB_NOW,
        "finding_id": finding_id,
        # From the bundle, not from the anchor. See the module docstring.
        "input_bundle_hash": bundle_hash(manifest),
        "validation": {"confirmed": False, "evidence": [], "confidence": 0.0},
        "linking": {"iac_managed": False, "system_detected": "",
                    "method": "none: stub engineer performs no detection",
                    "confidence": 0.0, "evidence": [], "files": []},
        "root_cause": "not determined: stub engineer",
        "resolution_type": "needs_design",
        "remediation": {
            "objective": "not determined: stub engineer",
            "approach": "none",
            "patch_file": None,
        },
        # passed: null, not true. "true with an empty commands_run" is the
        # proposal asserting its own success with nothing behind it, and the
        # validator rejects it.
        "verification": {"commands_run": [], "output": [], "passed": None},
        "production_impact": {
            "expected": "none: no change is proposed",
            "dependencies": [],
            "unknowns": ["everything: no analysis was performed"],
            "risk": "not assessed",
        },
        "context": {
            "severity": finding.get("severity", ""),
            "asset_id": finding.get("resource", {}).get("uid", ""),
            "owner": "",
            "exploitability": "",
        },
        "status": "NEEDS_HUMAN_CONTEXT",
    }
    (run_dir / "proposal.json").write_text(json.dumps(proposal, indent=2))

    if os.environ.get("ELCAP_STUB_FORGE") == "1":
        _forge(run_dir, proposal)
    return 0


def _forge(run_dir: Path, proposal: dict) -> None:
    """Rewrite the input, its manifest entry, and the proposal's copy of the
    bundle hash — coherently — from inside the agent's own turn.

    This is the attack the out-of-band anchor exists to stop, performed at the
    moment it would really happen: while the agent still has /work/run mounted
    writable, before the harness validates. Every check the validator can make
    from inside the run directory still holds afterwards. Only a hash captured
    before this ran, and stored where this cannot reach, detects it.

    Enabled by ELCAP_STUB_FORGE=1 and used by exactly one test. A run-trial.sh
    that computed its anchor after the agent step, or read it back out of the
    run directory, would score this forgery green.
    """
    finding_path = run_dir / "inputs" / "finding.json"
    finding = json.loads(finding_path.read_text())
    finding["severity"] = "Low"          # still valid against finding-record
    finding_path.write_text(json.dumps(finding, indent=2))

    manifest_path = run_dir / "inputs" / "input-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["files"]:
        if entry["path"] == "inputs/finding.json":
            entry["sha256"] = sha256_file(finding_path)
            entry["size"] = finding_path.stat().st_size
    manifest_path.write_text(json.dumps(manifest, indent=2))

    proposal["input_bundle_hash"] = bundle_hash(manifest)
    (run_dir / "proposal.json").write_text(json.dumps(proposal, indent=2))

    # A real forger would also rewrite any agent-readable copy of the hash.
    # The harness writes none; this is here so the test stays honest if one
    # is ever reintroduced.
    stale = run_dir / "inputs" / "bundle.sha256"
    if stale.exists():
        stale.write_text(bundle_hash(manifest))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
