"""A deterministic stand-in for the challenger agent.

Lets bin/run-trial.sh be exercised end to end — collector, bundle, verdict
assembly, validator — without an LLM, an API key, a container or an egress
proxy. Invoked by run-trial.sh when ELCAP_STUB=1:

    stub_challenger.py <run-dir> <bundle-path>

Deliberate properties:

- **It reads the bundle it was handed and cites only what is in it.** A stub
  that emitted fixed evidence ids would pass the citation check by luck on
  some bundles and fail it on others, and the failure would look like a real
  contamination finding. Reading the manifest makes the stub's citations true
  by construction, which is what leaves `validate_verdict_against_bundle` free
  to catch a real one.

- **It returns NEEDS_MORE_EVIDENCE, not APPROVE or REJECT.** A stub that
  guessed a decision would put rows in the matrix that look like judgements
  and are not. NEEDS_MORE_EVIDENCE is the honest answer for a reviewer that
  did not reason: it says the evidence was not evaluated. Combined with the
  stub bundle's `scoring_valid: false`, a dry run cannot contribute to any
  result.

- **It writes an empty MoA trace.** `parse_member_positions` records an empty
  trace as `extraction_incomplete`, never as unanimity, so a dry-run verdict
  is visibly one nobody deliberated over.

- **Deterministic.** No wall-clock, no randomness: two stub trials over the
  same bundle produce byte-identical verdicts.
"""
import json
import sys
from pathlib import Path


def main() -> int:
    run_dir, bundle_path = Path(sys.argv[1]), Path(sys.argv[2])

    manifest_path = bundle_path / "bundle.json"
    if not manifest_path.is_file():
        print(f"stub_challenger.py: no bundle manifest at {manifest_path} — the "
              f"collector step did not produce one", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text())
    evidence_ids = sorted(r["evidence_id"] for r in manifest["artifacts"])
    if not evidence_ids:
        print("stub_challenger.py: the bundle carries no artifacts", file=sys.stderr)
        return 2

    verdict_dir = run_dir / "verdict"
    verdict_dir.mkdir(parents=True, exist_ok=True)
    (verdict_dir / "verdict.json").write_text(json.dumps({
        "decision": "NEEDS_MORE_EVIDENCE",
        "objections": [
            "This verdict was produced by tests/stub_challenger.py, which does not "
            "read or reason about the evidence. It is a harness artifact and must "
            "never be scored."
        ],
        # Cited from the manifest so the citation check is exercised against a
        # real bundle rather than trivially satisfied.
        "evidence_cited": evidence_ids[:1],
        "reasoning": "stub: no evaluation was performed",
    }, indent=2) + "\n")

    # Empty on purpose — see the module docstring.
    (verdict_dir / "moa-trace.json").write_text("[]\n")
    print(f"  stub challenger: NEEDS_MORE_EVIDENCE over {len(evidence_ids)} artifacts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
