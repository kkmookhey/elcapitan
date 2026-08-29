# Contributing

El Capitan is preparing for a `v0.1.0` technical preview. Contributions must
preserve its fail-closed evidence and authority boundaries.

## Local setup

Install Python 3.12 and `uv`, then run:

```bash
uv sync --locked --dev
uv run pytest -q
uv run python scripts/check_release_tree.py
uv run python -m compileall -q src tests scripts
uvx --from ruff==0.16.0 ruff check --select E9,F63,F7,F82 src tests scripts
uv build --out-dir dist-ci
uv run python scripts/check_distributions.py dist-ci
```

Maintainers can run the complete cloud-free clean-checkout gate with
`./scripts/rehearse_release_candidate.sh`. It requires Docker, the local Docker
SBOM plugin, Gitleaks, and already populated offline `uv` and Docker caches.

Tests must use synthetic, sanitized fixtures. Do not use customer data, live
cloud credentials, external model calls, or personal cloud sessions. A change
that adds network access must document its exact boundary and include a local
fake or contract fixture.

## Pull requests

Keep each change bounded and describe the security invariant it preserves.
Add success, failure, malformed, absent-property, and authorization-boundary
tests where applicable. Update the capability registry and generated matrix
when a control changes. Do not imply that validation coverage grants planning
or execution authority.

By participating, you agree to follow [the code of conduct](CODE_OF_CONDUCT.md).
No contribution may be publicly released until the repository license and
project name have recorded legal/business approval.
