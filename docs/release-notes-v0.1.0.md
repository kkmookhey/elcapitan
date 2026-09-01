# El Capitan v0.1.0 technical preview release notes

**Status:** unreleased; external release gates remain blocked

## Important limitations

- This is a self-hosted technical preview, not an autonomous replacement for a
  DevOps or SRE team and not a public multi-tenant SaaS.
- Read-only live validation covers 72 deterministic controls (35 Azure, 37 AWS),
  but only four controls support verified remediation planning and only two
  Azure Storage controls have a proven live action connector.
- Validation capability never grants planning or execution authority.
- Shared-token browser authentication is for local demonstration and bounded
  pilots, not production customer approval.
- Azure OpenAI and Cosmos DB controls are contract tested and export observed,
  not E2E measured. Key Vault diagnostic logging, the six added S3 controls,
  eight RDS controls, twenty EC2 security-group controls, and two EBS volume
  controls are contract tested but not yet measured in the lab.
- No unattended production remediation, generic VM/OS patching, arbitrary
  application-code remediation, broad AWS execution, or complete benchmark
  coverage is claimed.

## What is included

- OCSF and AWS Security Hub ASFF intake with exact FAIL/PASS/MANUAL accounting,
  replay deduplication, tenant isolation, correlation, and transparent priority.
- Authenticated read-only fleet console with explicit source, outcome,
  validation, planning, execution, and evidence-grade labels.
- Bounded Azure and AWS collectors with minimized typed evidence and
  deterministic fail-closed evaluation.
- Conservative Terraform linkage, isolated complete-file proposals, and real
  format, validation, and no-refresh plan checks.
- Independent SRE, change-window, rollback, human-decision, execution,
  verification, certificate, and originator-handoff records.
- Durable runtime budgets, idempotent replay, equivalent-failure circuit
  breaking, and operator-visible needs-human outcomes.
- Docker Compose quickstart with PostgreSQL and a checked-in synthetic finding.
- Generated capability/evidence matrix, pinned container inputs, package and
  container security checks, CycloneDX SBOM, provenance, and guarded release
  automation.

## Local preview

```bash
docker compose up --build --detach --wait
```

Open `http://127.0.0.1:8770` and follow the [five-minute
quickstart](quickstart.md). It uses synthetic data and needs no cloud or model
credentials.

## Candidate evidence

The local clean-clone rehearsal at commit `44dd79e` passed 538 tests, inspected
the wheel and source distribution, ran the complete-history secret prevention
scan with its disclosed historical baseline, completed the authenticated
PostgreSQL quickstart, generated a 370-component CycloneDX container SBOM, and
recorded local OCI provenance. See the [dated rehearsal
record](release-rehearsal-2026-08-28.md).

The AWS parity checkpoint was built from source commit
`499382d278afee8f750af74b8e879bd1cfbd8c2c`. It passes 680 tests, package and
installed-wheel smoke checks, capability-matrix and release-tree checks,
narrow Ruff checks, and `git diff --check`. No AWS execution, cloud write,
model call, customer-system access, or external publication was performed.

The subsequent EBS volume checkpoint was built from source commit
`f441de9ecaa8d947a24e33acbd4b5e000c46bd88`. It passes 703 tests, compile and
narrow Ruff checks, generated-matrix and release-tree verification,
wheel/source builds, distribution inspection, and `git diff --check`. It used
only synthetic AWS contract fixtures and made no cloud or model call.

This evidence is not release approval. Before the version is tagged, the
GitHub Support must confirm retained PR-ref/cache cleanup, the approved public
visibility change and protected release environment must be configured, and a
committed digest-bound release approval must authorize the exact tag. The
changelog date and release artifacts must then be regenerated for that tag.
