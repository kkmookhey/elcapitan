# El Capitan v0.1.0 technical preview release notes

**Status:** unreleased; external release gates remain blocked

## Important limitations

- This is a self-hosted technical preview, not an autonomous replacement for a
  DevOps or SRE team and not a public multi-tenant SaaS.
- Read-only live validation covers 36 deterministic controls (35 Azure, 1 AWS),
  but only four controls support verified remediation planning and only two
  Azure Storage controls have a proven live action connector.
- Validation capability never grants planning or execution authority.
- Shared-token browser authentication is for local demonstration and bounded
  pilots, not production customer approval.
- Azure OpenAI and Cosmos DB controls are contract tested and export observed,
  not E2E measured. Key Vault diagnostic logging is contract tested but not yet
  measured in the lab.
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

The local clean-clone rehearsal at commit `4fb9dbd` passed 538 tests, inspected
the wheel and source distribution, ran the complete-history secret prevention
scan with its disclosed historical baseline, completed the authenticated
PostgreSQL quickstart, generated a 370-component CycloneDX container SBOM, and
recorded local OCI provenance. See the [dated rehearsal
record](release-rehearsal-2026-08-28.md).

This evidence is not release approval. Before the version is tagged, the
license and project name require recorded approval, historical secret findings
require authorized adjudication and remediation, the protected release
environment and remote CI evidence must exist, and the changelog date and
release artifacts must be regenerated for the exact approved tag.
