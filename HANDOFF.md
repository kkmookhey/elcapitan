# El Capitan — Session Handoff

**As of 2026-08-24.** Read this before touching anything.

---

## What this project is

A **capability probe**, not a demo and not a product. Its output is a results table.

> **The question.** Does telemetry materially improve an agent's ability to reject
> production-breaking security remediations, *without* making it reject safe changes
> indiscriminately?

**Thesis: findings are cheap, remediation is expensive.** Prowler ships hundreds of
checks free. Remediation is expensive because it needs context the scanner is
*architecturally blind to* — what the app does, what depends on this resource, what
breaks when it changes. That gap is the moat, and it is what this probe measures.

Specs and plans live in `docs/superpowers/`. Read the design spec first; it explains
why nearly every decision here is shaped the way it is.

---

## Status

| Stage | State |
|---|---|
| **0–1** substrate, harness, validator | ✅ merged — 345 tests, 13 tasks, all reviewed |
| **2** Eiger on Azure + the trap | ✅ merged — **the gate passed** |
| **3–5** the scored experiment | 🔨 **Task 1 done**, Task 2 next |

`feat/stage3-provider-agnostic-harness` (2 commits ahead of `main`), clean tree,
`372 passed, 11 skipped`.

---

## Two things that will trip you immediately

**1. The Eiger repo is on the wrong branch.**

`/Users/kkmookhey/Projects/eiger` is on `feat/s10-kill-chain-capstone`. Stage 2 depends
on two commits that are **unmerged** and not checked out:

```
80bfc4d fix(kb): make the blob dependency load-bearing for ordinary use, not just /reset
332b09c feat(kb): optional blob-backed RAG corpus, default off
```

They live on `feat/blob-backed-kb-source`. The **running Azure image was built from that
branch**, so the deployment works while the source tree does not reflect it. Do not
rebuild the image from `main` or you will silently lose the trap's whole premise. That
branch is unmerged on purpose — it is a PR against a Black Hat teaching repo and is the
human partner's call to land.

**2. ~~`bin/run-trial.sh` is AWS-only~~ — FIXED 2026-08-24, Task 1.**

The harness is provider-agnostic now. Which scanner credentials a trial needs is
derived from the environment adapter's `cloud:` field via
`constants.SCANNER_ENV_MAPS`, and `elcapitan.cloud` implements the Azure capture.
Two things follow that a new session should know:

- **`env.yaml` is now PARSED, not just hashed.** Its `cloud:` field decides the
  provider, and `run-trial.sh` refuses to start if it disagrees with the provider
  the scanner artifact declares. Adding an environment means declaring its cloud.
- **Azure credentials are `ELCAP_SCANNER_AZURE_CLIENT_ID` / `_CLIENT_SECRET` /
  `_TENANT_ID`** — the three `--sp-env-auth` names the scan already used. There is
  still no standing scanner principal in the tenant: Step 5 created one, measured
  with it, and deleted it. **A fresh principal cannot sign in for ~26 seconds**
  while the role assignment propagates, and nothing retries that on purpose.

## Live infrastructure — real money, real exposure

**Azure**, subscription `8cd2b4cc-c789-466d-a8f7-8f51fb20985d` (*Azure CIS Agent
Testing*), `centralindia`, resource group `eiger-rg`:

`eigeracr` · `eigercorpus8dlub3zy` · `eiger-logs` · `eiger-env` · `eiger-app`

- App: `eiger-app.delightfulflower-70c1e865.centralindia.azurecontainerapps.io`
- Health: `./environments/eiger/health.sh <fqdn>` — must report HEALTHY
- Budget: 50 USD/month, alerts at 50% / 90%
- **The storage account is deliberately public.** Do not leave it running longer than
  needed; `terraform -chdir=environments/eiger/infra destroy` when the experiment ends.

**Never point anything at `cb0d6ed4-a7c9-4929-8707-4a477a2cc9b5`** — that subscription
holds `transilience-demo-rg`, `shasta-test-rg` and other real work. `main.tf` has a
`lifecycle.precondition` that blocks it; leave that in place.

**AWS** (Anna, exploratory only): profile `sara-sales`, account `331145994818`,
`ap-south-1`. No standing El Capitan credential — the scanner role was deleted and
purged.

---

## Invariants that will silently ruin the experiment if broken

1. **Blob versioning must stay DISABLED** on `eigercorpus8dlub3zy` or the CONTROL
   finding stops firing and the control vanishes from the scan. Note: removing the
   Terraform block does **not** disable it — Terraform stops managing the property and
   Azure keeps it on. Disable explicitly with `az`.
2. **A fresh `HERMES_HOME` per scored trial.** Hermes has no hard gate on skill
   self-authoring; `creation_nudge_interval: 0` only suppresses the nudge. Trial
   independence rests entirely on this. Never reuse a home for speed.
3. **Ground truth stays out-of-band** at `~/.elcapitan-ground-truth/eiger/ground-truth.json`
   (mode 600), read only *after* artifacts are finalised. Never in the repo, never
   visible to an agent.
4. **Nothing inside `run_dir` can anchor `run_dir`.** The pre-trial bundle hash and repo
   state live under `anchors/<run-id>/`. A coherent forgery recomputes anything the
   agent can reach.
5. **The challenger holds no cloud credentials and runs `--network=none`.** Arms differ
   by *bundle content*, from one snapshot. Collecting twice makes drift a confound.

---

## What has actually been learned

The probe has **not** answered its own question yet. What it has produced:

- **The trap is real.** `public_network_access_enabled = false` → clean one-attribute
  plan → HTTP 403 in ~0.78s. Reproduced twice, confirmed from the container's traceback.
- **`/health` stays 200 through the outage.** Liveness checks cannot see this break.
- **The remediation breaks its own rollback** — `azurerm_storage_blob` is data-plane, so
  `apply` then fails refreshing at 403 and needs `-refresh=false`. An argument for
  REJECT nobody anticipated.
- **Prowler cannot distinguish "not configured" from "not permitted."** A least-privilege
  scanner *manufactures* findings a remediation pipeline would faithfully "fix". Found on
  AWS by cross-checking under a broader identity — now standard practice.
- **Check absence is as consequential as check error.** Prowler 5.37.1 has no
  storage-account diagnostic-settings check, so the specified CONTROL could not exist.
- **A transcript-reading integrity check penalises honesty** — it failed an honest agent
  four times for stating what it had *not* done. Replaced with direct state comparison.
- **CDK linking:** the agent links correctly, but the mechanism varies run to run. At
  n=2, only the weak claim holds.

---

## How work is done here

Subagent-driven: fresh implementer per task, an independent review gate after each, fix
rounds until clean. It is slow and it has repeatedly paid for itself.

**The dominant defect class is checks that pass against a synthetic artifact and fail
against the real one** — argv that never launched a container, a container never run on
Linux, a database never in WAL mode, a fixture in the wrong journal mode. **Measure; do
not assume.** Mutation-test load-bearing assertions: reintroduce the defect and confirm a
named test dies. A passing test is not evidence; a killed mutant is.

**Implementers have correctly overridden the controller thirteen times.** When one pushes
back with evidence, take it seriously — that is the process working.

**Do not background long commands.** Completion notifications route to the controller,
not the subagent, so a backgrounded command leaves the agent stalled. Foreground with an
explicit timeout (up to 600000 ms).

Ledgers are under `.superpowers/sdd/<plan-name>/progress.md` — gitignored, and the
recovery map if context is lost.

---

## Next steps

**Task 2 of `docs/superpowers/plans/2026-08-18-stages345-scored-trials.md`** — the
host-side evidence collector. Task 1 (provider-agnostic harness + the Azure capture)
is done and measured against the live account; nothing is blocked on it any more.

**Two decisions belong to the human partner:**

- **The Linux capability call.** Restoring `CAP_DAC_OVERRIDE` makes containers work on
  Linux and meaningfully weakens the isolation boundary. Moot on macOS — but on Linux the
  container currently exits 0 having done nothing, which is the false-green shape this
  project keeps finding.
- **Budget.** ~$60–110 per full 20-trial run, and re-running after a design change costs
  again. Not a one-off.

**One thing Task 1 established about how this code fails:** `bin/agent-run.sh` runs
only in non-stub mode, so renaming a constant broke it while all 365 tests stayed
green — the break would first have appeared in a real, money-spending trial. Any
shell script the stub path does not execute is untested by default. `test_shim.py`
now statically checks the names `agent-run.sh` imports; the same hole may exist
elsewhere in `bin/`.

**The most dangerous failure mode in the next plan:** telemetry ingestion lag is ~2
minutes. A collector reading a window that has not landed makes Arm B look empty,
silently turning the experiment into A-versus-A and producing a clean-looking null
result. Task 2 must assert the window is populated and fail loudly otherwise.

**The honest uncertainty:** nobody knows whether an MoA challenger given real telemetry
reasons about it at all, versus pattern-matching on the patch. If both arms behave
identically *and* Arm B's evidence is demonstrably well-formed, that is a real finding
about agentic judgement — not a bug to engineer around.
