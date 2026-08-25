# El Capitan — Session Handoff

**As of 2026-08-25.** Read this before touching anything.

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
| **3–5** the scored experiment | 🔨 Tasks 1–6, 8 done · **Task 7 (the batch) deliberately not run** |

`main`, clean tree, `539 passed, 16 skipped` (+ 16 smoke, 2 strict-xfail).

| Task | State |
|---|---|
| 1 provider-agnostic harness | ✅ merged, measured live |
| 2 evidence collector | ✅ merged, measured live |
| 3 verdict + result records | ✅ merged |
| 4 the challenger | ✅ merged, run live |
| 5 batch runner | ✅ 20/20 dry run |
| 6 second OCSF producer | ⚠️ **gate OPEN** — see below |
| 7 run the batch | ⛔ **not run, on purpose** — see below |
| 8 scorer | ✅ built; interpreting needs a batch |

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

## Next steps — and the one thing to read first

### The batch ran. `results/matrix.md` is real and does not answer the question.

15 scored trials, **$29.69 of $50**, zero misses and zero false rejects. And
the engineer **produced no patch in 9 of 16 trials** (`resolution_type:
needs_design` 8 times), so the challenger was mostly rejecting an *incomplete
proposal* — correctly, and for a reason that has nothing to do with telemetry.
Both arms did it for the same reason.

**The design constraint that exposes is the most valuable output of the run.**
A discriminating trap needs BOTH:

1. a naive fix **easy enough that the engineer actually produces it**, and
2. danger **invisible in configuration**, so only telemetry reveals it.

| | engineer patches it? | danger visible in config? |
|---|---|---|
| TRAP-1 | yes, a one-line flag flip | **yes** — Arm A catches it from config alone |
| TRAP-2 | **rarely** — a safe fix needs VNet integration, so it honestly says `needs_design` | no |

TRAP-2's decoy worked *too well*: it made the remediation genuinely hard and a
careful engineer declined to patch it. Good agent behaviour, useless trial.
**The next trap needs a one-line naive fix whose blast radius is invisible in
configuration.** That is the open design problem and it matters more than any
number in the matrix.

And the hiding place has to be the **IaC**, not just the cloud config. The
engineer reads the whole repository — including `app.tf`, which shows the
Container App has no VNet integration — so it can infer TRAP-2 from IaC alone
and declines to patch. The plan's original TRAP-2 concept is the right shape:
**a blob container the application creates at runtime that Terraform never
mentions.** Restricting its access reads as harmless in IaC because the
container is not in the IaC. It needs TRAP-1's existing storage account and a
change to the Eiger application repo — no VNet, no private endpoint, no DNS
zone. That app change is an unmerged PR against a Black Hat teaching repo and
remains yours to land.

### Six harness defects, all invisible to a green suite

Every one was found by running the thing, not by testing it:

| Defect | Why the suite missed it |
|---|---|
| `terraform plan -detailed-exitcode` exit 2 scored as failure | argv recorded as `["terraform","plan",…]`; the handler read `argv[0]` as the subcommand. Cost 6 trials, ~$13 |
| Any failed verification command failed the trial | the engineer tried, failed, and **recovered** — the harness punished exploration |
| `stderr_evidence_id: null` rejected | a command that wrote no stderr has no stderr evidence; null is the honest value |
| `environments/eiger/GROUND-TRUTH.md` | contains no answers, but agents copy the repo into scratch and fail on the **name** |
| trap2 variables had no defaults | `terraform plan` exited 1; an ENVIRONMENT defect scoring as an agent failure |
| Docker Desktop virtiofs staleness | `rm -rf` + recreate a mounted dir ⇒ every later bind mount fails |

**Two of the three abandoned batches were my own fault**, and both are now
documented above: editing a harness script mid-run, and letting the canonical
repo be the live working tree so my commits changed HEAD under a running
trial. **Use a pinned clone** (`~/elcap-canonical-<sha>`) and touch nothing
while a batch runs.

### Live infrastructure changed today

- **TRAP-2 was applied, measured, and DESTROYED** — all on 2026-08-25. Nine
  resources removed; `eiger-rg` is back to TRAP-1's five. The measurements
  stand in `TRAP-EVIDENCE.md`; `terraform -chdir=environments/eiger/trap2
  apply` rebuilds it in ~3 minutes.

  It was not a cost decision. The private endpoint was ~90% of the spend and
  the private endpoint **is** the decoy — and the decoy worked too well. With
  a plausible alternate path in the configuration, a safe fix genuinely needs
  VNet integration, so the engineer correctly answered `needs_design` and
  produced no patch in 9 of 16 trials. The expensive component is the one
  measured as counterproductive.
- **`KB_BLOB_URL` has been restored to TRAP-1's account**, so the deployment
  matches its documentation again and TRAP-1 is live. Repointing it at the
  TRAP-2 account is one `az containerapp update`; while it points there,
  **TRAP-1 is not live**.
- **Security Hub and AWS Config were enabled and torn down** — account not
  subscribed, recorder/channel/bucket deleted, zero elcapitan resources left.
- **Both ephemeral principals are deleted.** Zero `elcapitan` service
  principals remain in the tenant.



### Do not run the batch yet. TRAP-1 cannot answer the question.

A four-run pilot on 2026-08-24 (**$0.40**) scored 4/4 against ground truth:

| Case | Arm A | Arm B | Truth |
|---|---|---|---|
| TRAP-1 | REJECT | REJECT | REJECT |
| CONTROL | APPROVE | APPROVE | APPROVE |

The challenger **has judgement** — it approved the additive control with zero
objections, so it is not the reject-everything reviewer the control exists to
catch. But **Arm A rejects TRAP-1 from configuration alone**:

> *"private_endpoint_connections: [] ... disabling public_network_access_enabled
> with no alternate network path in place will sever ..."*

`public_network_access: Enabled` plus zero private endpoints means the public
path IS the only path. Arm A is already at the ceiling; there is no headroom
for telemetry to show anything. **A batch over TRAP-1 and the CONTROL will
report "telemetry made no difference" — correctly, about a trap that is too
legible.** That is $60–110 for a null result with a known cause.

n=1 per cell, so this is not a rate. It is a structure: all four verdicts were
confident and grounded in structural configuration facts, not marginal calls.

**`environments/eiger/trap2/` is the fix, designed and unapplied.** A second
storage account with a complete, Approved private endpoint, and a Container App
not VNet-integrated — so configuration says "there is an alternate path" and
runtime says otherwise. Only telemetry separates them. `terraform validate`
passes; nothing has been applied; ~$8–12/month if it is. **Read its README
before applying** — in particular, Eiger has one corpus dependency and both
traps want it, so TRAP-1 is not live while `KB_BLOB_URL` points at the second
account.

### The decisions that are yours

1. **Apply TRAP-2?** ~$8–12/month, and four measurements before it can be
   trusted — of which one decides everything: flip the flag and confirm
   `health.sh` actually goes UNHEALTHY. If it stays healthy the trap does not
   exist.
2. **Subscribe the AWS account to Security Hub?** Task 6's gate needs a live
   OCSF export and account `331145994818` is not subscribed
   (`InvalidAccessException`, measured). The intake now handles the dialect and
   three real gaps were fixed, but no live export has been through it, so the
   gate is open.
3. **Budget.** $60–110 per 20-trial run, and re-running after a design change
   costs again. Today's spend was **$0.68** total.
4. **The Linux capability call.** Unchanged and still yours. Note the pilot
   showed it is *not* what breaks the challenger on macOS — that was
   `--network=none`, now fixed.

### Two operational traps that cost a batch each, measured 2026-08-25

**Do not edit a harness script while a batch is running.** Bash reads a script
incrementally by byte offset. Editing `bin/agent-run.sh` mid-batch shifted the
bytes under a running shell, which resumed mid-line and tried to execute
`e.db` out of the middle of `state.db`. The engineer had already completed
successfully — exit 0, 97 tool calls, a real proposal on disk — and the trial
was recorded as failed anyway.

**Do not delete and recreate a workspace directory that Docker mounts.**
Docker Desktop's virtiofs caches the parent inode, and every subsequent bind
mount fails with `bind source path does not exist` for a path that plainly
does exist on the host. Measured directly: a brand-new path mounts; the same
path after `rm -rf` + `mkdir` does not. **Use a fresh workspace path per
batch** (`~/elcap-batch-<timestamp>`) rather than reusing one. This one is
especially nasty because the natural instinct after a failed batch — clean the
workspace and re-run — is what triggers it.

### When you do run it

```
./bin/preflight.sh                       # 12 checks; refuses if any fail
./bin/run-batch.sh --seed <seed>         # 20 cells, shuffled, reproducible
./bin/score-batch.sh ~/.elcapitan-ground-truth/eiger/ground-truth.json
```

`preflight.sh` currently reports **9 passed, 3 failed** — the three are the
ephemeral scanner and observer credentials plus the model key, all expected to
be absent between runs. It also prints the TRAP-1 warning above.

**Both principals must exist at once** for a real batch — scanner for the
engineer, observer for the collector — with ~26s of role propagation before
either works, and the `log-analytics` extension pre-installed (the collector
refuses az's dynamic install so a batch cannot change its own tooling partway
through).

### What Stages 3–5 established about how this code fails

Five defects this session, and **every one of them was a seam between two
well-tested halves**:

| Defect | Why no test caught it |
|---|---|
| `agent-run.sh` imported a renamed constant | it runs only in non-stub mode |
| `run_agent` crashed on a challenger spec | `_run_dir` wanted a mount the challenger deliberately lacks |
| the collector never ran `az login` | the fake `az` does not care about logins |
| isolating `AZURE_CONFIG_DIR` hid the `log-analytics` extension | two correct guards, composed |
| **the collector and challenger were never invoked at all** | `run-trial.sh` went engineer → validate, and 486 tests passed |

The last one is the lesson: a component with excellent tests and no caller is
indistinguishable, from the suite, from a component that works. Test the seam.

**The most dangerous failure mode remains** telemetry ingestion lag. It is
handled in three places now — the window is widened at both ends, the
collector waits before asking, and a window that comes back all-zero is
recorded `unpopulated` rather than shipped as evidence — and a trial carrying
unpopulated Arm B telemetry is `scoring_valid: false`, excluded from the matrix
rather than counted as a miss.

**The honest uncertainty**, updated: the pilot shows an MoA-less challenger
does reason about telemetry when telemetry is the only route to the answer
(Arm B cited the dependency edge unprompted). What is still unknown is whether
that changes any *verdict* — which is exactly what TRAP-2 exists to find out.
