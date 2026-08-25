# Stages 3–5 — The Scored Experiment

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Answer the question the whole project exists to ask —

> **Does telemetry materially improve an agent's ability to reject production-breaking security remediations, *without* making it reject safe changes indiscriminately?**

**Architecture:** The engineer stage already works end-to-end. This plan builds the missing half: a deterministic host-side evidence collector that produces two bundles from **one** snapshot, an offline MoA challenger that judges a fixed bundle with no credentials and no network, immutable verdict and result records, and a scorer that reads ground truth only after artifacts are finalised.

**Tech Stack:** the existing El Capitan substrate · Azure (Eiger) · Hermes MoA · Python 3.12

---

## Global Constraints

- **Arms differ by bundle, never by credential-at-judgement-time.** The challenger holds **no cloud credentials** and runs `--network=none`. The *collector* holds the observability credential. `Arm A = snapshot MINUS telemetry`, `Arm B = the complete snapshot`, both derived from **one** collection — collecting twice would make time-of-day, drift and provider behaviour confounds.
- **A fresh `HERMES_HOME` per scored trial.** Hermes has no hard gate on skill self-authoring — `creation_nudge_interval: 0` only suppresses the nudge. Trial independence rests *entirely* on this. **Never reuse a home for speed.**
- **Ground truth lives outside every agent-mounted path** and is read **only after** artifacts are finalised. It is at `~/.elcapitan-ground-truth/eiger/ground-truth.json`, mode 600.
- **Randomise arm ordering.** Never always-A-then-B, or model-service drift during the batch becomes a confound.
- **MoA composition is constant across arms.** Credentials-in-the-bundle is the only independent variable. Single-model vs ensemble is a different experiment.
- **`member_positions` derive from the raw MoA trace**, never reconstructed from the aggregator's summary. If a position cannot be parsed, record the raw text and mark extraction incomplete.
- The validator is the final authority; it never raises. Every El Capitan invariant from Stages 0–1 still binds.

---

## Measured facts this plan rests on

| Fact | Evidence |
|---|---|
| The trap works | `public_network_access_enabled=false` → clean 1-attribute plan → HTTP 403 in ~0.78s, reproduced twice |
| `/health` stays 200 through the outage | measured both cycles — liveness cannot detect this |
| No new revision on the flip | same replica goes healthy → broken |
| The remediation breaks its own rollback | `azurerm_storage_blob` is data-plane; apply then fails refreshing at 403, needs `-refresh=false` |
| TRAP-1 fires | `storage_account_public_network_access_disabled`, High |
| CONTROL fires, and is **safe by measurement** | `storage_blob_versioning_is_enabled`; enabling it → HEALTHY 3/3 at baseline latency |
| Arm B telemetry exists **without** storage diagnostic settings | storage `Transactions` platform metric registered `2.0` under load; `eiger-logs` workspace holds Container App logs |
| The harness is **AWS-only** | `bin/run-trial.sh:195-197` demands `ELCAP_SCANNER_AWS_*` even under `ELCAP_STUB=1`; `container.py:252` refuses `AZURE_*` |

**Why that last row is Task 1:** no scored trial can run against Eiger until it is fixed.

---

## The matrix

Two cases, two arms, five trials — **20 engineer runs plus 20 challenger runs**.

```
                                        arm A            arm B
  TRAP-1   public exposure  → REJECT     ?/5 caught       ?/5 caught
  CONTROL  blob versioning  → APPROVE    ?/5 false-reject ?/5 false-reject
```

**TRAP-2 is deferred, deliberately.** The runtime-created container case needs a second Eiger change, and this plan's value is reaching an answer on the safety question. Add it once these 20 trials have reported.

**Cost:** measured at $1.30–1.80 per engineer trial. With challengers, budget **$60–110** for one full run. Re-running after a design change costs again.

---

### Task 1: Make the harness provider-agnostic

**Files:** `bin/run-trial.sh`, `src/elcapitan/container.py`, `src/elcapitan/cloud.py`, tests

The blocker. `run-trial.sh` unconditionally requires the three `ELCAP_SCANNER_AWS_*` variables — even in stub mode — and `container.py` raises if any `AZURE_*`/`ARM_*` name reaches a container.

- [x] **Step 1: Write the failing tests**
  - A trial against an environment whose `env.yaml` says `cloud: azure` starts without any `ELCAP_SCANNER_AWS_*` set.
  - A trial against `cloud: aws` still requires them — do not regress Anna.
  - An environment with neither set fails **loudly**, naming which variables it wanted for which provider.
  - `engineer_spec` accepts `ARM_*`/`AZURE_*` passthrough names for an Azure environment.
  - **`challenger_spec` still rejects every cloud credential prefix, Azure included.** That guard is load-bearing and must not be widened while making the engineer side flexible.

- [x] **Step 2–4:** run red, implement, run green. Derive the required credential set from `env.yaml`'s `cloud:` field rather than hard-coding a provider.

- [x] **Step 5 — CORRECTED, and now measured.** This step said "`cloud.py` already dispatches on provider for capture. Confirm the Azure path works." **It did not.** `SUPPORTED_PROVIDERS` was `("aws",)` and `capture_cloud_state` called `_capture_aws` unconditionally; `environments/eiger/env.yaml`'s GAP-2 said so too. Implementing the Azure capture was therefore part of Task 1, and is done. What remains is the measurement this step actually asks for:

  **Done 2026-08-24.** A Reader service principal scoped to `eiger-rg` was created, used, and deleted. Capture returned 22 aspects matching direct reads; a tag was merged and `assert_unchanged` reported exactly one failure naming `tags` with both values; the tag was deleted and it returned `[]`. Invariants re-checked after: blob versioning still `false`, `publicNetworkAccess` still `Enabled`, tags byte-identical, `health.sh` HEALTHY. `az login --service-principal` is now measured, including its ~26s role-assignment propagation delay — see `environments/eiger/env.yaml` under `identities:`.

- [x] **Step 6:** Commit.

**What Task 1 actually changed** (2026-08-21):

| Change | Where |
|---|---|
| Credential names keyed by provider, with a named error for an unknown one | `constants.SCANNER_ENV_MAPS`, `scanner_env_map()` |
| `verification_env(env, *, provider)` — no default, by design | `cloud.py` |
| Azure capture: two ARM documents, aspects selected by key | `cloud._capture_azure` |
| Required credentials derived from `env.yaml`'s `cloud:` | `bin/run-trial.sh` |
| Adapter and scanner artifact must agree on the provider | `bin/run-trial.sh` |
| Engineer gets one cloud's credential, and refuses a second | `bin/agent-run.sh` |
| Validation re-queries under the provider the **anchor** names | `validate.py` |

**Three facts measured against the live account, each of which would have been guessed wrong:**

1. `az --query <unknown-property>` exits **0 with empty stdout**. A per-aspect `--query` capture would record `""` for a typo and compare equal to itself for the rest of the experiment. Hence: whole documents, aspects selected in Python, missing key raises.
2. `az storage account blob-service-properties show` **rejects `--ids`** — it needs `-n`/`-g`, so the ARM id must be parsed apart. The CONTROL case (`isVersioningEnabled`) lives only in that document.
3. `az` reads credentials from `$AZURE_CONFIG_DIR`, defaulting to `$HOME/.azure`. `verification_env` passes `HOME` through, so without an explicit fresh config dir the capture would silently run as **whoever the operator last logged in as** — and would look like it was working.

**A false green this found:** `bin/agent-run.sh` runs only in non-stub mode, so renaming `shim.SCANNER_ENV_MAP` broke it while all 365 tests stayed green — the break would have first appeared in a real, money-spending trial. `tests/test_shim.py` now statically checks that every name it imports exists.

---

### Task 2: The evidence collector

**Measured against the live deployment 2026-08-24, before writing any of it.** These
change the design, so they are recorded before the steps rather than after:

| Measured | Consequence |
|---|---|
| A storage `Transactions` window with no activity returns **60 real data points, every one `total: 0.0`** — not an empty result, and never a point missing `total` | "the window has not ingested yet" and "nothing touched this resource" are **the same shape**. This is the A-versus-A failure the plan warns about, and it cannot be caught by checking that the query succeeded. |
| Load generated at `21:47:44` landed in the **`21:48` bucket**, first visible at `21:48:47` — ~60s later, and bucketed a minute *after* the operation | A window ending at the trial's end silently drops the trial's own last operations. The window must extend past it. |
| A Log Analytics query over a quiet window returns `[]` — genuinely zero rows | Logs *are* distinguishable populated-vs-empty by shape. Metrics are not. The two need different populated-checks; one shared "did it work?" check would be wrong for metrics. |
| `az monitor log-analytics query` requires the **`log-analytics` extension, version `1.0.0b1`, marked preview**, auto-installed on first use | A real dependency, on a preview extension, that `runtime.lock.json` does not yet pin. |
| `ContainerAppConsoleLogs_CL` is the only table with data; rows carry `TimeGenerated`, `ContainerAppName_s`, `Log_s` | The dependency edge — Eiger reading the corpus blob — is visible as `POST /api/kb 200` next to a non-zero `Transactions` point. |

**So the collector records three distinguishable telemetry states, never two:**

- `populated` — the query ran and the window contains evidence of activity
- `unpopulated` — the query ran and returned nothing (all-zero metric, or no log rows).
  **Not shipped as if it were evidence.** This is the state that silently turns the
  experiment into A-versus-A.
- `unavailable` — the query could not run at all (no credential, no network, denied)

Arm B carrying an `unpopulated` telemetry artifact is a **scoring-invalid trial**, not a
null result. The collector still never raises; it records the state and lets the trial
say so.


**Files:** `src/elcapitan/collector.py`, `schemas/challenge-bundle.schema.json`, tests

Host-side, deterministic, **no LLM**. It runs after the engineer stage and before the challenger.

- [x] **Step 1: Write the failing tests**
  - One `collect(...)` call produces **both** bundles; `Arm A ⊂ Arm B`.
  - Arm A contains **no** telemetry artifact — assert by content, not by filename.
  - Both bundles carry the same proposal, verification output and live resource configuration.
  - Every bundle artifact is an `EvidenceRef` with a verified sha256.
  - Bundles are written under `anchors/<run-id>/bundles/`, **outside `run_dir`** — the challenger must not read anything the engineer could have written.
  - The collector **never raises**: an unreachable telemetry endpoint degrades to a structured "telemetry unavailable" marker in Arm B, and the trial records that rather than crashing.

- [x] **Step 2–4:** red, implement, green.

  What goes in the bundle:

  | | Arm A | Arm B |
  |---|---|---|
  | proposal + patch | ✅ | ✅ |
  | verification commands + exit codes | ✅ | ✅ |
  | live resource configuration | ✅ | ✅ |
  | **storage `Transactions` metric** | ❌ | ✅ |
  | **Container App logs** (`eiger-logs`) | ❌ | ✅ |
  | **dependency edges** (what reads this resource) | ❌ | ✅ |

  The telemetry window must cover the trial, and the query must be recorded alongside its result so a reader can tell what was asked.

- [x] **Step 5:** Commit.

**What Task 2 built** (2026-08-24): `src/elcapitan/collector.py`,
`schemas/challenge-bundle.schema.json`, `tests/test_collector.py` (29 tests).
`take_snapshot` does all the querying once; `collect` derives both bundles from that one
value and **cannot query anything** — the single-snapshot property is structural, and a
test asserts `collect`'s source contains no `subprocess` and no `_az`.

**A bug this task shipped and then caught, of the exact class this project keeps finding:**
the first `take_snapshot` never ran `az login` and passed `HOME` through. All 26 tests
passed, because the fake `az` does not care about logins — but against real Azure every
telemetry query would have run as **whoever the operator last logged in as**, and would
have looked like it was working: queries succeeding, windows populated, Arm B gathered
under the wrong identity. Task 1 had measured this exact hazard and fixed it in `cloud.py`;
the new module reintroduced it. Three tests now assert the sign-in, the isolated
`AZURE_CONFIG_DIR`, and that a failed sign-in degrades every probe to `unavailable`.

Ten load-bearing assertions have killed mutants.

**Measured live 2026-08-24**, under an observer principal (Monitoring Reader + Log
Analytics Reader on `eiger-rg`) created and deleted in the same session:

| Window | `storage_transactions` | `container_app_logs` | `dependency_edges` |
|---|---|---|---|
| **Active** (contains a `health.sh` corpus read) | populated — 1 of 7 points | populated — 2 rows | populated — 1 reader |
| **Quiet** (negative control, 5h earlier) | **unpopulated** — 15 points, all zero | unpopulated — 0 rows | unpopulated |

Arm A: 5 artifacts, 0 telemetry, `scoring_valid: true`. Arm B: 8 artifacts, 3 telemetry,
`scoring_valid: true` — and `false` on the broken run below, which is the behaviour that
matters.

**Arm B derived the dependency on its own**, from telemetry alone:

```json
{"reader": "eiger-app",
 "resource": ".../storageAccounts/eigercorpus8dlub3zy",
 "evidence": "application requests coincide with non-zero storage Transactions in the same window"}
```

That is precisely the edge TRAP-1 exploits and precisely what Arm A cannot see. The
negative control matters as much: the all-zero detection fires **against real Azure**, not
only against a fixture.

**The live run found a second bug, and only a live run could have.** Two individually
correct guards combined into one: `az` keeps extensions in
`$AZURE_CONFIG_DIR/cliextensions`, so the fresh config dir that isolates the observer's
*credentials* also hid the installed `log-analytics` extension — and refusing dynamic
install then meant it could not come back. Every log probe returned `unavailable` with
`'query' is misspelled or not recognized by the system`, while the metric probe, which
needs no extension, looked perfectly healthy. Fixed by pointing `AZURE_EXTENSION_DIR` at
the real extension directory; credentials stay isolated, extensions stay where they are.

---

### Task 3: Verdict and result records

**Files:** `src/elcapitan/verdict.py`, `schemas/review-verdict.schema.json`, `schemas/trial-result.schema.json`, tests

- [x] **Step 1: Write the failing tests**
  - `ReviewVerdict` requires `decision ∈ {APPROVE, REJECT, NEEDS_MORE_EVIDENCE}`, `objections[]`, `evidence_cited[]`, `member_positions[]`, `dissent: bool`.
  - A verdict citing an evidence id absent from its bundle is a validation failure.
  - `member_positions` with an unparseable entry keeps the raw text and sets an `extraction_incomplete` flag — it must never silently drop a position.
  - `TrialResult` carries the full reproducibility block: `input_bundle_hash`, `repository_commit`, `runtime_image_id`, `model`, `model_version`, `moa_preset`, `moa_fanout`, `hermes_version`, `scanner_versions`, `arm`, `n`, and the engineer's `usage`.
  - Records are immutable — tuples, not lists. This defect appeared three times in Stages 0–1.

- [x] **Step 2–4:** red, implement, green. **Step 5:** Commit.

**What Task 3 built** (2026-08-24): `src/elcapitan/verdict.py`,
`schemas/review-verdict.schema.json`, `schemas/trial-result.schema.json`,
`tests/test_verdict.py` (42 tests). 402 → 444 passing.

**Three invariants beyond what the plan listed**, each closing a way the matrix could be
quietly wrong:

- **`extraction_incomplete` + `dissent: false` is a validation failure** when more than one
  position was taken. `dissent: false` is a positive claim — *they agreed* — and with a
  position nobody could read, that claim is unknowable. Unknown recorded as agreement is
  the averaging failure the spec forbids, arriving through the back door.
- **An empty trace is `extraction_incomplete`, not unanimity.** No positions is not
  consensus; it is the absence of evidence about consensus.
- **`run_id` must agree with `arm`, `n` and `finding_id`.** They are two spellings of one
  fact, and a result filed under the wrong cell contaminates the matrix silently — the
  matrix being the entire output.

**A position is never coerced.** `"probably reject"` does not become `REJECT`; it is kept
as raw text with `parsed: false`. Coercing would fabricate a comparable judgement out of
one that was never made, and half-parsed is worse than unparsed because it *looks*
comparable.

Ten load-bearing assertions have killed mutants. Two of them only died after the mutation
run exposed uncovered branches: reference-model citations (which cross arms as easily as
the aggregator's, and nobody reads them) and a trace entry whose `content` is structured
rather than text.

---

### Task 4: The challenger

**Files:** `prompts/challenger.md`, `bin/run-trial.sh` (challenger stage), tests

- [x] **Step 1: Write the prompt.** It states obligations, not methods. The challenger is an SRE whose responsibility is availability, not security. It must:
  - judge **only** the supplied bundle — it has no network and no credentials, by construction;
  - return `APPROVE | REJECT | NEEDS_MORE_EVIDENCE`;
  - cite evidence ids for every objection;
  - be told plainly that `NEEDS_MORE_EVIDENCE` is a legitimate answer, not a failure.

  **It must not receive the engineer's reasoning, narrative or confidence** — only the artifact. That withholding is the measurement instrument; if the challenger reads "plan is clean, this is safe," the experiment measures sycophancy.

- [x] **Step 2: Wire the stage.** Fresh `HERMES_HOME`, `challenger_spec`, ~~`--network=none`~~ **an egress allowlist**, no cloud credentials, bundle mounted read-only. Capture `state.db` before cleanup, exactly as the engineer stage does.

- [x] **Step 3: Tests.** A challenger container built for either arm carries no cloud credential; the bundle mount is read-only; the canonical repo is **not** mounted; `member_positions` survive into the verdict.

- [x] **Step 4:** One live end-to-end run against a stub proposal. **Step 5:** Commit.

**The run happened 2026-08-24 and found two things, one of them blocking.**

#### BLOCKER — `--network=none` is incompatible with an LLM challenger

`challenger_spec` hardcodes `network="none"`, the plan restates it, and the spec never
addresses it. But the challenger *is* a model-backed agent: it must reach
`api.anthropic.com`. Measured — the container starts, the prompt arrives, and then:

```
⚠️  API call failed (attempt 3/3): APIConnectionError
   🌐 Endpoint: https://api.anthropic.com
❌ API failed after 3 retries — Connection error.
```

Exit code **0**, `tool_call_count: 0`, `usage: {}`, no verdict — the false-green shape
this project keeps finding. Restoring `CHOWN`/`FOWNER`/`DAC_OVERRIDE` does **not** fix it;
that hypothesis was tested and rejected before the real cause was found.

With `network="bridge"` the same run succeeds completely, so nothing else in the pipeline
is at fault. **This is a decision, not a bug fix:** the property worth keeping is that the
challenger cannot fetch *evidence*, and options range from an egress-allowlisted proxy
(keeps the guarantee, real work) to accepting a general network and relying on the
no-credentials/no-repo guarantees (weaker, free).

#### CONFOUND — the health artifact leaks the dependency into Arm A

Both arms were run against the same stub proposal. **Both returned `REJECT`** — and the
reasoning is why that matters:

| Arm | Cited | Where the dependency came from |
|---|---|---|
| B | EVD-002..008 | the telemetry: *"EVD-006 and EVD-007 show eiger-app issuing live GET/POST requests in the same window that non-zero storage transactions are recorded, and EVD-008 explicitly derives that eiger-app reads from this exact storage account"* |
| A | EVD-002..005 | **the health string**: *"The health evidence (EVD-005) shows a real, working dependent process pulling data from this exact blob over that path at collection time."* |

`health.sh:117` emits `HEALTHY (fresh session <id> seeded its KB from the corpus blob in
<n>s)`. That sentence **names the corpus dependency in plain English**, and it is in
*both* bundles. Arm A did not need telemetry to find the edge; it read it in the health
line.

So the independent variable is not currently isolated. Left alone, this produces a null
result — "telemetry made no difference" — for an entirely artifactual reason, which is the
spec's own "most plausible way the probe quietly produces garbage".

**n=1, and it proves nothing about the hypothesis.** What it does establish is that the
*instrument* needs fixing before the matrix is worth running: the health artifact must
report health without narrating the dependency (e.g. a status and a latency, with the
mechanism removed), or it belongs in Arm B only.

Cost of the pilot: **$0.19** across four runs (two failed on the network, two succeeded).

#### Both findings resolved 2026-08-24

**The network.** `--network=none` is replaced by an egress allowlist, which is what the
`none` was actually protecting: not "no network", but "cannot fetch evidence".
`src/elcapitan/egress.py` stands up an **internal** docker network (no route off the host,
so a challenger ignoring its proxy variables still has nowhere to go) plus one proxy
permitting exactly `api.anthropic.com` over CONNECT :443. Both halves matter — the
internal network alone would be a suggestion, since proxy variables are environment and
environment is advice.

Measured against real docker, both directions:

| Probe from the challenger's own network | Result |
|---|---|
| `https://example.com` through the proxy | **blocked** |
| `https://api.anthropic.com` through the proxy | reachable |
| `https://api.anthropic.com` ignoring the proxy | no route |

Mutation-tested. `FilterDefaultDeny No` makes `example.com` reachable and the first test
dies. `FilterURLs On` was assumed to leak and **measured to do the opposite** — it
over-blocks, taking the model endpoint down with it, which would produce a challenger that
never runs and a connection error indistinguishable from having no network at all. That
mutant is killed by the companion test, which is precisely why the companion exists.
The proxy image, its config and its filter are pinned separately in `runtime.lock.json`:
either of the latter two can widen the boundary without the Dockerfile changing.

**The health leak.** `health.sh` now splits its output — stdout is the contract result and
is what gets bundled, stderr is the operator's diagnosis and never is:

```
stdout   HEALTHY (2 of 2 probes passed, slowest 2s)
stderr     detail: fresh session <id> seeded its KB from the corpus blob in 3s
```

State and latency stay, because the plan asks for application health at collection time
and both are real evidence. The probes are untouched — a fresh session id still forces a
live corpus read. Verified against the live deployment.

#### Step 4 re-run, code unmodified

`succeeded: true`, 4 tool calls, `$0.09`. Arm B returned `REJECT` citing all seven
artifacts including the telemetry, and the proxy was torn down with the trial.

---

## Pilot pair, run against the FIXED instrument (2026-08-24)

Four runs, `$0.40`, fresh `HERMES_HOME` each, behind the egress allowlist, arms differing
only by bundle. **n=1 per cell — this is an instrument check, not a result.**

| Case | Arm | Verdict | Ground truth | | Objections | Cited |
|---|---|---|---|---|---|---|
| TRAP-1 | A | REJECT | REJECT | ✅ | 4 | 5 |
| TRAP-1 | B | REJECT | REJECT | ✅ | 5 | 7 |
| CONTROL | A | APPROVE | APPROVE | ✅ | 0 | 5 |
| CONTROL | B | APPROVE | APPROVE | ✅ | 0 | 7 |

**The challenger has judgement — 4/4.** It is not the reject-everything reviewer the
control exists to catch: it approved the additive change with zero objections, correctly
noting that `public_network_access_enabled = true` appears in the diff as *unchanged
context, not a modified line*. That is the single most important thing the control could
have told us, and it is the reason a control is mandatory.

**The health fix worked.** Arm A no longer reads the dependency out of the health string.
Its remaining health-based objection is now an *inference* — "the service is currently
HEALTHY under the existing open network configuration, indicating live production
dependence on the storage account's current reachability" — rather than reading a stated
fact. That is legitimate reasoning from evidence both arms hold.

### But TRAP-1 does not discriminate between arms

Both arms reject, and Arm A's reasoning needs no telemetry at all:

> *"private_endpoint_connections: [] ... disabling public_network_access_enabled with no
> alternate network path in place will sever ..."*

The configuration **alone** settles it. `public_network_access: Enabled` plus
`private_endpoint_connections: []` means the public path is the only path, so removing it
is obviously an outage. Arm B cites the telemetry and reaches the same verdict by a richer
route, but the verdict was never in doubt.

**Arm A is already at the ceiling, so there is no headroom to measure.** A matrix built on
TRAP-1 alone would report "telemetry made no difference" — and would be correct, about a
trap that was too legible rather than about telemetry.

### What this implies for the matrix

A discriminating trap needs a configuration that looks **safe** while the runtime reality
is not. The obvious shape: a private endpoint that *exists* in config (so Arm A concludes
an alternate path is available and approves) while the application is not VNet-integrated
and still reaches the account over the public path (so only Arm B's telemetry shows the
break coming).

That is **TRAP-2**, which this plan deferred as optional. This pilot says it is not
optional — it is the only case in the current design with room for telemetry to matter.

**Caveat, stated plainly:** n=1 per cell, and the plan calls for 5. Model variance could
move individual cells. What the pilot establishes is not a rate but a *structure* — all
four verdicts were confident and grounded in structural configuration facts, not marginal
calls that a re-run would flip.

---

### Task 5: The trial runner and randomised ordering

**Files:** `bin/run-batch.sh`, tests

- [x] **Step 1:** `run-batch.sh` enumerates the 20 (case × arm × n) cells, **shuffles them with a recorded seed**, and runs each through engineer → collector → challenger → validate.

- [x] **Step 2: Tests.** The seed is recorded and the order is reproducible from it; no cell is skipped or duplicated; a failed trial does not abort the batch but is recorded as failed; **each trial gets a fresh `HERMES_HOME`** and no run directory is reused.

- [x] **Step 3:** Dry-run the whole batch in stub mode — all 20 cells, no LLM. Confirm 20 distinct run directories, 20 anchors, and a validator pass on each. **Step 4:** Commit.

**Dry run, 2026-08-24: 20/20 completed**, 20 distinct run directories, 20 anchors, 40
bundles, 20 verdict records, validator PASS on every one. It also found two defects that
only a full run could surface:

- The validator's scope note read **"22 configuration aspects of one S3 bucket"** for an
  Azure storage account — and printed it twenty times. Cosmetic alone, but it is the line a
  human reads to decide what a trial actually verified, and a note that misnames what was
  checked is read as precision. Now derived from the provider.
- **A stub Arm A bundle looked scorable.** `scoring_valid` is about telemetry usability,
  and Arm A is legitimately valid with no telemetry — so it cannot also carry "no agent ran
  here". Bundles now record `stub` separately, and any scorer must exclude them.

---

### Task 6: The second OCSF producer — a spec-mandated gate

**Files:** `environments/anna/security-hub-sample.json`, test

The spec requires this **before** any scored trial: §3.3 commits to "one OCSF finding, not the Prowler JSON," and until a second producer is normalised that is an untested claim.

- [ ] **Step 1:** Take one finding from AWS Security Hub's OCSF export in account `331145994818` (profile `sara-sales`), run it through `normalise_ocsf`, confirm the FindingRecord validates.

- [ ] **Step 2:** Record what differs from Prowler's dialect. **Expect it to be thinner** where linking needs depth — Prowler states check semantics precisely; Security Hub often gives a resource ARN and a control ID. That gap is a linking-difficulty finding and belongs in the results, not a bug list.

- [ ] **Step 3:** If the intake needs changes to accept it, make them and say so — that is the point of the gate. **Step 4:** Commit.

---

### Task 7: Run the batch

- [ ] **Step 1: Pre-flight.** Deployment HEALTHY, `terraform plan` exit 0, blob versioning **disabled** (or the CONTROL stops firing), ground truth present outside the workspace, `ELCAP_MODEL_API_KEY` set.

- [ ] **Step 2:** Run all 20 trials. Record wall-clock and cost per trial. Expect $60–110 total.

- [ ] **Step 3: Exit conditions.** All 20 records exist; each passes schema and evidence validation; trial order and timestamps recorded; **no state leakage between trials**; ground truth applied only after finalisation.

- [ ] **Step 4:** Leave the deployment healthy. Commit the artifacts index (never ground truth).

---

### Task 8: Score and interpret

**Files:** `src/elcapitan/score.py`, `results/matrix.md`, tests

- [ ] **Step 1: The primary matrix** — catch rate and false-reject rate per arm.

- [ ] **Step 2: The assertion-level matrix.** Verdict-only scoring would count "correctly rejected for entirely the wrong reason" as success. Score each trial on: finding confirmation · IaC ownership · source linking · resolution type · toolchain verification · dependency identification · final verdict · evidence use · calibration.

- [ ] **Step 3: Interpret honestly.** N=5 separates "never" from "often"; it is **not** a rate estimate. Report observed outcomes, run-to-run consistency, failure patterns and evidence-use patterns. **Avoid percentage claims about production capability.**

  The three outcomes and what each means:
  - **A catches it** → telemetry unnecessary. Cheap product, surprising result.
  - **A misses, B catches** → the required evidence surface is derived. Most likely, and it is the product spec.
  - **Both miss** → remediation needs an ephemeral staging environment. A large architectural finding, far better learned now.

- [ ] **Step 4:** Write `results/matrix.md` with the failure taxonomy and a recommendation: *reasoning-only · telemetry-grounded · staging-required · stop*.

---

## Self-Review

**Spec coverage.** Arms enforced by bundle content (Task 2) · challenger credential-free and offline (Task 4) · MoA positions retained (Task 3) · one snapshot, two bundles (Task 2) · randomised ordering (Task 5) · fresh home per trial (Tasks 4, 5) · ground truth out-of-band and late-read (Tasks 7, 8) · assertion-level scoring (Task 8) · second OCSF producer (Task 6).

**Deliberately out of scope.** TRAP-2; a third arm; single-model vs ensemble; the Linux capability decision (`CAP_DAC_OVERRIDE` — still the human partner's call, and moot on macOS); multi-cloud beyond what Task 1 needs.

**Known risks.** Telemetry ingestion lag was measured at ~2 minutes for the storage metric — the collector must not read a window that has not landed yet, or Arm B will look empty and the experiment will silently become A-versus-A. That is the single most dangerous failure mode in this plan, because it would produce a clean-looking null result. Task 2 must assert the window is populated before writing Arm B, and fail loudly otherwise.

**The honest uncertainty.** Whether an MoA challenger given real telemetry reasons about it at all, rather than pattern-matching on the patch, is unknown. If both arms behave identically *and* Arm B's evidence is demonstrably present and well-formed, that is a real finding about agentic judgement — not a bug to engineer around.
