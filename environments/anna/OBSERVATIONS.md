# Anna — Stage 1 shakedown observations

**Status of these results: EXPLORATORY. Human-adjudicated. Excluded from every
scored matrix.** Anna changes cloud, IaC language and environment-reality
simultaneously and has no constructed ground truth. One trial, n=1, arm A.
Nothing below is evidence of generalisation, and no number here should be
carried into a results table.

| | |
|---|---|
| Run id | `anna-FIND-001-armA-n1` |
| Date | 2026-08-10 (UTC) |
| Account / region | 331145994818 / ap-south-1 |
| Repository pin | `59ff298327ded23eadc9472bc583590cf2a86e6b` (branch `feat/dos-wallet-defenses`) |
| Model | `anthropic/claude-sonnet-5` |
| Session | `20260810_040126_9b46b9`, 72 tool calls, 65 API calls, `finish_reason=stop` |
| Wall clock | 569 s |
| Cost | `estimated_cost_usd = 1.2640772` (see §7 — the plan's estimate was 25–125x low) |

---

## 1. What was built

- `environments/anna/env.yaml` — the adapter. Not parsed by the harness;
  `bin/run-trial.sh` hashes it into `input-manifest.json`
  (`environment_adapter_sha256`), which binds the trial to it.
- `environments/anna/trust-policy.json` — trust policy for the scanner role
  (principal: `arn:aws:iam::331145994818:user/sara-sales`).
- `environments/anna/scanner-policy.json` — the inline policy actually
  attached to `elcapitan-anna-scanner`. **Kept byte-identical to what was
  applied**, defects and all, so that `aws iam get-role-policy` and this file
  agree. See §6 for the two gaps it has and the exact fix.

Role: `arn:aws:iam::331145994818:role/elcapitan-anna-scanner`.
Credentials: `sts assume-role`, 3600 s, passed to the container by name via
`ELCAP_SCANNER_AWS_*` → `AWS_*` (`shim.SCANNER_ENV_MAP`). No long-lived
access key was created at any point.

## 2. Why this finding, and not another

`FIND-001` = `s3_bucket_object_versioning` on
`arn:aws:s3:::nisalesagentstack-decksbaf8b4c9-mrusb2mpyvne`, Medium.

The choice is the whole experiment. Three resources in this stack —
`ni-sales-deals`, `ni-sales-agent`, `ni-sales-render` — have their physical
names **hard-coded** in `aws/infra/cdk/ni-sales-agent-stack.ts` (lines 19, 49,
67). A finding on any of them links by grepping the literal string, which
measures nothing. The decks bucket's physical name appears **zero times** in
either `.ts` file:

```
$ grep -c "nisalesagentstack-decksbaf8b4c9-mrusb2mpyvne" *.ts
ni-sales-agent-stack.ts:0
app.ts:0
```

Also considered and rejected: `transilience-demo-public-331145994818`, a
bucket in the same account with no source anywhere in Anna's repository. It
can never link, so a shakedown against it would prove nothing.

**The finding is real, and that was verified independently of the scanner.**
Prowler ran under the scoped role; `get-bucket-versioning` was re-run under
the broader `sara-sales` identity and returned empty output — versioning was
never enabled — so the FAIL is not an artifact of the scanner's permissions.
That check mattered: §6 shows one *other* finding in the same scan that **is**
such an artifact.

## 3. The `Deny` is enforcement, not intent — measured

Under the assumed-role credentials:

```
$ aws logs filter-log-events --log-group-name /aws/lambda/ni-sales-agent --limit 1
An error occurred (AccessDeniedException) when calling the FilterLogEvents operation:
User: arn:aws:sts::331145994818:assumed-role/elcapitan-anna-scanner/elcapitan-shakedown
is not authorized to perform: logs:FilterLogEvents on resource:
arn:aws:logs:ap-south-1:331145994818:log-group:/aws/lambda/ni-sales-agent:log-stream:
with an explicit deny in an identity-based policy
```

`secretsmanager:GetSecretValue` returns the same `with an explicit deny`
wording. Both are the `Sid=NoDataPlaneOrLogs` statement firing.

Two honest qualifications:

- `logs:DescribeLogGroups` is refused too, but with *"because no
  identity-based policy allows"* — an **implicit** deny. Only the eight
  actions named in the Deny are explicitly denied; everything else in `logs:`
  is merely unlisted. That is sufficient here (no allow exists to override)
  but it is a weaker property than the Deny, and a future policy that
  broadened the Allow could open it.
- The `s3:GetObject` probe could **not** be made to demonstrate the explicit
  deny: with `s3:ListBucket` unlisted, S3 answers a GetObject on an unknown
  key with the ListBucket implicit-deny message instead, and no object key was
  knowable without the list permission. The explicit deny on `s3:GetObject` is
  therefore *asserted from the policy document, not observed*. The two probes
  that did land (`logs:FilterLogEvents`, `secretsmanager:GetSecretValue`)
  exercise the same statement.

## 4. The prediction — REFUTED, with a confound that blunts the test

The spec predicted: *the agent greps the resource name in `*.ts` rather than
resolving ARN → physical name → CFN logical ID → construct path → source.*

`linking.method`, **verbatim**:

> Located aws/cdk.json (app: npx tsx infra/cdk/app.ts), aws/infra/cdk/ni-sales-agent-stack.ts defining s3.Bucket(this,'Decks',...), and a committed aws/cdk.out/NiSalesAgentStack.template.json + manifest.json. The CloudFormation logical id in the committed template (DecksBAF8B4C9) and its aws:cdk:path metadata (NiSalesAgentStack/Decks/Resource) match the aws:cloudformation:logical-id and aws:cloudformation:stack-name tags recorded on the actual scanned bucket in the Prowler raw event (EVD-001), and the bucket's physical name in both the finding and the raw event (nisalesagentstack-decksbaf8b4c9-mrusb2mpyvne) follows CDK's own logical-id-derived S3 bucket naming pattern. Confirmed the pre-fix committed template has no VersioningConfiguration on this resource (EVD-002), matching the raw event's explicit "versioning": false field.

`linking.files`: `aws/infra/cdk/ni-sales-agent-stack.ts`,
`aws/cdk.out/NiSalesAgentStack.template.json`, `aws/cdk.json`.
`linking.iac_managed`: `true`. `linking.confidence`: `0.9`.

**Which branch occurred: the agent resolved the chain. The prediction did not
hold.** It did open with a grep of the resource name — command 4 of 72 was
`grep -ril "nisalesagent" /work/canonical` — but it did not treat the `.ts`
miss as terminal. The first twelve commands, in order:

```
01. cat /work/run/inputs/finding.json
02. cat /work/run/inputs/input-manifest.json
03. find /work/canonical -maxdepth 2 | head -100
04. grep -ril "nisalesagent" /work/canonical 2>/dev/null | head -50
05. grep -n -i "decks|versioning|Bucket" /work/canonical/aws/infra/cdk/ni-sales-agent-stack.ts
06. grep -n -i "decks" /work/canonical/aws/cdk.out/NiSalesAgentStack.template.json
07. sed -n '1,140p' /work/canonical/aws/infra/cdk/ni-sales-agent-stack.ts
08. sed -n '80,135p' /work/canonical/aws/cdk.out/NiSalesAgentStack.template.json
```

Command 06 is the step the prediction said would not happen: it takes `decks`
— a substring only meaningful if you have realised the physical name embeds
the lowercased logical ID — and searches the synthesized template for it. The
agent then went further than the plan's route required and re-synthesized the
stack itself (`cdk synth --no-lookups` against a throwaway copy under
`/work/run/scratch`, since removed) to prove the fix changes the template.

**The confound, and it is a real one.** Prowler's raw OCSF event carries the
answer as a resource tag:

```
"labels": [ ..., "aws:cloudformation:logical-id:DecksBAF8B4C9" ]
```

`normalise_ocsf` drops that from `finding.json` — it keeps only
`resource.{uid,type}` — but it writes the **entire** raw event to
`evidence/EVD-001.bin`, which the prompt tells the agent about and which the
agent read (command 11 hashes it). So the hardest step in the predicted chain,
*deriving* the logical ID from the physical name, was available for free. The
agent's own `method` cites the tag match as its primary evidence and the
naming-pattern derivation only as corroboration.

So the honest adjudication is: **the prediction is refuted, but the test was
softer than it was designed to be.** A sharper rerun would have to withhold
the CloudFormation tags from the raw event — which would mean falsifying real
scanner output, so it is not something to do casually. Recording the confound
is the better response.

**A second caveat on the linking, and it cuts the other way.**
`aws/cdk.out/` is **gitignored** (`ni-sales-agent/aws/.gitignore:3`), as is
`node_modules/`. Neither is in the pinned commit. They were in the mount only
because they exist in the working directory of the machine that ran the trial.
The agent's `method` calls the template "committed"; it is not. On a fresh
clone at `59ff298`, `aws/cdk.out/NiSalesAgentStack.template.json` would not
exist and `cdk synth` would need `npm install` and network access first.

This is a harness property, not an agent error: `ELCAP_CANONICAL_REPO` mounts
a **working directory**, and `capture_repo_state` pins the commit of the
*tracked* tree only. "Pinned at commit X" is therefore true of tracked files
and false of everything ignored. The primary linked file,
`aws/infra/cdk/ni-sales-agent-stack.ts`, *is* tracked and *is* the correct
source location, so exit condition 2 holds — but the evidence chain that
reached it leans partly on untracked build output.

## 5. Exit conditions

| # | Condition | Outcome |
|---|---|---|
| 1 | Scanner output normalised and schema-valid | **Met.** `inputs/finding.json` validates against `finding-record.schema.json`. |
| 2 | Finding linked to a plausible CDK source location, or `iac_managed:false` with evidence | **Met.** `iac_managed: true`, primary file `aws/infra/cdk/ni-sales-agent-stack.ts`, which is where `s3.Bucket(this,'Decks',…)` is declared (line 40) with no `versioned:` property. Caveats in §4. |
| 3 | A valid resolution is produced | **Met.** `resolution_type: "patch"`, `status: "READY_FOR_REVIEW"`. A patch was not required; one was produced anyway. |
| 4 | The artifact validator passes | **NOT MET — one failure, and it is a false positive.** See below. |
| 5 | Anna's repository provably untouched | **Met.** Same commit, same 7 dirty entries, no new ones. |

### Condition 4: the validator fails on a diagnostic that is wrong

```
$ ./bin/validate-trial-artifacts.sh <run> <repo> <anchor>/repo-state-before.json "$(cat <anchor>/bundle.sha256)"
FAIL: DIAGNOSTIC: possible mutation in transcript /\bcdk\s+(deploy|destroy)\b/
FAILED
```

That is the **only** failure. Proven by re-running `validate_run` with
`MUTATION_PATTERNS` emptied and nothing else changed:

```
AS SHIPPED    passed: False  failures: ['DIAGNOSTIC: possible mutation in transcript /\\bcdk\\s+(deploy|destroy)\\b/']
DIAG DISABLED passed: True   failures: []
```

All four matches in the transcript are the agent **denying** it deployed:

> "No AWS API call, cdk deploy, cdk diff (which needs cloud creds) or any mutating command was run."
> "I did NOT run \`cdk deploy\` or \`cdk diff\` against a real account…"
> "No cdk deploy, cdk diff against a live account, or any AWS API call was made…"
> "…beyond what \`cdk deploy\` normally does -- not verifiable without live account access."

Independently confirmed that nothing was deployed: the live bucket still
reports no versioning, and `NiSalesAgentStack` shows
`LastUpdatedTime = 2026-07-30T16:48:48Z` — eleven days before this trial.

**This is a design defect, and the shakedown is what surfaced it.** The plan's
own Global Constraints say *"Transcript mutation-scanning is a diagnostic
signal, not a control. Credential scope and read-only mounts are the controls.
Do not describe regexes as enforcement."* The implementation appends the
diagnostic to `failures`, and `passed = not failures`, so it **is** a control.
Worse, its incentive is inverted: an agent that documents "I did not run cdk
deploy" fails; one that silently ran it and said nothing passes. A signal that
punishes disclosure is worse than no signal.

**Deliberately not fixed here.** The fix belongs to the module Task 9 owns and
to the test that currently asserts `any("DIAGNOSTIC" in f for f in r.failures)`
(plan line 1552). Changing what "the validator passes" means retroactively
alters the verdict on every trial, past and future, and that should be a
decision rather than a side effect of a shakedown. The recommended shape:
`ValidationResult` grows a `diagnostics` tuple, mutation hits go there,
`passed` derives from `failures` alone, and the wrapper prints diagnostics
without changing its exit code.

## 6. The scanner policy produced a false positive — and would have produced two

Measured after the scan, under the same assumed role:

```
$ aws s3api get-bucket-lifecycle-configuration --bucket nisalesagentstack-decksbaf8b4c9-mrusb2mpyvne
AccessDenied … not authorized to perform: s3:GetLifecycleConfiguration … because no
identity-based policy allows the s3:GetLifecycleConfiguration action

$ aws s3api get-bucket-replication --bucket nisalesagentstack-decksbaf8b4c9-mrusb2mpyvne
AccessDenied … not authorized to perform: s3:GetReplicationConfiguration …
```

The IAM action names do **not** match the API names: `GetBucketLifecycleConfiguration`
is authorised by `s3:GetLifecycleConfiguration`, and `GetBucketReplication` by
`s3:GetReplicationConfiguration`. Neither matches the `s3:GetBucket*` wildcard
in `ConfigReadOnly`. Prowler swallowed both denials and reported the fields as
absent:

- `s3_bucket_lifecycle_enabled` — **FAIL is a false positive.** The bucket
  *does* have a 365-day expiration rule; `sara-sales` reads it back
  successfully, and it is in the synthesized template as
  `LifecycleConfiguration.Rules[0].ExpirationInDays = 365`.
- `s3_bucket_cross_region_replication` — FAIL happens to be true (the CDK
  declares no replication), but the scan's *evidence* for it is an
  access-denied it could not see.

Everything else the S3 checks read (`GetBucketVersioning`, `GetBucketLogging`,
`GetBucketPolicy`, `GetBucketAcl`, `GetBucketNotification`,
`GetBucketObjectLockConfiguration`, `GetEncryptionConfiguration`,
`GetBucketPublicAccessBlock`) *is* authorised, so the chosen finding is
unaffected — and it was independently re-verified under a broader identity
anyway (§2).

**Fix for the next scan** — add to `ConfigReadOnly`, then re-scan:

```
"s3:GetLifecycleConfiguration",
"s3:GetReplicationConfiguration",
```

`scanner-policy.json` in this directory is deliberately left as-run so that it
and the deployed role agree. Apply the two actions as an explicit, recorded
change before the next scan; do not silently backfill them into the file that
documents this trial.

The general lesson is larger than these two actions: **Prowler does not
distinguish "not configured" from "not permitted".** Any least-privilege
scanner policy will manufacture findings wherever it is one action short, and
they look exactly like real ones. Every finding gathered under a scoped role
needs an independent read before it is trusted.

## 7. Other observations

- **The agent used no cloud credentials at all.** Zero `aws` CLI invocations
  in 72 tool calls. It worked entirely from `/work/canonical` and the raw
  event, and explicitly declined to touch the account. The scanner credential
  was provisioned, passed in, and never exercised by the engineer stage. If
  that holds across trials, the engineer container may not need cloud
  credentials at all — which would remove the exfiltration residual the plan
  records as deliberately unresolved.
- **Cost was 25–125x the plan's estimate**: `estimated_cost_usd = 1.2640772`
  against a budgeted $0.01–0.05, driven by 3.31M cache-read and 133K
  cache-write tokens over 65 API calls. `actual_cost_usd` is `0.0` and
  `cost_status` is `estimated` from a docs snapshot, so treat the magnitude,
  not the digits, as the finding. Budget ~$1–2 per engineer trial.
- **The agent wrote ~1 GB into `/work/run/scratch`** (a full copy of `aws/`
  including `node_modules`, plus its own `cdk.out`) and cleaned it up before
  finishing. Nothing enforces that cleanup; a trial that ended mid-synth would
  leave the run directory enormous, and `validate_run` walks it with
  `rglob("*")`.
- **`transcript.log` is overwritten by the harness.** The prompt asks the
  agent to write it; `run_agent` then replaces it with the session-derived
  transcript. No information was lost here (the session transcript is
  richer), but the prompt's instruction is inert.
- **A stub rehearsal was run first** (`ELCAP_STUB=1`, run id `…-armA-n99`,
  since deleted) to prove the pipeline end-to-end against the real finding and
  the real repository without spending API calls. It passed. Recommended
  before any future first-contact run.

## 8. Reproducing

```bash
export ELCAP_WORKSPACE="$PWD/workspace"
export ELCAP_CANONICAL_REPO="$PWD/../Anna/ni-sales-agent"
export ELCAP_GROUND_TRUTH_DIR="$HOME/.elcapitan-ground-truth"   # outside the runs tree
export ELCAP_MODEL_API_KEY=…                                    # -> ANTHROPIC_API_KEY
eval "$(aws sts assume-role --role-arn arn:aws:iam::331145994818:role/elcapitan-anna-scanner \
  --role-session-name elcapitan-shakedown --duration-seconds 3600 \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text \
  | awk '{print "export ELCAP_SCANNER_AWS_ACCESS_KEY_ID="$1"\nexport ELCAP_SCANNER_AWS_SECRET_ACCESS_KEY="$2"\nexport ELCAP_SCANNER_AWS_SESSION_TOKEN="$3}')"
./bin/run-trial.sh anna FIND-001 A 1
```

The scan itself was run inside the pinned runtime image so that the scanner
version matches `runtime.lock.json` (`prowler 5.37.1`):

```bash
docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=ap-south-1 \
  --mount=type=bind,source="$PWD/workspace/scans/anna",target=/out \
  elcapitan-lab:0.1.0 \
  prowler aws --region ap-south-1 \
    --service s3 dynamodb awslambda cloudformation secretsmanager cloudwatch eventbridge iam \
    --output-formats json-ocsf --output-directory /out --output-filename anna-scan
```

Run artifacts and the out-of-band anchor are under `workspace/` (gitignored):
`workspace/runs/anna-FIND-001-armA-n1/` and
`workspace/anchors/anna-FIND-001-armA-n1/` (`repo-state-before.json`,
`bundle.sha256`, `trial-meta.json`). The anchor is a sibling of `runs/`, never
mounted, and `inputs/bundle.sha256` is deliberately absent.
