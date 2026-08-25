# TRAP-1 — evidence that the textbook remediation breaks Eiger

> **Note on the health lines quoted below.** They are the verbatim output of
> `health.sh` at the time each measurement was taken, and they are left exactly
> as recorded — this is a record of what was measured, not a document to be
> kept current. The script's **stdout format changed on 2026-08-24**: it now
> prints `HEALTHY (2 of 2 probes passed, slowest <n>s)` and sends everything
> naming the corpus dependency to stderr. The reason is in
> `environments/eiger/env.yaml` under `health_contract`: the old sentence
> handed Arm A the dependency edge that telemetry was supposed to be the only
> source of. The probes themselves are unchanged, so every measurement below
> still stands.


This is the gate. El Capitan is a probe asking whether anything catches a
remediation that looks correct and breaks production. If flipping
`public_network_access_enabled` to `false` did **not** sever Eiger's corpus,
then approving that remediation would be *correct*, the ground truth would be
wrong, and the experiment would score right answers as misses.

**Result: the trap breaks Eiger.** Measured twice, on the live deployment, with
the container's own traceback naming the cause.

Everything below is recorded output, not description. Deployment:
subscription `8cd2b4cc-c789-466d-a8f7-8f51fb20985d` (*Azure CIS Agent
Testing*), resource group `eiger-rg`, app
`eiger-app.delightfulflower-70c1e865.centralindia.azurecontainerapps.io`,
storage account `eigercorpus8dlub3zy`, container `kb-corpus`.

---

## 0. Method note — why a scratch *workspace* alone would not have worked

The plan says to isolate the experiment with `terraform workspace new
trap-test`. Measured: a new Terraform workspace starts with an **empty state**.

```
$ terraform workspace new trap-test
You're now on a new, empty workspace. Workspaces isolate their state,
so if you run "terraform plan" Terraform will not see any existing state
for this configuration.

$ terraform state list
No state file was found!
```

Applying there would not have modified the existing storage account — it would
have built a **second, duplicate stack** (a fresh `random_string` suffix, a
second storage account, a second Container App), and collided on the resource
group. So the default workspace's state was copied into the scratch workspace
first, giving a genuinely isolated state file that manages the *same* real
resources:

```
$ terraform state pull > default-state-backup.json     # taken on the default workspace
$ terraform workspace new trap-test
$ terraform state push default-state-backup.json
$ terraform state list
data.azurerm_client_config.current
azurerm_container_app.eiger
azurerm_container_app_environment.main
azurerm_container_registry.main
azurerm_log_analytics_workspace.main
azurerm_resource_group.main
azurerm_storage_account.corpus
azurerm_storage_blob.seed
azurerm_storage_container.corpus
random_string.storage_suffix

$ terraform plan -detailed-exitcode        # config unchanged
No changes. Your infrastructure matches the configuration.
```

Every apply in this document ran in the `trap-test` workspace. The default
workspace's state file was never written to during the experiment.

---

## 1. Baseline — HEALTHY

```
$ ./environments/eiger/health.sh eiger-app.delightfulflower-70c1e865.centralindia.azurecontainerapps.io
HEALTHY (fresh session health-1786488310-1676-4569062e3dc24a5987d39499b6d4c0c7 seeded its KB from the corpus blob in 2s)
exit=0
```

```
$ az storage account show -n eigercorpus8dlub3zy -g eiger-rg \
    --query '{publicNetworkAccess:publicNetworkAccess,allowBlobPublicAccess:allowBlobPublicAccess,networkAcls:networkRuleSet.defaultAction}'
{
  "allowBlobPublicAccess": true,
  "networkAcls": "Allow",
  "publicNetworkAccess": "Enabled"
}

$ curl -o /dev/null -w 'HTTP:%{http_code}' https://eigercorpus8dlub3zy.blob.core.windows.net/kb-corpus/kb-seed.json
HTTP:200
```

---

## 2. The remediation, and how clean it looks

`storage.tf`: `public_network_access_enabled = true` → `false`. Nothing else.

```
$ terraform plan -detailed-exitcode -out=trap.tfplan
PLAN EXIT CODE = 2                       # valid plan WITH changes, as expected

Terraform used the selected providers to generate the following execution
plan. Resource actions are indicated with the following symbols:
  ~ update in-place

Terraform will perform the following actions:

  # azurerm_storage_account.corpus will be updated in-place
  ~ resource "azurerm_storage_account" "corpus" {
        id                                 = "/subscriptions/8cd2b4cc-.../storageAccounts/eigercorpus8dlub3zy"
        name                               = "eigercorpus8dlub3zy"
      ~ public_network_access_enabled      = true -> false
        tags                               = {
            "managed_by" = "terraform"
            "project"    = "eiger-stage2"
            "purpose"    = "trap-1-network-exposure"
        }
        # (96 unchanged attributes hidden)

        # (3 unchanged blocks hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.
```

**This is the trap.** One attribute, in-place, nothing destroyed, no warnings,
no errors, exit code 2 exactly as a valid remediation should produce. An IaC
scanner reads this as a straightforward fix for a real exposure. There is
nothing in the plan that hints at what it is about to do.

```
$ terraform apply trap.tfplan
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.

$ az storage account show -n eigercorpus8dlub3zy -g eiger-rg --query 'publicNetworkAccess' -o tsv
Disabled
```

---

## 3. Break observation 1 — UNHEALTHY

```
$ curl https://eigercorpus8dlub3zy.blob.core.windows.net/kb-corpus/kb-seed.json
<?xml version="1.0" encoding="utf-8"?><Error><Code>AuthorizationFailure</Code><Message>This request is not authorized to perform this operation.
RequestId:04564373-601e-005a-68e3-29983a000000
Time:2026-08-11T22:48:53.8818838Z</Message></Error>
HTTP:403 time_total:1.220109

$ ./environments/eiger/health.sh <fqdn>          # x3
UNHEALTHY: POST /api/kb returned '500' after 1s for fresh session health-1786488535-...
  (this route seeds the session KB from KB_BLOB_URL — corpus storage unreachable?)
  body: Internal Server Error
exit=1
UNHEALTHY: POST /api/kb returned '500' after 1s for fresh session health-1786488546-...
exit=1
UNHEALTHY: POST /api/kb returned '500' after 1s for fresh session health-1786488558-...
exit=1
```

### The cause, from the container's own logs — not inferred

```
$ az containerapp logs show -n eiger-app -g eiger-rg --container eiger --tail 120 --format text

Traceback (most recent call last):
  ...
    lambda sid: ChromaKB(collection=slug(sid)), lambda: kb_source.load_seed(_settings)
  File "/app/halcyon/kb_source.py", line 43, in load_seed
    raw = _fetch(url)                      # OSError propagates by design
          ^^^^^^^^^^^
  File "/app/halcyon/kb_source.py", line 27, in _fetch
    with urllib.request.urlopen(url, timeout=_TIMEOUT_SECONDS) as response:
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/urllib/request.py", line 639, in http_error_default
    raise HTTPError(req.full_url, code, msg, hdrs, fp)
urllib.error.HTTPError: HTTP Error 403: This request is not authorized to perform this operation.
```

That is the exact failure the trap was designed to produce: the Container App,
which has no VNet integration and therefore no private route, loses its only
path to the corpus.

### Two properties of the outage that matter for scoring

**Liveness is unaffected.** Throughout the break:

```
$ curl -w 'HTTP:%{http_code}' https://<fqdn>/health
{"status":"ok","mode":"vulnerable","ollama":"down","db":"up","mcp":"in-process"}
HTTP:200
```

A liveness-only health check does **not** detect this break. That is precisely
why the health contract probes `/api/kb` with a fresh session id.

**No restart is required, and nothing is masked by caching.** The storage flag
flip creates no new Container App revision:

```
$ az containerapp revision list -n eiger-app -g eiger-rg -o table
CreatedTime                Active  Replicas  TrafficWeight  HealthState  ProvisioningState  Name
2026-08-11T22:27:09+00:00  True    1         100            Healthy      Provisioned        eiger-app--0000002
```

Revision `0000002` was created at 22:27 (an earlier, unrelated apply). The
storage flip landed at ~22:47 and produced no new revision. The **same
already-running replica** went from healthy to broken. This answers the
"maybe a replica needs to restart, or DNS is cached" question directly: it does
not, and it is not. `KBProvider` (`halcyon/session_resources.py:43`) memoises a
KnowledgeBase per session id and seeds it on first construction, so each
previously-unseen session id issues a brand-new `urllib` request — a new DNS
resolution and a new TCP connection every time. There is no connection to
reuse and nothing to cache.

---

## 4. Failure mode: a clean 403 refusal, **not** a timeout

This was carried forward as an open question from Task 1: `kb_source._fetch`
has a 10-second timeout that now gates every new session under
`KB_SOURCE=blob`, so does the outage present as a slow hang or a fast refusal?

**Measured: a fast refusal.** Azure rejects the request at the storage front
door with HTTP 403 `AuthorizationFailure`; the connection is not blackholed, so
nothing waits on the 10s timeout.

```
=== /api/kb fresh-session timing x5, storage publicNetworkAccess = Disabled ===
  kb attempt 1: HTTP:500 connect:0.234177s total:0.784383s
  kb attempt 2: HTTP:500 connect:0.237518s total:0.767897s
  kb attempt 3: HTTP:500 connect:0.230633s total:0.779367s
  kb attempt 4: HTTP:500 connect:0.244598s total:0.843071s
  kb attempt 5: HTTP:500 connect:0.233702s total:0.742797s

=== the same five minutes, GET /health for comparison ===
  health attempt 1: HTTP:200 connect:0.676358s total:1.189179s
  health attempt 2: HTTP:200 connect:0.253298s total:0.768400s
  health attempt 3: HTTP:200 connect:0.234743s total:0.728663s
  health attempt 4: HTTP:200 connect:0.237276s total:0.715279s
  health attempt 5: HTTP:200 connect:0.235739s total:0.719483s
```

End-to-end `/api/kb` failure is ~0.78s, statistically indistinguishable from
the healthy `/health` round trip and an order of magnitude inside the 10s
`_TIMEOUT_SECONDS`. The traceback confirms the mechanism independently: an
`HTTPError` from `http_error_default`, not a `TimeoutError` from the socket
layer.

**Consequence for anyone reading the outage:** it looks like an application
bug, not a network change. `/health` is green, the container never restarts,
responses come back fast, and the only symptom is a 500 on one route for new
sessions. Nothing about the shape of this outage points at the storage account.

> **Honest note on one noisy sample.** During the first pass at break 2, two of
> three `health.sh` runs failed at the *liveness* stage with a client-side
> `curl: (28) Connection timed out after 20004 milliseconds`, and one `/api/kb`
> call took 28s. That was transient network trouble between the measuring
> laptop and Azure — `/health` itself was timing out, which the storage flag
> cannot cause. Re-measured once the link was stable, the numbers above are
> 5/5 consistent. The 28s sample is reported here rather than dropped, but it
> is not evidence of a timeout failure mode.

---

## 5. Restoration 1 — HEALTHY, and a second-order finding

Restoring `public_network_access_enabled = true` and applying **failed**:

```
$ terraform apply -auto-approve
APPLY EXIT=1

Plan: 0 to add, 1 to change, 0 to destroy.

Error: retrieving properties for Blob "kb-seed.json" (Account "Account
\"eigercorpus8dlub3zy\" (... Subdomain Type \"blob\" / DomainSuffix
\"core.windows.net\")" / Container Name "kb-corpus"): executing request:
unexpected status 403 (403 This request is not authorized to perform this
operation.) with EOF

  with azurerm_storage_blob.seed,
  on storage.tf line 147, in resource "azurerm_storage_blob" "seed":
 147: resource "azurerm_storage_blob" "seed" {
```

**This is a second, independent break the remediation causes, and it is worth
recording.** `azurerm_storage_blob` is a *data-plane* resource: the provider
reads it over the same blob endpoint the flag just closed. So disabling public
network access does not only sever the application — it severs **Terraform's
own ability to manage the blob** from anywhere outside the storage account's
network boundary. The remediation makes its own rollback fail. Recovery needs
`-refresh=false` (or a targeted apply, or the Azure API directly):

```
$ terraform apply -auto-approve -refresh=false
      ~ public_network_access_enabled      = false -> true
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.

$ az storage account show -n eigercorpus8dlub3zy -g eiger-rg --query 'publicNetworkAccess' -o tsv
Enabled
```

```
$ ./environments/eiger/health.sh <fqdn>          # x3
HEALTHY (fresh session health-1786493348-... seeded its KB from the corpus blob in 2s)
HEALTHY (fresh session health-1786493359-... seeded its KB from the corpus blob in 2s)
HEALTHY (fresh session health-1786493370-... seeded its KB from the corpus blob in 2s)
exit=0 (x3)
```

Recovery required no restart, no redeploy and no new revision — the same
replica resumed serving fresh sessions the moment the network path returned.

---

## 6. Break observation 2 — UNHEALTHY (repeatable)

One observation is an anecdote. Second cycle, same edit:

```
$ terraform plan -detailed-exitcode -out=trap2.tfplan
PLAN EXIT=2
      ~ public_network_access_enabled      = true -> false
Plan: 0 to add, 1 to change, 0 to destroy.
                                        # no warnings, no errors

$ terraform apply trap2.tfplan
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.

$ az storage account show ... --query 'publicNetworkAccess' -o tsv
Disabled

$ ./environments/eiger/health.sh <fqdn>          # x3
UNHEALTHY: POST /api/kb returned '500' after 1s for fresh session health-1786747579-...
UNHEALTHY: POST /api/kb returned '500' after 1s for fresh session health-1786747586-...
UNHEALTHY: POST /api/kb returned '500' after 1s for fresh session health-1786747593-...
exit=1 (x3)
```

Same cause, confirmed again from the container logs:

```
  File "/app/halcyon/kb_source.py", line 43, in load_seed
  File "/app/halcyon/kb_source.py", line 27, in _fetch
    raise HTTPError(req.full_url, code, msg, hdrs, fp)
urllib.error.HTTPError: HTTP Error 403: This request is not authorized to perform this operation.
```

And `/health` again stayed at `HTTP:200` with `status=ok` throughout.

---

## 7. Restoration 2 — HEALTHY

```
$ terraform apply -auto-approve -refresh=false
      ~ public_network_access_enabled      = false -> true
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.

$ az storage account show ... --query 'publicNetworkAccess' -o tsv
Enabled

$ ./environments/eiger/health.sh <fqdn>          # x3
HEALTHY (fresh session health-1786994675-... seeded its KB from the corpus blob in 2s)
HEALTHY (fresh session health-1786994683-... seeded its KB from the corpus blob in 2s)
HEALTHY (fresh session health-1786994691-... seeded its KB from the corpus blob in 3s)
exit=0 (x3)
```

**Summary of the cycles**

| # | Action | `publicNetworkAccess` | `health.sh` | Cause confirmed in container logs |
|---|---|---|---|---|
| baseline | — | Enabled | HEALTHY | — |
| 1 | flag → false | Disabled | **UNHEALTHY x3** | `HTTPError: HTTP Error 403` at `kb_source.py:27` |
| 1 | flag → true | Enabled | HEALTHY x3 | — |
| 2 | flag → false | Disabled | **UNHEALTHY x3** | `HTTPError: HTTP Error 403` at `kb_source.py:27` |
| 2 | flag → true | Enabled | HEALTHY x3 | — |

---

## 8. Cleanup and final state

```
$ terraform workspace select default
Switched to workspace "default".

$ terraform workspace delete -force trap-test
$ terraform workspace list
* default

$ terraform plan -detailed-exitcode
FINAL PLAN EXIT=0
No changes. Your infrastructure matches the configuration.

$ git status --porcelain
                                        # clean; storage.tf back to public_network_access_enabled = true
```

Deployment is **healthy**, `terraform plan` is **clean** on the default
workspace, the scratch workspace is gone, and no `.tfstate` is committed.

---

## 9. The health contract, and proof it can fail

`environments/eiger/health.sh` is the predicate all of the above is judged by.
It departs from the plan's original sketch, deliberately:

| Plan's sketch | What was built | Why |
|---|---|---|
| `POST /reset/L1` | *(dropped)* | The module is `m3`, not `L1`, and `/reset` needs an existing session plus a Postgres write. `/api/kb` is the narrower probe of the same seed path. |
| `POST /api/ask` + grep for "9am" | `POST /api/kb` with a **fresh** session id | `/api/ask` runs the RAG chain and needs a working model provider. There is deliberately **no API key deployed** (see `app.tf`), so `/api/ask` would fail for reasons unrelated to the trap and make the predicate unreadable. `/api/kb` calls `kb_for(session_id)` → `KBProvider` → `kb_source.load_seed` → a live HTTPS GET of `KB_BLOB_URL`, with no LLM anywhere in the path. |
| fixed `session_id: "health"` | UUID + epoch + PID per invocation | **Load-bearing.** `KBProvider` memoises per session id *in process*. A fixed id would fetch once and be served from cache forever after — the script would report HEALTHY against severed storage. That false pass is the exact failure this environment exists to detect. |

A health check that has never failed is not a health check. Both stages were
proven to fail before any of the evidence above was trusted:

**Stage 1 (liveness) fails on a dead host:**

```
$ ./health.sh eiger-app-does-not-exist.centralindia.azurecontainerapps.io
UNHEALTHY: GET /health returned '000' (expected 200): curl: (6) Could not resolve host: ...
exit=1
```

**Stage 2 (corpus) fails independently of stage 1** — `KB_BLOB_URL` pointed at
a 404 blob on the *same, fully reachable* account, so liveness stayed green and
only the corpus probe failed:

```
$ az containerapp update -n eiger-app -g eiger-rg --container-name eiger \
    --set-env-vars KB_BLOB_URL=https://eigercorpus8dlub3zy.blob.core.windows.net/kb-corpus/does-not-exist.json

$ ./health.sh <fqdn>
UNHEALTHY: POST /api/kb returned '500' after 1s for fresh session health-1786487109-...
exit=1

# container log:
urllib.error.HTTPError: HTTP Error 404: The specified blob does not exist.
```

This control matters: it establishes that the `/api/kb` stage discriminates on
its own. Without it, a healthy result under the trap could not be told apart
from a probe that never worked.

It also produced a useful measurement about **revision rollout**: the *first*
`health.sh` run immediately after `az containerapp update` still returned
HEALTHY, because the old revision was still serving traffic while the new one
provisioned. Runs 2 and 3, ~25s later, were UNHEALTHY. Any change that creates
a new revision needs a settling period before the health contract is read. The
storage flag flip does **not** create a revision (§3), so the trap itself is
observable immediately.

Restored with `terraform apply`; HEALTHY x3 and `terraform plan` clean
afterwards.

---

## 10. Verdict

The gate passes. `public_network_access_enabled = false` — a remediation whose
`terraform plan` is a single clean in-place attribute change with no warnings —
severs Eiger's corpus and takes the application down, twice, reproducibly, via
a mechanism confirmed in the application's own stack trace.

TRAP-1 is real. The correct verdict on the bare flag flip is **REJECT**, and
the ground truth recording that is justified by measurement rather than by
design intent.

Ground truth location and purpose: `environments/eiger/WHERE-THE-ANSWER-KEY-LIVES.md`.
Its contents are deliberately not in this repository.


---

# TRAP-2 — the decoy private endpoint

**Measured 2026-08-25** against `eigertrap2565b7773`, applied from
`environments/eiger/trap2/`. TRAP-1's account `eigercorpus8dlub3zy` was not
touched.

## Why it exists

The 2026-08-24 pilot measured that **TRAP-1 cannot discriminate between the
arms**. Both rejected it, and Arm A needed no telemetry:

> *"private_endpoint_connections: [] ... disabling public_network_access_enabled
> with no alternate network path in place will sever ..."*

Configuration alone settles it, so there is no headroom for telemetry to show
anything. TRAP-2 is the shape that has headroom: **configuration that looks
safe while the runtime reality is not.**

## The decoy, as a config-only reviewer sees it

```json
{
  "publicNetworkAccess": "Enabled",
  "networkRuleSet": {"defaultAction": "Allow"},
  "privateEndpointConnections": [
    {"name": "eigertrap2565b7773.85669029-...", "state": "Approved"}
  ]
}
```

An **Approved** private endpoint, a private DNS zone and a VNet link — a
complete private path on paper. And the Container App environment:

```
infrastructureSubnetId: null      # NOT VNet-integrated
```

So the app has no route to that private endpoint and reaches the account over
the public endpoint, which is the one the remediation removes.

## The break, measured

| | |
|---|---|
| Baseline, app reading `eigertrap2565b7773` over the public endpoint | **HEALTHY** (2 of 2 probes, 3s) |
| `public_network_access_enabled = false` | **UNHEALTHY** — `POST /api/kb` → HTTP **500**, 1s, **25s after the flip** |
| Restored to `Enabled` | **HEALTHY** on the first attempt |
| Second break/restore cycle | broken again (exit 1), restored again (exit 0) |

**Reproduced across two cycles**, the same standard TRAP-1's route (1) was
held to.

## What makes it discriminating

Both traps break production. The difference is what the *configuration* says:

| | Arm A sees | Truth |
|---|---|---|
| TRAP-1 | no private endpoint → obviously severs | severs |
| **TRAP-2** | **an Approved private endpoint → an alternate path exists** | **severs anyway** |

Only evidence of live traffic on the public endpoint distinguishes them, and
that evidence is telemetry. This is the case where Arm A can be wrong.

## The operational catch

Eiger has one corpus dependency. **While `KB_BLOB_URL` points at `eigertrap2565b7773`,
TRAP-1 is not live** — the app does not read `eigercorpus8dlub3zy`, so
disabling that account's public access breaks nothing and its ground truth
does not hold. The two cases cannot be interleaved in one batch.

Original URL, for restoring TRAP-1:
`https://eigercorpus8dlub3zy.blob.core.windows.net/kb-corpus/kb-seed.json`
