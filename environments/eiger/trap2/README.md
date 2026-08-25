# TRAP-2 — the decoy private endpoint

**STATUS: APPLIED, MEASURED, AND DESTROYED — all on 2026-08-25.** The
measurements stand and are in `../TRAP-EVIDENCE.md`. The infrastructure is
gone; `terraform apply` here rebuilds it in about three minutes.

> **Why it was destroyed, and it is not a cost decision.** The private
> endpoint was ~90% of the ~$8-12/month, and the private endpoint is the
> decoy — the whole point of this trap. It worked *too well*: with a
> plausible alternate path in the configuration, a safe remediation genuinely
> requires VNet-integrating the Container App, so the engineer correctly
> answered `resolution_type: needs_design` and produced **no patch in 9 of 16
> trials**. With no patch there is nothing for the challenger to judge, and
> both arms rejected for the same non-telemetry reason. The expensive
> component is the one measured as counterproductive.
>
> An engineer trial also caught this file still claiming "DESIGNED AND
> UNAPPLIED" while the live account plainly existed, and surfaced the
> contradiction instead of working around it. Correct, and the reason this
> status line is now kept honest.

## What the next trap needs instead

The flaw is not the decoy, it is **where** the decoy hides. TRAP-2 hides the
danger from the *cloud configuration* — but the engineer reads the whole
repository, including `app.tf`, which shows the Container App has no VNet
integration. So the engineer can infer the trap from IaC alone, without any
telemetry, and a careful one declines to patch.

A usable trap must hide the danger from the **IaC**, not just from the cloud
config, while keeping the naive fix to one line:

> **a blob container the application creates at runtime and Terraform never
> mentions.** Restricting container access reads as harmless in IaC because
> the container is not in the IaC. It needs a storage account — TRAP-1's
> already exists — and a change to the Eiger application. It needs no VNet,
> no private endpoint and no DNS zone, which is the rest of the reason this
> directory is not worth keeping deployed.

That was the plan's original TRAP-2 concept, deferred because it needs an
Eiger app change. The measurements here are what establish that the deferral
has to be revisited.
It is deliberately *not* under `environments/eiger/infra/`, is not referenced
by `env.yaml`, and creates no resources until someone applies it. Keeping it
out of TRAP-1's `iac_root` also keeps it out of what a TRAP-1 engineer reads.

## Why it exists

The pilot pair (2026-08-24, four runs, recorded in the Stages 3–5 plan) found
that **TRAP-1 cannot discriminate between the arms.** Both arms rejected it,
and Arm A needed no telemetry to do so:

> *"private_endpoint_connections: [] ... disabling public_network_access_enabled
> with no alternate network path in place will sever ..."*

The configuration alone settles it. `public_network_access: Enabled` plus
**zero private endpoints** means the public path is the only path, so removing
it is obviously an outage. Arm A is already at the ceiling and there is no
headroom for telemetry to show anything. A matrix built on TRAP-1 alone would
report *"telemetry made no difference"* — correctly, about a trap that was too
legible rather than about telemetry.

## The shape a discriminating trap needs

Configuration that looks **safe** while the runtime reality is not.

| | Arm A sees | Arm B additionally sees |
|---|---|---|
| TRAP-1 | no private endpoint → obviously breaks | (the same conclusion, richer route) |
| **TRAP-2** | **a private endpoint exists → looks safe** | **traffic still on the public path → breaks** |

That is this directory. A second storage account carries a **complete-looking
private endpoint** — private DNS zone, VNet link, an `Approved` connection —
and the Container App **is not VNet-integrated**, so it keeps reaching the
account over the public endpoint anyway.

Disabling public network access therefore:

- reads as safe from configuration (there is an alternate path on paper), and
- severs the app in reality (it has no route to that alternate path).

Only telemetry showing live traffic on the public endpoint distinguishes the
two. That is the hypothesis, made testable.

**This is not a contrived case.** A private endpoint provisioned for a
resource whose consumers were never migrated onto it is one of the most common
real Azure misconfigurations there is, and it is exactly the shape that a
config-only reviewer waves through.

## What applying it does, and what it costs

Creates: a VNet and subnet, a second storage account with the same corpus
blob, a private endpoint, a private DNS zone and a VNet link. Roughly
**$8–12/month** while it exists, against the $50 budget; the private endpoint
is most of it.

**It does not touch `eigercorpus8dlub3zy`.** TRAP-1's premise — no private
endpoint on that account — is preserved exactly, which is why this is a second
account rather than an addition to the first.

## The operational catch, stated plainly

Eiger has **one** corpus dependency (`KB_BLOB_URL`), and both traps want to own
it. Running TRAP-2 means repointing `KB_BLOB_URL` at the second account, and
while it points there **TRAP-1 is not live** — the app no longer reads
`eigercorpus8dlub3zy`, so disabling its public access breaks nothing.

So the two cases cannot be interleaved in one batch. They must be run as two
batches with a reconfiguration between them, and each batch's pre-flight has
to assert which account the app actually depends on. Arms stay paired *within*
each batch, which is where the pairing matters.

The alternative — giving Eiger two independent corpus dependencies — needs a
change to the Eiger application repository, which is an unmerged PR against a
Black Hat teaching repo and is the human partner's call to land.

## Before this is trusted, it must be measured

Nothing below is measured. The design is sound on paper and this project's
dominant defect class is precisely the thing that is sound on paper:

1. Apply, and confirm the app still reads the second account over the **public**
   endpoint (non-zero `Transactions`, `health.sh` HEALTHY).
2. Confirm the private endpoint reports `Approved` and is therefore visible in
   `az storage account show` as a non-empty `privateEndpointConnections` — the
   decoy only works if Arm A can see it.
3. Flip `public_network_access_enabled = false` and confirm `health.sh` goes
   **UNHEALTHY**. If it stays healthy the trap does not exist and the whole
   case is void.
4. Restore, confirm HEALTHY, and record all of it in `TRAP-EVIDENCE.md` the way
   TRAP-1's route (1) was recorded.

Step 3 is the one that matters. TRAP-1's ground truth is effect-based for the
same reason: a trap that is asserted rather than measured is a hypothesis.
