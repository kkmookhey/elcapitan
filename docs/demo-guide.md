# El Capitan demo guide

The browser demo uses the production workflow services with an isolated local
deployment target. The scanner finding, 28-day traffic profile, and service
health observations are synthetic and clearly separated from live cloud
evidence. No Eiger resource or repository is read or changed.

## Run locally

Prerequisites: Python 3.12, `uv`, and Terraform on `PATH`.

```bash
UV_CACHE_DIR=/private/tmp/elcapitan-uv-cache \
  uv run elcapitan serve-demo --prepare
```

Open `http://127.0.0.1:8765`.

The server stores each run under `.elcapitan-demo/runs`. Resetting starts a new
session; it deliberately does not delete earlier audit evidence.

## Five-minute presentation

1. Start at the fleet pipeline and explain that agents emit typed records while
   deterministic policy gates control state transitions.
2. Show the risk score, evidence count, Terraform checks, implementation diff,
   selected low-usage window, SRE review, and rollback triggers.
3. Select **Review & approve**. Explain that approval binds the exact package,
   hashes, case, and window; it is not approval of an open-ended agent action.
4. Choose **Deploy healthy change**. Show the post-change probes, remediation
   certificate, and originator handoff.
5. Reset, approve a second run, and choose **Simulate SLO failure**. Show that
   the health policy restores the exact checkpoint and records rollback proof.

## Honest demo boundaries

- The local reference driver changes only a copied Terraform file.
- The selected future maintenance window is executed with a deterministic demo
  clock so the audience does not wait until the real date.
- Recorded model outputs make the demo reliable and prevent customer evidence
  from leaving the machine. Live provider adapters remain available separately.
- Browser approval is an explicit demonstration control, not production SSO.
  Production deployment must put Microsoft Entra authentication in front of it.
- A separate `azure-storage-lifecycle` command has already exercised the same
  action plane against the tagged non-production Azure Storage account using a
  least-privilege user-assigned managed identity.

## Azure packaging

The root `Dockerfile` runs as UID 10001, contains no provider keys, includes the
Terraform CLI for deterministic plan checks, exposes port 8080, and writes demo
state only under `/data`. The synthetic lifecycle demo uses SQLite. The customer
shadow service selects PostgreSQL when `ELCAPITAN_DATABASE_URL` is set and also
persists its hash-checked evidence blobs there.

When `ELCAPITAN_DEMO_ACCESS_TOKEN` is set, every dashboard asset and API is
protected by a login. The server stores only a one-way derived value in the
browser's HttpOnly, Secure, SameSite=Strict cookie, rejects cross-origin writes,
and leaves only `/healthz` anonymous for platform probes. Store the token as a
Container Apps secret; never put it in the image or repository.

Build the image with ACR and initially deploy it with internal ingress. Configure
`ELCAPITAN_DEMO_ACCESS_TOKEN` from a Container Apps secret before a security
review approves external HTTPS ingress:

```bash
az acr build --registry <registry> --image elcapitan-demo:<tag> .

az containerapp create \
  --name elcapitan-demo --resource-group <lab-resource-group> \
  --environment <container-app-environment> \
  --image <registry>.azurecr.io/elcapitan-demo:<tag> \
  --ingress internal --target-port 8080 --min-replicas 1 --max-replicas 1 \
  --secrets demo-access-token=<generated-secret> \
  --env-vars ELCAPITAN_DEMO_ACCESS_TOKEN=secretref:demo-access-token
```

After initial validation, enable Microsoft Entra authentication and attach the
existing `elcapitan-executor-lab` identity only when exposing live Azure actions
through the UI. Do not place provider API keys in the image or app environment.
