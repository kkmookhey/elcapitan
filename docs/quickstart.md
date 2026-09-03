# Five-minute local quickstart

This path starts the read-only shadow console and PostgreSQL with Docker
Compose. It uses one checked-in synthetic finding and requires no cloud or
model credentials.

## Prerequisites

- Docker Engine or Docker Desktop with Compose v2.
- Ports 8770 available on loopback.

From the repository root:

```bash
docker compose up --build --detach --wait
```

Open `http://127.0.0.1:8770`, sign in with
`local-preview-not-a-secret-00000000`, and select **Try safe sample**. The
console checks the sample locally and shows an import preview before retaining
anything. Confirm **Import 1 finding** to open the results workspace. The
finding remains labeled synthetic, and its detail separates cloud checking,
planning, execution, and evidence authority. The cloud check stays unavailable
because no cloud binary or scanner identity is present.

To evaluate scanner compatibility instead, select **Choose scanner export**.
The preview reports FAIL/PASS/MANUAL accounting, provider and format detection,
resource and account counts, and supported versus unsupported findings. It
makes no cloud or model request and retains no source data; only the explicit
import confirmation creates findings and resource cases.

To test business-aware ordering, expand **Add per-resource asset context** and
choose a JSON manifest shaped like
[`asset-context-manifest.example.json`](asset-context-manifest.example.json).
The preview joins by exact resource ID, reports matched resources, finding
resources without context, and asset rows without failing findings, and makes
no cloud request. Azure ARM IDs compare case-insensitively; all other IDs remain
exact. Context is never fuzzily assigned. Synthetic owner, environment, or
criticality labels must set `synthetic_business_context` to `true`, while
observed exposure must include its timestamp and evidence reference.

The fallback finding fields apply only to resources without a matched asset
row. Asset criticality now defaults to zero rather than silently treating
unknown assets as medium criticality.

The Compose file publishes only the shadow service on loopback. PostgreSQL is
not published to the host. Its trust authentication and the documented access
token are deliberately restricted to this local synthetic preview; they are
not deployment defaults and must never be used for customer data or a shared
host.

Stop without deleting the local preview data:

```bash
docker compose down
```

Delete the preview database and hydrated artifacts as well:

```bash
docker compose down --volumes
```

## Automated clean-machine acceptance

The acceptance script builds an isolated project, waits for real PostgreSQL
health, authenticates, imports the checked-in synthetic finding, verifies the
fleet/capability response, enforces the ten-minute budget, and deletes its
containers and volumes:

```bash
./scripts/accept_quickstart.sh
```

It passes no host cloud or model environment variables into either container.
The runtime, Terraform, and PostgreSQL base images are pinned by digest, and
the application image installs a hash-locked export of every runtime Python
dependency.
Use [the customer shadow-run guide](customer-shadow-run.md), not this local
credential scheme, for any authorized real environment.
