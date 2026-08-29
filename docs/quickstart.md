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
`local-preview-not-a-secret-00000000`, select **Load safe sample**, and submit
it for tenant `SYNTHETIC-QUICKSTART`. The fleet shows a synthetic input,
separate validation/planning/execution authority, and its E2E-measured control
grade. Live validation stays unavailable because no cloud binary or scanner
identity is present.

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
