# Operations lifecycle

These procedures cover the self-hosted technical preview. Test backup and
restore with synthetic data before adopting customer retention requirements.

## Upgrade

1. Record the running image digest or wheel hash and export the current
   capability matrix.
2. Stop intake, validation, review, and workers. Confirm no job has an active
   lease and preserve the current release bundle and configuration.
3. Back up PostgreSQL and the deployment configuration. Local SQLite users copy
   the database and artifact directory while all El Capitan processes are
   stopped.
4. Verify the new artifact checksum and GitHub attestation. Read the changelog
   for schema or configuration migration notes.
5. Start the new version against a restored copy first. Run `/healthz`, import a
   synthetic fixture, inspect evidence, and compare `elcapitan capabilities`.
6. Upgrade the intended environment, repeat health and synthetic smoke checks,
   then resume intake. Roll back to the recorded digest and restored database if
   a migration or smoke check fails.

`v0.1.0` introduces no automatic database migration command. A future release
that changes durable schemas must supply an explicit forward and rollback path
before the tag.

## Backup and restore

For PostgreSQL, use the platform-supported `pg_dump`/`pg_restore` versions and
include all El Capitan tables. Encrypt backups, restrict access, record a
checksum, and keep them in a different failure domain. A valid backup includes
the database plus deployment configuration, identity references (never secret
values), proxy policy, and the exact application image digest.

The PostgreSQL artifact store is durable and hydrates local runtime artifacts;
there is no separate customer artifact volume to back up in that mode. For
SQLite development, back up `product.db` and `artifacts/` together while the
service is stopped.

A restore rehearsal must use an isolated database, start the same artifact
version, pass `/healthz`, reconcile record and evidence counts, open several
case timelines, and verify hashes before it is accepted. Never validate against
live cloud resources during a restore test unless that access is separately
authorized.

## Retention and deletion

The operator owns the retention schedule. Before a pilot, record retention for
source exports, normalized findings, evidence, model manifests/responses,
reviews, access logs, backups, and aggregate reports. Default to the shortest
period that supports the agreed audit purpose. Do not retain raw provider
responses, log bodies, secrets, Terraform state, or customer payload data.

Deletion is an operator-controlled maintenance event: stop writes, export any
agreed audit package, delete the customer-specific database and backups under
the provider's lifecycle policy, revoke identities and tokens, and record what
was deleted, when, and by whom. Logical row deletion is not a substitute for a
customer-specific database boundary in the first pilot.

## Uninstall

1. Stop and remove shadow, review, scheduler, and worker services.
2. Remove ingress, DNS, proxy policy, volumes, containers, and versioned images
   according to local registry policy.
3. Revoke workload identities, role assignments, federation, tokens, and model
   credentials created for El Capitan.
4. Delete or archive the database and backups according to the retention
   agreement, then verify deletion.
5. Preserve only the consented audit record and aggregate lessons. Do not keep
   customer exports in the source repository or issue tracker.

Infrastructure examples under `deploy/azure` are not an automatic uninstall
contract. Review the deployment plan before destroying any shared resource.
