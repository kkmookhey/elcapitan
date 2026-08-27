# Eiger operational-review input

This directory is a read-only, sanitized planning snapshot for the El Capitan
demonstration. It is not Eiger's source of truth and must never be applied.

- `repository/infra/storage.tf` reconstructs the current target declaration from
  local Terraform state because no Terraform source exists in Eiger's Git history.
- `target-state.json` contains only the target storage-account state. Access keys,
  connection strings, Terraform private instance data, and sensitive markers were
  removed before it was checked in.
- `usage.json` contains a small, exact subset of real Azure Monitor hourly samples.
- `service-context.json` records explicit operational assumptions for the SRE agent.

The review worker has a Reader identity only. Its Terraform plan is run with
`refresh=false`, constrained to the state-linked resource, inspected as JSON, and
accepted only when it contains exactly one in-place update with no create, delete,
or replacement action. The binary plan and temporary state are deleted when the
worker exits. Human approval is the terminal state of this worker.
