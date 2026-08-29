# Security design: evidence before authority

El Capitan's security posture begins with a refusal to treat a scanner finding,
model response, or approval click as sufficient authority for a cloud change.
The technical preview separates observation, reasoning, decision, and action so
each boundary can be constrained and audited.

## Read-only observation

Live validation accepts only explicit scanner credentials. Ambient cloud
profiles are ignored. Each control pack defines the exact management-plane
reads it needs and the normalized evidence fields it may retain. Collectors do
not list application data, storage keys, Key Vault secrets, or arbitrary cloud
configuration.

The public shadow service exposes intake, portfolio, validation, evidence, and
timeline operations. It has no approval, scheduling, model, or execution route.
An action identity therefore has no place in a shadow deployment.

## Minimized, typed evidence

Evidence records preserve provider, resource, control, observation time,
availability, provenance, and the small set of fields consumed by a
deterministic evaluator. Large or sensitive inputs remain behind hashed
artifact references. Terraform state is used only to resolve an exact resource
when necessary; the stored record contains the matched address and a state
hash, not the complete state document.

Unknown enum values, malformed shapes, authorization denial, absent required
properties, and stale or mismatched evidence fail closed. They cannot silently
become a passing observation.

## Package-bound human approval

Planning happens in an isolated repository copy and never runs `terraform
apply`. A review package identifies the exact evidence, source/proposal hashes,
verified plan, operational review, window, rollback steps, triggers, and
verification criteria. Approval requires an authenticated, typed confirmation
and creates an immutable decision bound to that package hash. Changing the
package invalidates the authority.

Shared access tokens in the preview are local/demo and pilot bridges, not
production authentication. Customer approval requires the planned trusted
Entra ID adapter or an independently reviewed identity-aware proxy.

## Separate, narrow action authority

Approval does not imply executability. A live change also requires a connector
implemented for that exact control, a separately scoped mutation identity, a
declared health contract, a checkpoint, monitoring, verification, and a tested
rollback path. The current live action surface is limited to two Azure Storage
controls in an explicitly tagged non-production lab. Other validated controls
do not inherit that authority.

Workers enforce leases, change windows, drift checks, and post-change health.
A failed health or verification gate stops rollout and invokes the recorded
rollback path. Every terminal outcome remains visible to the originator.

## Build and release boundary

The repository pins container bases by digest and runtime dependencies by
version and hash. CI checks distributions, generated capability metadata,
dependency changes, new secret findings, and container vulnerabilities. The
guarded release workflow produces checksums, SBOM and provenance attestations,
but it cannot run without an approved tag, an exact confirmation phrase, and a
protected release environment.

The preview is not ready for public publication yet. Legal/business owners must
approve the license and project name, and an authorized security owner must
adjudicate the checked-in baseline of 22 historical secret-scan fingerprints,
rotate any live material, and approve history cleaning where required. The
baseline prevents regression; it is not a declaration that old matches are
safe.
