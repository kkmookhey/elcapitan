# Azure asset-context shadow trial — 2026-09-01

## Scope and safety boundary

The repository owner authorized one test-only Azure subscription and supplied a
Prowler ZIP export. This acceptance used the primary OCSF report and explicit
read-only Azure CLI management-plane queries targeted with `--subscription`;
it did not change the CLI default subscription. No cloud mutation, data-plane
read, model call, approval, scheduling, deployment, or execution occurred.

The original ZIP remained unchanged. Two derived local files were written with
mode `0600` under the owner's Downloads directory: the extracted primary OCSF
report and an asset-context manifest. They are private trial inputs and are not
tracked by this repository. The browser imports used disposable local shadow
workspaces.

## Input and inventory accounting

The primary report contained:

- 274 OCSF observations;
- 179 explicit failures, 91 passes, and 4 manual checks;
- 59 unique failing resource identifiers;
- 95 findings supported for deterministic read-only validation and 84 not yet
  supported.

The live management-plane inventory contained 45 current resources. Read-only
exposure observations covered Storage, SQL Server, Cognitive Services/Azure
OpenAI, Search, public IP, network-interface/VM attachment, and broad inbound
NSG configuration. Explicit Prowler `internet-exposed` evidence was used only
where the live query contract did not expose the needed property. Unknown
exposure remained `null`.

Business context was intentionally synthetic and deterministic:

- 12 resources labeled production;
- 14 resources assigned criticality of at least 0.8;
- synthetic owners and services derived consistently for the trial;
- no reachability or runtime-dependency points, because no path or dependency
  evidence was supplied;
- every row marked `synthetic_business_context: true`.

## Exact join result

The no-write preview reported:

- 45 asset rows;
- 26 exact normalized ARM-ID matches covering 123 failing observations;
- 33 finding resource identifiers without top-level asset context;
- 19 current inventory resources without a failing finding;
- 21 matched resources with observed internet exposure; and
- 10 matched critical resources.

The gaps are expected and useful. They include subscription, Entra, Defender
pricing, logical check, key/secret, subnet, and other subresource identifiers
that should not inherit top-level business context through fuzzy matching.

## Prioritization result

The 59 resource cases produced 2 high, 44 normal, and 13 low priorities. No
urgent priority was fabricated without exploit, reachability, or active-
exploitation evidence.

The top case scored 64 from one score-driving observation:

- critical scanner severity: 40;
- synthetic asset criticality 0.7: 14;
- observed internet exposure: 10.

The deliberately synthetic-critical, public-IP-attached Juice Shop VM scored
60 from high severity, criticality 1.0, and observed internet exposure. The UI
shows the score-driving observation first and lists every other observation on
the same resource with its independent score. Finding scores are not summed,
and the case-level factors and evidence IDs come only from the winning
observation.

## Browser acceptance

Authenticated local Chrome acceptance covered:

- native selection of the 1.9 MiB primary report;
- the scanner-only preview before asset context was attached;
- native selection of the 45-row asset manifest;
- automatic collapse of the large manifest editor and visible row count;
- exact match/gap, critical, exposure, supported, and skipped accounting;
- explicit import of all 179 failures into 59 resource cases;
- resource ordering and synthetic-business-context labels;
- the score-driving observation, per-observation scores, asset provenance, and
  context digest in the case drill-down; and
- an empty browser warning/error console.

## Evidence-to-outcome demo refresh

The populated private trial workspace is now the review target for the local
shadow demo. The UI presents two deliberately separate layers:

1. findings and their scanner/source format;
2. normalized resource-oriented cases;
3. bounded validation state;
4. transparent priority and its score-driving evidence;
5. the current customer outcome;
6. then, beyond a visible human-authority boundary, remediation preparation,
   package assembly, human review, deployment, and monitoring.

The second layer is explanatory and locked in shadow mode. Authenticated API
acceptance confirmed 179 `Prowler 5.36.0` findings in `OCSF 1.5.0`, 59 cases,
the expected 2 high / 44 normal / 13 low distribution, and six cases whose
registered controls have planning and execution capability. Capability counts
do not grant workflow authority: the shadow API still reports approval,
scheduling, and execution as prohibited and exposes none of those routes.

## Owner-authorized live validation

The owner then authorized a real read-only validation pass against the exact
test subscription. The ambient Azure CLI user was not accepted: its default
subscription differed and the identity contract deliberately ignores ambient
sessions. No reusable scanner identity existed, so an owner-approved temporary
service principal named `elcapitan-test-shadow-scanner` was created with only
the Reader role on the test subscription. After evidence collection completed,
the Reader assignment, service principal, application registration, local
credential, and cleanup metadata were removed on 2026-09-03 and verified
absent. The Azure CLI default subscription was not changed.

The pass processed all 23 resource cases containing deterministic support:

- 93 of 95 supported findings were confirmed against current Azure state;
- 21 cases advanced to validated;
- 2 cases remained blocked because the findings claimed Azure OpenAI while
  the live accounts reported the broader `CognitiveServices` kind;
- 19 unsupported sibling findings were recorded explicitly in mixed cases;
- 36 unsupported-only cases remained prioritized without a cloud conclusion;
- no supported finding was reported cleared; and
- no data-plane read, model call, planning, approval, scheduling, deployment,
  or resource-configuration mutation occurred.

The first pass also exposed two integration gaps. An absent optional ARM
container-retention policy is now correctly treated as soft delete not being
configured, while malformed non-null policy shapes still fail closed. Prowler's
canonical `fileServices/default` child resource is now resolved to its owning
storage account for the bounded account/blob/File Service reads while the
original child ARM ID remains in the evidence envelope. A recoverable private
archive preserves the first run; the active workspace was restored from its
pre-validation snapshot and rerun after both fixes.

## Layer 2 preparation boundary

Six validated Azure Storage resource cases contain one or more controls with
deterministic remediation-planning support. They are now represented as
preparation candidates, not prepared plans. For mixed cases, promotion selects
only the exact findings that are both live-confirmed and planning-capable;
unsupported, unavailable, cleared, and confirmed-but-unplannable siblings stay
visible as excluded scope. The promotion token and downstream plan record bind
that exact finding/evidence set.

The supplied project checkout does not contain authoritative Terraform for
these six test resources. The result is therefore intentionally 6 candidates,
0 prepared plans, 0 packages, and 0 human-review decisions. Actual preparation
requires the owner-controlled IaC/state, service context and health contract,
usage telemetry, and explicit maker/SRE/window/rollback reviewer routes. No
cloud mutation or approval authority was added to the shadow service.

A subsequent owner-authorized pilot generated a private, non-authoritative
Terraform baseline and disposable local state for one single-control storage
candidate. Reader-only Shared Key import failed on the intentionally absent
`listKeys` permission; Azure AD storage mode succeeded without storing a key or
connection string. The exact-target, no-refresh plan contains one in-place
public-network-access update and no create or delete action.

The account has no private endpoint, virtual-network rule, or IP rule, so
public-network removal would eliminate its only configured connectivity path.
The owner subsequently confirmed that the test resource is unused and requested
human-review package preparation. No apply or Azure resource-configuration
mutation was performed.

A 30-day, owner-requested Azure Monitor assessment then found only 15
transactions, all service-property reads, across four hourly buckets. No
object/blob read, write, list, or delete API appeared in the dimensioned metric
series; used capacity was 374 bytes and no resource Activity Log event appeared
in the period. The owner attestation now supplies the previously missing usage
decision. The assessment read no storage object content or identifiers.

The private workspace contains a `HumanReviewPackageCandidate.v1` body, owner
attestation, identity-cleanup evidence, Markdown guide, and large-type HTML
review page. Its canonical body SHA-256 is
`40b5547350985d20ab26a99f9d17492447eaeea3a2b1a076e9c62e7ab1b19d8f`.
This is ready for reviewer routing but has not been admitted as
`HumanReviewPackage.v1`: formal maker records, independent SRE review, a future
window, independent rollback review, and the configured model-diversity policy
must pass first. The shadow case remains `validated`; no approval, schedule, or
execution authority was added.

## First owner calibration

The first queue review produced one direct calibration decision: the two NSG
findings for broad inbound SSH should carry equal risk. Their earlier scores of
58 and 56 differed only because the synthetic criticality assignments were 0.9
and 0.8. The second NSG is now 0.9, its manifest evidence records the owner
calibration, and both observations score 58.

Two tightly scoped read-only follow-ups added decision context without changing
the trust boundary:

- One inactive Azure OpenAI demo resource has public networking enabled, no
  network ACL, no private endpoint, no model deployments, a demo-project tag, and zero
  `TotalCalls` from 2026-06-01 through 2026-09-01. Its public exposure is real,
  but the production label and 0.9 criticality remain synthetic and likely
  overstate an inactive demo resource unless an owner identifies a dependency.
- One storage account is the system datastore for a public Azure ML workspace.
  Anonymous blob access is disabled, while the storage network default is
  `Allow`, minimum TLS is 1.0, no private endpoint exists, and the workspace
  uses access-key authentication for system datastores. Four private containers
  identify Azure ML artifacts and Azure diagnostics. Object listing was denied
  by data-plane RBAC, so no blob was downloaded and data sensitivity remains
  unverified; Shared Key access was not used as a bypass.

## Remaining prioritization work

- Add first-class inventory identities for Entra, endpoint, and other
  non-resource entities before consuming a production CTEM dataset.
- Add finding-level threat context keyed by CVE or control identity; do not put
  EPSS, KEV, or active-exploitation facts in the asset inventory.
- Add observed reachability and dependency graphs with their own evidence
  contracts.
- Decide how asset context is versioned or refreshed after immutable intake;
  this checkpoint deliberately binds the context row present at ingestion.
- Calibrate customer-specific weights and thresholds against an owner-ranked
  top set rather than treating the current defaults as universal.
