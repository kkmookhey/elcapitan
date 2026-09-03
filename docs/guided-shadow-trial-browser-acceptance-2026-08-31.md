# Guided Shadow Trial browser acceptance — 2026-08-31

This record covers rendered acceptance of the local Guided Shadow Trial
checkpoint. It is product-review evidence, not authorization to connect a
cloud identity, use customer data, deploy, publish, or release.

## Environment and boundaries

- The authenticated shadow service ran on loopback from source base `7e2b0b4`
  with an isolated temporary work directory and ephemeral local access token.
- Chrome was reviewed at its default desktop viewport, a 1024 × 768 tablet
  breakpoint, and a 390-pixel-class mobile breakpoint.
- Inputs were the built-in synthetic Azure sample and the checked-in AWS
  Security Hub ASFF fixture at `tests/fixtures/securityhub-asff-real.json`. No
  customer export or customer identifier was used.
- Connectors remained offline. No cloud request, model request, execution
  request, external write, deployment, or publication occurred.

## Observed flows

| Flow | Rendered evidence |
|---|---|
| Restricted access | The login page identifies the shadow trial, explains the read-only restriction, and opens the read-only workspace with an operator-supplied token. |
| First-use welcome | The three starting paths—scanner-export preview, safe sample, and connector status—are visible with the preview/import/check/review sequence and workspace-data warning. |
| Safe sample | The synthetic Azure sample opens directly into a no-write preview. Counts, support status, safety boundary, and explicit import action remain visible without exposing raw JSON by default. |
| ASFF input | A checked-in AWS Security Hub export was selected through the native Chrome file chooser and previewed as one failing ASFF finding, one unsupported control, and zero findings eligible for a cloud check. The same fixture was previously imported through the visible paste path into an isolated workspace. |
| Results | Supported and unsupported findings use plain-language current-result and next-step labels. Synthetic and real inputs remain visibly distinct. Findings render before optional connectors. |
| Detail and evidence | Scanner context, exact cloud scope, separate validation/planning/execution authority, evidence grade, safety boundary, next step, current evidence, and immutable timeline are readable through progressive disclosure. |
| Fail-closed states | An unsupported control has no cloud-check action, says planning is unavailable for that control, remains in the scanner workflow, and produces no inferred cloud conclusion. The batch-check action remains disabled when connectors or control support leave nothing ready. |
| Responsive and keyboard | The import action remains visible in the mobile preview; finding rows become labeled mobile cards; tablet and desktop tables remain legible; Enter opens a workspace; Escape closes native dialogs; the chosen workspace survives reload. |

## Defects found and corrected

The acceptance pass found and corrected activation issues before this record
was finalized:

1. The safe sample expanded raw JSON by default and pushed the import action
   below the useful mobile preview area.
2. Several result and detail labels exposed workflow vocabulary instead of a
   customer outcome, and an empty portfolio-rank value rendered as a stray
   dash.
3. The optional connector panel appeared before findings on narrow screens,
   while the results table remained a dense horizontally oriented table.
4. The selected workspace was not written back after every load, so a reload
   could reopen the previous workspace.
5. A prior action toast could remain while changing workspaces.
6. An unsupported control said a cloud check was required even though no
   deterministic check existed.
7. The inherited login copy described a generic demo rather than the
   restricted shadow-trial surface.

The corrected implementation keeps the import decision close to its preview,
uses outcome-oriented language, renders labeled mobile result cards, places
findings before optional connectors, persists the current workspace, clears
stale status, gives unsupported controls an honest scanner-workflow next step,
and uses shadow-specific access copy.

## Native file-picker verification

After enabling **Allow access to file URLs** for the Chrome automation
extension, the native chooser selected
`tests/fixtures/securityhub-asff-real.json`. The rendered dialog showed the
expected filename and size, identified one AWS Security Hub ASFF failure, and
offered an explicit **Import 1 finding** action. The preview remained a separate
no-write step and made no cloud or model request.

## Screen-recording follow-up — 2026-09-01

The 43-second owner recording
`CC56D092-257F-4015-AF86-F19FA840BDB3.mov` exercised the first-use welcome,
native chooser, safe preview, explicit import, results, evidence detail,
return-to-start path, repeated sample intake, and connector-offline batch
action. It exposed three remaining activation ambiguities:

1. supported findings were described as immediately checkable even while both
   connectors were offline;
2. **Switch workspace** returned to the start screen without changing the
   current workspace; and
3. two observations grouped into one resource row were not explained.

The corrected surface now separates **supported** from **ready now**, disables
the batch action and labels it **No cloud checks ready** when no resource can
run, names the destination workspace in the import preview, renames the return
action **Back to start**, and reports both observations and resources in the
summary and grouped row. Import feedback distinguishes a new resource from an
observation added to an existing resource.

The recording is internal acceptance evidence only. It includes browser tabs,
profile and extension indicators, and operating-system capture controls, so it
must not be used as a public or release-safe asset.

This pass is not a full screen-reader certification or a broad physical-device
matrix. Semantic labels, dialog names/descriptions, live status, focus styling,
reduced-motion behavior, authentication, request bounds, and tenant isolation
retain automated contract coverage.
