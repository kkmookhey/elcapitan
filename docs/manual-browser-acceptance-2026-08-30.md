# Manual browser acceptance — 2026-08-30

This record covers rendered acceptance of the local, synthetic El Capitan
browser surfaces. It is release evidence, not authorization to tag, publish,
connect a cloud identity, or use customer data.

## Environment

- Chromium was operated manually because no in-app browser surface was
  connected to Codex.
- The shadow console used the checked-in `SYNTHETIC-QUICKSTART` finding and
  local PostgreSQL Compose deployment.
- The review and lifecycle services used locally generated `TEN-DEMO` records,
  recorded agent results, and filesystem reference execution only.
- No cloud request, model request, customer data, production resource, or
  Eiger operation occurred.

## Surfaces reviewed

| Surface | Rendered proof |
|---|---|
| Shadow fleet | Fleet overview, exact one-case/one-finding accounting, offline connector state, synthetic-input label, and read-only boundary rendered correctly |
| Shadow case detail | Case identity, synthetic ARM identifier, control target, risk rationale, separate validation/planning/execution authority, evidence grade, operational-review block, and immutable timeline were legible |
| Human review | Tenant-bound queue, exact package and hash, Terraform checks, live validation, SRE decision, change window, rollback review, deterministic policy checks, and package-specific approval dialog rendered correctly |
| Synthetic lifecycle | Evidence-bound product label, review package, exact diff, audit timeline, stage sequence, and human-approval boundary rendered correctly |
| Keyboard focus | The shadow and review tenant inputs showed a visible focus indicator contained within their joined input/button controls |

## Defects found and corrected

The first manual pass found four release-polish defects:

1. The synthetic lifecycle still used an `Autonomous remediation fleet` label,
   contradicting the technical-preview promise.
2. The tenant-input focus outline collided with the adjacent action button.
3. Dense evidence typography was too small.
4. The lifecycle stage dialog recursively rendered the complete human-review
   package, producing excessive vertical whitespace, deeply narrowed columns,
   and truncated mobile content. A populated package also retained its empty
   placeholder because component CSS overrode the HTML `hidden` state.

The corrected implementation uses the `Evidence-bound remediation fleet`
label, contains the joined-control focus ring, increases dense-text sizes,
enforces hidden-state display, summarizes the human-review package to its
decision, case, risk, and bound record IDs, limits evidence-ID display to a
count and four samples, and stacks nested values responsively. The focused
HTTP/asset contracts and JavaScript syntax checks passed before the second
manual pass. The owner then reloaded all three services and accepted the
corrected rendering.

## Screenshot handling and remaining limits

The manually supplied captures are acceptance evidence only. They were not
copied into the repository because several include personal browser chrome,
extension/profile indicators, or non-viewport UI. Release screenshots still
must be captured from a clean profile, cropped to the application viewport,
reviewed pixel by pixel, and committed under sanitized launch filenames.

This pass is not an exhaustive screen-reader certification or a broad device
matrix. Semantic HTML, accessible dialog names/descriptions, live status
regions, reduced-motion behavior, cross-origin rejection, and keyboard-focus
styling retain their automated contract coverage.
