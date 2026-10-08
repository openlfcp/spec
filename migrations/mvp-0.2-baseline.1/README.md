# Value changes for `mvp-0.2-baseline.1`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.9`.
`scripts/check-baseline-changes.mjs` always checks the newest
`mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

The first MVP 0.2 baseline changes no published value of MVP 0.1: the Wire
vectors, the Shared Objects vectors and the Automerge reference corpus are
those of `mvp-0.1-baseline.9`. It adds two suites, which did not exist at
the previous baseline (`"previous": "absent"`): the shared sections corpus
SHARED-SECTIONS-TEST-VECTORS-01 and the Markdown fixtures
MARKDOWN-SECTIONS-FIXTURES-01 (ADR 0009). Their rationale for every case
that departs from the MVP 0.2 planning material is recorded in the suites
themselves, in each case's `notes` or fixture's `rationale`.
