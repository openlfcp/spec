# Value changes for `mvp-0.1-baseline.9`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.8`, with the
SPEC-PATCH-09 decision that approved it (ADR 0008).
`scripts/check-baseline-changes.mjs` always checks the newest
`mvp-0.1-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SPEC-PATCH-09 changes no published value. It only adds cases: the Wire
vectors gain eight `data_put_previous` cases (the server's `previous` link
check, LFCP-WIRE-01 §51.1) and four `have_difference` cases (§68.1), and the
Automerge reference corpus gains the `collision` section
(SHARED-OBJECTS-PROFILE-01 §14.1, POST-001). The vector format lets an
expected error carry NACK details.
