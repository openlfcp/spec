# Value changes for `mvp-0.1-baseline.5`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.4`, with the
SPEC-PATCH-05 decision that approved it (ADR 0004).
`scripts/check-baseline-changes.mjs` always checks the newest
`mvp-0.1-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SPEC-PATCH-05 changes no published value. It only adds cases: the
`actor_chain` cases of G-DP1-GAP, the `invite_uri` parsing cases, and the
INVALID_AUTOMERGE_BYTES negatives of the Automerge reference corpus.
