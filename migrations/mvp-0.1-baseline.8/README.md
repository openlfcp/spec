# Value changes for `mvp-0.1-baseline.8`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.7`, with the
SPEC-PATCH-08 decision that approved it (ADR 0007).
`scripts/check-baseline-changes.mjs` always checks the newest
`mvp-0.1-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SPEC-PATCH-08 changes no published value. It only adds the Automerge
reference corpus `depth` section: change sequences at and past the §11.2
document depth bound, and Snapshots at depths 256 and 257.
