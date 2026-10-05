# Value changes for `mvp-0.1-baseline.6`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.5`, with the
SPEC-PATCH-06 decision that approved it (ADR 0005).
`scripts/check-baseline-changes.mjs` always checks the newest
`mvp-0.1-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SPEC-PATCH-06 changes no published value. It only adds cases: the
behavioral scenarios S15 and S16 (a concurrent scalar title conflict, then
a write to the conflicted object) with their Automerge corpus entries, and
the corpus `validations` for SO-STRINGS pointer granularity.
