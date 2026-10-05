# Value changes for `mvp-0.1-baseline.7`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.6`, with the
SPEC-PATCH-07 decision that approved it (ADR 0006).
`scripts/check-baseline-changes.mjs` always checks the newest
`mvp-0.1-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SPEC-PATCH-07 changes no published value. It only adds cases to the
Automerge reference corpus:
- the `expansion` section: change cases at and past the exact §11.1
  limits, the measured RLE bomb, a compressed change, and Snapshot cases
  at and past the §13.1 floor;
- the `validations` `SO-DEPTH-64` (valid) and `SO-DEPTH-65` (one
  `INVALID_FIELD_TYPE`) for the §30 nesting bound.
