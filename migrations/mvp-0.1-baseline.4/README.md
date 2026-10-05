# Value changes for `mvp-0.1-baseline.4`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.3`, with its old
value, its new value (`null` when the value was removed; `from: null` for
an added value that changes what an existing case means) and the
SPEC-PATCH-04 decision that approved it (ADR 0003). `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.1-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

The Automerge reference corpus,
`test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json`,
is new in this baseline (SPEC-CORPUS) and is marked `"previous": "absent"`:
every value in it counts as added, including the SO-SEC1 negative.

Changed values: `hpke_recipient_mismatch_KP0` (KP-1), the note of
`extension_type_non_owner_C1` (general code rule) and the S04 and S08
intent names (G-SC5). Added values listed explicitly: the error codes of
four codeless negatives and the issuer descriptor reference of
`extension_type_non_owner_C1`. The G-SC5 values are also recorded in
[`../vector-format-1/shared-objects-01.mapping.json`](../vector-format-1/shared-objects-01.mapping.json).
