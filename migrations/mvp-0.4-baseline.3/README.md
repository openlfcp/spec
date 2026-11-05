# Value changes for `mvp-0.4-baseline.3`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.4-baseline.2`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.4-baseline.3` clarifies the depth of admission rule AI2
(IDENTITY-PROFILE-01 §3, task LFCP-04-403d) and adds vectors for it. The
rule is that of `mvp-0.4-baseline.2`. Every suite of `mvp-0.4-baseline.2` is
listed and compared value by value.

No published value changes.

Added, with no published value changed, in `IDENTITY-PROFILE-TEST-VECTORS-01`:
the `identity_doc_*` cases of the AI2 depth boundary, with their
`change.D0_*` and `change.D1_*` records.

- Admitted:
  - a device's scalar over its own list `devices[k].missing_keys[X]`
    (depth 4), with a `.entry` state case in which §4 marks the entry
    invalid;
  - a scalar over the list `devices[k].future[X]` of an unknown field, with
    a `.entry` state case in which the entry stays valid;
  - a scalar over the map `roster[k].ext.a` (depth 4);
  - a scalar over a list held directly at `devices[k]`, which is not an
    entry map.
- Controls:
  - a scalar over the map `roster[k].ext` (depth 3) is `CONTAINER_REPLACED`;
  - the root's scalar over a device's `missing_keys[X]` is
    `UNAUTHORIZED_WRITER` (AI5), not an AI2 refusal.

The cases answer findings of the SDK reviews: sdk-rs#5 P2-1 and sdk-ts#16
P1.
