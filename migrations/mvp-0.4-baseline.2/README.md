# Value changes for `mvp-0.4-baseline.2`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.4-baseline.1`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.4-baseline.2` clarifies rules of `mvp-0.4-baseline.1` (decisions I8,
I9 and I12, tasks LFCP-04-403b and LFCP-04-403c) and adds vectors for them.
Every suite of `mvp-0.4-baseline.1` is listed and compared value by value.

One published value changes:

- `IDENTITY-PROFILE-TEST-VECTORS-01`, `suite.description`: the corpus now
  covers the admission rule AI5 (IDENTITY-PROFILE-01 §3, decision I8), so
  the description names "admission AI0 to AI5" instead of "AI0 to AI4". No
  case changes.

Added, with no published value changed: in `LFCP-IDENTITY-TEST-VECTORS-01`
the six `key_epoch_wrong_number*` and `key_epoch_repeats_current_number`
cases (LFCP-WIRE-01 §19, §62 class 2, decision I9); in
`IDENTITY-PROFILE-TEST-VECTORS-01` the `missing_keys_*` admission cases and
scenarios of AI5, with their `change.*` records.
