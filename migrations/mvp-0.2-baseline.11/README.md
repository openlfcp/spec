# Value changes for `mvp-0.2-baseline.11`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.10`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.11` changes no published value and no normative text. It
adds three negative Wire vectors for a rule LFCP-WIRE-01 §48 already
states: every live Have Vector, not only the one in `DATA_HAVE`, rejects a
range with `start > end` or one that includes sequence `0` with
`MALFORMED_MESSAGE`. Fuzzing the server found that it answered
`RESOURCE_OPENED` to a `RESOURCE_OPEN` whose Have held such a range (finding
S2); the only published negative was `data_have_reversed_range`.

- `resource_open_reversed_range`: `RESOURCE_OPEN` with a BOB extra range
  written 7..5.
- `resource_open_range_sequence_zero`: `RESOURCE_OPEN` with a BOB extra
  range 0..2.
- `resource_opened_reversed_range`: `RESOURCE_OPENED` with a BOB extra
  range written 7..5, for the client side.

For an implementation the change is: check the Have of `RESOURCE_OPEN` and
`RESOURCE_OPENED` as that of `DATA_HAVE`.
