# Value changes for `mvp-0.2-baseline.11`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.10`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.11` changes no published value. It adds four negative
Wire vectors, three for a rule LFCP-WIRE-01 §48 already states and one for
an order of checks that §32 and §33 now state.

§48 says every live Have Vector, not only the one in `DATA_HAVE`, rejects a
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

§32 and §33 now say that a receiver checks the envelope before the message
type. §32 made a missing Message ID `MALFORMED_MESSAGE` and §33 an
unassigned type `PROTOCOL_UNSUPPORTED`, and neither said which comes first.
Fuzzing the two SDKs against each other found one that decoded the body by
type before it read the Message ID and answered `PROTOCOL_UNSUPPORTED`,
while the other answered `MALFORMED_MESSAGE` (finding W3).

- `unassigned_type_without_message_id`: an envelope of the unassigned type
  117 without field `1`: `MALFORMED_MESSAGE`.

For an implementation the change is: check the Have of `RESOURCE_OPEN` and
`RESOURCE_OPENED` as that of `DATA_HAVE`; and check the envelope (§32)
before the message type (§33).
