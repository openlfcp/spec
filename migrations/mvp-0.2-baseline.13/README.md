# Value changes for `mvp-0.2-baseline.13`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.12`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

No published value changes. LFCP-WIRE-01 §26.2 already says that a writer
names its latest own unit still accepted, or none: after a first unit that
went stale (a Key Epoch cut it off) or was abandoned, its unit at sequence 2
has a null `previous`, and a receiver that accepted no unit of the actor
links it. No vector showed a null `previous` after sequence 1, and a client
refused to write one (sdk-ts `createDataUnit`), so a member whose first unit
went stale could not write again.

New cases in LFCP-TEST-VECTORS-01, kind `actor_chain`:

- `chain_prev_null_first_stale_seq2`: CAROL's sequence 2 with a null
  `previous`, received with no accepted unit of CAROL (no `accepted_*`
  inputs): it links and is accepted.
- `chain_prev_null_after_accepted_seq3`: CAROL's sequence 3 with a null
  `previous`, after her accepted sequences 1 and 2: it is held and reported
  (`disposition` `report`).

The server side is already covered by `put_previous_null` (§51.1 does not
check a null `previous`).
