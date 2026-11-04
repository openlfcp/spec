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

Three published values change:

- `IDENTITY-PROFILE-TEST-VECTORS-01`, `suite.description`: the corpus now
  covers the admission rule AI5 (IDENTITY-PROFILE-01 §3, decision I8), so
  the description names "admission AI0 to AI5" instead of "AI0 to AI4". No
  case changes.
- `LFCP-IDENTITY-TEST-VECTORS-01`, `READY_identity_01`: a corpus defect.
  The case was generated with envelope type `1` (`CHALLENGE`) and the wire
  profile `"lfcp-1"`, so its bytes were not a `READY` message (LFCP-WIRE-01
  §33, §37) and a strict decoder rejects them as `MALFORMED_MESSAGE`. It now
  uses type `3` (`READY`) and the profile `"LFCP-WIRE-01"`, as every other
  `READY` of the corpora. `expected.message_cbor` and
  `inputs.wire_profile` change; field `5` (`["identity-01"]`), the Message
  ID, the correlation and the other fields are unchanged. An implementation
  that compared only field `5` passes before and after; one that decoded
  the whole message rejected the old bytes and accepts the new ones.

Added, with no published value changed: in `LFCP-IDENTITY-TEST-VECTORS-01`
six cases, `key_epoch_repeats_current_number` and the five
`key_epoch_wrong_number*` cases (LFCP-WIRE-01 §19, §62 class 2, decision
I9); in `IDENTITY-PROFILE-TEST-VECTORS-01` the `missing_keys_*` admission
cases and scenarios of AI5 (own, foreign and concurrent writes, and hidden,
deleted and replaced entry maps) and the `identity_doc_*entry*` cases of
AI2 on a hidden entry value, with their `change.*` records.
