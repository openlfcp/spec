# Value changes for `mvp-0.2-baseline.8`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.7`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.8` changes no published value. SHARED-SECTIONS-PROFILE-01
§14.1 names a refused change from its chunk alone: one type 1 chunk whose
length field covers exactly the rest and whose checksum matches, by the
SHA-256 of the chunk from its type byte on. The profile now says outright
that the change header is not read for this, so a chunk whose header is
malformed is named all the same. One SDK named a refusal only when it
could read the header, and left a chunk unnamed whose header held a length
running past its end; the other named it (finding C3 of the differential
fuzzing).

The shared sections corpus gains SS79: A's change whose header gives a
message length of 1 MiB, past the end of the chunk, with its length field
and checksum recomputed. It is refused with `INVALID_AUTOMERGE_BYTES` and
named by its hash. Its change record carries the hash, dependencies, actor
and sequence number read from the start of its header, which Automerge
does not decode.

For an implementation the change is: name a refused type 1 chunk of exact
length whose checksum matches without parsing its header.
