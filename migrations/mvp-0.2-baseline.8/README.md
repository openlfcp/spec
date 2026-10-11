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

SHARED-SECTIONS-PROFILE-01 §9 also surfaces a move that a deletion hides.
A new placement of a node (a move or `node.resolve_placement`) concurrent
with the deletion of the node itself or of an effective ancestor (in the
merged state) is reported as `EDIT_UNDER_DELETED_ANCESTOR` on that node,
as a concurrent content edit already was; before, the node was hidden and
the move was lost silently (a finding of the Obsidian integration). A
child moved out of a deleted subtree stays visible with no diagnostic, as
before. The diagnostic is decided from the changes' dependencies and does
not alter convergence. No existing case's value changes: no published case
had such a move.

The shared sections corpus gains SS80 (a move concurrent with the
deletion of the moved node), SS81 (a move under a parent that is
concurrently deleted), both with T in `retainedConcurrentEdits`, and SS82
(a move after the deletion it saw), without. The reference model records a
change's writes to a node's `placement` register as moves.

For an implementation the change is: count a write to a node's
`placement`, like a content change, when checking which hidden nodes were
changed concurrently with a deletion of the node or an effective ancestor.
