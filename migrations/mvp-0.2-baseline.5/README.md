# Value changes for `mvp-0.2-baseline.5`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.4`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.5` changes no published value. It clarifies
SHARED-OBJECTS-PROFILE-01 §11.3 rule 8: the start op is below 2^32 even for
a change without operations. The rule bounded the change's last operation
counter, `start op + N - 1`, which for `N = 0` is `start op - 1`, so a
change without operations and a start op of 2^32 passed it, while
automerge-rs 0.12 refuses that start op (`CounterTooLarge`); found by the
fuzzing of the baseline.3 admission (N1). The Automerge reference corpus
gains `CAN-8-start-op-empty`, that change, refused.

For an implementation the change is: refuse a change whose start op is
2^32 or more, whatever its number of operations.

It also adds SHARED-OBJECTS-PROFILE-01 §11.4 R8 and R9, which Shared
Sections inherits. R8: an increment (action 5) has at least one
predecessor, and every predecessor is a put of a counter value on the same
object and key; this is what Automerge writes, an increment naming the puts
that set the counter (two after a merge of two concurrent counters).
R9: no operation is a mark (action 7); neither profile writes marks, and
how marks pair and where they go is not defined. Both close what §11.4 left
open (the fuzzing of the baseline.3 admission). No writer of either profile
emits increments or marks; the existing references cases, whose history
increments a counter, keep their values. The references section gains
`REF-control-increment` and `REF-control-increment-two-counters` (admitted),
three R8 refusals and `REF-R9-mark`,
appended after the earlier cases, which are addressed by index.

For an implementation the change is: refuse an increment without a
predecessor or with a predecessor that is not a counter put, and refuse any mark operation, with
`INVALID_AUTOMERGE_BYTES`.

SDK-SECTIONS-INTEGRATION-01 §5 now says which nodes a `nodes-changed`
event lists: those of the `affectedNodeIds` rule of §3.2, for every origin
(`local`, `remote`, `rebuild`), with a Task's fields counted as its task
node's and the title as the section's. §5 listed the event's fields but not
its nodes, and an SDK did not report remote edits of Task fields or of the
title (the native run of LFCP-02-066, sdk-ts 06ead0d). An SDK may list more
nodes, never fewer. No vector changes.

SHARED-OBJECTS-PROFILE-01 §11.4 also gains R10: no operation makes a
table (action 6). A change that makes a table and writes into it is
canonical and refers only into its history, but automerge 0.12 aborts
applying it ("Missing from Index"), and Automerge JS terminates its wasm
module (finding D1 of the fuzzing). No writer of either profile makes
tables, and no corpus change does. The references section gains
`REF-R10-make-table` and `REF-R10-write-into-table-D1`, and the shared
sections corpus SS64, the same change on the section receive path; all
refused. An implementation refuses a table before its engine sees the
change.

