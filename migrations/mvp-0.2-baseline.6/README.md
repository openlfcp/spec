# Value changes for `mvp-0.2-baseline.6`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.5`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.6` changes no published value. It bounds the header
numbers of a change in SHARED-OBJECTS-PROFILE-01 §11.3 rule 2: the sequence
number is below 2^53, and the time is above -2^53 and below 2^53. A
JavaScript number holds these exactly; Automerge JS does not decode a change
outside them ("can't be represented as a JavaScript number"), while
automerge-rs 0.12 applies it, so the two SDKs disagreed (finding D2 of the
differential fuzzing). Rule 8 already bounds the start op below 2^32.

SHARED-OBJECTS-PROFILE-01 §14.1 and SHARED-SECTIONS-PROFILE-01 §14.1 now
say when each check is made. What a change's bytes alone decide (the chunk
of §11, the column walk of §11.1, the canonical encoding of §11.3, then the
change's actor) is checked when the change arrives: a change that fails it
is refused at once, before its actor is compared with the signer's and
whether or not its dependencies are present. The checks that read the
document (the other actors of §11.1, §11.2, §11.4, the sequence checks of
§14.1, the section rules) wait for the dependencies. One SDK held a change
with a missing dependency and a time beyond 2^53 until the dependency came,
the other refused it (the D2b form); one refused a foreign change with a
sequence number of 2^53 for its actor, the other for its bytes (the D7
form).

The Automerge reference corpus gains five `canonical` cases, appended after
the earlier ones, which are addressed by index: `CAN-2-time-largest` and
`CAN-2-time-smallest` (the times 2^53 - 1 and -(2^53 - 1), admitted), and
`CAN-2-time-2pow53`, `CAN-2-time-minus-2pow53` and `CAN-2-seq-2pow53`
(refused). The shared sections corpus gains SS66 to SS69, all refused with
`INVALID_AUTOMERGE_BYTES`: the time 2^53; the time 2^56 - 1 with a
dependency no replica holds, and the sequence number 2^53 with one, refused
rather than held; and a change signed by another Principal with the sequence number 2^53,
refused for its bytes rather than its actor.

For an implementation the change is: refuse a change whose sequence number
is 2^53 or more, or whose time is 2^53 or more or -2^53 or less, with
`INVALID_AUTOMERGE_BYTES`, as part of the canonical check; and make the
checks of a change's bytes, then its actor, before waiting for its
dependencies.

SHARED-OBJECTS-PROFILE-01 §14.1 also allows an Automerge author only in an
actor's first change. The extra bytes after a change's columns are free
(§11.3 rule 4), but automerge 0.12 reads an author from them (an unsigned
LEB128 1, a length `L`, then `L` bytes) and asserts that the change's
sequence number is 1: on a later change, Automerge JS aborts applying it
while sdk-rs refused it (finding D5). A receiver checks this with the
sequence number, once the dependencies are present. The shared sections
corpus gains SS70: A's third change with an author, refused with
`INVALID_AUTOMERGE_BYTES`. The sections reference admission now compares
its canonical re-encoding up to the extra bytes, which rule 4 allows.

For an implementation the change is: refuse, with `INVALID_AUTOMERGE_BYTES`,
a change whose extra bytes begin with an author and whose sequence number
is not 1.

SHARED-SECTIONS-PROFILE-01 A5 now names where collaborative Text is
refused: in any field of the section, of a node other than its `text` and
of a placement, and anywhere in a Task (SOP §30), whether or not the
profile defines the field. One SDK checked only the fields the profile
names, and admitted Text in a node field `texr` (finding D3). The shared
sections corpus gains SS71 to SS74, Text in an undefined field of a node,
the section, a new placement and in a Task's `extensions`, all refused with
`INVALID_FIELD_TYPE`; the reference admission checks every field.

For an implementation the change is: refuse, with `INVALID_FIELD_TYPE`, a
change that makes Text in any such field, not only in the fields of §4.
