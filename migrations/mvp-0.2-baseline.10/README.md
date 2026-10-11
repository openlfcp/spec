# Value changes for `mvp-0.2-baseline.10`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.9`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.10` changes no published value. It makes three rules of
SHARED-SECTIONS-PROFILE-01 explicit, each after a divergence the
differential fuzzing found between the two SDKs.

§14.1 checks the sequence (SHARED-OBJECTS-PROFILE-01 §14.1) before the
structural rules. The profile now says that the sequence checks count
every change of the document, not only those of the change's causal
history: a change whose actor and sequence number another change holds is
held, whatever the structural rules would say of it. One SDK checked a
change that did not depend on the change holding its sequence number
against its causal history alone, found the number free, and refused it
for a section rule (finding E1). SS88 is A's second change at sequence
number 1, without dependencies, creating the section with `ready` =
"yes": held.

A5 refuses a change that writes a scalar to a node's `text`. The profile
now adds: whatever the node's kind, and even when the merged value is a
Text. One SDK checked the text only of a paragraph, item or raw node, as
the merged state shows it (finding E2). SS89 writes a scalar to the
`text` of an item whose `kind` the same change removes; SS90 writes a
scalar and then Text to an item's `text`, both without predecessors, so
the Text wins the merge and the scalar stays a conflicting value. Both
are refused with `INVALID_FIELD_TYPE`.

§14.1 names a refused type 1 chunk of exact length whose checksum matches
without reading its header. The profile now names a header whose
dependencies or actor do not read as one more example. One SDK read the
dependency count and the actor before naming the chunk and named nothing
when they did not read (finding F1). SS91 is such a chunk, its body an
unterminated dependency count: refused with `INVALID_AUTOMERGE_BYTES` and
named by its hash. Its change record carries only that name, since no
dependencies, actor or sequence number read.

The reference model holds a change at a taken sequence number before its
other checks, reads scalar writes to a node's `text` from the change's
operations, and names a malformed chunk whose header does not read.

For an implementation the change is: check the actor's sequence number
against the whole document first; refuse any put of a scalar to the
`text` key of a node map; and name a refused chunk from its type, length
and checksum alone.
