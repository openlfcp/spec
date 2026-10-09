# Value changes for `mvp-0.2-baseline.4`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.3`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.4` changes one published value (below). It adds SS61 to SS63
to the shared sections corpus (below) and clarifies SDK-SECTIONS-INTEGRATION-01 §3.4, §3.5 and §7.7: releasing a
receipt ends the adapter's use of the operation ID, not the batch's status.
A batch released before its status is final (accepted or rejected) is still
reported in the batch statuses, the status snapshot and its events until it
is final, and then forgotten; a new commit with its operation ID replaces it.
An adapter SHOULD release only final batches. `receiptOf` answering `none`
proves that nothing was committed only for an operation that was not
released.

The Obsidian plugin released a receipt when its journal finished an
operation, before the server accepted the batch; after an offline edit and
a restart, the batch was gone from the status while its unit was still
queued, and the plugin showed the updates as accepted (found by the native
run of LFCP-02-066). The orchestrator decided that the SDK keeps reporting
such a batch, with the earlier release only recommended against.

For an implementation the change is: on `releaseReceipt` of a batch that is
not final, stop answering `receiptOf` for it but keep reporting its status
until it is final.

The shared sections corpus gains SS61 to SS63 (B18, hostile maps): A's
next change, valid in every other respect, whose operations exceed a
SHARED-OBJECTS-PROFILE-01 §11.1 limit: 1,000,000 operations in one
run-length-encoded column, one operation with 16,385 predecessors, and
16,384 rows of a 257-byte key. Each is refused with
`INVALID_AUTOMERGE_BYTES` before it is decoded and named by its hash, the
SHA-256 of its chunk from the type byte on. Until now this was checked
only in sdk-ts. The reference admission now applies §11.1 to the raw bytes
(`generator/expansion.mjs`); SS01 to SS60 regenerate byte for byte.

The one changed value: SS44 no longer names its refused change.
SHARED-SECTIONS-PROFILE-01 §14.1 now says how a refused change is named:
by its hash only when its bytes are one type 1 change chunk whose length
field covers exactly the rest, computed without decoding. SS44 is a
compressed chunk (type 2); its name until now was the hash of the inflated
change, so a receiver had to inflate refused bytes to name them, with no
limit on that (a zip bomb). The orchestrator decided that such bytes are
not named. The refusal and its diagnostic are unchanged; the entry has no
`change` field (`value-changes.json` records the field as removed).

For an implementation the change is: name a refused change only from the
header of a type 1 chunk of exact length, and never inflate or decode
refused bytes to name them.
