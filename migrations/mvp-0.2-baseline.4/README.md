# Value changes for `mvp-0.2-baseline.4`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.3`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.4` changes no published value and adds no vector. It
clarifies SDK-SECTIONS-INTEGRATION-01 §3.4, §3.5 and §7.7: releasing a
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
