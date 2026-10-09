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
