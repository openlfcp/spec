# Value changes for `mvp-0.1-baseline.3`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.2`, with its old
value, its new value (`null` when the value was removed) and the
SPEC-PATCH-03 decision that approved it.

`scripts/check-baseline-changes.mjs` (run by `scripts/validate.sh`) reads
both suites at the previous baseline tag and compares them with the current
files, case by case:

- a changed or removed value that is not listed fails;
- a listed entry that matches no actual difference fails, so the list
  cannot go stale;
- added cases and added fields are allowed and only counted (`--verbose`
  lists them).

Values that also existed before the move to `lfcp-vector-format/1` are, in
addition, recorded under `changed` in
[`../vector-format-1/`](../vector-format-1/README.md).
