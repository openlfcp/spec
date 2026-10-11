# Value changes for `mvp-0.2-baseline.9`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.8`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.2-baseline.9` changes no published value. SHARED-SECTIONS-PROFILE-01
§9 compares an edit or a new placement only with the deletions the
lifecycle register of the node or of an effective ancestor still holds. A
deletion is no longer held once a later write to the same register depends
on it. Before, every deletion in the history counted, so deleting a node
again, a fresh lifecycle write (§9), could not clear
`EDIT_UNDER_DELETED_ANCESTOR`, and a user had no way to keep a node deleted
without the attention staying. An edit concurrent with the new deletion
still raises it. No published case deletes a node twice in sequence, so no
value changes.

The shared sections corpus gains SS83 (SS80, then the node deleted again:
no attention), SS84 (the node deleted again concurrently with a title edit:
attention for the edit), SS85 (SS81, then the ancestor deleted again: no
attention), SS86 (a move concurrent with one of two concurrent deletions:
attention) and SS87 (SS86, then the node deleted again: no attention). The
reference model records each change's last write to a node's lifecycle
register, the Task's for a task node, and counts a deletion only while no
later write to that register depends on it. It also no longer misses a
deletion merged after a concurrent one, which SS86 checks.

For an implementation the change is: when checking which hidden nodes were
changed concurrently with a deletion, skip a deletion of the node or an
ancestor when a later write to the same lifecycle register (one whose
change has the deletion's change among its dependencies) exists.
