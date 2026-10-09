# Value changes for `mvp-0.2-baseline.3`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.2`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works. Until `mvp-0.2-baseline.2` is tagged, the manifest names the
commit that tag names.

`mvp-0.2-baseline.3` changes no published value. It clarifies
SHARED-SECTIONS-PROFILE-01 §7.6: a node whose lifecycle is in conflict is
blocked, not hidden, whichever value the engine shows provisionally, and an
edit under it is not an edit under a deleted ancestor until the conflict is
resolved. The two SDKs differed here (found by the seeded schedules,
LFCP-02-024, seed 2); the orchestrator decided for blocking, as for a
placement conflict (§7.2). The shared sections corpus gains SS60, the
reference model follows the rule, and no earlier case changes: the
regenerated corpus is byte-identical for SS01 to SS59.

For an implementation the change is: under a lifecycle conflict, do not
report the node as hidden and do not report an edit under it as retained
under a deleted ancestor.
