# Value changes for `mvp-0.2-baseline.12` (draft)

**Draft.** This directory belongs to a proposed baseline that is not tagged.
The owner decides whether and when `mvp-0.2-baseline.12` is tagged, and
approves the decisions below.

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.11`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SHARED-OBJECTS-PROFILE-01 §45 now says that concurrent equal values of a
scalar register agree: a field is conflicted only when its concurrent values
differ, and its conflict set is the set of its distinct values.
SHARED-SECTIONS-PROFILE-01 already said so for `LIFECYCLE_CONFLICT` (§14.3)
and now says it for every scalar register, placements included (§7).

Two published values follow from the rule:

- SS86: A moves T and then deletes it while B deletes it, so both branches
  write `lifecycle = deleted`. The corpus listed that as a scalar conflict
  with the values `deleted`, `deleted`. The values agree, so
  `expected.state.scalarConflicts` is now empty. The case's tree, hidden
  nodes, recovery and attention are unchanged: §14.3 already treated it as
  no `LIFECYCLE_CONFLICT`.
- The Automerge reference corpus convention `conflicts` says the conflict
  sets list distinct values, and only when there are two or more. No
  scenario's conflicts change: none of S01 to S16 has equal concurrent
  values.

New cases: S17 (equal status writes), S18 (equal restores) and S19 (two
equal writes and a different one) in SHARED-OBJECTS-TEST-VECTORS-01; SS92
(equal restores), SS93 (equal status writes) and SS94 (different status
writes) in the shared sections corpus.

MARKDOWN-SECTIONS-01 §4.3 now says that a paragraph marker followed directly
by another node marker binds an empty paragraph that keeps its identity. The
fixture MS17-empty-adjacent is added after MS45, so the published fixtures
keep their index; the fixture ID pattern of
`test-vectors/shared-sections-01/schemas/markdown-fixtures.schema.json` allows
more than one suffix part for it. No fixture value changes.

LFCP-WIRE-01 §47 adds a writer rule (SHOULD): a writer chains each new
Control Record on its own latest pending record and, on
`CONTROL_HEAD_MISMATCH`, re-proposes a still-authorized, still-meaningful
record on the new head with its intent unchanged, with bounded attempts.
`wire/LFCP-WIRE-01.cddl` and `wire/LFCP-WIRE-01.summary.cddl` are re-extracted
(source line numbers only). No vector is added or changed: the rule binds a
writer's choices, which a vector of single messages does not show.
