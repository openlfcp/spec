# ADR 0010: Canonical changes and operation references

- **Status:** accepted (see the Status column)
- **Decided by:** the orchestrator, from an external review (findings F2
  to F4); the norm's form (properties of the format, not an engine's
  output) set by the orchestrator on 2026-10-09.
- **Applied by:** SPEC-PATCH-10 (baselines `mvp-0.1-baseline.10` and
  `mvp-0.2-baseline.2`)

## Context

An external review fuzzed the Data Unit admission of sdk-rs and found
changes that the §11 and §11.1 checks admit but an Automerge engine cannot
live with:
- **F2.** An object counter of 2^32 or more passes §11.1, which bounds
  counts, not values; automerge-rs 0.12 aborts parsing the change.
- **F3.** Changes Automerge applies but cannot write again: (a) a column
  with more rows than operations, (b) a predecessor on another key, (c) an
  empty change with a start op that is not its actor's next, (d) a deletion
  without predecessors. An engine keeps operations, not bytes, and writes a
  change again whenever it saves or hands it out; the written change no
  longer has the admitted hash, the save does not load ("mismatching
  heads", "missing ops"), and every Snapshot of the document is refused.
- **F4.** After such a change is admitted, automerge-rs 0.12 aborts in
  `get_changes` and `get_change_by_hash`, which rebuilds, merges and the
  duplicate check call.
- §11 required "the canonical binary format defined by the Automerge
  implementation", which no receiver could check, and nothing said which
  operations a change may refer to.

Worker2's probes against automerge-rs 0.12 extended the list: an
insertion into a map, an element key naming a non-inserting operation or
an element of another list, and an object that is not a made object make
the apply itself abort (in Automerge JS a trap terminates the wasm
module); a start op that reuses the actor's counters, and a change whose
actor's previous change is not in its history, reuse operation IDs and
abort later. A predecessor outside the change's causal history is
survived by the engine, but admitting it would make acceptance depend on
what else a replica holds.

## Value changes

None. SPEC-PATCH-10 changes no published vector value; it only adds
cases. Every change of the published corpora is canonical and refers only
to its history: Automerge JS 3.5.0 and automerge-rs 0.12 write all 288
of them byte for byte as §11.3 defines.
[`migrations/mvp-0.1-baseline.10/value-changes.json`](../migrations/mvp-0.1-baseline.10/value-changes.json)
and
[`migrations/mvp-0.2-baseline.2/value-changes.json`](../migrations/mvp-0.2-baseline.2/value-changes.json)
list no change.

## Decisions

| ID | Status | Decision | Sections changed | Vectors |
| --- | --- | --- | --- | --- |
| CANONICAL-CHANGE | Decided by the orchestrator (2026-10-09) | A change's bytes are the one encoding of its content that §11.3 defines by properties of the change version 1 format: shortest LEB128; sorted dependencies and other actors, exactly the actors the operations name; a fixed set of columns in order, each present exactly when its rule says, with `N` rows; maximal runs; canonical values; counters below 2^32; sorted predecessors. Re-encoding and comparing is an implementation, not the definition, so a new Automerge version cannot invalidate accepted changes. Checked after §11.1 and before the engine | SHARED-OBJECTS-PROFILE-01 §11, §11.3, §74.1 | corpus `canonical`: one case per rule, F2 and F3a |
| OPERATION-REFERENCES | Decided by the orchestrator (2026-10-09) | A change's operations refer only to its causal history (or earlier in the change): R1 the actor's previous change is in it, R2 the start op follows its largest counter, R3 objects are made objects with matching key forms, R4 insertions go into sequences after an element of the same object and have no predecessors, R5 other sequence operations name an element of the same object, R6 predecessors are non-deleting operations on the same object and key, R7 a deletion has a predecessor. Decided against the history only, so every replica decides alike | SHARED-OBJECTS-PROFILE-01 §11.4, §74.1 | corpus `references`: one case per rule, F3b, F3c, F3d, F4; shared sections SS57 to SS59 |
| SNAPSHOT-CHANGES | Decided by the orchestrator (2026-10-09) | A Snapshot whose document holds a change §11.3 or §11.4 refuses is rejected; the receiver falls back to the units | SHARED-OBJECTS-PROFILE-01 §11.4, §13 | none (a conforming engine cannot save such a document loadably) |

## Consequences

- Both SDKs read a change's content without their engine and check it
  before the engine sees it, and keep an index of their document's
  history (each change's clock and largest counter, each operation's
  object, key and kind) to check references. A Snapshot's changes are
  checked once, when it is loaded.
- Writers that commit on their Automerge document never break the rules;
  a writer checks its own changes and takes back one that does.
- Shared sections inherit the rules unchanged (SHARED-SECTIONS-PROFILE-01
  §2, SOP §§7–18).
