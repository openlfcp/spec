# ADR 0009: Shared sections profile

- **Status:** Accepted. Decisions P1, P2, P3 and P5 approved by the project
  owner on 2026-10-08 (MVP 0.2 review); normative details by the
  orchestrator. Not applied in any baseline yet: the profile text follows in
  LFCP-02-084 and LFCP-02-007 to LFCP-02-010.
- **Proposed by:** Worker2 for the orchestrator, 2026-10-08 (LFCP-02-083 in
  `.github: docs/BACKLOG-MVP-0.2.md`).
- **Supersedes:** nothing. **Closes:** NEXT-001 in
  `.github: docs/BACKLOG-MVP-0.1.md`.

Citations: `P` is `profiles/SHARED-OBJECTS-PROFILE-01.md` (this repository,
`mvp-0.1-baseline.9`); `SSP` is the MVP 0.2 planning draft
SHARED-SECTIONS-PROFILE-01, Working Draft 0.2, to be published in this
repository with LFCP-02-007; `CMP` is the MVP 0.2 compatibility draft,
published with LFCP-02-007/083.

## Context

Users want to share a whole section of a note: a heading with its Tasks
and supporting text, in order and nested, where content one person adds
appears for the others by itself (NEXT-001). Shared Objects v1 cannot say
this: `objects` is an unordered map, nothing groups Tasks, and a heading is
local presentation.

The MVP 0.2 planning batch proposes a Data Profile for it: one section per
Resource, made of stable nodes (Task references, paragraphs, list items),
immutable placements in insert-only children lists, collaborative Text for
prose, and conflicts that stay visible (SSP). The owner-approved review of the planning batch (2026-10-08) found it implementable on Automerge 3.5.0
and automerge 0.12, and found four gaps that need a decision: the profile
did not inherit the 0.1 admission rules; one invalid change blanked the
whole section; a 100-200 Task import does not fit one change under P
§11.1; and two moves into one parent conflict.

## Decision

### P1. A new profile, `org.openlfcp.shared-sections.v1`

A shared section is its own Resource, created with the Data Profile
`org.openlfcp.shared-sections.v1`. One Resource holds one section.

**Why not a list type inside Shared Objects** (NEXT-001's design). P §114
allows new namespaced object types in the same profile only "if old
clients can preserve them". Sections cannot meet that: they change what
P §115 lists as breaking:
- tombstone semantics: deleting a node hides its whole subtree, and a
  Task's lifecycle drives its node;
- collection conflict policy: placements are scalar registers whose
  concurrent values are a structural conflict, and children lists are
  insert-only;
- new invariants an old client does not know: one effective parent, no
  cycles, a placement created and inserted atomically.

A 0.1 client would preserve the bytes but could delete a Task a section
still references, or write a change that breaks the tree. P §94's reason
for one profile, future relationships inside one Resource, does not
outweigh that.

**Compatibility.** Clients that know only Shared Objects do not see
sections at all: the Resource's Genesis names a profile they do not
support (`PROFILE_UNSUPPORTED`). From plugin 0.3.2 on, a client refuses
such an invitation before it claims it (LFCP-02-086, LFCP-02-087).
Existing Task Resources keep their profile; moving Tasks into a section is
an explicit copy into a new Resource, with new Task IDs (CMP §5 to §9).
NEXT-001's requirement that "clients that only know Tasks keep the Tasks
and ignore the list" is dropped.

**What the profile inherits.** P §§7-18 apply unchanged, with this
profile's actor domain `OPENLFCP-SHARED-SECTIONS-ACTOR-v1` (P §8): the
engine, actor binding and `CHANGE_ACTOR_MISMATCH`, the framing, the exact
change expansion limits (§11.1), the document depth bound (§11.2), the
Snapshot limits (§13.1), the replica state rule and rebuild (§14.1)
including holding a change whose actor sequence is taken (POST-001), the
root rules and extension namespaces. Diagnostics follow the model of
P §74.1: `PROFILE_INVALID` with exactly one diagnostic. No limit is raised.
The Task schema and semantics are P §§19-83, as SSP §2 says.

### P2. Invalid history: refused at admission, or isolated per subtree

**Refused at admission.** A receiver refuses, before its engine applies it,
a change that does one of the following. Each rule is decided from the
change's own operations and the objects they write into, which are in the
change's causal history; every replica therefore decides it the same way,
in time linear in the change. The change is `PROFILE_INVALID` with the
diagnostic named and is not merged, like `CHANGE_ACTOR_MISMATCH` (P §11).

| Rule | The change … | Diagnostic |
| --- | --- | --- |
| A1 | deletes or replaces an element of a children list (`section.children`, a node's `children`) | `CHILDREN_LIST_MUTATED` (new) |
| A2 | inserts into a children list a PlacementId whose placement it does not create, or whose `parent_id` is not the list's owner; or creates a placement that it does not insert exactly once and assign to its node's `placement` | `PLACEMENT_NOT_ATOMIC` (new) |
| A3 | writes or deletes a key of a placement map it did not create; or writes an immutable key (`id`, `kind`, `created_by`, `task_id`, `node_id`, `parent_id`, and the Task keys of P §75) of an object it did not create | `IMMUTABLE_FIELD_MUTATED` |
| A4 | replaces or deletes a container: the root's `profile`, `section`, `nodes`, `placements`, `objects` or `extensions` after the initial change, or an existing node's `children`, `text` or `extensions` | `CONTAINER_REPLACED` (new) |
| A5 | writes collaborative Text where a scalar is required (P §30), a scalar to a node's `text`, or a non-scalar into a children list | `INVALID_FIELD_TYPE` |

The new diagnostics are declared here. Their registry, with its order of
precedence, belongs to the profile text (LFCP-02-007).

A refused change blocks the changes that depend on it, in practice the
rest of its writer's history, as an `INVALID_AUTOMERGE_BYTES` change does
in Shared Objects.

**Isolated per subtree.** Everything else that is invalid is merged and
isolated, not refused, in the spirit of P §77: a placement register naming
a missing placement, a `task_id` naming a missing Task, a placement whose
`node_id` is another node, an invalid value or enum, a non-canonical ID,
an `OBJECT_ID_COLLISION`. The node concerned is invalid, its descendants
are blocked (`BLOCKED_PARENT`), and the rest of the section is projected.
`PLACEMENT_CONFLICT`, `PARENT_CYCLE` and `LIFECYCLE_CONFLICT` are model
facts that need a resolution, not errors.

The batch corpus cases SS13 (A3), SS19 (A2), SS20 (A4, A5) and SS21 (A1),
which expected the whole section `PROFILE_INVALID` with an empty tree,
become admission refusals; their expectations are rewritten with this
rationale (LFCP-02-010).

### P3. Import and long edits in several changes

The 0.1 admission limits stay. Content that does not fit one change is
written in several.

**Readiness marker.** The section map has a key `ready`, a scalar boolean.
- A section created in one change sets `ready = true` in that change. An
  import in several changes writes `ready = true` in its last change, and
  only then.
- A section without `ready` is being imported. A reader shows it as
  "section is being imported": it projects nothing and writes nothing into
  it.
- Admission (P2) refuses a change that deletes `ready`, writes a value
  other than `true`, or writes `ready` while not being a change of the
  actor of the section's `created_by` (`IMMUTABLE_FIELD_MUTATED`).
- Invitations are issued only after `ready` (CMP §9).

**Abandoned import.** The creator continues an interrupted import from its
local import journal (CMP §8), with the same Principal and its actor
state. A section left without `ready` can only be continued by its
creator or deleted locally; it is never offered for invitation. Several
devices of one Principal share one Automerge actor in a Resource (P §8);
continuing an import on another device therefore needs that device to hold
the Principal's actor state, not only its keys. Two devices writing as one
Principal concurrently equivocate (LFCP-WIRE-01 §26.2), and the receivers'
rules exclude both units; the Principal's later work is re-issued and held
until the rebuild (POST-001). An implementation continues an import only
from the device that holds the actor state, or from a restored copy of it.

**Authoring budgets.** So that both SDKs write histories every receiver
accepts, a writer puts in one change at most:
- 8,192 operations on Text elements (characters inserted plus characters
  deleted);
- 256 nodes created.

A longer insertion or deletion is split into consecutive changes, each
taking a contiguous run after the previous one; together they are one user
action. Receivers apply the exact P §11.1 limits only; the budgets bind
writers. The figures come from the batch corpus: about 21 rows per node,
so 256 nodes and 8,192 characters take about 13,600 of the 16,384 rows
(SS23: 200 Tasks, 200 paragraphs and 2,109 characters took 10,439 rows).
LFCP-02-084 confirms them with worked examples at the limit and one above
it, and states the profile's limit table.

### P5. Two moves into one parent stay a conflict

Two concurrent moves of one node into the same parent (batch case SS22)
remain a `PLACEMENT_CONFLICT` that a user resolves. A deterministic
automatic choice by list order is deferred: it is revisited after the
pilot, with the number of such conflicts the pilot records.

## Consequences

- The profile text, its admission rules, the diagnostics registry and the
  limit table are written in LFCP-02-084 and LFCP-02-007; vectors in
  LFCP-02-008 and LFCP-02-010; both SDKs implement the admission rules
  A1-A5 next to the inherited 0.1 checks (LFCP-02-085).
- A long insertion split into several changes may be seen by a peer in
  part, between its Data Units. This is acceptable: the writer's UI shows
  the usual pending state until the last unit is acknowledged, and readers
  converge when it arrives.
- A writer whose change is refused at admission stops progressing on every
  replica; this is the intended containment of a buggy or hostile writer,
  and the diagnostic names the rule.
- Legacy clients see nothing of a section, and existing collaborations do
  not become sections.

## Spec work

- LFCP-02-084: the import and readiness rules, the authoring budgets and
  the profile limit table, with worked examples.
- LFCP-02-007: the profile text with P §§7-18 and §74.1 imported, A1-A5,
  per-subtree isolation, the diagnostics registry and its precedence; the
  Markdown decisions M1-M7.
- LFCP-02-010: admission negatives for A1-A5 and the inherited rules,
  subtree isolation cases, a multi-change import, an insertion above the
  budget, and the rewritten SS13, SS19, SS20 and SS21.

## Open items

- The authoring budgets are estimates until LFCP-02-084 measures them.
- Text history and the Snapshot floor of P §13.1 (about 262,000 typed
  characters over a section's life): measured in LFCP-02-067.
- How an SDK coalesces keystrokes into changes, and how many Data Units a
  typing session produces (LFCP-02-025, LFCP-02-026).
- One Resource per section meets the public server's per-Principal quota
  of 20 hosted Resources and 10 new Resources per client IP per day (server
  0.2.0 defaults). Raising them on sync.openlfcp.org, or stating the limit,
  is decided by the project owner before the beta (LFCP-02-003).
