# SHARED-SECTIONS-PROFILE-01

**Title:** OpenLFCP Shared Sections Data Profile  
**Status:** Working Draft 0.3 for MVP 0.2, not in any implementation baseline; decisions of ADR 0009 applied, independent interoperability pending  
**Date:** 2026-10-08  
**Profile identifier:** `org.openlfcp.shared-sections.v1`  
**Dependencies:** LFCP-WIRE-01 and SHARED-OBJECTS-PROFILE-01 at `mvp-0.1-baseline.9`; ADR 0009  
**Companions:** MARKDOWN-SECTIONS-01; the MVP 0.2 compatibility and migration draft, to be published with LFCP-02-007

> **Revision note.** Imported from the MVP 0.2 planning draft (Working
> Draft 0.2) and revised for [ADR 0009](../adr/0009-shared-sections-profile.md):
> the 0.1 admission rules are inherited (§2), structural violations are
> refused at admission and other invalid history is isolated per subtree
> (§14), import and long edits take several changes (§12, §16, LFCP-02-084),
> and raw nodes carry unsupported Markdown blocks (§4.2). Not part of any
> implementation baseline.

## 1. Contract and boundaries

This profile defines one shared section per Resource: an ordered, nested collection of Task references, paragraphs and list items. It does not share the containing Markdown document. Resource capabilities remain the authorization boundary for every object in the Resource.

MUST, MUST NOT, SHOULD and MAY describe conformance requirements of this Working Draft. The profile is not Stable. Implementers may prototype against this exact revision, but release requires the reference corpus and compatibility gates in §19. The JavaScript reference corpus exercises specified cases; no production SDK or independent Rust implementation has been verified against this profile as part of authoring this document.

The separate profile identifier is deliberate. A Resource created under `org.openlfcp.shared-objects.v1` remains on that profile. New section behavior is not installed by changing its Genesis or silently adding tree semantics to old Tasks.

## 2. Reused LFCP and Task contracts

LFCP encryption, signing, capability checks, Control Chain, epochs, anti-entropy, transport and snapshots remain governed by LFCP-WIRE-01. The server does not parse section contents.

This profile adopts SHARED-OBJECTS-PROFILE-01 (written `SOP` below) at `mvp-0.1-baseline.9`, as follows (ADR 0009, P1).

**Inherited unchanged: SOP §§7–18.**
- §7: Automerge is the engine. Implementations pin `@automerge/automerge` 3.5.0 or the Rust `automerge` 0.12.0, as SOP's corpus does.
- §8: the actor binding, with this profile's domain:

  ```text
  actor_id = SHA-256(ASCII("OPENLFCP-SHARED-SECTIONS-ACTOR-v1") || resource_id || principal_id)
  ```

  Both IDs are their raw 32-byte values. The change carried by a Data Unit MUST be a change of the actor of the unit's signer; otherwise `PROFILE_INVALID` with `CHANGE_ACTOR_MISMATCH`, and nothing is merged.
- §9: actor state safety and writing after a rebuild.
- §10 and §12: one semantic transaction per change and one change per Data Unit, with the exceptions of §12 of this profile.
- §11 and §13: the framing `[1, change_bytes]` (an uncompressed change chunk with a verified checksum) and `[1, full_save_bytes]`.
- §11.1, §11.2 and §13.1: the exact change expansion limits, the document depth bound and the Snapshot limits, checked before the engine (§16.1).
- §14 and §14.1: Snapshot equivalence, the replica state rule, rebuilds, the sequence check, and holding a change whose actor and sequence number another change holds (POST-001).
- §§15–18: the root rules, as extended by §3 of this profile; reserved keys; extension namespaces.

**Inherited for Tasks: SOP §§19–83.** The Task schema, status/priority/date meanings, tags and assignees, scalar conflicts, tombstones and intents apply to the Task objects of a section. This profile adds the section structure; it does not change a Task.

**Diagnostics: the model of SOP §74.1.** Every profile validation failure is `PROFILE_INVALID` with exactly one diagnostic from the registry of §14.2, which extends SOP's.

Task title/status/date/priority/lifecycle values are Automerge scalar strings (`ImmutableString` in Automerge JS, `ScalarValue::Str` in Rust), never collaborative Text (SOP §30). Never infer the distinction from a plain JSON dump.

## 3. Root structure and primitive types

```text
root
  profile       scalar string = org.openlfcp.shared-sections.v1
  section       map, exactly one
  objects       map<ObjectId, Task or preserved unknown Shared Object>
  nodes         map<NodeId, Node>
  placements    map<PlacementId, Placement>
  extensions    map<reverse-domain namespace, unknown>
```

Maps and lists are persistent Automerge objects created once, not rebuilt from JSON during ordinary edits. A change that replaces a root map, the section map, a node's map, children list or Text is refused at admission (§14.1, A4). Unknown extension state MUST survive edits, synchronization and snapshots.

IDs are canonical lowercase UUIDv7 strings. Section, Task, non-Task node and placement IDs MUST be collision-free within the Resource. A Task node deliberately uses its Task's ID; all other ID collisions are errors. UUID timestamps and lexical ordering MUST NOT establish causality or conflict precedence.

Every textual field below is a scalar string unless explicitly labeled **Text**. All strings MUST be valid Unicode; lone surrogate code points are invalid. No normalization is applied to prose. Existing tag normalization rules remain inherited.

`PrincipalRef` is `p:` followed by canonical unpadded Base64url of 32 bytes. Optional creation timestamps are informational only. Standard map keys below are reserved; vendor data belongs in `extensions`.

## 4. Section and content schema

### 4.1 Section

```text
section.id          SectionId, immutable
section.title       scalar string, conflict-preserving
section.created_by  PrincipalRef, immutable
section.created_at  optional UTC timestamp
section.children    Automerge list<PlacementId>, permanent, insert-only
section.ready       scalar boolean true; absent while being imported (§12.1)
section.extensions  map
```

The section remains the Resource's single root container. This draft does not define section deletion or Resource tombstoning. Detaching a local projection is not a shared mutation.

The creator initializes root, section and their empty maps/lists in one change before inviting others. A second independent initialization or conflicting root identity is `PROFILE_INVALID`, not a mergeable second section.

### 4.2 Node

```text
nodes[id] = {
  id,                 NodeId; immutable; equals map key
  kind,               "task" | "paragraph" | "item" | "raw"; immutable
  created_by,         PrincipalRef; immutable
  created_at?,        optional timestamp
  lifecycle,          "active" | "deleted"; scalar register
  placement,          PlacementId; scalar register
  children,           Automerge list<PlacementId>; permanent, insert-only
  extensions,         map
  task_id?,           TaskId; immutable; task nodes only
  text?,              Automerge Text; paragraph/item/raw nodes only
  list_style?         "bullet" | "ordered"; scalar register; task/item only
}
```

Task nodes MUST have `id == task_id` and reference an existing Task in `objects`. Their `text` field is absent. Their lifecycle is always `active`; effective deletion is governed by the Task lifecycle. This prevents independent Task/node tombstones from making restore ambiguous. An unplaced Task may exist in `objects`; there is at most one node for it.

Paragraph nodes MUST have Text and an empty children list. They cannot parent content. Raw nodes likewise MUST have Text and an empty children list and cannot parent content; their Text is a Markdown block carried verbatim, which no reader interprets as nodes or bindings (MARKDOWN-SECTIONS-01 §4.4). Item nodes MUST have Text and may parent paragraphs, raw nodes, Tasks or items. Task nodes may parent the same types. `list_style` expresses ordered versus unordered list membership, not a Task's status.

Text holds Markdown inline source and soft line breaks, without list prefixes or LFCP metadata. Marker-like text is ordinary literal content only when escaped or in inline code according to the Markdown companion. Paragraph boundaries belong to separate nodes. Typed bytes that cannot yet be interpreted are retained locally until a safe intent can be formed.

### 4.3 Placement

```text
placements[id] = {
  id,          PlacementId; immutable
  node_id,     NodeId; immutable
  parent_id,   SectionId or Task/item NodeId; immutable
  created_by   PrincipalRef; immutable
}
```

Placement maps are immutable after creation. Each PlacementId MUST occur exactly once in its parent's children list and nowhere else. It is created and inserted atomically with the node's `placement` assignment. Entries in children lists are immutable scalar strings; list deletion, element replacement and duplicate placement insertion are prohibited.

Old placements remain as invisible ordering anchors. They are not copied Task content. No physical garbage collection of placements, nodes or Tasks is defined in v1.

## 5. Why placements are separate

A Task/node has stable identity; its position can change. A move creates a new placement, inserts its ID in the destination parent's list and writes that PlacementId into the existing node's `placement` register. The former list entry remains but no longer emits that node.

This uses Automerge's sequence merge for sibling ordering and scalar conflict detection for competing locations. It does not claim that Automerge provides an application-level tree move primitive. It also avoids delete/recreate operations on the moved Task or its descendants.

Example:

```text
Task T selects placement P1 under the section.
Move T under item A:
  create P2 for (T, A)
  insert P2 into A.children
  set T-node.placement = P2
P1 remains in section.children, but emits nothing.
```

## 6. Insertion, reorder and reparent

The structural API accepts a parent and an optional preceding visible sibling, not a line number.

1. Merge all currently available local heads.
2. Require a valid, visible, unconflicted target parent and an eligible preceding sibling in that parent. Do not author new children under a currently deleted/blocked parent.
3. Allocate a fresh PlacementId.
4. With no preceding sibling, insert the placement at physical index zero in the parent's list.
5. Otherwise locate the preceding sibling's selected PlacementId in that list and insert immediately after that physical entry. Invisible historical slots are not removed.
6. Create the immutable Placement map and assign its ID to the node's placement register in the same change.

Append uses the last visible sibling; empty parents use index zero. A move to an already occupied equivalent position MAY be a no-op. A requested self-parent, descendant-parent or self-predecessor is rejected before mutation. Moving a subtree changes only its root placement; its descendant relationships remain attached to stable node IDs.

Concurrent insertions are ordered by the merged Automerge list. Clients MUST use that sequence as stored, not sort by UUID or timestamp. Byte-identical save files are not required; the resulting list order must be identical for the same changes. The implementation corpus must exercise historical invisible placements as well as fresh lists.

## 7. Effective tree and structural conflict algorithm

Derive structure from the fully available Automerge state, never from arrival order:

1. Validate schema, ID consistency, immutable data and placement/list membership. A missing Automerge dependency is pending, not an empty state.
2. Read all concurrent assignments for each placement register. More than one assignment yields `PLACEMENT_CONFLICT`; no assignment is silently chosen. This applies even if an API exposes one provisional value.
3. For an otherwise eligible node, resolve its selected placement and parent. Paragraph parents, wrong-Resource references, missing objects or mismatched node IDs are invalid, not alternate destinations.
4. Build the selected node-to-parent graph. Compute strongly connected components. Every cycle member is `PARENT_CYCLE`; a self-cycle is included.
5. Propagate structural blocking to descendants of conflicted/invalid/cyclic parents until a fixed point. These nodes are `BLOCKED_PARENT` unless they already have a more direct error.
6. Determine effective visibility. A deleted node/Task or a descendant of one is hidden but retained. Lifecycle conflicts block that branch until resolved. Task scalar title/status conflicts may use a provisional value with a visible conflict indicator, as in the inherited Task contract.
7. Starting from section.children, scan each merged children list in order. Emit a node only if it is structurally eligible, visible, and selects exactly that entry's PlacementId. Recurse through its children. Historical non-selected slots emit nothing.

The normal output is a forest rooted at the section. There is never an arbitrary cycle-breaking write or duplicate Task emitted to make the tree appear valid.

Recovery information lists affected node IDs, selected/candidate placements, parent IDs and reasons. Sort diagnostic records by NodeId solely for stable presentation, not winner selection. Retain all blocked content and causal alternatives.

A structurally conflicted section MUST NOT automatically rewrite its Markdown projection into a tree that omits the blocked content. Freeze structural projection, retain the last safe/local text, and expose a resolution view. Text/field edits on still unambiguous bindings may continue. After resolution, reconcile pending local edits before projecting a new tree.

## 8. Explicit structural resolution

`node.resolve_placement` loads the merged state, then creates a fresh placement at the chosen valid location and writes its ID to the conflicted register. It supersedes all placements observed at that causal point. New unseen moves may introduce a later conflict.

For a parent cycle, `structure.resolve` can relocate one or more cycle members atomically. The chosen result must be acyclic and have valid parents in the observed state. No clock, user name, server arrival order or principal privilege silently chooses the user's desired location.

A node with missing or invalid immutable data is not repaired by changing its identity. Preserve its invalid history, diagnose the cause and create a new valid object only through an explicit repair operation. The exact invalid change is available to diagnostics without exporting private text by default.

## 9. Lifecycle and subtree deletion

Deleting a paragraph/item sets that node's lifecycle to `deleted`. Deleting a Task, whether from a section or an explicit global Task command, sets the Task lifecycle to `deleted`; its node remains and uses that lifecycle. Descendants are not recursively rewritten.

Thus deletion hides the selected subtree but retains child text, Task state and placements. Concurrent child edits remain stored. A child concurrently moved out of that subtree is visible in its new valid location. A concurrent child added under the deleted parent remains hidden and recoverable.

Restore changes only the selected node or Task lifecycle to `active`; descendants with their own tombstones remain deleted. Delete versus restore is a visible lifecycle conflict. Restoring a child alone does not make it visible while an ancestor remains deleted; the UI offers restore-ancestor or move-out explicitly.

An explicit lifecycle intent is a fresh causal register assignment even when the requested value equals the currently visible value. Some Automerge bindings suppress same-value assignment; implementers MUST ensure that the intent creates the required operation. For the two-valued lifecycle register, the JavaScript reference corpus writes the opposite valid value and then the requested value within one atomic change when necessary. Only the final value is exposed as the semantic result. This is not two user actions or two Data Units. Ordinary rendering/reconciliation MUST NOT emit repeated lifecycle intents merely to refresh state. The corpus includes concurrent delete versus explicit restore and resolution back to the already visible value.

Clients MUST make retained hidden content inspectable. If a content change is concurrent with deletion of its effective ancestor, surface `EDIT_UNDER_DELETED_ANCESTOR` as recoverable attention rather than claiming the edit is visibly applied. Compare change dependencies for this diagnostic; it does not alter convergence.

Removing a local section/Task projection or deleting a host file is not one of these shared delete intents.

## 10. Text edits and block transformations

Text edits are Automerge text insert/delete operations on the existing Text object. Replacing the Text object on each edit is prohibited. SDK intent indices use Unicode scalar positions; editor UTF-16 or byte offsets must be translated. Input to an indexed edit includes the local base revision; the SDK must not apply stale offsets to a different merged text without rebasing.

### Split

`paragraph.split` and `item.split` operate on one unconflicted node at a specified local Text position. The original ID keeps the prefix. Create a new same-kind node for the observed suffix, immediately after the original under the same parent, in one change. For item.split the original retains its existing children; the new item starts without children. Section source edits that imply moving children require explicit reparent intents in the same transaction.

Concurrent edits retain normal Text history, possibly under the original node. Automatic transfer of unseen concurrent characters to the new node is not promised. A detected concurrent split/text or split/split ambiguity must be inspectable; the adapter must not discard either result.

### Join

Joining two adjacent paragraph nodes, or two adjacent item nodes with the same list style, requires both to have no children and no unresolved structure. The first keeps its ID. Append the observed second text using an explicit separator (default one LF), tombstone the second, and retain its original Text history. Concurrent edits to the second are retained under its tombstone and exposed for recovery. There is no automatic silent merge of those unseen edits into the copied text.

### Kind changes

Node kind is immutable. Task-to-plain-text or item-to-Task conversion uses an explicit replace operation: allocate new identity, preserve/import represented content, reparent observed children and tombstone the old entity atomically. Show the identity consequence when other projections exist. Ordinary Task status edits never perform such conversion.

## 11. Minimum semantic API

| Intent | Effect |
| --- | --- |
| section.create | Initialize one Resource profile document and root section |
| section.set_title | Write a scalar title; preserve concurrent title conflict |
| task.create_in_section | Create Task, task node and placement atomically |
| task.place_existing | Create the sole node for an unplaced Task in this Resource |
| paragraph.create / item.create / raw.create | Create node, Text, children list and placement atomically |
| text.edit | Apply edits to existing Text against a known base |
| node.move | New placement and assignment, same node identity |
| node.set_list_style | Update ordered/bullet presentation semantics |
| node.delete / node.restore | Lifecycle operation under §9 |
| node.resolve_placement / structure.resolve | Causal structural resolution under §8 |
| paragraph.split / item.split / node.join | Restricted transformations under §10 |
| task.* | Imported Task field/lifecycle operations |

These are SDK/application operations, not new LFCP wire message types. Exact programming-language API names may differ, but the semantics and atomic groups must match. UI detach/copy-plain actions need not produce any shared change.

## 12. Transactions, import and persistence

One semantic transaction produces one Automerge change and therefore one Data Unit, unless the budgets of §16.2 make it more. Content that does not fit one change is written in several (ADR 0009, P3); the admission limits of §16.1 are never raised for it.

### 12.1 Readiness

The section map carries a key `ready`, a scalar boolean.

```text
section.ready   true; absent while the section is being imported
```

- A section created in one change writes `ready = true` in that change.
- An import in several changes writes `ready = true` in its last change, and in no earlier one. Every change of the import leaves the section consistent on its own: each node it creates is placed (§4.3), and nothing it writes refers to a node or placement a later change creates.
- A reader that finds no `ready` shows the section as being imported ("section is being imported"). It projects none of its content, authors no change in it, and offers no invitation to it.
- `ready` is written once. A receiver refuses, before its engine, a change that deletes `ready`, writes a value other than `true`, or writes `ready` while its actor is not the actor of the section's `created_by` Principal (§2): `PROFILE_INVALID` with the diagnostic `IMMUTABLE_FIELD_MUTATED`.
- Invitations to the section are issued only after `ready` (MVP 0.2 compatibility draft, §9).

### 12.2 Interrupted and abandoned import

The creator records an import in a local, durable import journal before its first change (MVP 0.2 compatibility draft, §8) and continues an interrupted import from it, with the same Principal and its actor state (SHARED-OBJECTS-PROFILE-01 §9).

One Principal has one Automerge actor in a Resource (§2). An import is therefore continued only on the device that holds that actor state, or from a restored copy of it. Two devices that write concurrently as one Principal equivocate (LFCP-WIRE-01 §26.2): receivers exclude both units, and the Principal's re-issued work is held until the rebuild (SHARED-OBJECTS-PROFILE-01 §14.1).

A section that stays without `ready` is never offered for invitation. Its creator continues the import or deletes the section locally; no shared operation abandons it.

### 12.3 Long Text edits

A Text insertion or deletion that exceeds the Text budget of §16.2 is written as consecutive changes. Each change inserts, or deletes, one contiguous run that starts where the previous run ended, in order. Together they are one user action: an application undoes them together and shows them as one pending edit. A peer may observe the edit in part, between its Data Units; it converges when the last one arrives.

### 12.4 Persistence

Persist actor history, state and the outbound queue with restart-safe commit ordering. Retried transmission sends identical queued bytes. SDKs may store local change-to-node mappings for UI pending indicators; such metadata is not part of replicated section content.

## 13. Projection contract

Section projections show all supported visible section content. A compact standalone Task projection shows only its represented fields. Omitting children from the latter is not evidence of deletion.

Markdown is parsed against a known projection base. Unknown bindings, incomplete load, malformed boundaries or unsupported syntax suspend unsafe translation; they never generate a replacement empty section. Remote projection patches use document-revision checks to avoid overwriting unprocessed local edits.

The exact portable syntax and external-file behavior are defined by MARKDOWN-SECTIONS-01. This profile does not encode local file paths, heading depth, UI badges, participant labels or clipboard decorations.

## 14. Validation and error classes

### 14.1 Admission

A receiver checks a change when every dependency of it is in the document (SOP §14.1), before its engine applies it: first SOP's checks (§11, §11.1, §11.2, the sequence check of §14.1, `CHANGE_ACTOR_MISMATCH`), then the structural rules below (ADR 0009, P2). Each rule is decided from the change's operations and the objects they write into, which are in the change's causal history; every replica decides it the same way, in time linear in the change.

| Rule | The change … | Diagnostic |
| --- | --- | --- |
| A1 | deletes or replaces an element of a children list (`section.children` or a node's `children`) | `CHILDREN_LIST_MUTATED` |
| A2 | inserts into a children list a PlacementId whose placement it does not create, or whose `parent_id` is not the list's owner; or creates a placement that it does not insert exactly once into its parent's children list and assign to its node's `placement` | `PLACEMENT_NOT_ATOMIC` |
| A3 | writes or deletes a key of a placement map it did not create; writes an immutable key (`id`, `kind`, `created_by`, `task_id`, `node_id`, `parent_id`, and the Task keys of SOP §75) of an object it did not create; or writes `section.ready` against §12.1 | `IMMUTABLE_FIELD_MUTATED` |
| A4 | replaces or deletes a container: the root's `profile`, `section`, `nodes`, `placements`, `objects` or `extensions` after the initial change, or an existing node's `children`, `text` or `extensions` | `CONTAINER_REPLACED` |
| A5 | writes collaborative Text where a scalar is required (SOP §30), a scalar to a node's `text`, or a value other than a scalar string into a children list | `INVALID_FIELD_TYPE` |

A change that breaks a rule is `PROFILE_INVALID` with that rule's diagnostic and is not merged. When it breaks several, the diagnostic is the first that applies in the order `INVALID_AUTOMERGE_BYTES`, `CHANGE_ACTOR_MISMATCH`, `CONTAINER_REPLACED`, `CHILDREN_LIST_MUTATED`, `PLACEMENT_NOT_ATOMIC`, `IMMUTABLE_FIELD_MUTATED`, `INVALID_FIELD_TYPE`. A refused change blocks the changes that depend on it, as SOP §14.1 holds any change with a missing dependency.

### 14.2 Values: isolation per subtree

Every other invalid value is merged and isolated, as SOP §77 isolates an invalid object. A failing value reports one diagnostic from this registry, which is SOP §74.1's with the section rows added; when one value breaks several rules, its diagnostic is the first that applies in this order.

| Diagnostic | Meaning |
| --- | --- |
| `INVALID_ROOT` | `profile` differs, or a root container of §3 is missing or not a map |
| `INVALID_OBJECT_ID` | a Section, Node, Placement or Task ID, or a map key holding one, is not a canonical UUIDv7 |
| `OBJECT_ID_MISMATCH` | an object's `id` differs from its map key, or a Task node's `id` differs from its `task_id` |
| `MISSING_REQUIRED_FIELD` | a required section, node, placement or Task field is absent |
| `INVALID_FIELD_TYPE` | a field has the wrong type (SOP §30, §76), e.g. `text` that is not Text, a `children` that is not a list |
| `INVALID_ENUM_VALUE` | `kind`, `lifecycle`, `list_style`, or a Task's `status` or `priority` is outside its domain |
| `INVALID_EXTENSION_NAMESPACE` | an `extensions` key is not a reverse-domain namespace |
| `INVALID_PRINCIPAL_REF` | a `created_by` or assignee is not `p:` + base64url of 32 bytes |
| `INVALID_TIMESTAMP` | a `created_at` is not an RFC 3339 UTC timestamp |
| `INVALID_LOCAL_DATE` | a Task date is not a valid `YYYY-MM-DD` |
| `INVALID_COLLECTION_REPRESENTATION` | Task `tags` or `assignees` are not a map of `true` |
| `INVALID_TAG` | a Task tag is empty or starts with `#` |
| `INVALID_REFERENCE` | a node's `placement` names no placement, or a placement of another node; a placement's `node_id` or `parent_id` names no node or section; a Task node's `task_id` names no Task; a parent is a paragraph or raw node |
| `IMMUTABLE_FIELD_MUTATED` | an immutable field has concurrent values (a write refused at admission cannot be merged) |

`OBJECT_ID_COLLISION` (SOP §21) stays a separate named error, not a diagnostic. A collision is an ID under which `nodes`, `objects` or `placements` holds concurrent values, each a map created by a different change. A node whose own ID, Task ID or selected PlacementId collides is not validated and not projected, and no value is chosen; its descendants are `BLOCKED_PARENT`; the section is reported with the colliding IDs and classifies `STRUCTURAL_ATTENTION`. A children-list entry naming a colliding PlacementId emits nothing.

An invalid node is not projected, and its descendants are `BLOCKED_PARENT`; the rest of the section is projected. A Task whose object is invalid isolates its Task node the same way. Section-level problems (`INVALID_ROOT`, an invalid `section` map) leave nothing to project and are reported for the whole Resource.

Validation inspects every concurrent value of a field, not only the binding's default visible value (SOP §45, §74.1). Readers converge on the same classification for the same accepted history.

### 14.3 Model facts

These are not errors: the history is valid, and a user resolves them (§8).

| Fact | Meaning |
| --- | --- |
| `PLACEMENT_CONFLICT` | Concurrent location assignments of one node |
| `PARENT_CYCLE` | A cycle in the selected parent graph |
| `BLOCKED_PARENT` | A node under a conflicted, cyclic or invalid parent; content retained |
| `LIFECYCLE_CONFLICT` | Concurrent active/deleted values; concurrent equal values agree and are not a conflict |
| `EDIT_UNDER_DELETED_ANCESTOR` | Retained content changed concurrently with its ancestor's deletion |

A valid concurrent merge may have placement conflicts or cycles; they are not grounds to discard a peer's valid history. A client that does not implement this profile reports the Resource as `PROFILE_UNSUPPORTED` (LFCP-WIRE-01 §62) and neither interprets nor writes it.

## 15. Required behavioral examples

Notation below names existing objects; symbols are not literal IDs or a binary vector format.

| Case | Concurrent or sequential input | Required result |
| --- | --- | --- |
| SS01 | A creates Task T and paragraph child P | T fields authoritative in objects; P is node Text |
| SS02 | A and B insert different siblings after T | Both survive; merged list gives identical order at both peers |
| SS03 | A completes T; B edits P | Both effects visible, no structural conflict |
| SS04 | A moves T under X; B moves T under Y | Two placement assignments; one recovery entry, no duplicated normal T |
| SS05 | A moves X under Y; B moves Y under X | Both cycle members blocked; text retained; resolution required |
| SS06 | A deletes X; B edits child P | X subtree hidden; P edit retained and inspectable |
| SS07 | A deletes X; B moves P to root | P visible at root if selected placement is unconflicted |
| SS08 | A deletes T; B restores T | Lifecycle conflict; no false healthy status |
| SS09 | Move T repeatedly across parents | One visible T, stable identity; historical slots remain |
| SS10 | A detaches a local section | No Resource/Task delete or capability revoke |
| SS11 | Standalone Task title edited | Same Task updates in section; child content untouched |
| SS12 | Snapshot load then further changes | Same tree, Text and conflicts as complete change replay |
| SS13 | Corrupt immutable placement parent | Refused at admission (§14.1, A3); no silent relocation |
| SS14 | Concurrent paragraph edit in TS and Rust | Same Text after merge, including Cyrillic/emoji |

## 16. Limits and serialization

### 16.1 Admission limits

The admission limits are those of SHARED-OBJECTS-PROFILE-01 at `mvp-0.1-baseline.9`, exact and shared by every receiver, because acceptance decides the replica state. This profile raises none of them (ADR 0009).

| Limit | Value | Source |
| --- | --- | --- |
| Values in any one change column, except a group's entries | 16,384 | SHARED-OBJECTS-PROFILE-01 §11.1 |
| Sum of the values of a change's group columns | 262,144 | §11.1 |
| Expanded string bytes of a change | 4,194,304 (4 MiB) | §11.1 |
| Dependencies of a change | 1,024 | §11.1 |
| Other actors of a change | 1,024 | §11.1 |
| Depth of any object below the root | 256 | §11.2 |
| Snapshot floor: values in a column, group sum | 262,144 each | §13.1 |
| Snapshot floor: expanded string bytes, inflated column data | 32 MiB each | §13.1 |
| Snapshot floor: actors, heads | 1,024 each | §13.1 |
| Maximum LFCP message size, default | 8 MiB | LFCP-WIRE-01 §31 |

The section's own structure is flat in Automerge terms: nodes and placements are entries of root maps, so a node's nesting in the section adds no Automerge depth.

### 16.2 Authoring budgets

So that every writer produces changes every receiver accepts, one change carries at most:

- 8,192 operations on Text elements: characters inserted plus characters deleted, over all Text objects of the change;
- 256 created nodes;

and, counted as SHARED-OBJECTS-PROFILE-01 §11.1 counts it, stays within §16.1. A writer counts a change before it publishes it; a change over a budget or a limit is split (§12) before it is published, never sent to be refused.

### 16.3 Worked examples

Values in the largest column of one change, counted as §11.1 counts them, with Automerge 3.5.0. A Task node with its Task (the required fields of SHARED-OBJECTS-PROFILE-01 §31, no tags, assignees or dates) and placement takes 27; a paragraph or item node with its placement and an empty Text takes 15; each Text character takes 1 more.

| Change | Largest column | Within §16.1 |
| --- | --- | --- |
| 1 Task node | 27 | yes |
| 1 paragraph with 100 characters | 115 | yes |
| 100 Task nodes | 2,700 | yes |
| 200 Task nodes and 200 paragraphs, 2,109 characters | 10,509 | yes |
| At the budgets: 128 Task nodes, 128 paragraphs, 8,192 characters | 13,568 | yes |
| At the budgets: 255 Task nodes, 1 paragraph, 8,192 characters | 15,092 | yes |
| Over the Text budget: 200 Task nodes, 200 paragraphs, 8,192 characters | above 16,384 | no: refused (`INVALID_AUTOMERGE_BYTES`) |
| Over the Text budget: one paragraph of 16,384 characters | above 16,384 | no: refused |

Tasks with tags, assignees, dates or extension fields take more per node, so 256 Task nodes and a full Text budget can exceed §16.1: the count of §16.2, not the node budget alone, decides. Reproducible with LFCP-02-010's import vectors.

An import of 200 Tasks with a paragraph of about 200 characters each (40,000 characters) therefore takes at least five changes: the Text budget gives five, and the node budget alone two.

### 16.4 Implementation limits

Implementations declare local limits for rendering, number and depth of nodes, text size and retained history. These limits never refuse received content that §16.1 accepts: exceeding local rendering capacity must not erase received valid content. Snapshotting is not authorization to prune historical slots or tombstones. Use iterative graph traversal, or a documented depth limit for rendering only, to avoid call-stack-dependent behavior.

The initial product benchmark is 100–200 Tasks with nested supporting content. It is not a protocol maximum.

## 17. Compatibility decision

The new profile reuses Task semantics, not cross-Resource identity. Existing legacy Tasks remain on the legacy path. Creating a new section from their contents is an explicit copy into a new Resource with a recorded source-to-target map; it is not continuing their existing synchronization history. See the migration companion for the exact workflow.

New clients must dispatch by Resource Genesis profile before interpreting a `#task:` reference. The same textual Task ref shape does not mean two Resources use the same application profile.

## 18. Technical references

The slot/placement scheme and conflict policy are OpenLFCP design decisions. They are not claims about built-in Automerge tree semantics.

- [Automerge conflicts](https://automerge.org/docs/reference/documents/conflicts/) describes scalar conflict inspection and sequence merge behavior.
- [Automerge text](https://automerge.org/docs/reference/documents/text/) describes collaborative text operations.
- [Automerge API](https://automerge.org/automerge/api-docs/js/) is the binding reference; the project pins 3.5.0 (§2).

## 19. Required before implementation baseline freeze

1. Publish SHARED-SECTIONS-TEST-VECTORS-01 with real Automerge change/save bytes, generated with Automerge 3.5.0, for SS01–SS28 and the admission, isolation and import cases of LFCP-02-010.
2. Verify scalar strings versus Text types, the actor derivation and the admission rules of §14.1 in sdk-ts and sdk-rs.
3. Validate slot ordering, repeated moves, cycle/conflict classification, Text operations and snapshot replay against the same corpus.
4. Validate MARKDOWN-SECTIONS-01 fixtures and legacy profile-dispatch behavior.
5. Test crash/restart, data-size limits and the 100–200 Task scenario.

Until these gates pass, claim “implements Working Draft Shared Sections profile at revision …”, not Stable interoperability or production validation.
