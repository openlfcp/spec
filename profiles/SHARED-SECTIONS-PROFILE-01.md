# SHARED-SECTIONS-PROFILE-01

**Title:** OpenLFCP Shared Sections Data Profile  
**Status:** Working Draft 0.2 for MVP 0.2; JavaScript reference corpus prepared separately, independent interoperability pending  
**Date:** 2026-10-07  
**Profile identifier:** `org.openlfcp.shared-sections.v1`  
**Dependencies:** LFCP-WIRE-01; Task semantics imported from SHARED-OBJECTS-PROFILE-01  
**Companions:** MARKDOWN-SECTIONS-01 and the MVP 0.2 compatibility and migration draft, to be published with LFCP-02-007

> **Imported as drafted; superseded in part by
> [ADR 0009](../adr/0009-shared-sections-profile.md) (P1–P5) and being
> revised in LFCP-02-084 and LFCP-02-007.** In particular: §2 imports only
> SHARED-OBJECTS-PROFILE-01 §§19–83, while ADR 0009 also imports §§7–18 and
> §74.1; §14 classifies invalid history as a whole-section
> `PROFILE_INVALID`, while ADR 0009 refuses structural violations at
> admission (A1–A5) and isolates the rest per subtree; §12 forbids a
> multi-change import, which ADR 0009 requires. The draft's references to
> the Task contract and Automerge versions are re-pinned to
> `mvp-0.1-baseline.9` and Automerge 3.5.0 in LFCP-02-007. Not part of any
> implementation baseline.

## 1. Contract and boundaries

This profile defines one shared section per Resource: an ordered, nested collection of Task references, paragraphs and list items. It does not share the containing Markdown document. Resource capabilities remain the authorization boundary for every object in the Resource.

MUST, MUST NOT, SHOULD and MAY describe conformance requirements of this Working Draft. The profile is not Stable. Implementers may prototype against this exact revision, but release requires the reference corpus and compatibility gates in §19. The JavaScript reference corpus exercises specified cases; no production SDK or independent Rust implementation has been verified against this profile as part of authoring this document.

The separate profile identifier is deliberate. A Resource created under `org.openlfcp.shared-objects.v1` remains on that profile. New section behavior is not installed by changing its Genesis or silently adding tree semantics to old Tasks.

## 2. Reused LFCP and Task contracts

LFCP encryption, signing, capability checks, Control Chain, epochs, anti-entropy, framing transport and snapshots remain governed by LFCP-WIRE-01 and its scoped implementation requirements. The server does not parse section contents.

Application Data Unit plaintext is deterministic CBOR `[1, change_bytes]`, containing exactly one Automerge change. Snapshot plaintext is `[1, full_save_bytes]`. Multiple semantic mutations may occur in one atomic Automerge change; concatenating several change byte streams in one payload is forbidden. This adopts the existing framing shape under a different profile identifier.

Automerge actor derivation for this profile is:

```text
SHA-256(ASCII("OPENLFCP-SHARED-SECTIONS-ACTOR-v1") || resource_id || principal_id)
```

Both IDs are their raw 32-byte values. Actor state MUST be durable; a missing actor history MUST NOT be replaced with a fresh history under the same actor. The change's author actor MUST match the authenticated LFCP Data Unit author under this derivation. This defines application authorship; it does not replace LFCP authorization.

The Task schema, status/priority/date meanings, tags and assignees, scalar conflicts, tombstones and field intents are imported from SHARED-OBJECTS-PROFILE-01, §§19–69 and §§70–83 where applicable. This profile overrides its root structure, actor domain and profile identifier only, and adds explicit section structure. A conformance release MUST record the exact adopted revision of that Task contract.

Task title/status/date/priority/lifecycle values remain Automerge scalar values, not collaborative text objects. This distinction is a binary data-type requirement even when a language binding presents both as strings. In TypeScript bindings exposing `RawString`, use the scalar-string representation for scalar fields. Rust must use the equivalent scalar string, not a Text object. Never infer this distinction from a plain JSON dump.

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

Maps and lists are persistent Automerge objects created once, not rebuilt from JSON during ordinary edits. Replacing a root map, section map, node map or children list is a profile violation. Unknown extension state MUST survive edits, synchronization and snapshots.

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
section.extensions  map
```

The section remains the Resource's single root container. This draft does not define section deletion or Resource tombstoning. Detaching a local projection is not a shared mutation.

The creator initializes root, section and their empty maps/lists in one change before inviting others. A second independent initialization or conflicting root identity is `PROFILE_INVALID`, not a mergeable second section.

### 4.2 Node

```text
nodes[id] = {
  id,                 NodeId; immutable; equals map key
  kind,               "task" | "paragraph" | "item"; immutable
  created_by,         PrincipalRef; immutable
  created_at?,        optional timestamp
  lifecycle,          "active" | "deleted"; scalar register
  placement,          PlacementId; scalar register
  children,           Automerge list<PlacementId>; permanent, insert-only
  extensions,         map
  task_id?,           TaskId; immutable; task nodes only
  text?,              Automerge Text; paragraph/item nodes only
  list_style?         "bullet" | "ordered"; scalar register; task/item only
}
```

Task nodes MUST have `id == task_id` and reference an existing Task in `objects`. Their `text` field is absent. Their lifecycle is always `active`; effective deletion is governed by the Task lifecycle. This prevents independent Task/node tombstones from making restore ambiguous. An unplaced Task may exist in `objects`; there is at most one node for it.

Paragraph nodes MUST have Text and an empty children list. They cannot parent content. Item nodes MUST have Text and may parent paragraphs, Tasks or items. Task nodes may parent the same types. `list_style` expresses ordered versus unordered list membership, not a Task's status.

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
| paragraph.create / item.create | Create node, Text, children list and placement atomically |
| text.edit | Apply edits to existing Text against a known base |
| node.move | New placement and assignment, same node identity |
| node.set_list_style | Update ordered/bullet presentation semantics |
| node.delete / node.restore | Lifecycle operation under §9 |
| node.resolve_placement / structure.resolve | Causal structural resolution under §8 |
| paragraph.split / item.split / node.join | Restricted transformations under §10 |
| task.* | Imported Task field/lifecycle operations |

These are SDK/application operations, not new LFCP wire message types. Exact programming-language API names may differ, but the semantics and atomic groups must match. UI detach/copy-plain actions need not produce any shared change.

## 12. Transactions and persistence

One semantic transaction should produce one Automerge change and therefore one Data Unit. An import may create many nodes atomically if within negotiated size limits. If chunking is necessary, stage locally and publish only a complete initialized representation through a separately specified import boundary; do not expose a half-built section as the final shared result.

This draft requires preflight rejection when initial import exceeds the implementation's declared safe transaction limit. Chunked atomic publication is not assumed. The 100–200 Task acceptance fixture must fit the declared supported limit or the limit must be addressed before release.

Persist actor history, state and the outbound queue with restart-safe commit ordering. Retried transmission sends identical queued bytes. SDKs may store local change-to-node mappings for UI pending indicators; such metadata is not part of replicated section content.

## 13. Projection contract

Section projections show all supported visible section content. A compact standalone Task projection shows only its represented fields. Omitting children from the latter is not evidence of deletion.

Markdown is parsed against a known projection base. Unknown bindings, incomplete load, malformed boundaries or unsupported syntax suspend unsafe translation; they never generate a replacement empty section. Remote projection patches use document-revision checks to avoid overwriting unprocessed local edits.

The exact portable syntax and external-file behavior are defined by MARKDOWN-SECTIONS-01. This profile does not encode local file paths, heading depth, UI badges, participant labels or clipboard decorations.

## 14. Validation and error classes

| Code | Classification / handling |
| --- | --- |
| UNSUPPORTED_PROFILE | No interpretation or writes by a legacy-only client |
| PROFILE_INVALID | Wrong root, types, immutable mutation, missing required fields or broken slot invariants |
| OBJECT_ID_COLLISION | Conflicting identity creation; do not reinterpret as one object |
| PLACEMENT_CONFLICT | Concurrent location assignments; explicit resolution |
| PARENT_CYCLE | Selected parent graph cycle; explicit resolution |
| BLOCKED_PARENT | Dependent structural blockage; retain content |
| LIFECYCLE_CONFLICT | Active/deleted alternatives; explicit resolution |
| EDIT_UNDER_DELETED_ANCESTOR | Retained content requiring recovery visibility |

Validate each change against its causal predecessor state for authored invariants such as immutable slot creation and insert-only list mutation, then classify the merged graph separately. A valid concurrent merge may have placement conflicts or cycles; these are not grounds to discard one peer's valid history. Descendants of an unavailable or rejected causal change remain pending/quarantined rather than being applied to invented base state.

Profile-invalid authenticated history is retained for diagnostics and recovery without projecting unsafe state. Readers must converge on the same classification for the same history. Validation must inspect conflicting values, not just the language binding's default visible value.

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
| SS13 | Corrupt immutable placement parent | PROFILE_INVALID; no silent relocation |
| SS14 | Concurrent paragraph edit in TS and Rust | Same Text after merge, including Cyrillic/emoji |

## 16. Limits and serialization

Implementations declare safe limits for payload size, number/depth of nodes, text size and retained history. Limits are checked before local authoring; exceeding local rendering capacity must not erase received valid content. Snapshotting is not authorization to prune historical slots or tombstones.

The initial product benchmark is 100–200 Tasks with nested supporting content. This is not a protocol maximum. Use iterative graph traversal or enforce a documented depth limit to avoid call-stack-dependent behavior. A release corpus must include that limit and a non-destructive overflow case.

## 17. Compatibility decision

The new profile reuses Task semantics, not cross-Resource identity. Existing legacy Tasks remain on the legacy path. Creating a new section from their contents is an explicit copy into a new Resource with a recorded source-to-target map; it is not continuing their existing synchronization history. See the migration companion for the exact workflow.

New clients must dispatch by Resource Genesis profile before interpreting a `#task:` reference. The same textual Task ref shape does not mean two Resources use the same application profile.

## 18. Technical references

The proposed slot/placement scheme and conflict policy are OpenLFCP design decisions. They are not claims about built-in Automerge tree semantics.

- [Automerge conflicts](https://automerge.org/docs/reference/documents/conflicts/) describes scalar conflict inspection and sequence merge behavior.
- [Automerge text](https://automerge.org/docs/reference/documents/text/) describes collaborative text operations.
- [Automerge API](https://automerge.org/automerge/api-docs/js/) provides the current binding reference; its current version is not automatically the project's pinned version.

References checked 2026-10-07. This document does not choose a dependency upgrade without checking the actual repositories.

## 19. Required before implementation baseline freeze

1. Publish SHARED-SECTIONS-TEST-VECTORS-01 with real Automerge change/save bytes for SS01–SS14 and additional negative cases.
2. Record exact TypeScript/Rust dependency versions and adopted Task-spec revision. Verify scalar strings versus Text types and actor derivation in both.
3. Validate slot ordering, repeated moves, cycle/conflict classification, Text operations and snapshot replay against the same corpus.
4. Validate MARKDOWN-SECTIONS-01 fixtures and legacy profile-dispatch behavior.
5. Test crash/restart, data-size limits and the 100–200 Task scenario.

Until these gates pass, claim “implements Working Draft Shared Sections profile at revision …”, not Stable interoperability or production validation.
