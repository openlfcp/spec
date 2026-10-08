# MARKDOWN-SECTIONS-01

**Title:** Portable Markdown Bindings for OpenLFCP Shared Sections  
**Status:** Working Draft for MVP 0.2, not in any implementation baseline; grammar decisions M1–M7 of the MVP 0.2 review applied, fixture validation pending  
**Date:** 2026-10-08  
**Profile:** `org.openlfcp.shared-sections.v1`  
**Dependencies:** SHARED-SECTIONS-PROFILE-01; MARKDOWN-REFS-01

> **Revision note.** This is the MVP 0.2 planning draft of this grammar,
> revised for LFCP-02-007 with the decisions of the MVP 0.2 review:
> Task refs inside sections use the child-line form, as in 0.1 (M1); tabs
> are accepted in indentation (M2); the start marker follows the heading
> (M4); every node carries a marker, hidden in Live Preview by default
> (M5); unsupported blocks are carried as raw blocks (M6); Tasks-local
> tokens stay local (M7). Host facts H2–H6 are cited from
> `obsidian: docs/devel/testing/obsidian-host-facts.md`. Fixtures are
> rewritten in LFCP-02-010.

## 1. Purpose and precedence

Bind one shared section and its nodes to ordinary local Markdown while keeping surrounding text private. Binding metadata is persistent source text; checkmarks, outlines, tooltips and access cards are rendered decorations and are never serialized as content.

MUST, MUST NOT, SHOULD and MAY describe this draft's conformance requirements. Existing standalone Task refs keep both forms and their behavior from MARKDOWN-REFS-01. Inside a valid bound section, this document governs ownership and structural interpretation. It does not modify the behavior of old-profile Resources or unbound notes.

Only the new profile permits a section reference, `lfcp1:<resource>#section:<section-id>`. It appears only in the section boundary comments of §2, never in an `lfcp-ref` comment: MARKDOWN-REFS-01's object-type grammar is unchanged, and `#section:` in an `lfcp-ref` comment stays malformed there. Dispatch by the Resource's validated profile, not by a comment name alone. A file marker does not grant access or create a collaboration.

## 2. Canonical section boundaries

```text
## Section title
<!-- lfcp-section: lfcp1:<resource>#section:<section-id> -->
... bound section content ...
<!-- /lfcp-section: lfcp1:<resource>#section:<section-id> -->
```

Boundary lines:

- occupy an entire physical line at column zero;
- carry identical canonical references at start and end;
- contain no server address, local path, credential, key material or participant name;
- use LF or CRLF consistently with the host file; preserving existing line endings is required.

A parser recognizes a boundary comment by its fixed parts, with the whitespace rule of MARKDOWN-REFS-01 §6: `<!--`, one or more ASCII spaces or horizontal tabs, the literal `lfcp-section:` or `/lfcp-section:`, one or more spaces or tabs, the section reference, one or more spaces or tabs, and `-->`. Extra whitespace at each separator is accepted. A serializer emits exactly one ASCII space at each separator. Trailing horizontal whitespace after the comment is accepted.

`resource` is canonical unpadded Base64url of exactly 32 bytes. `section-id` is canonical lowercase UUIDv7. Re-encoding MUST reproduce the original Resource token. The `lfcp1:` prefix is an application reference format, not a new Wire version.

A parser MUST NOT infer boundary lines inside list indentation, blockquotes, inline code, fenced code, an Obsidian comment (`%%…%%`) or another literal context. Unsupported reserved-marker spellings produce diagnostics, not an expanded sharing range.

## 3. Heading and region

A section starts with exactly one ATX heading line at column zero (one to six `#` characters, one space and the title), and the start marker is the line right after it, with no line in between (decision M4). The heading is the section's visible title; its level is local presentation and its title text is shared. Empty title text is representable during editing but discouraged.

The marker sits below its heading because Obsidian moves a heading with the lines down to the next heading of the same or a higher level: a marker above a heading would stay behind when the heading is dragged in the Outline view and would capture whatever lands between (host fact H4). A heading that is not immediately followed by its start marker, or a start marker not immediately preceded by a heading, is `SECTION_HEADING_INVALID`: the parser fails closed for that section (§9).

The matching end marker closes the exact owned region. A later heading is not an alternative terminator. Changing the title or heading level cannot expand the region.

Headings inside the region are not supported in this version (decision M6). A heading line between the boundaries is `SECTION_UNSUPPORTED_SYNTAX`; the share command offers to split the section at that heading instead.

Obsidian folds, drags and embeds a heading with every line down to the next heading of the same or a higher level, including the end marker and any private text after it (host fact H5). The share and insert commands SHOULD warn when private text lies between the end marker and the next such heading.

The boundary lines and binding comments themselves are metadata, not shared prose. The initial-sharing command can use a heading range to propose a selection; it MUST preview that exact selection before creating the permanent markers.

One file may contain multiple non-overlapping sections. The same section may have several local projections. Nested or overlapping section ranges are invalid. A section may not be nested in a list or blockquote in v1, although it fully supports nested list content inside its boundaries.

## 4. Node binding forms

Every node carries one binding marker (decision M5). An editor SHOULD hide binding markers in Live Preview by default, with a setting to show them; Obsidian itself renders HTML comments on their own line or at the end of a Task line as visible source (host fact H3), so hiding them is the adapter's decoration work. Raw-source mode always shows them. Hidden markers must not hide where sharing begins and ends (§6).

### 4.1 Task nodes

A Task node reuses the existing Task ref, in its child-line form (decision M1):

```markdown
- [ ] Prepare contract
  <!-- lfcp-ref: lfcp1:<resource>#task:<task-id> -->
```

The Task ID is also the task NodeId under SHARED-SECTIONS-PROFILE-01. A serializer emits the child-line form inside a section, as it does for standalone Tasks. A parser accepts both forms of MARKDOWN-REFS-01, with its association rules unchanged: the child-line ref immediately follows its Task line, and two refs on one Task are invalid even when identical.

Child-line is required in practice: the Obsidian Tasks plugin, completing a Task, appends `✅ <date>` after an inline ref, which then is no longer last on the line (`LFCP_REF_NOT_AT_LINE_END`); a child-line ref is untouched (host fact H6). The Enter key after a Task with a child-line ref splits the Task line from its ref line; keeping the ref with its Task is the adapter's work, in the editor transaction (requirement fixtures MS19–MS21).

Resource IDs on Task refs inside a section MUST equal the enclosing Resource. The Task must either resolve to a valid Task in that Resource or be part of an explicitly prepared local creation transaction. A foreign Resource ref is a blocking diagnostic, not an access shortcut.

### 4.2 Non-Task list items

```markdown
- Check company details
  <!-- lfcp-node: item:<node-id> -->
```

The `item` marker is the only non-whitespace content on its line, at the list item's content indentation, and follows the item's last continuation line: an HTML comment interrupts a paragraph in CommonMark, so a marker right after the first line would cut the item's text short. The host is an unordered or ordered list item without a Task checkbox. The node's `kind` must be `item`.

An ordered example:

```markdown
1. Review draft
   <!-- lfcp-node: item:<node-id> -->
```

There is no inline `lfcp-node` form.

### 4.3 Paragraphs

```markdown
<!-- lfcp-node: paragraph:<node-id> -->
Use the updated draft.
This continues the same paragraph.
```

The paragraph marker prefixes its paragraph at the same content indentation. The next physical line begins the paragraph without an intervening blank line. Its node kind must be `paragraph`. A paragraph ends at a blank line, a valid following node boundary or list item, or the section end.

Under a Task or item, the paragraph marker and paragraph sit at that parent's content indentation. The paragraph marker and item marker have distinct tokens, so a paragraph directly below a Task or item is not bound to its parent by accident.

Paragraph nodes may contain soft line breaks. Separate paragraphs are separate nodes. An empty paragraph during editing is retained locally; an empty saved paragraph may be represented by its marker followed by an empty line and keeps its node identity. This explicit empty case is the only exception to the immediate non-blank paragraph rule.

### 4.4 Raw blocks

A block the section grammar does not model is shared verbatim as a raw node (decision M6), instead of pausing the section:

```markdown
<!-- lfcp-node: raw:<node-id> -->
| Item | Owner |
| --- | --- |
| Contract | Anna |
```

The `raw` marker is on its own line at the parent's content indentation, immediately before the block. The block is:

- a fenced code block: from its opening fence through its closing fence; an unclosed fence is `SECTION_UNSUPPORTED_SYNTAX` and fails closed;
- a table, a callout or blockquote, or an HTML block other than a comment: from the line after the marker through the line before the next blank line or the next node marker, whichever comes first. A blank line inside a multi-line HTML comment does not end the block: the comment is literal through the line containing its `-->`.

The node's `kind` is `raw`; its Text holds the block's source lines exactly, relative to the content indentation, without the marker. A raw node has no children. Peers render it as the same Markdown; nothing inside it is interpreted as a binding, a Task or a heading.

### 4.5 Comments stay local

An Obsidian comment (`%%` … `%%`), or an HTML comment (`<!--` … `-->`) that is not an LFCP marker, inside a section is never shared: Obsidian hides both in Reading view, users write private notes in them, and a comment typed into a section later would otherwise reach the other participants without any preview. A comment runs from its opening delimiter through the line that holds its closing one, blank lines included. It is `SECTION_UNSUPPORTED_SYNTAX` with the message "Comments can't be shared; move them out of the section", and it fails closed for that comment only:

- the comment's lines are not extracted: they become no node and no Text, and the comment never enters a payload;
- the rest of the section keeps synchronizing;
- the comment stays in the local file where it is. A remote patch applies around it and keeps it next to the line it follows; a remote change that would remove or move that line, or the nodes around the comment, pauses the section's projection with the same message until the user moves the comment out;
- markers inside a comment are literal, as in MARKDOWN-REFS-01.

This is deliberately the stricter choice: carrying comments as raw blocks later would be a compatible relaxation, while text already sent cannot be taken back.

### 4.6 Identity interpretation

The enclosing section supplies Resource context for `lfcp-node` markers. Such a marker outside a valid section does not independently authorize or activate sharing. Node IDs are permanent; line numbers, text equality and indentation are not identities.

Exactly one structural occurrence of each NodeId/TaskId is allowed per section projection. The same IDs in another complete projection of the section are legitimate. Duplicate IDs inside one projection are diagnosed before any upload or source regeneration.

## 5. Supported syntax and indentation

| Syntax | Binding treatment |
| --- | --- |
| Root Task or list item | `-`, `+`, `*`, or ordered decimal marker; preserve local marker where possible |
| Nested Task/item | Structural child of the nearest valid containing Task/item |
| Supporting paragraph | Root paragraph or child of a Task/item |
| Inline emphasis, code spans, link source | Text source preserved; target content is not transferred |
| Soft line break | Text LF in the same node; host line ending remains local |
| Blank line | Paragraph separation/local layout; not a standalone shared node |
| Task metadata | Existing adapter field contract; date-only values are not reinterpreted |
| Tasks-local tokens (`🔁`, `🛫`, `➕`, `❌`, priority signs such as `🔼`) | Local presentation of the Task line, not shared fields (decision M7); kept in the local line, shown in the share preview, never written to the Task |
| Fences, tables, callouts, blockquotes, HTML blocks | Raw node (§4.4) |
| Obsidian comments (`%%` … `%%`) and HTML comments that are not LFCP markers | Never shared: `SECTION_UNSUPPORTED_SYNTAX` for the comment only; it stays local (§4.5) |
| Headings inside the region | Unsupported: `SECTION_UNSUPPORTED_SYNTAX`; the share command offers to split the section |
| File embeds/transclusion | No file transfer or automatic dereference; the embed's source text is shared as text |

Canonical list emission uses `- ` for bullet items and consecutive decimal numbers starting at 1 for an ordered sibling run. Existing cosmetic spelling/numbering may be retained while the structure is unchanged. The shared `list_style` distinguishes ordered from bullet; exact starting number and marker glyph are not shared semantics in this version.

Content indentation is leading indentation plus the physical list marker and the following space (`- ` is two columns; `10. ` is four). Child content is emitted at the parent's content indentation; deeper children apply the same rule recursively.

Tabs are accepted in structural indentation (decision M2): Obsidian indents nested lists with tabs by default (host fact H2). A node marker, like a child-line ref (MARKDOWN-REFS-01 §12), may stand at the content column or up to three columns to its right after tab expansion; a serializer emits it at the content column. A parser expands a tab to the next multiple of 4 columns, as CommonMark does, and compares the resulting columns. A serializer keeps the indentation characters of existing lines; for new lines it follows the line it nests under (a tab-indented parent's children are tab-indented, one tab per level). Mixed tabs and spaces on one line are accepted by the same expansion.

**Text extraction.** A node's Text is derived from its source lines as follows; line endings in Text are always LF, and a file's CRLF is local presentation.
- `item`: the inline text after the list marker and its following space, plus the continuation lines of the same paragraph (lazy continuation lines included), joined with LF. Child paragraphs with their own marker are separate nodes.
- `paragraph`: the paragraph's lines without the marker line, each with its indentation removed up to the parent's content column, joined with LF.
- `raw`: the block's lines, each with its indentation removed up to the parent's content column, joined with LF, without a trailing LF.
- Indentation is removed by columns after tab expansion: a tab that reaches past the content column leaves its remaining columns as spaces in Text.
- A Task node has no Text: its title and fields come from the Task line by the 0.1 adapter field contract (MARKDOWN-REFS-01). A Task title is one line.

All metadata lines are excluded from Text and Task title extraction. Continuation lines belonging to an item's inline text must be distinguished from a child paragraph by the paragraph marker/blank-line grammar. Content must round-trip through the defined node tree without guessing a private versus shared interpretation.

A Tasks recurring Task completed inside a section gets its next occurrence on a new line above, without a ref (host fact H6). Inside a healthy section that line is new unbound content and becomes a new shared Task (§7); the completed occurrence keeps its child-line ref.

## 6. Full illustrative projection

The following uses shape placeholders for IDs; it is readable documentation, not a valid identifier fixture:

```markdown
My private planning notes.

## Joint launch
<!-- lfcp-section: lfcp1:<R>#section:<S> -->
- [ ] Prepare contract 📅 2026-10-10
  <!-- lfcp-ref: lfcp1:<R>#task:<T1> -->
  <!-- lfcp-node: paragraph:<P1> -->
  Use the updated draft.

  - Check company details
    <!-- lfcp-node: item:<I1> -->
  - [ ] Obtain approval
    <!-- lfcp-ref: lfcp1:<R>#task:<T2> -->

<!-- lfcp-node: paragraph:<P2> -->
The release date is still under discussion.

<!-- lfcp-node: raw:<B1> -->
| Milestone | Date |
| --- | --- |
| Launch | TBD |

- [ ] Update website
  <!-- lfcp-ref: lfcp1:<R>#task:<T3> -->
<!-- /lfcp-section: lfcp1:<R>#section:<S> -->

My private follow-up notes.
```

The plugin hides metadata lines in Live Preview by default (§4). Hidden presentation must not conceal where sharing begins and ends: the section boundary indicator remains discoverable independently of comment visibility.

## 7. New content and missing metadata

An ordinary unbound Task outside a section remains local-only under MARKDOWN-REFS-01. New supported content inside a healthy, authorized, fully loaded section (SHARED-SECTIONS-PROFILE-01 §12.1: the section is `ready`) becomes shared automatically.

For a newly inserted unbound node, the adapter generates an identity and inserts the appropriate marker under a mutation guard as part of durable local reconciliation. It then publishes the semantic change. The user does not need to type or manage IDs.

Missing metadata on previously bound content is not automatically new content. Use editor transaction mapping or a retained projection base to distinguish new insertion, deliberate deletion, cut/paste and marker removal. If no reliable distinction is possible, report `NODE_BINDING_LOST` and preserve text; do not duplicate the old object or delete it remotely.

A line without a marker under a bound Task, where the grammar expects one (for example a paragraph without its `paragraph` marker), is new content only when the editor transaction shows it was typed or pasted as new; otherwise it is `NODE_BINDING_LOST`.

Inside a shared section, removing only a Task ref does not create a private exception. It damages the binding and needs repair or an explicit move/detach workflow. Outside a section, removing the same Task ref retains the existing standalone detach meaning. The UI must explain this context difference; the standalone Detach command does not apply inside a section.

## 8. Initial sharing and unsupported content

Before first sharing, parse the selected range, identify all content including nested children, and preview the actual boundary, including raw blocks that become shared and comments that stay local. If it contains existing bindings to another Resource, use the explicit conversion workflow of the MVP 0.2 compatibility draft. Never include the entire old Resource as a hidden side effect.

Constructs that are neither modeled nor carried as raw blocks (§5: headings inside the region) block creation unless the user splits or excludes them with a new visible boundary.

If unsupported syntax appears during editing, retain it locally, mark the section as needing attention, and pause unsafe section extraction/projection. Other sections may continue. Do not erase the unsupported text when a peer sends a valid update.

## 9. Boundary integrity and fail-closed scanning

The scanner must track Markdown lexical context; a global regex is insufficient. Literal examples inside fenced code, inline code or `%%` comments are not live markers. A code fence opened inside a shared region is a raw block (§4.4); the scanner must not guess a boundary through an unclosed fence.

Diagnose missing/mismatched start/end, multiple starts before an end, overlapping ranges, a start marker not right after its heading, reserved malformed markers and invalid IDs. On a boundary error:

1. Keep all source text unchanged.
2. Suspend outbound extraction and destructive inbound patches for the affected region.
3. Show a repair preview based on the last known boundary when available.
4. Do not extend to the next heading, the next unrelated end marker or end-of-file.
5. Require an explicit range choice if the intended extent cannot be established.

If damaged boundaries could affect several candidate ranges, pause all those candidates. An otherwise valid unrelated section can continue. A whole-file or whole-projection disappearance removes a local projection; it never implies deletion of the Resource or all its Tasks.

## 10. Copy, cut, move, detach and delete

| Operation | Required meaning |
| --- | --- |
| Copy complete bound section | Another projection of the same section; no new Resource or Task IDs |
| Copy complete standalone Task unit | Existing Task-ref behavior: another projection of the same Task |
| Copy readable text action | Strip binding metadata in clipboard output; preserve visible task/text content |
| Copy incomplete section markers | Invalid partial binding; do not infer a shared region |
| Copy bound node within same section | Duplicate structural ID diagnostic; offer explicit duplicate-as-new |
| Move node within same section | Preserve ID and descendants; emit placement change |
| Remove only binding metadata | Repair/detach semantics depend on bound-section context; never global deletion |
| Delete visible node content in a healthy section | Shared delete intent after reliable reconciliation; retained tombstone semantics |
| Detach whole section | Strip its local section/node/Task bindings; retain readable text; no shared mutation |
| Delete host file | Remove local projections only |

Moving a Task out to a private area through the explicit "Insert Task projection" action creates another projection, not a structural move out of the section. Moving content across Resource boundaries is an explicit copy/conversion workflow, not one atomic tree move.

For editor cut/paste, preserve the complete bound unit in the transaction/clipboard. If a cut is locally committed as a recoverable deletion before paste, a matching same-session paste may restore that identity and move it through a compensating transaction. Peers may briefly observe the tombstone; atomic cross-file movement is not promised. Never physically destroy the source object. An external ambiguous cut/paste cannot be resolved by matching titles alone and must be diagnosed.

## 11. Projection bases, rebuild and external edits

Maintain a durable local projection record: Resource/section identity, last applied shared heads, last reconciled source revision/hash, source ranges and node bindings. This record is local and contains no new shared authorization.

Source markers allow reconstruction of identity/index mappings after metadata loss. They do not prove whether an offline source difference is an unuploaded edit or merely a stale rendering. Without a trusted base, preserve the local candidate, fetch shared state and require reconciliation before publishing differences or overwriting source.

External file changes must be compared to a trusted prior projection. Do not treat a stale copied note as an authoritative replacement for the shared section. With multiple local projections, process unambiguous edits against their bases; expose an inconsistency when causal intent cannot be reconstructed.

A remote patch must check the current document revision and relevant source ranges before application. If local typing has changed them, rebase or pause. Mutation guards prevent generated metadata and projection writes from creating duplicate semantic edits. Edits by another plugin carry no editor `userEvent` (host fact H6); they are external edits for this rule.

## 12. Structural and content conflicts

When the profile reports placement conflicts, parent cycles or broken structure, preserve the last safe Markdown and pending local edits. Show the conflicting alternatives in a separate resolution surface. Do not remove blocked nodes from the source merely because the canonical tree currently excludes them.

After a resolution, reconcile the resulting model with local pending edits, then apply a guarded patch. Scalar Task conflicts retain existing provisional-value behavior with explicit indicators; structural resolution is not a whole-section "server wins" overwrite.

## 13. Decoration and clipboard invariant

Synchronization indicators, boundary highlights, participant names and popovers are DOM/editor decorations only. A status update MUST NOT modify Markdown, create a file-write event solely for styling, or enter the document's text undo history.

Test both editor and reading views. Plain-text and rich-text clipboard serialization must exclude the decorative SVG/CSS mark, status labels and popover contents. This requirement does not silently strip durable `lfcp-ref`/section metadata from a raw-source copy; use the explicit readable-copy action for that.

## 14. Parser outputs and diagnostics

The parser returns section reference, heading range/level, start/end ranges, node kind/ID/parent/order, owned source spans, Task-ref placement, unbound new-node candidates and diagnostics. Offsets are local implementation details and never serve as object identity.

At minimum expose:

```text
SECTION_BOUNDARY_MISSING
SECTION_BOUNDARY_MISMATCH
SECTION_BOUNDARY_OVERLAP
SECTION_HEADING_INVALID
SECTION_PROFILE_MISMATCH
SECTION_UNSUPPORTED_SYNTAX
NODE_BINDING_LOST
NODE_BINDING_DUPLICATE
NODE_BINDING_ORPHAN
NODE_KIND_MISMATCH
FOREIGN_RESOURCE_REF
PROJECTION_BASE_UNKNOWN
PROJECTION_DIVERGED
```

Existing `MALFORMED_LFCP_REF`, `DUPLICATE_LFCP_REF`, `LFCP_REF_NOT_AT_LINE_END`, invalid-ID and orphan diagnostics continue to apply. Diagnostics retain text; they are never instructions to delete it.

## 15. Mandatory fixture cases

| Case | Required assertion |
| --- | --- |
| MS01 | Parse a full section with Task children and root paragraphs |
| MS02 | Accept both Task-ref placements and preserve them on remote completion |
| MS03 | Insert unbound Task inside a valid region; assign one ID and share once |
| MS04 | Insert identical-looking Task outside region; publish nothing |
| MS05 | Remove one end marker; no adjacent private text enters payloads |
| MS06 | Marker-shaped fenced example stays literal |
| MS07 | Copy a complete section to another note; same shared identities |
| MS08 | Duplicate a node inside the section; diagnosis without duplicate semantic creation |
| MS09 | Rename heading/change level; same section boundary and identity |
| MS10 | Delete body node versus detach projection; distinct shared effects |
| MS11 | Restart after index loss; recover IDs without publishing unbased differences |
| MS12 | CRLF, Cyrillic and emoji round-trip without unrelated source changes |
| MS13 | Task/item/paragraph nesting and ordered markers parse consistently |
| MS14 | Structural conflict freezes unsafe projection while preserving local text |
| MS15 | No decorative icons/labels in plain or rich clipboard output |
| MS16 | A fence typed inside the region becomes a raw node (M6); unsupported syntax such as a heading (MS34) remains intact and visible as a problem |
| MS17 | Empty paragraph, transient list edits and undo preserve identity or diagnose ambiguity |
| MS18 | Cut/paste across files never physically destroys shared content |
| MS19 | Mismatched end reference blocks extraction |
| MS20 | A foreign Resource Task ref is not silently adopted |
| MS21 | Removing only a Task ref does not make a private exception |
| MS22 | Nested section boundaries suspend both ranges |
| MS23 | A missing heading is not inferred |
| MS24 | Payload extraction excludes surrounding private text |
| MS25 | The readable-copy action strips metadata only in its output |
| MS26 | Deleting a local file does not delete the collaboration |
| MS27 | Enter at the end of a Task line with a child-line ref and no children: the new Task line is unbound, the ref stays with the original Task (adapter requirement) |
| MS28 | Enter at the end of a Task line with a child-line ref and a nested paragraph: the ref and the paragraph stay with the original Task (adapter requirement) |
| MS29 | Tasks completes a Task with a child-line ref: `✅ <date>` is appended to the Task line, the ref is untouched, the completion is shared (H6) |
| MS30 | Tasks completes a recurring Task: the next occurrence above is new shared content, the done occurrence keeps its ref (H6) |
| MS31 | Tab-indented and mixed tab/space nesting parse to the same tree as space indentation (M2, H2) |
| MS32 | A heading moved away from its start marker fails closed (H4) |
| MS33 | A table and a fence inside the region round-trip as raw nodes (M6) |
| MS34 | A heading inside the region is `SECTION_UNSUPPORTED_SYNTAX` and blocks sharing until split |
| MS35 | Tasks-local tokens on a Task line stay local and appear in the share preview (M7) |
| MS36 | Fold, Outline drag and `![[note#heading]]` embed of a section heading with private text before the next heading: the warning of §3 appears; nothing private is shared (H5) |
| MS37 | The standalone Detach command inside a section is refused or redirected; outside it keeps its 0.1 meaning |
| MS38 | A `%%` comment and a multi-line HTML comment with a blank line inside the region: not extracted, the rest of the section syncs, a remote edit next to them keeps them in place, a remote removal of the line one follows pauses the section with the comment message (§4.5) |

Examples in this document are not a substitute for byte-exact before/action/after fixture files. Freeze grammar only after rendering these fixtures in the selected Obsidian/Tasks versions and testing them through the independent Markdown parser. Until then this remains a Working Draft.

## 16. Relationship to existing files

MARKDOWN-REFS-01 remains authoritative for standalone Task refs, canonical Resource/Task encoding and both existing placements. This document adds bounded section context, the section reference and non-Task node markers. Its context-specific missing-ref behavior is carried into the Obsidian architecture.

SHARED-SECTIONS-PROFILE-01 defines the shared structure; this document defines its source projection. Source order creates structural intents only when bindings and a trusted projection base are available. Neither specification turns an arbitrary private file into a synchronized document.
