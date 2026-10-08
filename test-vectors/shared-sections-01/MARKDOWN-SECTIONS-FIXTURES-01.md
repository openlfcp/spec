# MARKDOWN-SECTIONS-FIXTURES-01

**Project:** OpenLFCP  
**Target:** MVP 0.2  
**Date:** 2026-10-08  
**Status:** Working Draft golden fixture set for MVP 0.2, not in any implementation baseline; 41 reference checks pass, real editor integration pending  
**Normative companions:** `integration/MARKDOWN-SECTIONS-01.md`; `integration/MARKDOWN-REFS-01.md`

> **Revision note (LFCP-02-010).** Rewritten from the MVP 0.2 planning
> fixtures for the grammar decisions of MARKDOWN-SECTIONS-01: the start
> marker follows the heading (M4), so every fixture's section changed;
> MS16 now expects a raw node instead of a suspension (M6). Identities
> MS01–MS26 are kept; MS27–MS38 are added for M1, M2, M4–M7, the comment
> rule and host facts H2–H6. Each changed or added expectation states its
> reason in the fixture's `rationale` or in this document.

## 1. Purpose

These fixtures specify exact source documents, user/remote events and expected resulting Markdown for shared sections. They cover boundaries, both Task-ref placements, nested content, insertion, deletion, detachment, copying, Unicode, CRLF and non-destructive error handling.

Each case has concrete valid Resource and UUIDv7 IDs. The input and output files are also extracted under `markdown-files/` for direct use by test agents.

The reference checks verify JSON/hash consistency, reference lexical boundaries, selected diagnostics, private-text exclusion and three narrow projection operations. It does not claim that Obsidian, the Tasks plugin, a full Markdown-to-model adapter or the OS clipboard has passed these fixtures.

## 2. Files

| File | Purpose |
| --- | --- |
| `MARKDOWN-SECTIONS-FIXTURES-01.json` | Machine-readable before/event/after contract |
| `markdown-files/CASE/before/` | Exact starting file bytes |
| `markdown-files/CASE/observed/` | Source after the user/external action, before adapter reconciliation |
| `markdown-files/CASE/after/` | Expected source after adapter handling |
| `generator/generate-markdown.mjs` | Deterministic construction of concrete fixtures |
| `generator/verify-markdown.mjs` | Reference lexical checks, small smoke executor and optional product-adapter runner |
| `schemas/markdown-fixtures.schema.json` | Structural JSON contract |
| `scripts/check-shared-sections-corpus.mjs` (repository root) | Schema, byte-for-byte regeneration and the reference checks, in `validate.sh` |

The reference lexer uses markdown-it 14.1.0 (pinned in `package.json`) with a small LFCP metadata scanner. It is a fixture checker, not the implementation of the Obsidian parser.

## 3. Event model

Each fixture contains:

- before_files: local files before the action.
- projection_base: trusted or unknown; unknown does not permit guessing whether a local difference is an edit.
- event.kind and observed_files: the initiating action and current source.
- expected.after_files: exact resulting UTF-8 strings, including line endings.
- expected.diagnostics: required error/attention identifiers.
- expected.publication: none, semantic or suspended.
- rationale: present where an expectation changed from the planning fixtures or a case was added for a decision.
- expected.intents: semantic actions that may be published.
- files_sha256: byte identity checks for every supplied file.
- Additional assertions for clipboard output, private canaries, identity preservation or forbidden effects.

An absent filename in after_files means the local file is absent. It is not an instruction to delete a remote Resource. A suspended case has no publishable intents and must preserve the observed local text unless an explicit repair event says otherwise.

## 4. Verification levels

| Level | What has actually run |
| --- | --- |
| Static contract integrity | Hashes, extracted-file equality, expected case structure and consistency |
| Reference lexical checks | Section boundaries, literal fenced examples, refs, selected diagnostics and owned-text canaries |
| Golden operation smoke | Remote checkbox update with preserved ref placement/CRLF; whole-section detach |
| Product adapter | Not run; optional runner interface is provided |
| Obsidian/UI/OS integration | Not run; requires an actual plugin/editor harness |

The three smoke fixtures are MS02, MS10-detach and MS12. Their small executor does not prove the complete projection algorithm or all editor interactions.

Diagnostics depending on a durable projection base or actual model state, such as NODE_BINDING_LOST, PROJECTION_BASE_UNKNOWN and PARENT_CYCLE, remain product-adapter expectations. The default report does not mark them as independently implemented by the lexical scanner.

## 5. Fixture catalog

| ID | Scenario | Expected behavior |
| --- | --- | --- |
| MS01 | Heading, start marker, Task with child paragraph/item | Parse one section and stable refs; private surrounds excluded |
| MS02 | Two projections with inline/child refs | Remote completion preserves both placements |
| MS03 | New Task inside section | Allocate exactly one identity and publish task.create_in_section |
| MS04 | New Task outside section | No shared mutation |
| MS05 | Missing end marker | Suspend; never capture following private text |
| MS06 | Fenced Markdown example | No live section or refs |
| MS07 | Copy complete section to another note | Another projection of the same identities |
| MS08 | Duplicate Task ID inside one projection | Diagnose; no silent new object or duplicate publication |
| MS09 | Rename/change heading level | Same section identity; title edit only |
| MS10-delete | Delete child paragraph | Shared node.delete intent |
| MS10-detach | Detach section | Readable private source; no shared deletion |
| MS11 | Rebuild without causal base | Preserve source; reconcile before publishing |
| MS12 | CRLF and Cyrillic/emoji | Minimal checkbox update; line endings and private text unchanged |
| MS13 | Ordered Task and nested item | Content indentation remains 3 and 6 columns respectively |
| MS14 | Remote parent cycle | Preserve last safe source; show conflict |
| MS15 | Copy rendered Task title | No SVG, status label or participant popover in clipboard |
| MS16 | Fence typed inside the region | Becomes a raw node with a new identity (M6); was a suspension in the planning fixtures |
| MS17-empty | Empty paragraph | Keep its node identity |
| MS17-transient | Incomplete Task syntax while typing | Do not create a new object from damaged binding |
| MS17-undo | Undo an acknowledged completion | New compensating reopen intent, not retracted history |
| MS18 | Ambiguous external cut/paste | Preserve content; no physical shared deletion |
| MS19 | Mismatched end ref | Suspend extraction |
| MS20 | Task ref to another Resource | Diagnose foreign reference; do not silently adopt |
| MS21 | Remove only Task ref inside section | No private exception; repair binding |
| MS22 | Nested section boundaries | Suspend overlapping ranges |
| MS23 | Missing required heading before the start marker | Diagnose rather than infer one |
| MS24 | Owned-content extraction | Includes shared body but neither private canary |
| MS25 | Copy readable section | Strip metadata only from clipboard output; source unchanged |
| MS26 | Delete local file | No shared delete or capability change |

| MS27 | Enter after a Task with a child-line ref | The ref stays with its Task; the new empty Task is unbound and unpublished (M1, adapter) |
| MS28 | Enter after a Task with a nested paragraph | The ref and the paragraph stay with the original Task (adapter) |
| MS29 | Tasks completes a Task | `✅ <date>` appended, child-line ref untouched, completion shared (H6) |
| MS30 | Tasks completes a recurring Task | The next occurrence above becomes a new shared Task; the done one keeps its ref (H6) |
| MS31 | Tab-indented nesting | Same counts and owned text as spaces (M2, H2) |
| MS32 | A line between the heading and the start marker | `SECTION_HEADING_INVALID`, suspended (M4, H4) |
| MS33 | A table and a fence with raw markers | Two raw nodes; their text is owned (M6) |
| MS34 | A heading typed inside the region | `SECTION_UNSUPPORTED_SYNTAX`, suspended until split |
| MS35 | Tasks-local tokens on a Task line | Not shared Task fields (M7) |
| MS36 | Private text between the end marker and the next heading | The share preview warns (H5) |
| MS37 | Standalone Detach inside a section | Refused or redirected |
| MS38 | `%%` and multi-line HTML comments inside the region | Not extracted; the rest of the section is extracted (§4.5) |

The split IDs extend the original MS01–MS18 outline without renumbering its meaning; MS27–MS38 are numbered after the planning fixtures.

## 6. Private-text and source-preservation checks

Fixtures contain explicit private canaries before and after the region. The reference checker verifies that they remain in source when expected and are absent from its owned-content extraction.

The production adapter must repeat this check against the actual semantic payload before encryption. A clean server plaintext scan cannot prove correct extraction: an accidentally included private paragraph would still be encrypted.

Compare source bytes outside intended edits. Preserve LF/CRLF, inline versus child refs and unrelated text. A scanner that recognizes markers is not yet proof that a minimal-diff updater preserves all formatting; that is an independent adapter test.

## 7. Clipboard distinction

UI decorations and persistent binding comments are different:

- Rendered SVG/checkmarks, tooltip text and popover content must never leak into clipboard content.
- Raw-source copying may retain persistent refs according to the format.
- The explicit readable-copy action removes persistent section/node/Task metadata from its output without changing the source file.

MS15 provides a rendered title-selection contract, including forbidden fragments for plain and rich output. MS25 provides exact readable-section text. Their real browser/editor clipboard paths have not been executed here.

## 8. Run reference checks

From the repository root, after `pnpm install --frozen-lockfile`:

    node scripts/check-shared-sections-corpus.mjs

To regenerate the fixtures deliberately:

    node test-vectors/shared-sections-01/generator/generate-markdown.mjs

The standalone JSON contains all strings; the expanded files are conveniences and are checked against those strings. Preserve byte order and line endings when importing the corpus into repository tests.

## 9. Product adapter interface

Provide a module exporting:

    async function runFixture(input) { /* return actual observed effects */ }

Run:

    node test-vectors/shared-sections-01/generator/verify-markdown.mjs <directory holding the fixtures> --adapter /absolute/path/adapter.mjs

Input contains id, concrete identifiers, before_files, event and projection_base. Expected results are not supplied to the adapter. Return after_files, diagnostics, intents, publication and clipboard output where applicable.

The runner compares exact expected files and effects. Use real plugin/model APIs or a headless harness for these actions. An adapter that merely echoes observed_files does not exercise reconciliation. For rendered clipboard cases, connect the adapter to the actual editor DOM/clipboard implementation.

The input assumes the section identity and existing nodes are established in a test Resource. Model-backed harnesses should initialize them from the bound before projection and the shared IDs, then retain a trusted projection base. Unknown-base cases deliberately omit that trust. Do not reconstruct expected source edits as incoming remote changes.

## 10. Integration work still required

1. Full Markdown AST-to-node mapping, including child paragraphs, ordered lists, empty blocks and ambiguous partial edits.
2. Obsidian Live Preview, source and reading mode behavior.
3. The installed Tasks plugin's date/priority/ref parsing.
4. Editor transaction grouping, selection/caret stability, undo and cut/paste.
5. Plain and rich clipboard serialization with actual decorations.
6. Restart, external-file edits, multiple projections and conflict-resolution UI.
7. Desktop platform checks and performance on the 200-Task section.

These fixtures specify those expected outcomes without claiming those integrations have already passed.

## 11. Change control

The Markdown specification remains authoritative. If a fixture and prose disagree, fix the Working Draft and fixture together; do not quietly implement the convenient interpretation. Existing standalone Task refs keep their original semantics outside a bound section.

Any intentional change to expected files requires review of private boundaries, semantic intents, identity preservation and hashes. Regenerating snapshots is not an acceptable substitute for explaining changed behavior.
