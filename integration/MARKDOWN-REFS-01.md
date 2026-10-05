# MARKDOWN-REFS-01: OpenLFCP Markdown Projection Reference Format

**Status:** Working Draft 0.1  
**Project:** OpenLFCP  
**Profile dependency:** `org.openlfcp.shared-objects.v1`  
**Primary consumers:** Obsidian, VS Code, other Markdown editors  
**Revision date:** 2026-10-05

> This document defines the portable Markdown syntax used to bind an ordinary local Markdown projection to an LFCP Shared Object. It deliberately does not define Task semantics, LFCP networking, or editor UI.

---

## 1. Design goal

A Markdown projection should remain ordinary readable Markdown while carrying a stable LFCP object reference.

Version 1 supports **two equivalent placements** for the same `lfcp-ref` comment:

1. **inline form**, on the host Task line;
2. **child-line form**, on the immediately following child HTML-comment line.

Both forms are conforming and identify the same Shared Object.

Compact inline form:

```md
- [ ] Prepare API contract <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

Preferred compatibility form:

```md
- [ ] Prepare API contract
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

The child-line form is RECOMMENDED when the host editor or another Markdown plugin attaches semantics to the end of the Task line, or when compatibility is not known.

The inline form MAY be used when the adapter knows that a trailing HTML comment does not interfere with the host syntax, or when a user explicitly prefers the compact representation.

---

## 2. Placement policy

The two placements are semantically equivalent.

A conforming parser MUST accept both.

A conforming serializer MAY emit either form, subject to these rules:

- an Obsidian adapter SHOULD use the child-line form by default because task-oriented plugins may parse suffix metadata at the end of the Task line;
- an adapter that knows inline comments are harmless MAY emit the inline form;
- a user-facing adapter MAY expose a placement preference;
- when updating an existing valid projection, an adapter SHOULD preserve its current placement form rather than converting it gratuitously;
- an adapter SHOULD use the child-line form when compatibility is uncertain.

`MARKDOWN-REFS-01` therefore standardizes the **reference syntax and association**, not one mandatory visual layout.

---

## 3. Why child-line is preferred for Obsidian Tasks compatibility

Task-oriented Markdown plugins may assign meaning to suffixes at the end of the Task line, including due dates, completion dates, recurrence markers, priorities, or other metadata.

For example:

```md
- [ ] Prepare API contract 📅 2026-10-10
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

keeps the Task line itself untouched by LFCP metadata.

The equivalent inline form is valid OpenLFCP Markdown:

```md
- [ ] Prepare API contract 📅 2026-10-10 <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

but an Obsidian adapter SHOULD avoid emitting it by default when Obsidian Tasks or another suffix-sensitive parser is in use.

This is a compatibility preference, not a difference in LFCP semantics.

---

## 4. Projection unit

A Task projection has one host Task line and exactly one associated `lfcp-ref` comment.

### 4.1 Inline projection unit

One physical line:

```text
TASK_LINE_WITH_REF
```

Example:

```md
- [ ] Prepare API contract <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

### 4.2 Child-line projection unit

Two consecutive physical lines:

```text
TASK_LINE
REF_LINE
```

Example:

```md
- [ ] Prepare API contract
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

There MUST be no blank line between a Task and its child-line ref.

An adapter SHOULD treat the complete projection unit as one logical unit when moving, copying, detaching, or repairing a shared Task.

---

## 5. Task-line independence

The Task line is parsed according to the editor/application adapter.

`MARKDOWN-REFS-01` does not define:

- checkbox status syntax beyond locating the projection host;
- Obsidian Tasks emojis;
- priority syntax;
- due-date syntax;
- recurrence syntax;
- tags;
- completion dates.

For semantic Task parsing, the inline `lfcp-ref` comment MUST be treated as projection metadata rather than Task title content.

For child-line form, the ref line MUST NOT be interpreted as Task title or Shared Object semantic content.

---

## 6. Canonical ref comment payload

Both placement forms use exactly the same comment payload:

```text
<!-- lfcp-ref: <object-ref> -->
```

Canonical spacing is:

- `<!--`;
- one ASCII space;
- literal `lfcp-ref:`;
- one ASCII space;
- object reference;
- one ASCII space;
- `-->`.

A serializer MUST emit this canonical comment spelling regardless of placement.

A parser recognizes the comment by its fixed parts: `<!--`, then one or more whitespace characters, then the literal `lfcp-ref:`, then one or more whitespace characters, the object reference, one or more whitespace characters, and `-->`. Whitespace here is an ASCII space or horizontal tab. A parser MUST accept extra whitespace at each separator, and SHOULD normalize it to the canonical single space if it deliberately rewrites the comment. A comment that begins `<!--` and contains `lfcp-ref:` but does not have this shape (for example `<!--lfcp-ref:` with no separator) is a malformed ref (Section 15).

---

## 7. Object reference

For Shared Objects v1, the portable textual object reference is:

```text
lfcp1:<resource-b64url>#<object-type>:<object-id>
```

where:

- `resource-b64url` is unpadded Base64url of the raw 32-byte LFCP Resource ID;
- `object-type` is the Shared Objects type identifier;
- `object-id` is the canonical profile Object ID.

For a Task:

```text
lfcp1:<resource-b64url>#task:<uuidv7>
```

Example (the Resource ID `c8c3041c…c241` of the LFCP Wire vectors and a UUIDv7 Object ID):

```text
lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad
```

The textual `lfcp1:` representation defined here is an application reference encoding. It does not change the raw 32-byte Resource ID used by LFCP Wire.

---

## 8. Resource encoding

A Resource ID inside a Markdown ref MUST be encoded as:

```text
base64url-no-padding(resource_id)
```

The decoder MUST reject:

- padding `=`;
- non-Base64url characters;
- decoded lengths other than 32 bytes.

Re-encoding the decoded Resource ID MUST reproduce the exact canonical token.

---

## 9. Object type

The v1 Shared Objects standardized type is:

```text
task
```

Object type tokens are case-sensitive and follow this grammar (RFC 5234 ABNF):

```abnf
object-type = "task" / reverse-domain  ; reverse-domain: SHARED-OBJECTS-PROFILE-01 §18
```

A token that does not match the grammar makes the ref malformed (`MALFORMED_LFCP_REF`). A token that matches it but names a type the adapter does not support, such as `org.example.poll` for an adapter that only projects Tasks, is not malformed: the parser reports `OBJECT_TYPE_UNSUPPORTED`, binds nothing and leaves the text untouched.

Future standardized or namespaced object types may be added by profile specifications.

The type encoded in the ref MUST agree with the referenced Shared Object's immutable `type` field.

A mismatch is an invalid projection binding and MUST NOT be silently repaired by changing the Shared Object type.

---

## 10. Object ID

For `org.openlfcp.shared-objects.v1`, Object IDs are canonical lowercase UUIDv7 strings.

Example:

```text
019a2f85-7b31-7c42-b85a-fc843e2f40ad
```

The Markdown adapter MUST apply the same Object ID validation rules as `SHARED-OBJECTS-PROFILE-01`.

UUIDv7 provides the Object identity format. Its timestamp/order properties MUST NOT be used as LFCP causality, conflict precedence, or authorization ordering.

---

## 11. Inline placement grammar

In inline form, the canonical LFCP comment MUST be the final non-whitespace element of the physical Task line.

Canonical:

```md
- [ ] Prepare API contract <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

The Task semantic text is the line content before the LFCP comment, after normal adapter parsing.

A serializer MUST NOT place application metadata after the LFCP comment.

Example of a non-canonical ordering:

```md
- [ ] Prepare API contract <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad --> 📅 2026-10-10
```

A robust parser MAY diagnose or recover such text, but a conforming serializer MUST NOT emit it.

---

## 12. Child-line indentation

In child-line form, the ref comment SHOULD be emitted as child content of the Markdown list item.

For a Task line, let:

- `base-indent` be the leading whitespace before the list marker;
- `marker-width` be the number of ASCII characters in the list marker.

For common unordered-list syntax, canonical indentation is the Task's content indentation.

Examples:

```md
- [ ] Top-level task
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

```md
- [ ] Parent task
    - [ ] Nested task
      <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

Here the parent Task is local-only (Section 17); the ref line belongs to the nested Task, whose content indentation it uses.

```md
1. [ ] Ordered task
   <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

Adapters MAY parse equivalent child indentation accepted by their Markdown engine, but SHOULD emit a stable canonical indentation for that engine.

---

## 13. Association rules

A Task has one LFCP ref when either the inline rule or child-line rule matches.

### 13.1 Inline association

An inline ref belongs to a Task when:

1. the physical line is a recognized Markdown Task line;
2. it contains exactly one syntactically valid `lfcp-ref` HTML comment;
3. the comment is outside code/literal syntax;
4. the comment is the final non-whitespace element of the line in canonical form.

### 13.2 Child-line association

A child-line ref belongs to a Task when:

1. the previous physical line is a recognized Markdown Task line;
2. there is no blank line between Task and ref;
3. the ref line contains exactly one syntactically valid `lfcp-ref` payload;
4. its indentation is compatible with the preceding list item;
5. neither line is inside a fenced code block or another context treated as literal text.

The child refs of a Task are the unbroken run of ref lines that starts on the line right after the Task line: consecutive lines, each holding an `lfcp-ref` comment, with no blank line or other line between them. The whole run belongs to that Task as one projection unit, and Section 14 then requires it to hold exactly one ref in total, counting an inline ref on the Task line. A ref line separated from the Task by a blank line or by any other line is not part of the unit; it is an orphan (Section 16).

A scanner MUST NOT search arbitrarily through surrounding prose to associate an orphan ref with a distant Task.

---

## 14. Exactly one ref per projection

A Task projection MUST have exactly one LFCP ref if it is shared.

Two child refs are invalid:

```md
- [ ] Prepare API contract
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-9f24-8f933f2a91c0 -->
```

Inline plus child-line is also invalid, even if both refs are byte-identical:

```md
- [ ] Prepare API contract <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

A parser MUST surface `DUPLICATE_LFCP_REF` and MUST NOT silently choose one.

When a projection unit with two or more refs includes a malformed one, the parser reports both diagnostics: `DUPLICATE_LFCP_REF` for the unit and `MALFORMED_LFCP_REF` for the malformed ref. The Task gets no binding: the valid ref in the unit is not used either.

---

## 15. Malformed refs

A syntactically recognizable but invalid LFCP ref MUST be surfaced as a projection diagnostic.

Examples:

- invalid Base64url Resource token;
- decoded Resource ID not 32 bytes;
- missing fragment;
- malformed object type token;
- invalid UUIDv7 Object ID;
- extra unparsed content inside the LFCP comment.

The adapter MUST NOT delete the Task because its ref is malformed.

---

## 16. Orphan refs

A child-line ref without an immediately preceding compatible host is an orphan. A ref line separated from a Task by a blank line or by another line is an orphan too, even when it is indented like a child of that Task (Section 13.2).

Example:

```md
Paragraph.

<!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

The adapter SHOULD surface `ORPHAN_LFCP_REF` and leave the text untouched.

An inline LFCP comment on a physical line that is not a recognized projection host SHOULD similarly be diagnosed rather than treated as a Task binding.

The adapter MUST NOT infer a remote object insertion target from unrelated surrounding prose.

---

## 17. Missing refs

An ordinary Markdown Task without a ref is local-only:

```md
- [ ] Local task
```

It MUST NOT generate LFCP application mutations solely because it resembles a Task.

Sharing is explicit.

---

## 18. Detach semantics

Removing the associated LFCP comment detaches that Markdown projection from LFCP.

Child-line before:

```md
- [x] Prepare API contract
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

Child-line after:

```md
- [x] Prepare API contract
```

Inline before:

```md
- [x] Prepare API contract <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

Inline after:

```md
- [x] Prepare API contract
```

Detaching a projection MUST NOT delete or tombstone the Shared Object.

A UI command SHOULD perform detachment deliberately. If an external editor removes the ref, an adapter MAY report that a previously indexed projection was detached, but it MUST NOT recreate the ref indefinitely against explicit user edits.

---

## 19. Placement preservation

Placement is local presentation, not Shared Object semantics.

A remote Shared Object update MUST NOT force conversion between inline and child-line forms.

If a valid projection is currently inline, ordinary remote Task changes SHOULD leave it inline.

If it is currently child-line, ordinary remote Task changes SHOULD leave it child-line.

A deliberate user command MAY convert placement without changing the referenced Shared Object.

This minimizes unnecessary Git and file diffs.

---

## 20. Remote updates

A remote Shared Object update SHOULD modify only Task fields owned by the adapter.

The LFCP comment SHOULD remain byte-identical unless:

- the object is explicitly migrated to another Object ID;
- the Resource is explicitly migrated to a new Resource identity;
- the user repairs malformed ref syntax;
- the user explicitly changes the local placement form.

Ordinary LFCP server migration does NOT modify the Markdown ref because server location is not part of Resource identity.

---

## 21. Task plugin compatibility rule

Adapters MUST account for host syntax compatibility when choosing placement.

For Obsidian, the plugin SHOULD default to child-line placement because this avoids consuming trailing syntax positions that may be significant to Obsidian Tasks or other task plugins.

If the user does not use a suffix-sensitive Task plugin, an Obsidian adapter MAY offer inline placement as a compact option.

Other editors MAY default to inline when that is known to be safe.

A parser MUST accept both regardless of the local emission preference.

---

## 22. Copy and paste

Copying the complete projection unit copies another projection of the same Shared Object.

Inline:

```md
- [ ] Prepare API contract <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

Child-line:

```md
- [ ] Prepare API contract
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```

Multiple projections of one Shared Object are valid.

For child-line form, copying only the Task line creates an ordinary local Task unless the adapter explicitly offers a command to restore the missing projection binding.

---

## 23. File rename and movement

The ref contains no file path.

Moving or renaming a Markdown file MUST NOT change the object ref.

Only the local projection index changes.

---

## 24. Server independence

The ref MUST NOT contain a sync endpoint.

Non-conforming identity:

```text
wss://server.example/resource/...
```

Portable object identity uses the LFCP Resource ID.

Routing belongs to LFCP route state and local route caches.

---

## 25. Fenced-code protection

Examples inside fenced code blocks MUST NOT be interpreted as live projections.

Example:

````md
```md
- [ ] Example task
  <!-- lfcp-ref: lfcp1:yMMEHNHocAnDmj_loC9IErjKJzPzqmwBF1MNTPw8wkE#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad -->
```
````

The scanner therefore needs Markdown-aware lexical context rather than a blind global regular expression.

---

## 26. Required parser outputs

For each valid projection, a parser SHOULD return a structure equivalent to:

```ts
type MarkdownProjectionRef = {
  resourceId: Uint8Array;
  objectType: string;
  objectId: string;

  placement: "inline" | "child";
  taskLine: number;
  refLine: number; // equals taskLine for inline placement

  rawRef: string;
};
```

An implementation MAY additionally return exact byte/column ranges for minimal-diff editing.

Errors SHOULD carry stable diagnostic codes.

---

## 27. Required diagnostic codes

Version 1 defines at least:

```text
MALFORMED_LFCP_REF
DUPLICATE_LFCP_REF
ORPHAN_LFCP_REF
OBJECT_TYPE_MISMATCH
OBJECT_TYPE_UNSUPPORTED
OBJECT_ID_INVALID
RESOURCE_ID_INVALID
```

`OBJECT_TYPE_UNSUPPORTED` reports a well-formed ref whose object type the adapter does not project (Section 9); it is not a malformed ref.

Editor-specific diagnostics may add further codes.

---

## 28. Serializer policy

A serializer MUST support producing a syntactically valid ref comment.

An editor adapter that creates Task projections MUST be able to emit its preferred conforming placement.

Portable/reference tooling SHOULD support both placements.

Recommended defaults:

```text
Obsidian                      child-line
Obsidian + Tasks plugin       child-line
unknown Markdown environment  child-line
known-safe compact client     inline or child-line
```

These defaults are recommendations, not semantic differences.

---

## 29. LFCP-060 acceptance contract

The backlog task `LFCP-060` MUST implement this specification rather than inventing its own placement rules.

Minimum acceptance cases:

1. parse a valid inline top-level Task ref;
2. parse a valid child-line top-level Task ref;
3. parse a valid nested child-line Task ref;
4. parse an ordered-list Task ref if the adapter supports ordered Tasks;
5. normalize both forms to the same `(resource, object_type, object_id)` binding;
6. reject malformed Resource encoding;
7. reject malformed Object ID;
8. report two child refs as duplicate;
9. report inline + child ref as duplicate;
10. report orphan child refs;
11. ignore examples inside fenced code blocks;
12. distinguish a missing ref from a malformed ref;
13. preserve Task semantic content separately from inline metadata;
14. preserve an existing valid placement during unrelated rewrites;
15. serializer can emit child-line form;
16. serializer can emit inline form when requested;
17. Obsidian default policy emits child-line form unless explicitly configured otherwise;
18. accept extra whitespace at each separator of the ref comment (Section 6);
19. report a well-formed ref of an unsupported object type as `OBJECT_TYPE_UNSUPPORTED`, not as malformed;
20. report a ref line separated from its Task by a blank or other line as an orphan;
21. report both `DUPLICATE_LFCP_REF` and `MALFORMED_LFCP_REF`, and bind nothing, for a unit with two refs of which one is malformed.

---

## 30. Core invariant

```text
Task content     = user/application Markdown semantics
lfcp-ref comment = portable collaboration binding
placement        = local presentation choice
```

The binding is explicit, independent of server routing, portable across editor adapters, and semantically identical in inline and child-line forms.
