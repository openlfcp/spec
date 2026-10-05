# SHARED-OBJECTS-PROFILE-01

**Title:** OpenLFCP Shared Objects Data Profile  
**Status:** Working Draft 0.1  
**Profile identifier:** `org.openlfcp.shared-objects.v1`  
**Protocol dependency:** LFCP / `LFCP-WIRE-01`  
**Initial CRDT engine:** Automerge  
**Date:** 2026-10-04

> This document defines the first application-level LFCP Data Profile. It standardizes a portable CRDT representation for shared objects such as Tasks while keeping LFCP Core and LFCP servers application-agnostic.

---

## 1. Purpose

`SHARED-OBJECTS-PROFILE-01` defines a collaborative object graph that can be embedded into local-first applications.

The first standardized object type is `task`.

The profile is designed so that the same LFCP Resource can be consumed by:

```text
Obsidian plugin
VS Code extension
browser todo application
CLI client
future desktop/mobile clients
```

without any client owning a privileged or proprietary representation of the data.

The primary product pattern is:

```text
Local private document
      │
      ├── Shared Task A ──┐
      ├── Shared Task B   │
      └── Shared object   │
                         ▼
                 LFCP Resource
                         │
                    CRDT state
                         │
              replicated via LFCP
```

The host document is outside this profile.

---

## 2. Normative language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in BCP 14 when they appear in all capitals.

---

## 3. Scope

This profile defines:

- the profile identifier;
- the Automerge document model;
- LFCP Data Unit plaintext framing;
- snapshot plaintext framing;
- deterministic mapping between LFCP Principals and Automerge actors;
- Shared Object identifiers;
- the `task` object schema;
- scalar conflict semantics;
- collection merge semantics;
- object tombstones;
- application intent semantics;
- unknown-field preservation;
- profile validation;
- interoperability requirements;
- adapter requirements for editor clients.

This profile does **not** define:

- Markdown syntax;
- Obsidian UI;
- VS Code UI;
- LFCP authorization;
- LFCP encryption;
- LFCP routing;
- per-object ACL;
- human identity discovery;
- attachments;
- arbitrary rich-text documents;
- server-side task indexing;
- global task search.

Those concerns belong to LFCP Core, LFCP Wire, editor adapters, or future profiles.

---

# Part I. Architectural Model

## 4. Resource as the security boundary

One LFCP Resource normally contains multiple Shared Objects.

Example:

```text
Resource: Project Alpha
│
├── task:019a...
├── task:019b...
├── task:019c...
├── decision:...
└── comment-thread:...
```

All objects inside a Resource share the LFCP Resource-level:

- Control Chain;
- participants;
- write authority;
- encryption epoch;
- routing;
- storage endpoints.

A client that has `data/read` access to the Resource may eventually receive the encrypted Data Plane state required to reconstruct every object in that Resource.

Therefore:

> Objects requiring different access boundaries SHOULD be placed in different LFCP Resources.

Version 1 does not define per-object cryptographic ACL.

---

## 5. Server opacity

LFCP servers MUST NOT need to understand this profile.

From the server's perspective, Shared Objects changes remain ordinary encrypted LFCP Data Units.

```text
Task change
   ↓
Automerge change
   ↓
Shared Objects framing
   ↓
LFCP encryption/signature
   ↓
opaque Data Unit
   ↓
LFCP server
```

The server does not need to know:

```text
task title
status
assignee
due date
object type
Automerge schema
```

---

## 6. Profile identifier

A Resource implementing this specification MUST declare the LFCP Data Profile:

```text
org.openlfcp.shared-objects.v1
```

This identifier is immutable for the lifetime of the LFCP Resource because the Data Profile is established by Resource Genesis.

Breaking changes require a different profile identifier.

Additive compatible evolution is permitted under the rules in this document.

---

# Part II. Automerge Binding

## 7. CRDT engine

Version 1 uses Automerge as the required CRDT engine.

An implementation claiming full `org.openlfcp.shared-objects.v1` conformance MUST be capable of:

- loading a full Automerge document;
- applying arbitrary valid Automerge changes;
- preserving conflicts;
- preserving unknown map fields;
- preserving unknown object types;
- producing interoperable Automerge changes;
- producing interoperable Automerge save bytes.

A future profile MAY use another CRDT engine without changing LFCP Wire.

---

## 8. Automerge actor identity

Each LFCP writing Principal maps deterministically to one Automerge actor for a specific Resource.

The Automerge actor identifier is:

```text
actor_id = SHA-256(
    ASCII("OPENLFCP-SHARED-OBJECTS-ACTOR-v1") ||
    resource_id ||
    principal_id
)
```

where:

- `resource_id` is the raw 32-byte LFCP Resource ID;
- `principal_id` is the raw 32-byte LFCP Principal ID.

The resulting 32 bytes are used as the Automerge actor identifier.

This mapping ensures that the same operational Principal editing two different LFCP Resources receives different Automerge actor IDs.

It also binds Automerge history to LFCP signatures: the Automerge change carried by a Data Unit MUST be a change of the actor that this mapping gives for the Data Unit's signer (its LFCP actor Principal) in that Resource. A receiver does not merge a change of any other actor (Section 11), so no Principal can write into another Principal's Automerge history.

---

## 9. Actor state safety

An implementation MUST persist the Automerge state required to continue writing safely as the same actor.

If the client loses the local Automerge actor state and cannot reconstruct the correct actor sequence, it MUST NOT begin an unrelated new history using the same actor identifier.

The safest recovery strategy is to create a new LFCP operational Principal for future writes.

This mirrors LFCP Wire's protection against Principal sequence reuse.

A rebuild (Section 14.1) that removes changes of the writer's own actor is not lost state. The removed changes are the writer's own unit beyond an epoch cutoff, one of its own equivocating pair, or its own change that depends on an excluded change of another actor. The writer continues from the rebuilt document: its next change takes the actor's next Automerge sequence number in that document, which can equal the sequence number of a removed change. This is the same history, not an unrelated new one, and the writer MUST NOT refuse to write because of it. The writer's next Data Unit is in the current Data Epoch and names its latest own unit still accepted (LFCP-WIRE-01 §26.2). So a replica that still holds a removed change because it does not yet know the Key Epoch Record or the equivocating pair cannot accept the new unit before it rebuilds the same way. Stale work that the application keeps is re-applied in such a change (LFCP-WIRE-01 §19.1).

---

## 10. One application transaction per Automerge change

A client SHOULD map one semantic application transaction to one Automerge change.

Examples:

```text
create_task
complete_task
change_due_date
add_tag
resolve_status_conflict
```

Each application transaction SHOULD be atomic from the Shared Objects perspective.

For example, completing a Task may update both:

```text
status = done
completion_date = 2026-10-04
```

inside one Automerge change.

---

# Part III. LFCP Payload Framing

## 11. Data Unit plaintext

Every LFCP Data Unit carrying this profile contains exactly one Automerge change.

The decrypted LFCP Data Unit plaintext is deterministic CBOR encoding of:

```cddl
shared-objects-change = [
  1,       ; framing version
  bstr     ; exact Automerge change bytes
]
```

The first element MUST equal `1`.

The second element MUST contain one complete Automerge change in the canonical binary format defined by the Automerge implementation/specification used by the profile.

A receiver MUST reject profile plaintext that:

- is not valid CBOR;
- is not a two-element array;
- uses an unsupported framing version;
- contains invalid Automerge change bytes.

The second element MUST be an Automerge change chunk: a storage chunk whose chunk type is a change (an uncompressed or a compressed change), not a document chunk (a full save belongs in a Snapshot, Section 13). A receiver MUST verify the chunk checksum (the first four bytes of the chunk's hash, which the chunk header carries) and MUST reject a chunk whose checksum does not match, even when its Automerge library would parse it. These are "invalid Automerge change bytes". A receiver rejects any of the plaintexts above with `PROFILE_INVALID` and the diagnostic `INVALID_AUTOMERGE_BYTES` (Section 74.1).

The change's Automerge actor MUST be the actor of the Data Unit's signer for this Resource (Section 8). A receiver MUST NOT merge a change of any other actor; it rejects the plaintext with `PROFILE_INVALID` and the diagnostic `CHANGE_ACTOR_MISMATCH` (Section 74.1).

A rejected plaintext is not merged. The LFCP server does not perform this validation.

---

## 12. Change batching

Version 1 intentionally defines **one Automerge change per LFCP Data Unit**.

A sender MUST NOT concatenate multiple Automerge changes into one version-1 profile payload.

This provides a simple relationship:

```text
semantic transaction
      ↓
Automerge change
      ↓
LFCP Data Unit
```

Future framing versions MAY support batching if measurements show a clear need.

---

## 13. Snapshot plaintext

An LFCP Snapshot for this profile contains a complete Automerge save image.

The decrypted Snapshot plaintext is deterministic CBOR encoding of:

```cddl
shared-objects-snapshot = [
  1,       ; framing version
  bstr     ; exact Automerge full-save bytes
]
```

The second element MUST be an Automerge document chunk (a full save), not a change chunk; a receiver MUST verify the chunk checksum as for Data Units (Section 11) and MUST reject a Snapshot plaintext that fails either check, or that its Automerge library cannot load, with `PROFILE_INVALID` and the diagnostic `INVALID_AUTOMERGE_BYTES` (Section 74.1). The framing rules of Section 11 apply to the Snapshot plaintext as well.

A client loads the second element using the corresponding Automerge full-document load operation.

After loading a Snapshot, the client applies all LFCP Data Units beyond the Snapshot frontier.

---

## 14. Snapshot equivalence

Two conforming implementations are not required to produce byte-identical Automerge save images for logically equivalent states unless Automerge itself guarantees that property.

LFCP Snapshot identity is therefore about the exact encrypted Snapshot object published by a Principal, not a universal content hash of logical Shared Objects state.

Interoperability requires that a conforming implementation can successfully load another implementation's valid Snapshot and continue applying changes.

### 14.1 Replica state is a function of the accepted changes

A replica's Shared Objects state is a deterministic function of the set of LFCP Data Units it has accepted (LFCP-WIRE-01 §19.1): the Automerge changes those units carry, applied in any order their dependencies allow. Two replicas that accepted the same units have the same logical state and the same conflicts.

When a unit that a replica has already merged leaves the accepted set, the replica rebuilds its document without that unit's change and without every change that depends on it, then surfaces the excluded units to the application. Two LFCP events cause this:

- a newly known Key Epoch Record places the unit beyond its epoch's cutoff (LFCP-WIRE-01 §19.1);
- the unit turns out to be one of an equivocating pair, of which neither stays merged (LFCP-WIRE-01 §26.2).

A rebuild starts from the profile's initial document (Section 16), or from a Snapshot whose frontier excludes the removed units, and applies the remaining accepted changes.

A replica gives a change to its Automerge engine only when every dependency of the change is in its document. A change with a missing dependency, including one that depends on an excluded change, stays outside the document until its dependencies arrive. It is not handed to the engine as a pending change. Automerge refuses a change whose actor and sequence number match a change it holds, merged or pending. A pending change that can never be merged would therefore block its writer's next change (Section 9).

When every dependency of a change is in the document, its sequence number is exactly one more than that of the latest change of its actor in the document, or `1` for the actor's first change. A change with a higher sequence number is invalid. A receiver checks this before the engine sees the change, because an Automerge implementation may abort on it rather than return an error. It rejects the plaintext with `PROFILE_INVALID` and the diagnostic `INVALID_AUTOMERGE_BYTES` (Section 74.1).

---

# Part IV. Document Model

## 15. Root document

The Automerge document root MUST logically contain:

```ts
{
  profile: "org.openlfcp.shared-objects.v1",
  objects: { ... },
  extensions: { ... }
}
```

The conceptual schema is:

```text
root
├── profile: string
├── objects: map<object-id, shared-object>
└── extensions: map<namespace, unknown>
```

`profile` MUST equal:

```text
org.openlfcp.shared-objects.v1
```

`objects` MUST be an Automerge map.

`extensions` MUST be an Automerge map.

---

## 16. Initial document

A newly created Resource using this profile SHOULD initialize the Automerge document in one change:

```ts
{
  profile: "org.openlfcp.shared-objects.v1",
  objects: {},
  extensions: {}
}
```

The initialization change is transmitted as an ordinary LFCP Data Unit.

The profile does not require the LFCP Resource Genesis record and Automerge initialization change to be created by the same operational Principal, although normal implementations SHOULD do so.

---

## 17. Reserved root keys

Version 1 reserves these root keys:

```text
profile
objects
extensions
```

Writers MUST NOT create unrelated top-level keys outside `extensions`. Readers MUST preserve any unknown top-level key they find.

Future compatible revisions MAY reserve additional top-level keys only if older clients can preserve them safely.

---

## 18. Extension namespaces

Application extensions MUST be placed under `extensions` using reverse-domain names.

Example:

```text
extensions
└── com.example.calendar
    └── ...
```

Recommended namespace form:

```text
org.openlfcp.example
com.vendor.feature
```

A namespace key MUST match this grammar (RFC 5234 ABNF), which is also used by extension status and priority values (Sections 33 and 38):

```abnf
reverse-domain = label 1*("." label)                 ; at least two labels
label          = lower-alnum [*ldh-char lower-alnum]  ; no leading or trailing hyphen
ldh-char       = lower-alnum / "-"
lower-alnum    = %x61-7A / DIGIT                      ; a-z, 0-9
```

A conforming client that does not understand an extension MUST preserve it.

It MUST NOT rewrite or delete unknown extension state merely because it cannot render it.

---

# Part V. Object Identity

## 19. Object ID

Shared Object IDs MUST be UUIDv7 identifiers as specified by RFC 9562.

The canonical in-profile representation is the lowercase UUID string form:

```text
019a2f85-7b31-7c42-b85a-fc843e2f40ad
```

Requirements:

- lowercase hexadecimal;
- standard hyphen positions;
- UUID version 7;
- valid variant bits.

Object IDs are generated client-side.

No server allocation is required.

---

## 20. Object key

The key in the root `objects` map is exactly the canonical Object ID.

Example:

```text
objects["019a2f85-7b31-7c42-b85a-fc843e2f40ad"]
```

The contained object's `id` field MUST match the map key.

A mismatch is profile-invalid state.

---

## 21. Collision handling

UUIDv7 collisions should be extraordinarily unlikely.

If two concurrent creations use the same Object ID but produce different object identities, implementations MUST NOT silently merge them as though they were intentionally the same object.

The Resource MUST expose an `OBJECT_ID_COLLISION` profile error for that object. `OBJECT_ID_COLLISION` is a separate named profile error, not a `PROFILE_INVALID` diagnostic: each colliding object may be valid on its own, and the error describes their relationship.

A repair operation SHOULD create a new Object ID for one object and explicitly migrate any local projections.

---

## 22. Complete object reference

At the application layer, a complete object reference consists of:

```text
LFCP Resource ID
+
Object type
+
Object ID
```

Conceptual form:

```text
<Resource>#<type>:<object-id>
```

Example:

```text
lfcp1:...#task:019a2f85-7b31-7c42-b85a-fc843e2f40ad
```

The exact textual `lfcp1:` Resource representation and Markdown embedding grammar are defined outside this profile.

Object references MUST NOT include the current sync server as part of object identity.

---

# Part VI. Shared Object Base Schema

## 23. Base object

Every Shared Object, of any type including namespaced types, MUST logically contain:

```ts
{
  id: string,
  type: string,
  lifecycle: string,
  created_by: string,
  created_at?: string,
  extensions: { ... }
}
```

Required fields:

```text
id
type
lifecycle
created_by
extensions
```

`created_at` is optional informational metadata.

---

## 24. `id`

`id` MUST equal the canonical UUIDv7 object key.

The field is immutable after creation.

A conforming client MUST NOT intentionally modify an object's `id`.

---

## 25. `type`

`type` identifies object semantics.

Version 1 standardizes:

```text
task
```

Other types MAY exist through namespaced extensions.

Examples:

```text
org.example.poll
com.vendor.issue
```

The `type` field is immutable after object creation.

A conforming client MUST NOT reinterpret one existing object as another type by editing this field.

---

## 26. Lifecycle

`lifecycle` is a conflict-preserving scalar register.

Standard values:

```text
active
deleted
```

Version 1 defines `lifecycle` as a closed set of these two values. A reader MUST preserve any other value and treat the object as `PROFILE_INVALID` with diagnostic `INVALID_ENUM_VALUE` (Section 74.1).

Objects MUST NOT normally be removed from the Automerge `objects` map.

Deletion is represented by:

```text
lifecycle = deleted
```

This creates an application-level tombstone while preserving object state for:

- conflict recovery;
- old projections;
- offline replicas;
- explicit restore.

---

## 27. `created_by`

`created_by` contains the LFCP Principal ID that created the object, encoded as:

```text
p:<base64url-no-padding-of-32-byte-principal-id>
```

Example shape:

```text
p:j5I0...abc
```

The `created_by` field is immutable.

The Principal is an LFCP operational identity, not necessarily a stable human identity.

Applications MAY map Principals to human-friendly names using local contact metadata or future identity extensions.

---

## 28. `created_at`

`created_at`, if present, MUST use an RFC 3339 UTC timestamp with `Z` that names a real date and time (for example, not hour `25` or February `30`). This applies to every object type, since `created_at` is a base field (Section 23), not only to Tasks.

Example:

```text
2026-10-04T05:25:30Z
```

This field is informational.

It MUST NOT be used to decide LFCP authorization, causality, or conflict precedence.

Offline clients may have incorrect clocks.

---

## 29. Object extensions

Each standardized object MUST contain an `extensions` map.

Unknown extension namespaces MUST be preserved.

Example:

```text
extensions
├── org.openlfcp.obsidian
└── com.example.tracker
```

Portable semantics SHOULD NOT depend on editor-specific extension data unless a companion profile explicitly standardizes it.

---

# Part VII. Task Schema

## 30. Task logical schema

A version-1 Task logically contains:

```ts
type TaskObject = {
  id: string;
  type: "task";
  lifecycle: "active" | "deleted";

  created_by: string;
  created_at?: string;

  title: string;
  status: TaskStatus;

  due?: LocalDate | null;
  scheduled?: LocalDate | null;
  completion_date?: LocalDate | null;

  priority: TaskPriority;

  tags: Record<string, true>;
  assignees: Record<PrincipalRef, true>;

  extensions: Record<string, unknown>;
};
```

The actual Automerge representation uses maps and scalar registers with the concurrency semantics specified below.

Every string value the profile writes is an Automerge scalar string, never collaborative Automerge Text: the root `profile` and every string in any object, including `id`, `type`, `lifecycle`, `created_by`, `created_at`, `title`, `status`, dates, `priority`, and the string values inside object maps and `extensions`. A string field held as Text is profile-invalid with the diagnostic `INVALID_FIELD_TYPE` (Section 74.1).

---

## 31. Required Task fields

Every valid Task MUST contain:

```text
id
type
lifecycle
created_by
title
status
priority
tags
assignees
extensions
```

Optional:

```text
created_at
due
scheduled
completion_date
```

---

## 32. Title

`title` is a UTF-8 string represented as a conflict-preserving Automerge scalar register.

A client MUST permit an empty title at the data-model level so that offline or partially constructed states remain representable.

UI clients SHOULD discourage permanently empty Task titles.

Version 1 sets no maximum title length; a title is bounded only by the LFCP Wire maximum message size.

Concurrent title edits MUST NOT be silently treated as a resolved single value.

---

## 33. Status

`status` is a conflict-preserving scalar register.

Standard values:

```text
todo
in_progress
done
cancelled
```

Extensions MAY define namespaced statuses in the form:

```text
x/<reverse-domain>/<value>
```

Example:

```text
x/com.example/waiting_review
```

The grammar is:

```abnf
namespaced-value = "x/" reverse-domain "/" value     ; reverse-domain: Section 18
value            = 1*value-char                      ; non-empty
value-char       = %x00-2E / %x30-10FFFF             ; any character except "/"
```

A generic client MUST preserve unknown extension statuses.

It MAY display them as an unknown/custom status.

---

## 34. Task status meaning

Standard semantics:

### `todo`

The task is open and has not been started or its active progress is not represented.

### `in_progress`

The task is open and actively being worked on.

### `done`

The task is completed.

### `cancelled`

The task is intentionally closed without being completed.

A Markdown adapter decides how these values map onto checkbox syntax.

The Shared Objects profile does not define checkbox glyphs.

---

## 35. Local date

`due`, `scheduled`, and `completion_date` use a local calendar date:

```text
YYYY-MM-DD
```

Examples:

```text
2026-10-04
2027-01-15
```

Values MUST represent a valid Gregorian calendar date.

No time zone is associated with a Local Date.

This deliberately avoids converting a date-only task deadline into different dates in different time zones.

Future profiles may define timestamp-based scheduling separately.

---

## 36. Null and missing date fields

A date field may be absent or explicitly null at the application API boundary.

Implementations SHOULD normalize cleared date fields by deleting the corresponding map property rather than storing a persistent scalar `null`.

Profile readers MUST treat:

```text
missing
```

and:

```text
null
```

as the same semantic value: **no date**.

Writers SHOULD emit the missing-property representation.

---

## 37. Completion date

`completion_date` SHOULD normally be present when:

```text
status = done
```

and absent for:

```text
todo
in_progress
```

However, the profile permits temporarily inconsistent states because:

- concurrent changes may be merged;
- old clients may not manage completion dates;
- imported Markdown may contain partial metadata.

Clients MUST NOT discard a valid task solely because `status` and `completion_date` are temporarily inconsistent.

A repair or user intent may normalize them.

---

## 38. Priority

`priority` is a conflict-preserving scalar register.

Standard values:

```text
lowest
low
normal
high
highest
```

New standardized values require a profile revision.

Extensions MAY define namespaced values using the same `x/<reverse-domain>/<value>` grammar as statuses (Section 33).

---

## 39. Tags

`tags` is an Automerge map implementing an add-wins set.

Conceptual representation:

```ts
{
  "backend": true,
  "important": true
}
```

A tag is present when its key exists with scalar value `true`.

Clients MUST NOT store `false` values as a removal mechanism.

Removal deletes the map key.

---

## 40. Tag normalization

Portable Task tags:

- MUST NOT include leading `#`;
- MUST NOT be empty;
- MUST be valid Unicode strings;
- SHOULD be normalized to Unicode NFC before insertion.

Example Markdown:

```text
#backend
```

maps to Shared Objects tag:

```text
backend
```

Case folding is NOT performed by the profile.

Therefore:

```text
Backend
backend
```

are distinct tags.

Applications MAY warn users about visually similar duplicates.

---

## 41. Tag concurrency

Because tags use an Automerge map as an add-wins set:

```text
Peer A concurrently removes tag "backend"
Peer B concurrently adds tag "backend"
```

results in the tag being present after convergence.

This is the standardized version-1 semantic:

> concurrent add beats remove for the same tag.

Two independent additions of different tags naturally produce their union.

---

## 42. Assignees

`assignees` is an Automerge map implementing an add-wins set.

Keys are Principal references:

```text
p:<base64url-principal-id>
```

Conceptual representation:

```ts
{
  "p:ABC...": true,
  "p:XYZ...": true
}
```

An assignee is present when its key exists with scalar value `true`. As for tags, clients MUST NOT store `false` values as a removal mechanism; removal deletes the map key.

Version 1 permits multiple assignees.

---

## 43. Assignee concurrency

Assignees use the same add-wins semantics as tags.

Concurrent add/remove of the same Principal resolves to assigned.

This avoids losing an intentional concurrent assignment because another peer removed an older assignment while offline.

A future profile may offer configurable collection policies.

---

# Part VIII. Conflict Semantics

## 44. Conflict classes

Shared Objects distinguishes two broad classes of fields.

### Conflict-preserving scalar registers

Examples:

```text
lifecycle
title
status
due
scheduled
completion_date
priority
```

Concurrent assignments may produce multiple Automerge values.

### CRDT collections

Examples:

```text
tags
assignees
```

These merge automatically according to their collection semantics.

---

## 45. Scalar conflict detection

A scalar field is semantically conflicted whenever Automerge reports more than one concurrent value for that property.

A client MAY use one deterministic Automerge-selected visible value for provisional rendering.

However:

> A client MUST NOT describe the field as resolved while multiple concurrent values exist.

The conflict MUST remain discoverable through the application API.

---

## 46. Mandatory conflict surfacing

User-facing clients MUST visibly surface unresolved conflicts for:

```text
lifecycle
status
title
```

Clients SHOULD surface conflicts for:

```text
due
scheduled
completion_date
priority
```

A headless client MUST expose conflict metadata through its API even if it has no UI.

---

## 47. Conflict resolution

To resolve a scalar conflict, a client writes a chosen value to the same property **after loading the merged document containing all conflicting values**.

Example:

```text
status conflict:
  done
  cancelled
```

User chooses:

```text
done
```

Client performs a new Automerge change:

```text
status = done
```

causally descending from the merged state.

This new assignment supersedes all conflicting register values visible in that merged state.

---

## 48. Complete versus cancel

Example:

```text
Andrey offline:
status = done

Pavel offline:
status = cancelled
```

After synchronization:

```text
status:
  done
  cancelled
```

A conforming UI MUST NOT silently pretend this is simply `done` or simply `cancelled`.

It may render one provisional checkbox representation but MUST show a conflict indicator and resolution action.

---

## 49. Independent field concurrency

Concurrent updates to different fields merge normally.

Example:

```text
Peer A:
status = done

Peer B:
title = "Prepare final API contract"
```

Converged state:

```text
status = done
title = "Prepare final API contract"
```

No semantic conflict exists merely because the changes were concurrent.

---

## 50. Concurrent due dates

Example:

```text
Peer A:
due = 2026-10-10

Peer B:
due = 2026-10-12
```

The due field is conflicted.

Both values MUST remain available to the application until explicitly resolved.

---

## 51. Delete versus edit

Deletion changes only:

```text
lifecycle = deleted
```

The object remains in the CRDT.

If another peer concurrently changes:

```text
title
status
due
```

those changes are retained in the tombstoned object.

The object remains deleted unless there is a concurrent or later write to `lifecycle`.

This means deletion does not destroy concurrent user work.

If the object is later restored, retained field changes remain available.

---

## 52. Delete versus restore

If one peer writes:

```text
lifecycle = deleted
```

while another concurrently writes:

```text
lifecycle = active
```

`lifecycle` is conflicted.

User-facing clients MUST surface this conflict.

---

# Part IX. Object Lifecycle

## 53. Create

Task creation MUST occur in one Automerge change that creates the object map and all required fields.

Recommended initial Task:

```ts
{
  id,
  type: "task",
  lifecycle: "active",
  created_by,
  created_at,
  title,
  status: "todo",
  priority: "normal",
  tags: {},
  assignees: {},
  extensions: {}
}
```

The `created_at` field MAY be omitted if no reliable wall clock is available.

---

## 54. Delete

Delete intent:

```text
task.delete
```

writes:

```text
lifecycle = deleted
```

It MUST NOT remove the object key from `objects` in version 1.

---

## 55. Restore

Restore intent:

```text
task.restore
```

writes:

```text
lifecycle = active
```

A restore SHOULD operate on a merged document so that it resolves any known lifecycle conflict.

---

## 56. Physical garbage collection

Physical removal of tombstoned objects is outside version 1.

A client MUST NOT garbage-collect an object merely because it currently observes:

```text
lifecycle = deleted
```

Offline peers may still reference the object.

A future profile may define safe Resource-wide garbage collection with explicit retention frontiers.

---

# Part X. Intent Model

## 57. Purpose of intents

Intents are semantic operations exposed by client libraries.

They are not LFCP Wire message types.

The flow is:

```text
User/editor action
      ↓
Shared Objects intent
      ↓
Automerge transaction
      ↓
Automerge change
      ↓
LFCP Data Unit
```

Using intents allows Obsidian, VS Code, browser apps, and CLI clients to share the same mutation semantics.

---

## 58. Intent transport

Version 1 does NOT require intents themselves to be persisted or transmitted.

Only resulting Automerge changes are part of the profile's durable synchronization format.

Every intent MUST produce a real Automerge operation for each field it writes, even when the new value equals the current one. Where an Automerge library skips an assignment of the value already present, the implementation first deletes the property and then puts the value, in the same change. This keeps an intent visible to concurrency: for example, a restore of an active Task still conflicts with a concurrent delete (Section 52).

Implementations MAY record semantic events in an extension namespace, but such history is not required for profile conformance.

---

## 59. Standard Task intents

The SDK SHOULD expose at least:

```text
task.create
task.set_title
task.set_status
task.complete
task.reopen
task.cancel
task.set_due
task.clear_due
task.set_scheduled
task.clear_scheduled
task.set_priority
task.add_tag
task.remove_tag
task.add_assignee
task.remove_assignee
task.delete
task.restore
task.resolve_field_conflict
```

---

## 60. `task.create`

Input conceptually:

```ts
{
  title: string,
  due?: LocalDate,
  scheduled?: LocalDate,
  priority?: TaskPriority,
  tags?: string[],
  assignees?: PrincipalRef[]
}
```

Defaults:

```text
status = todo
priority = normal
lifecycle = active
```

The client generates a UUIDv7 Object ID.

---

## 61. `task.set_title`

Writes exactly one semantic title value.

The intent MUST operate on the latest merged state available locally.

If used to explicitly resolve a title conflict, the same write naturally supersedes all conflicting values currently known.

---

## 62. `task.set_status`

Accepts a standard or valid extension status.

It changes only the status unless an adapter uses one of the higher-level convenience intents below.

---

## 63. `task.complete`

`task.complete` SHOULD atomically:

```text
status = done
completion_date = supplied local date, if available
```

If no completion date is supplied, it MAY set only `status = done`.

The profile MUST remain valid in either case.

---

## 64. `task.reopen`

`task.reopen` SHOULD atomically:

```text
status = todo
clear completion_date
```

A UI MAY offer a separate `in_progress` transition after reopening.

---

## 65. `task.cancel`

`task.cancel` writes:

```text
status = cancelled
```

It SHOULD clear `completion_date` unless the application deliberately preserves historical completion information in an extension.

---

## 66. Date intents

Setting:

```text
task.set_due
task.set_scheduled
```

MUST validate the Local Date grammar before creating a change.

Clearing:

```text
task.clear_due
task.clear_scheduled
```

SHOULD delete the corresponding property.

---

## 67. Tag intents

Add:

```text
tags[tag] = true
```

Remove:

```text
delete tags[tag]
```

A client SHOULD normalize tags to NFC before mutation.

---

## 68. Assignee intents

Add:

```text
assignees[principalRef] = true
```

Remove:

```text
delete assignees[principalRef]
```

A client MUST validate the Principal reference encoding before mutation.

---

## 69. `task.resolve_field_conflict`

This intent is intended for explicit UI conflict resolution.

Inputs:

```text
object id
field
chosen value
```

The client MUST first merge all locally available heads.

It then writes the chosen value in a new change.

If new unseen remote conflicts arrive later, the field may become conflicted again. Conflict resolution is causal, not magical global consensus.

---

# Part XI. Unknown Data Preservation

## 70. Forward compatibility

A client implementing version 1 MUST preserve unknown:

- root extension namespaces;
- object extension namespaces;
- object fields it does not understand;
- Shared Object types it does not understand;
- custom status values;
- custom priority values.

This is essential because different editors may evolve at different speeds.

---

## 71. Unknown object types

Suppose a future client creates:

```text
type = decision
```

and an older Task-only Obsidian client receives it.

The older client MUST:

- preserve the object;
- preserve its Automerge state;
- replicate its changes;
- avoid modifying unknown semantic fields;
- optionally display it as an unsupported object.

It MUST NOT delete the object from the Resource.

---

## 72. Unknown task fields

An older client may understand:

```text
title
status
due
```

while a newer client adds:

```text
estimate
milestone
```

The older client may modify `status` while preserving the unknown fields.

This is one reason clients SHOULD perform minimal semantic transactions rather than serializing/replacing whole object maps.

---

# Part XII. Profile Validation

## 73. Validation levels

A client distinguishes:

```text
LFCP-valid Data Unit
Automerge-valid change
Shared-Objects-valid state
```

These are different layers.

A Data Unit may have a valid LFCP signature and authorization but still create application state that violates the Shared Objects profile.

---

## 74. Structural validation

A valid root requires:

```text
profile == "org.openlfcp.shared-objects.v1"
objects is map
extensions is map
```

A valid standardized object requires:

```text
id matches object key
type is valid text
lifecycle exists
created_by is valid Principal ref
extensions is map
```

A valid Task additionally requires the required Task fields defined above.

### 74.1 Validation codes and diagnostics

Every profile validation failure is reported with the code `PROFILE_INVALID` and exactly one diagnostic from this registry, naming what is wrong. A failure is one failing value: one field of one object, the root, or one received plaintext. An object with several failing fields reports one failure per field; an object has no single diagnostic of its own.

| Diagnostic | Meaning | Rule |
|---|---|---|
| `INVALID_ROOT` | `profile` differs, or `objects` or `extensions` is missing or not a map | §15 |
| `INVALID_OBJECT_ID` | an Object ID or `objects` key is not a canonical UUIDv7 | §19 |
| `OBJECT_ID_MISMATCH` | an object's `id` differs from its `objects` key | §20, §24 |
| `MISSING_REQUIRED_FIELD` | a required base or Task field is absent | §23, §31 |
| `INVALID_FIELD_TYPE` | a field has the wrong type, e.g. a non-text `title`, a string held as Automerge Text (§30), an `objects` entry that is not a map, or an object's `extensions` that is not a map | §15, §29, §30, §32, §76 |
| `INVALID_ENUM_VALUE` | `lifecycle`, `status` or `priority` is not a string, or is neither a standard value nor a valid `x/<reverse-domain>/<value>` extension value (for `lifecycle`, extension values are not allowed) | §26, §33, §38 |
| `INVALID_EXTENSION_NAMESPACE` | an `extensions` key does not match `reverse-domain` | §18 |
| `INVALID_PRINCIPAL_REF` | a Principal reference is not `p:` + base64url of 32 bytes | §27, §42 |
| `INVALID_TIMESTAMP` | `created_at` is not an RFC 3339 UTC timestamp | §28 |
| `INVALID_LOCAL_DATE` | a date field is not a string, or not a valid Gregorian `YYYY-MM-DD` | §35 |
| `INVALID_COLLECTION_REPRESENTATION` | `tags` or `assignees` is not a map, or a member's value is not `true` | §39, §42 |
| `INVALID_TAG` | a tag is empty or starts with `#` | §40 |
| `IMMUTABLE_FIELD_MUTATED` | `id`, `type` or `created_by` changed | §75 |
| `CHANGE_ACTOR_MISMATCH` | a Data Unit carries an Automerge change whose actor is not the §8 actor of the unit's signer; the change is not merged | §8, §11 |
| `INVALID_AUTOMERGE_BYTES` | a Data Unit or Snapshot plaintext is not the §11 or §13 framing, or its Automerge bytes are not a valid chunk of the required type with a matching checksum, or cannot be parsed or loaded, or the change skips a sequence number of its actor; nothing is merged | §11, §13, §14.1 |

When one value breaks several rules, its diagnostic is the first that applies in the order of this table: structure and value rules first, `IMMUTABLE_FIELD_MUTATED` last. Precedence applies within one value only. A changed `id` that is also not a UUIDv7, for example, is `INVALID_OBJECT_ID`.

A field with concurrent values (Section 45) is valid only if every one of its values is valid. Otherwise that field fails once, with the diagnostic that comes first in the order of this table among its invalid values, and its object is profile-invalid.

These are profile-level codes reported to the application. They are not LFCP Wire error codes.

`OBJECT_ID_COLLISION` (Section 21) is a separate named profile error, not a `PROFILE_INVALID` diagnostic.

---

## 75. Immutable field violations

These fields are immutable:

```text
object.id
object.type
object.created_by
```

If an authorized remote change modifies one of them, the Resource has profile-invalid object state.

Clients MUST NOT silently reinterpret the object.

Recommended UI state:

```text
PROFILE_INVALID
```

with diagnostics exposing the offending field and Automerge change hash if available.

---

## 76. Invalid values

Examples:

```text
malformed UUIDv7 object id
invalid Principal reference
invalid Local Date
non-map tags
non-map assignees
non-text title
```

A robust client SHOULD preserve the Automerge document but quarantine the affected object from normal mutation UI until repaired.

It MUST NOT discard unrelated valid objects in the same Resource.

---

## 77. Partial failure isolation

One invalid object MUST NOT make the entire Resource unusable if other objects can still be safely interpreted.

Recommended model:

```text
Resource READY
│
├── Task A READY
├── Task B PROFILE_INVALID
└── Task C READY
```

This is important for federated clients where one buggy implementation may emit malformed application state.

---

# Part XIII. Adapter Contract

## 78. Editor adapter responsibility

An editor adapter maps between external representations and Shared Objects intents.

For Obsidian:

```text
Markdown Task line
      ↕
Task adapter
      ↕
Shared Objects Task
```

For VS Code, the same Shared Object may be represented by the same Markdown syntax or by a custom editor UI.

---

## 79. Projection is not storage authority

A Markdown projection is not the complete authoritative representation of a Shared Task.

A Task may contain fields that are not represented in the Markdown line.

Examples:

```text
assignees
conflict metadata
future extensions
comments
```

Therefore an adapter MUST use semantic field updates instead of recreating the Shared Object from the visible line.

Bad:

```text
parse line
replace whole Task object
```

Correct:

```text
parse line
compare represented fields
emit specific intents
```

---

## 80. Adapter-owned fields

A Markdown Task adapter MAY claim semantic ownership of:

```text
title
status
due
scheduled
priority
tags
```

if it can reliably parse and minimally rewrite those fields.

Fields not represented by the adapter MUST remain untouched.

---

## 81. Local formatting

Formatting that is not defined by the Shared Objects semantic model remains local presentation state.

Examples:

```text
indentation
heading location
surrounding prose
local backlinks
editor-specific decorations
```

A remote Task status update MUST NOT rewrite unrelated local formatting.

---

## 82. Multiple projections

Multiple projections of the same Shared Object are valid.

```text
Task 123
  ├── Today.md
  ├── Project.md
  └── Dashboard.md
```

All projections observe the same Shared Object semantics.

An adapter SHOULD update all known local projections when a represented shared field changes.

---

## 83. Projection divergence

If two local projections of the same Task are manually edited differently before the plugin reconciles them, the adapter SHOULD convert each semantic edit into a causal Shared Objects intent in observed order.

If those edits touch the same scalar field without intervening shared state, the adapter MAY choose to flag a local projection inconsistency rather than inventing ordering.

The exact Obsidian reconciliation algorithm belongs to `OBSIDIAN-ARCHITECTURE-01` / `MARKDOWN-REFS-01`.

---

# Part XIV. Example States

## 84. Minimal Task

Conceptual JSON-like view:

```json
{
  "id": "019a2f85-7b31-7c42-b85a-fc843e2f40ad",
  "type": "task",
  "lifecycle": "active",
  "created_by": "p:...",
  "title": "Prepare API contract",
  "status": "todo",
  "priority": "normal",
  "tags": {},
  "assignees": {},
  "extensions": {}
}
```

---

## 85. Typical Task

```json
{
  "id": "019a2f85-7b31-7c42-b85a-fc843e2f40ad",
  "type": "task",
  "lifecycle": "active",
  "created_by": "p:...",
  "created_at": "2026-10-04T05:30:00Z",
  "title": "Prepare API contract",
  "status": "in_progress",
  "due": "2026-10-10",
  "scheduled": "2026-10-06",
  "priority": "high",
  "tags": {
    "backend": true,
    "important": true
  },
  "assignees": {
    "p:...": true
  },
  "extensions": {}
}
```

---

## 86. Completed Task

```json
{
  "title": "Prepare API contract",
  "status": "done",
  "completion_date": "2026-10-08"
}
```

Only relevant fields are shown.

---

## 87. Tombstoned Task

```json
{
  "id": "019a2f85-7b31-7c42-b85a-fc843e2f40ad",
  "type": "task",
  "lifecycle": "deleted",
  "title": "Prepare API contract",
  "status": "done"
}
```

Only relevant fields are shown.

The object remains addressable so old projections can report that the shared object was deleted.

---

# Part XV. Concurrency Examples

## 88. Concurrent completion and rename

Initial:

```text
title = Prepare API contract
status = todo
```

Peer A:

```text
status = done
```

Peer B:

```text
title = Prepare final API contract
```

Result:

```text
title = Prepare final API contract
status = done
```

No conflict.

---

## 89. Concurrent status transitions

Initial:

```text
status = todo
```

Peer A:

```text
status = done
```

Peer B:

```text
status = cancelled
```

Result:

```text
status conflict = {done, cancelled}
```

Explicit resolution required.

---

## 90. Concurrent tag additions

Initial:

```text
tags = {}
```

Peer A adds:

```text
backend
```

Peer B adds:

```text
urgent
```

Result:

```text
tags = {backend, urgent}
```

---

## 91. Concurrent tag add/remove

Initial:

```text
tags = {backend}
```

Peer A removes:

```text
backend
```

Peer B concurrently adds/retains through a fresh write:

```text
backend
```

Result under version-1 add-wins semantics:

```text
tags = {backend}
```

---

## 92. Delete and title edit

Initial:

```text
lifecycle = active
title = API contract
```

Peer A:

```text
lifecycle = deleted
```

Peer B:

```text
title = Final API contract
```

Result:

```text
lifecycle = deleted
title = Final API contract
```

The title edit is retained under the tombstone.

---

# Part XVI. Object Types Beyond Tasks

## 93. Version-1 standard object registry

Version 1 standardizes only:

| Type | Status |
|---|---|
| `task` | REQUIRED |

The architecture intentionally permits future standardized objects such as:

```text
decision
comment-thread
approval
project-status
```

but their field semantics are not defined in this document.

Implementations MUST NOT assume that every object is a Task.

---

## 94. Why future types share the same profile

Many collaborative objects benefit from one Resource-level CRDT graph:

```text
Project Alpha
│
├── Task A
├── Task B
├── Decision D
└── Approval E
```

Keeping them in one profile enables future relationships between objects without creating one LFCP Resource per object.

Examples:

```text
Task blocked_by Decision
Approval relates_to Task
Comment thread belongs_to Decision
```

These relationships are deferred until companion specifications define them.

---

# Part XVII. Security Model

## 95. Authorization belongs to LFCP

This profile does not grant permission to read or write.

A client must first validate LFCP Control Plane authority.

Only then should it apply an authorized LFCP Data Unit to the Automerge Resource replica.

Conceptually:

```text
LFCP signature valid?
      ↓ yes
LFCP data/write authorized?
      ↓ yes
correct Data Epoch?
      ↓ yes
Shared Objects framing valid?
      ↓ yes
Automerge change valid?
      ↓ yes
apply change
```

---

## 96. No per-object ACL

If Principal P has LFCP `data/write` authority for the Resource, profile version 1 does not prevent P from changing any object in that Resource.

An application MUST NOT present Task-level permissions as cryptographic security unless a future profile explicitly defines and enforces such semantics.

For strict separation:

```text
use separate LFCP Resources
```

---

## 97. Untrusted application values

Task titles, tags, extension fields, and other strings are untrusted user-controlled content.

Clients MUST escape values appropriately when rendering HTML or other executable contexts.

No Shared Objects text field should be interpreted as executable code merely because it came from an authenticated LFCP Principal.

---

# Part XVIII. Client API Recommendations

## 98. Resource API

A reusable SDK may expose:

```ts
interface SharedObjectsResource {
  getObject(id: string): SharedObjectView | undefined;
  listObjects(options?: ListOptions): SharedObjectView[];
  getTask(id: string): TaskView | undefined;

  apply(intent: SharedObjectsIntent): Promise<void>;

  onObjectChanged(handler: ObjectChangedHandler): Unsubscribe;
  onConflict(handler: ConflictHandler): Unsubscribe;
}
```

This API is informative, not wire normative.

---

## 99. Task view

A Task view SHOULD expose both a provisional visible value and conflict metadata.

Conceptual API:

```ts
interface ScalarView<T> {
  value: T | undefined;
  conflicts: T[];
  resolved: boolean;
}

interface TaskView {
  id: string;
  lifecycle: ScalarView<"active" | "deleted">;
  title: ScalarView<string>;
  status: ScalarView<string>;
  due: ScalarView<string | null>;
  scheduled: ScalarView<string | null>;
  completionDate: ScalarView<string | null>;
  priority: ScalarView<string>;
  tags: Set<string>;
  assignees: Set<string>;
}
```

The exact SDK shape may differ, but hiding Automerge conflicts from application code is NOT RECOMMENDED.

---

## 100. Change notification

Object change notifications SHOULD identify:

```text
resource id
object id
object type
changed semantic fields
whether conflicts appeared/disappeared
local or remote origin when known
```

This lets editor adapters update only affected projections.

---

# Part XIX. Interoperability Requirements

## 101. Cross-client interoperability

A valid Resource created in the Obsidian client MUST be loadable and editable by:

```text
VS Code client
browser example client
CLI client
independent third-party implementation
```

provided each supports:

```text
LFCP-WIRE-01
org.openlfcp.shared-objects.v1
```

No editor-specific field is allowed to be necessary for basic Task semantics.

---

## 102. Independent implementation requirement

The profile SHOULD be validated with at least two independent implementations or bindings before being declared stable.

Recommended initial matrix:

```text
TypeScript / Automerge JS
Rust / Automerge Rust
```

Both should exchange LFCP Data Units generated from the official profile vectors.

---

## 103. Test-vector document

Before profile release candidate status, the project SHOULD publish:

```text
SHARED-OBJECTS-TEST-VECTORS-01
```

The vectors should include:

- deterministic Principal and Resource IDs;
- derived Automerge actor IDs;
- initial document change;
- Task creation change;
- title update;
- status update;
- concurrent status conflict;
- conflict resolution;
- tag add/add merge;
- tag add/remove merge;
- delete/edit merge;
- full snapshot;
- post-snapshot change;
- unknown field preservation;
- unknown object type preservation;
- malformed profile states.

How a test vector writes down a conflicted field (for example a `<field>_conflict_set` list of the concurrent values) is a test-vector convention defined by the vector format, not part of this profile's logical state.

---

# Part XX. Required Conformance Scenarios

## 104. Scenario A: Create and replicate

Client A creates a Resource and Task.

Client B receives LFCP Data Units and reconstructs the same Task semantics.

Expected:

```text
same Object ID
same title
same status
same collection membership
```

---

## 105. Scenario B: Offline independent fields

A and B start from the same Task.

A offline:

```text
status = done
```

B offline:

```text
due = 2026-10-15
```

After merge:

```text
status = done
due = 2026-10-15
```

No conflicts.

---

## 106. Scenario C: Offline same field

A offline:

```text
status = done
```

B offline:

```text
status = cancelled
```

After merge:

```text
status conflict count = 2
```

After explicit resolution:

```text
status conflict count = 0
chosen status is visible on both replicas
```

---

## 107. Scenario D: Multiple projections

This is an adapter-level scenario but MUST be supported by profile semantics.

One Task is projected into two documents.

Editing either projection changes one Shared Object.

Both projections eventually display the same semantic state.

---

## 108. Scenario E: Unknown extension

Client A writes:

```text
extensions["com.example.foo"]
```

Client B does not understand it and edits Task status.

After B's change, Client A still observes its extension data unchanged.

---

## 109. Scenario F: Unknown object type

Client A creates:

```text
type = com.example.poll
```

Task-only Client B synchronizes the Resource and edits a Task object.

The Poll object MUST survive unchanged.

---

## 110. Scenario G: Delete and offline edit

A deletes Task while B edits its title offline.

After merge:

```text
lifecycle = deleted
new title preserved
```

Restoring the Task reveals the edited title.

---

# Part XXI. Performance Guidance

## 111. Resource sizing

The profile intentionally supports many objects per Resource.

However, implementations SHOULD avoid one global Resource containing a user's entire lifetime of unrelated shared state because:

- every reader receives Resource state;
- encryption and authorization boundaries become too broad;
- snapshots grow;
- sync costs grow;
- failure isolation becomes weaker.

Natural Resource boundaries include:

```text
project
team collaboration
family planning context
shared initiative
```

---

## 112. Avoid one Resource per Task

Creating one LFCP Resource per Task is NOT RECOMMENDED unless each Task truly requires independent access control or routing.

It would multiply:

```text
Control Chains
key epochs
route manifests
snapshots
Resource sessions
server bookkeeping
```

The preferred model is many Tasks per Resource.

---

## 113. Incremental object indexes

Client libraries MAY build local indexes for:

```text
object type
status
due date
tag
assignee
```

Such indexes are local derived state.

They MUST be reconstructable from the Automerge document and MUST NOT become part of LFCP protocol authority.

---

# Part XXII. Versioning

## 114. Compatible additions

The following MAY be introduced without changing the profile identifier if old clients can preserve them:

- new namespaced extensions;
- new namespaced object types;
- new namespaced statuses;
- new namespaced priority values;
- optional fields under extension namespaces.

---

## 115. Breaking changes

The following require a new profile identifier:

- changing CRDT engine incompatibly;
- changing LFCP Data Unit plaintext framing incompatibly;
- changing Object ID rules incompatibly;
- changing existing Task field semantics incompatibly;
- changing collection conflict policy incompatibly;
- changing tombstone semantics incompatibly.

Example future profile:

```text
org.openlfcp.shared-objects.v2
```

---

## 116. Resource migration

Because LFCP Resource Genesis fixes the Data Profile, moving from v1 to an incompatible v2 requires explicit application-level migration to a new Resource.

The old Resource SHOULD remain addressable for old projections until users migrate or detach them.

A future migration specification may define signed links between predecessor and successor Resources.

---

# Part XXIII. Open Questions

## 117. Questions before Release Candidate

The following require implementation experiments or companion specs:

1. Exact Automerge binary-version compatibility requirements.
2. Whether Automerge actor IDs of exactly 32 bytes are uniformly supported across reference bindings.
3. Whether `created_at` should remain in the base object or move to an optional extension.
4. Whether `completion_date` should be derived or persisted.
5. Whether tag comparison should remain case-sensitive.
6. Whether add-wins semantics for assignees is the best long-term behavior.
7. Whether the profile should standardize object-to-object links in v1.
8. Whether comments belong in v1 or a companion object-type spec.
9. How profile-invalid authorized changes should be repaired without losing history.
10. Whether Task status should remain free text plus standard values or become a structured object.
11. Exact behavior when two independent object creations collide on one UUIDv7.
12. Whether semantic intent history should become a standard extension.
13. Whether user-facing resource metadata such as a shared display name belongs in this profile.
14. Whether `task.reopen` should restore `todo` or preserve previous nonterminal state.
15. Exact canonical Principal-ref textual encoding test vectors.

---

# Part XXIV. Reference Implementation Layout

## 118. TypeScript package

Recommended package:

```text
openlfcp/sdk-ts/packages/profile-shared-objects
```

Suggested layout:

```text
src/
├── profile.ts
├── actor-id.ts
├── framing.ts
├── snapshot.ts
├── document.ts
├── object-id.ts
├── principal-ref.ts
├── validation.ts
├── conflicts.ts
│
├── tasks/
│   ├── schema.ts
│   ├── view.ts
│   ├── intents.ts
│   ├── mutate.ts
│   └── validate.ts
│
└── extensions/
    └── preserve.ts
```

---

## 119. Rust package

Recommended crate:

```text
openlfcp/sdk-rs/crates/lfcp-profile-shared-objects
```

Its public behavior should be validated against the same profile test vectors as TypeScript.

---

# Part XXV. Obsidian Relationship

## 120. Obsidian is an adapter, not the profile owner

The Obsidian plugin consumes this profile.

It does not define it.

Dependency direction:

```text
SHARED-OBJECTS-PROFILE-01
          │
          ▼
 @openlfcp/profile-shared-objects
          │
          ▼
 openlfcp/obsidian
```

A profile change MUST NOT be made only inside the Obsidian repository.

---

## 121. Obsidian Task projection

Conceptually:

```md
- [ ] Prepare API contract
  <!-- lfcp-ref: RESOURCE#task:OBJECT -->
```

maps to Task fields such as:

```text
checkbox -> status
text     -> title
metadata -> due / scheduled / priority / tags
```

The exact parsing and minimal-diff rewrite rules are defined by `MARKDOWN-REFS-01` and Obsidian adapter specifications.

---

## 122. Privacy consequence

Because the Shared Objects Resource contains only selected shared objects, an Obsidian Host Document may remain private.

Example:

```md
# Private notes

SECRET PRIVATE PARAGRAPH

- [ ] Shared API task
  <!-- lfcp-ref: ... -->

ANOTHER PRIVATE PARAGRAPH
```

Only the Shared Task semantics enter the Shared Objects Resource.

The profile never requires the entire Markdown document to be serialized into Automerge.

---

# Part XXVI. Summary of Normative Semantics

## 123. Profile invariants

A conforming implementation preserves these invariants:

```text
1. Profile ID is org.openlfcp.shared-objects.v1.

2. Version 1 uses Automerge.

3. One LFCP Data Unit contains one framed Automerge change.

4. LFCP Snapshot plaintext contains one framed Automerge full-save image.

5. LFCP Principal + Resource deterministically define the Automerge actor ID.

6. One Resource normally contains many Shared Objects.

7. Object IDs are canonical UUIDv7 strings.

8. Version 1 standardizes Task.

9. Scalar fields preserve concurrent conflicts.

10. Status conflicts must not be silently hidden.

11. Tags and assignees are add-wins map sets.

12. Delete uses a lifecycle tombstone; objects are not physically removed.

13. Unknown fields, extensions, and object types are preserved.

14. Intents are semantic client operations, not LFCP Wire messages.

15. Authorization belongs to LFCP, not this profile.

16. There is no per-object cryptographic ACL in v1.

17. Markdown is only an adapter/projection concern.

18. Editor-specific metadata must not become required portable state.
```

---

## 124. Core design statement

The Shared Objects profile is intentionally small.

It does not try to make a collaborative application out of every local file.

Instead it defines portable shared state that local applications can reference wherever useful:

```text
personal local workspace
        │
        ├── private state
        ├── private state
        │
        └── reference
              │
              ▼
         shared object
              │
              ▼
        federated LFCP Resource
```

A Task can therefore exist once as collaborative state while appearing in different files, folders, editors, and user workflows.

That is the central application-level abstraction built on LFCP.

---

# Appendix A. Compact Task Schema

```text
Task
├── id                 UUIDv7, immutable
├── type               "task", immutable
├── lifecycle          active | deleted                  [conflict-preserving]
├── created_by         PrincipalRef, immutable
├── created_at         RFC3339 UTC, optional
│
├── title              string                            [conflict-preserving]
├── status             status string                     [conflict-preserving]
├── due                YYYY-MM-DD, optional              [conflict-preserving]
├── scheduled          YYYY-MM-DD, optional              [conflict-preserving]
├── completion_date    YYYY-MM-DD, optional              [conflict-preserving]
├── priority           priority string                   [conflict-preserving]
│
├── tags               add-wins set<string>
├── assignees          add-wins set<PrincipalRef>
│
└── extensions         namespaced map
```

---

# Appendix B. Status transition guidance

The profile does not enforce a strict state machine because offline collaborative workflows may legitimately skip intermediate states.

Recommended UI transitions:

```text
              ┌──────────────┐
              │     todo     │
              └──────┬───────┘
                     │
               start │
                     ▼
              ┌──────────────┐
              │ in_progress  │
              └──────┬───────┘
                     │
            complete │
                     ▼
              ┌──────────────┐
              │     done     │
              └──────────────┘

Any non-deleted state may be explicitly cancelled.
A done/cancelled task may be reopened.
```

Clients MUST still accept authorized direct transitions such as:

```text
todo -> done
```

because a simple Markdown checkbox naturally produces that transition.

---

# Appendix C. Recommended next documents

After this profile, the project should define:

```text
SHARED-OBJECTS-TEST-VECTORS-01.md
MARKDOWN-REFS-01.md
OBSIDIAN-MVP-UX-01.md
```

Recommended order:

1. `SHARED-OBJECTS-TEST-VECTORS-01`
2. `MARKDOWN-REFS-01`
3. `OBSIDIAN-MVP-UX-01`

The first ensures the profile is implementable byte-for-byte across languages. The second standardizes portable editor references. The third can then focus entirely on user experience instead of inventing data semantics inside the plugin.
