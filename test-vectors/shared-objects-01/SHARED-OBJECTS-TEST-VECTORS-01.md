# SHARED-OBJECTS-TEST-VECTORS-01

**Status:** Working Draft 0.1  
**Profile:** `org.openlfcp.shared-objects.v1`  
**Date:** 2026-10-04  
**Companion specification:** `SHARED-OBJECTS-PROFILE-01.md`  
**Wire dependency:** `LFCP-WIRE-01`  
**Reference Automerge compatibility target:** `@automerge/automerge 3.5.0`

> This document defines interoperability vectors for the OpenLFCP Shared Objects profile. It deliberately distinguishes byte-deterministic profile rules from CRDT behavioral interoperability.

---

## 1. Why this suite has two kinds of vectors

Not every conforming implementation must emit identical Automerge bytes for the same human intent.

LFCP Shared Objects therefore tests two different properties:

### 1.1 Deterministic profile vectors

These MUST match exactly across implementations:

- Principal reference encoding;
- LFCP Principal + Resource -> Automerge actor derivation;
- canonical UUIDv7 validation;
- Shared Objects outer CBOR framing;
- deterministic hashes of that framing.

### 1.2 Behavioral Automerge vectors

These test:

- whether changes produced by one implementation can be applied by another;
- whether all replicas converge after receiving the same changes;
- whether required conflicts remain discoverable;
- whether add-wins collections converge according to the profile;
- whether tombstones preserve concurrent edits;
- whether snapshots round-trip across implementations.

Two independent implementations are **not** required to produce byte-identical Automerge changes or full-save images from the same semantic intent.

The normative result for those scenarios is the resulting state, conflict set, validation result, and cross-implementation acceptance behavior.

---

## 2. Automerge compatibility target

This suite uses Automerge `3.5.0` as the initial reference corpus target.

The profile itself remains defined by `SHARED-OBJECTS-PROFILE-01`; the reference package version exists so implementers can generate and exchange a concrete binary corpus while the project's long-term Automerge binary-version compatibility policy is finalized.

An implementation MAY use another compatible binding/version if it can:

1. consume the reference change corpus;
2. produce changes accepted by the reference implementation;
3. preserve the required logical/conflict semantics;
4. load/save interoperable documents for the declared compatibility range.

---

## 3. Deterministic fixture derivation

The suite derives fixed 32-byte test values as:

```text
fixture(label) = SHA-256(ASCII(label))
```

### 3.1 Resource A

```text
label = OPENLFCP-SHARED-OBJECTS-TV01-RESOURCE-A
resource_id = 1081b3b99d4f5d39d86d07bef0849a9ba40f00d0ca9a295a51f0fa65500f9f84
```

### 3.2 Resource B

```text
label = OPENLFCP-SHARED-OBJECTS-TV01-RESOURCE-B
resource_id = 95fd348d7d0f25fe9a03d5230acc6370f0f6e873ec920cf9c205041aff825099
```

### 3.3 Principals

| Principal | Principal ID hex | PrincipalRef |
|---|---|---|
| Andrey | `bd07952a86218f6f57a360520c0403acd3c72f275907e8cb38a3d6362ab4c9f4` | `p:vQeVKoYhj29Xo2BSDAQDrNPHLydZB-jLOKPWNiq0yfQ` |
| Pavel | `eba658a7f4d1ccadd2d2e46658c853a0b19fe587f355e8845f170d248ac2bbea` | `p:66ZYp_TRzK3S0uRmWMhToLGf5YfzVeiEXxcNJIrCu-o` |
| Masha | `1b1c18c7dde569d5415f7263ea1ad444d6add0f04f4044bea67894a8161d71e6` | `p:GxwYx93ladVBX3Jj6hrURNat0PBPQES-pniUqBYdceY` |

PrincipalRef is exactly:

```text
"p:" + base64url-no-padding(raw_32_byte_principal_id)
```

---

# Part I. Deterministic vectors

## D01. Automerge actor ID: Andrey / Resource A

Actor derivation:

```text
SHA-256(
  ASCII("OPENLFCP-SHARED-OBJECTS-ACTOR-v1") ||
  resource_id ||
  principal_id
)
```

Input:

```text
resource  = 1081b3b99d4f5d39d86d07bef0849a9ba40f00d0ca9a295a51f0fa65500f9f84
principal = bd07952a86218f6f57a360520c0403acd3c72f275907e8cb38a3d6362ab4c9f4
```

Expected:

```text
actor_id = 6c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c583
```

The result is exactly 32 bytes.

---

## D02. Resource separation

The same Principal in Resource B MUST derive a different actor ID.

```text
actor_id = 24f209777a84a134f5eb527ef26b00732dc123ab582bf58c4cf2ef3bc3c70cd4
```

An implementation producing the Resource-A actor for Resource B fails this vector.

---

## D03. PrincipalRef

Input raw Principal ID:

```text
bd07952a86218f6f57a360520c0403acd3c72f275907e8cb38a3d6362ab4c9f4
```

Expected text:

```text
p:vQeVKoYhj29Xo2BSDAQDrNPHLydZB-jLOKPWNiq0yfQ
```

No `=` padding is permitted.

---

## D04. Data Unit plaintext framing

This vector checks only Shared Objects framing. The enclosed bytes are intentionally synthetic and MUST NOT be interpreted as a valid Automerge change.

Synthetic change bytes:

```text
00010203a0ff
```

Logical framing:

```cddl
[
  1,
  h'00010203a0ff'
]
```

Expected deterministic CBOR:

```text
82014600010203a0ff
```

SHA-256 of the expected deterministic framed CBOR:

```text
8b04fa1dc8dc3cc339215889b2b6083059a10e81a35a61af9255a2457f662b99
```

---

## D05. Snapshot plaintext framing

Synthetic full-save bytes:

```text
aabbccddeeff00112233
```

Logical framing:

```cddl
[
  1,
  h'aabbccddeeff00112233'
]
```

Expected deterministic CBOR:

```text
82014aaabbccddeeff00112233
```

SHA-256 of the expected deterministic framed CBOR:

```text
d6e1b96b61dd66a7b2092e517d3536029da0a5042452fbba1a9c9cc3dee580cb
```

---

## D06. Canonical Object ID

Valid:

```text
019a2f85-7b31-7c42-b85a-fc843e2f40ad
```

Requirements checked:

```text
lowercase
canonical hyphens
version = 7
RFC 4122/RFC 9562 variant bits
```

---

## D07. Uppercase UUID is not canonical

Input:

```text
019A2F85-7B31-7C42-B85A-FC843E2F40AD
```

Expected:

```text
PROFILE_INVALID
INVALID_OBJECT_ID
```

---

## D08. Wrong UUID version

Input:

```text
019a2f85-7b31-6c42-b85a-fc843e2f40ad
```

Expected:

```text
PROFILE_INVALID
INVALID_OBJECT_ID
```

---

# Part II. Base Task fixture

The main test Task is:

```json
{
  "id": "019a2f85-7b31-7c42-b85a-fc843e2f40ad",
  "type": "task",
  "lifecycle": "active",
  "created_by": "p:vQeVKoYhj29Xo2BSDAQDrNPHLydZB-jLOKPWNiq0yfQ",
  "created_at": "2026-10-04T05:30:00Z",
  "title": "Prepare API contract",
  "status": "todo",
  "priority": "normal",
  "tags": {},
  "assignees": {},
  "extensions": {}
}
```

Object map key:

```text
objects["019a2f85-7b31-7c42-b85a-fc843e2f40ad"]
```

The contained `id` MUST equal that key.

---

# Part III. Behavioral interoperability scenarios

## S01. Create Task

Andrey creates the base Task in one application transaction / one Automerge change.

Expected materialized state:

```text
objects[019a2f85-7b31-7c42-b85a-fc843e2f40ad] exists
id = 019a2f85-7b31-7c42-b85a-fc843e2f40ad
type = task
lifecycle = active
status = todo
priority = normal
tags = {}
assignees = {}
extensions = {}
```

The change generated by implementation A MUST be applicable by implementation B.

---

## S02. Independent-field concurrency

Both peers start from S01.

Andrey, offline:

```text
task.complete
status = done
completion_date = 2026-10-08
```

Pavel, concurrently:

```text
task.set_title
title = Prepare final API contract
```

After exchanging changes:

```text
status = done
completion_date = 2026-10-08
title = Prepare final API contract
```

Expected semantic conflicts:

```text
none
```

Concurrent edits to different scalar properties do not create an application conflict merely because they were concurrent.

---

## S03. Concurrent status conflict

Start from S01.

Andrey:

```text
status = done
completion_date = 2026-10-08
```

Pavel concurrently:

```text
status = cancelled
```

After merge, the application MUST be able to observe the status conflict set:

```text
{ done, cancelled }
```

Ordering of conflict-map internals is not normative.

The client MUST report:

```text
status conflicted = true
```

It MAY use Automerge's deterministic selected scalar for provisional rendering, but MUST NOT claim the field is resolved.

---

## S04. Explicit status conflict resolution

Start from the merged S03 state containing both values.

Masha explicitly chooses:

```text
done
```

The resolver writes:

```text
status = done
```

from a document containing all known conflicting values.

Expected result:

```text
status = done
status conflict = false
```

A resolver that writes from only one pre-merge branch does NOT satisfy this vector.

---

## S05. Concurrent due dates

Andrey:

```text
due = 2026-10-10
```

Pavel concurrently:

```text
due = 2026-10-12
```

Expected conflict set:

```text
{ 2026-10-10, 2026-10-12 }
```

Both values remain available until explicit resolution.

---

## S06. Tag add/add

Andrey concurrently adds:

```text
backend
```

Pavel adds:

```text
important
```

Expected:

```text
tags = { backend, important }
```

---

## S07. Tag add/remove add-wins

Base state contains:

```text
tags = { backend }
```

Andrey removes `backend` by deleting the map key.

Pavel concurrently performs a fresh add of `backend` by writing:

```text
tags["backend"] = true
```

Expected:

```text
tags = { backend }
```

A `false` scalar MUST NOT be used to model removal.

---

## S08. Assignee add/remove add-wins

Base state assigns Pavel:

```text
assignees = { p:66ZYp_TRzK3S0uRmWMhToLGf5YfzVeiEXxcNJIrCu-o }
```

Andrey removes Pavel.

Masha concurrently writes a fresh assignment of Pavel.

Expected:

```text
assignees = { p:66ZYp_TRzK3S0uRmWMhToLGf5YfzVeiEXxcNJIrCu-o }
```

---

## S09. Delete versus independent edit

Andrey:

```text
lifecycle = deleted
```

Pavel concurrently:

```text
title = Final API contract
```

Expected:

```text
object remains present
lifecycle = deleted
title = Final API contract
```

The title change is retained beneath the tombstone.

Physical removal of the object fails this vector.

---

## S10. Delete versus restore

Andrey concurrently writes:

```text
lifecycle = deleted
```

Pavel writes:

```text
lifecycle = active
```

Expected lifecycle conflict set:

```text
{ active, deleted }
```

The conflict MUST be surfaced.

---

## S11. Unknown field preservation

Base object additionally contains:

```json
{
  "x_future_scalar": "future-value",
  "extensions": {
    "com.example.tracker": {
      "ticket": "ABC-42"
    }
  }
}
```

An older client that only understands standardized Task fields changes:

```text
status = in_progress
```

After its change, merge, and save/load round-trip, both unknown values MUST still exist unchanged.

---

## S12. Unknown object type preservation

Resource contains:

```json
{
  "id": "019a2f85-7b31-7c42-9f24-8f933f2a91c0",
  "type": "com.example.poll",
  "lifecycle": "active",
  "created_by": "p:vQeVKoYhj29Xo2BSDAQDrNPHLydZB-jLOKPWNiq0yfQ",
  "extensions": {},
  "question": "Ship on Friday?",
  "answers": {
    "yes": 1
  }
}
```

A client that does not understand `com.example.poll` MAY omit it from normal UI.

It MUST preserve the object through load, unrelated mutations, synchronization, and snapshot generation.

---

## S13. Object ID collision

Two actors concurrently create semantically different objects under exactly:

```text
019a2f85-7b31-7c42-b85a-fc843e2f40ad
```

Expected profile result:

```text
OBJECT_ID_COLLISION
```

The client MUST NOT silently present the merged map as though the two users intentionally created one object.

Repair is outside this vector; a conforming repair creates a new Object ID for one logical object.

---

## S14. Snapshot + post-snapshot change

1. Build a valid document containing the S01 Task and later tag changes.
2. Produce an Automerge full-save image.
3. Frame it as `[1, save-bytes]` when used as LFCP Snapshot plaintext.
4. Load the save image in an independent implementation.
5. Apply a later change:

```text
status = in_progress
```

Expected:

```text
all pre-snapshot objects preserved
status = in_progress
```

Independent implementations are not required to produce identical full-save bytes for equivalent logical state. They ARE required to load compatible reference images and obtain equivalent state.

---

# Part IV. Invalid profile states

## I01. Object key / id mismatch

Map key:

```text
019a2f85-7b31-7c42-b85a-fc843e2f40ad
```

Contained `id`:

```text
019a2f85-7b31-7c42-a43c-4b693e77d36b
```

Expected:

```text
PROFILE_INVALID
OBJECT_ID_MISMATCH
```

Only the affected object should be quarantined where safe.

---

## I02. Invalid Object ID

```text
NOT-A-UUID
```

Expected:

```text
PROFILE_INVALID
INVALID_OBJECT_ID
```

---

## I03. Non-text title

```text
title = 42
```

Expected diagnostic:

```text
INVALID_FIELD_TYPE
```

---

## I04. Invalid Local Date

```text
due = 2026-13-50
```

Expected:

```text
INVALID_LOCAL_DATE
```

---

## I05. Invalid tag representation

Invalid:

```json
["backend"]
```

Expected:

```text
INVALID_COLLECTION_REPRESENTATION
```

Version 1 requires an Automerge map used as an add-wins set.

---

## I06. Invalid assignee key

```text
not-a-principal
```

Expected:

```text
INVALID_PRINCIPAL_REF
```

---

## I07. Immutable field mutation

An existing Task is changed from:

```text
type = task
```

to:

```text
type = decision
```

Expected:

```text
PROFILE_INVALID
IMMUTABLE_FIELD_MUTATED
```

---

# Part V. Reference binary corpus

The companion file:

```text
SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json
```

is a concrete binary corpus generated by `generate_automerge_reference_01.mjs` with:

```text
@automerge/automerge 3.5.0
```

pinned exactly in the repository's `package.json`. The generator is deterministic (fixed actors from the fixtures, change time `0`, fixed messages), and `scripts/validate.sh` regenerates the corpus and compares it byte for byte.

For every behavioral scenario S01-S14 the corpus records:

```text
the exact Automerge changes that build the scenario, dependencies first
  (profile initialization, base state, each branch)
the heads and the full-save image of the converged document
the converged logical state
the scalar conflict sets (and Object ID collisions)
for S14, the Snapshot save image taken before the post-snapshot change
```

Every string is written as an Automerge scalar string, never as collaborative Text, because Task fields are scalar registers (SHARED-OBJECTS-PROFILE-01 §30); integers are Automerge `int` values. The corpus is supplementary: its bytes are not normative (SHARED-OBJECTS-PROFILE-01 §14), but its changes and save images are valid inputs every implementation must accept.

A conforming second implementation SHOULD demonstrate:

```text
reference JS change -> second implementation accepts it
second implementation change -> JS reference accepts it
reference save image -> second implementation loads it
second implementation save image -> JS reference loads it
```

This is stronger than comparing independently generated bytes, because it tests actual binary interoperability.

The corpus also lists `negatives`: inputs a receiver MUST NOT merge. `SO-SEC1-change-actor-mismatch` is a Data Unit plaintext signed by Andrey that carries a real change by Pavel's Automerge actor, on top of S01. SHARED-OBJECTS-PROFILE-01 §8 and §11 require the change's actor to be the §8 actor of the unit's signer, so the expected result is `PROFILE_INVALID` with the diagnostic `CHANGE_ACTOR_MISMATCH`, and the change is not merged.

---

# Part VI. Implementation-neutral test runner contract

The machine-readable file `SHARED-OBJECTS-TEST-VECTORS-01.json` is normative for fixture values and scenario inputs/expected outputs. It is laid out as an `lfcp-vector-format/1` suite (`schemas/lfcp-vector-format-1.schema.json` in the spec repository).

A test runner should expose operations similar to:

```text
newReplica(resource_id, principal_id)
applyIntent(replica, intent)
exportChanges(replica, since_heads)
applyChanges(replica, changes)
merge(replicaA, replicaB)
readObject(object_id)
readConflicts(object_id, field)
save(replica)
load(bytes, resource_id, principal_id)
validateObject(object_id)
```

The exact programming API is not standardized.

---

# Part VII. Cross-language conformance matrix

For each SDK pair:

```text
TypeScript <-> Rust
TypeScript <-> future Swift
Rust       <-> future Swift
```

run at least:

| Test | A produces / B consumes | B produces / A consumes | Same logical result |
|---|---:|---:|---:|
| Init change | REQUIRED | REQUIRED | REQUIRED |
| Task create | REQUIRED | REQUIRED | REQUIRED |
| Scalar update | REQUIRED | REQUIRED | REQUIRED |
| Concurrent conflict | REQUIRED | REQUIRED | REQUIRED |
| Tag add/remove | REQUIRED | REQUIRED | REQUIRED |
| Tombstone/edit | REQUIRED | REQUIRED | REQUIRED |
| Snapshot load | REQUIRED | REQUIRED | REQUIRED |
| Unknown fields | REQUIRED | REQUIRED | REQUIRED |

---

# Part VIII. Conformance rules

An implementation claiming `SHARED-OBJECTS-TEST-VECTORS-01` conformance MUST:

1. match D01-D08 exactly;
2. pass S01-S14 semantically;
3. expose the mandatory conflict sets;
4. implement add-wins tags and assignees;
5. retain tombstoned objects;
6. preserve unknown fields and unknown object types;
7. detect I01-I07 without corrupting unrelated valid objects;
8. exchange at least one concrete Automerge change corpus with an independent implementation;
9. exchange at least one Automerge full-save image with an independent implementation;
10. avoid assuming that same semantic intent implies identical Automerge binary bytes.

---

# Part IX. Explicit non-requirements

This suite does NOT require:

- Markdown;
- Obsidian;
- LFCP server transport;
- LFCP encryption;
- LFCP Control Plane;
- globally identical Automerge save bytes;
- globally identical conflict-map iteration order;
- a particular UI rendering of a conflict.

The suite tests the Shared Objects application profile in isolation.

---

# Part X. Files in this vector release

```text
SHARED-OBJECTS-TEST-VECTORS-01.md
SHARED-OBJECTS-TEST-VECTORS-01.json
generate_shared_objects_test_vectors_01.py
SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json
generate_automerge_reference_01.mjs
```

The Python generator reproduces deterministic fixture values and the machine-readable vector manifest without requiring Automerge.

The JavaScript generator reads the vector JSON and produces the supplementary Automerge binary reference corpus with the pinned reference dependency.

---

# Appendix A. Compact expected conflict table

| Scenario | Field | Expected |
|---|---|---|
| S03 | `status` | `{done, cancelled}` |
| S04 | `status` | resolved `done` |
| S05 | `due` | `{2026-10-10, 2026-10-12}` |
| S10 | `lifecycle` | `{active, deleted}` |

---

# Appendix B. Compact collection table

| Scenario | Collection | Expected |
|---|---|---|
| S06 | tags | `{backend, important}` |
| S07 | tags | `{backend}` |
| S08 | assignees | `{Pavel}` |

---

# Appendix C. Core invariant

The test suite exists to verify the central application-level promise:

```text
same valid set of Shared Objects changes
              +
profile-prescribed conflict semantics
              ↓
      same observable shared state
```

regardless of which conforming editor, SDK, or LFCP server transported those changes.
