# SHARED-SECTIONS-TEST-VECTORS-01

**Project:** OpenLFCP  
**Target:** MVP 0.2  
**Date:** 2026-10-08  
**Status:** Working Draft reference corpus for MVP 0.2, in the implementation baseline `mvp-0.2-baseline.1`; 28 JavaScript cases, independent SDK interoperability pending  
**Profile:** org.openlfcp.shared-sections.v1  
**Normative companion:** `profiles/SHARED-SECTIONS-PROFILE-01.md` (Working Draft 0.3); ADR 0009

> **Revision note.** Imported from the MVP 0.2 planning corpus and
> regenerated with the project's pinned engine (LFCP-02-008). LFCP-02-010
> applies ADR 0009 (P2): every change goes through the admission rules of
> the profile's §14.1 (`generator/admission.mjs`), and other invalid
> values are isolated per node (§14.2). Cases SS13, SS19, SS20 and SS21,
> which expected the whole section `PROFILE_INVALID` with an empty tree,
> now expect their change refused at admission and the section `VALID`;
> each case's `notes` give the rationale. Every case's `expected` gains
> `invalid`, `refused` and `held`. The shared initial state now writes the
> readiness marker of §12.1 in its last change, so every case's change and
> save bytes differ from the planning corpus while no expected value
> changes; a section without `ready` classifies as `IMPORTING`. SS29–SS41
> are added: import and readiness, admission refusals for each rule, a held
> dependent, per-node isolation, and the Text budget. The
> Markdown fixtures, rewritten for the grammar decisions of
> MARKDOWN-SECTIONS-01, are in `MARKDOWN-SECTIONS-FIXTURES-01.md` beside
> this document.

## 1. What this corpus establishes

This suite contains real Automerge changes and save images for shared sections, with human-authored semantic assertions and generated normalized expected states. It covers stable node identity, nested content, placement slots, concurrent moves, cycles, deletion/restore, collaborative text, snapshot continuation and invalid application states.

The corpus is generated and replayed with **@automerge/automerge 3.5.0**, the version `package.json` pins for this repository and the one sdk-ts uses; the Rust `automerge` 0.12.0 is its core. The generator records the version it ran with in `engine.version`.

All cases pass reference replay, reverse-order delivery with duplicate changes, save/load and snapshot-plus-tail checks (for the two long histories SS55 and SS56, the reverse and snapshot-plus-tail replays run only when the `CI` environment variable is set, as on GitHub Actions), and the suite regenerates byte-for-byte (`scripts/check-shared-sections-corpus.mjs`, run by `scripts/validate.sh`). The reference generator and verifier share a model inspector; this is not an independent correctness proof. Explicit semantic assertions prevent the output from being accepted solely because the generator produced it.

No production SDK, Rust implementation, server, signed/encrypted LFCP exchange or Obsidian installation was exercised. This corpus prepares their conformance inputs.

## 2. Files and entry points

| File | Purpose |
| --- | --- |
| `SHARED-SECTIONS-TEST-VECTORS-01.json` | 28 cases, real bytes, hashes, causal metadata and expected results |
| `generator/generate-vectors.mjs` | Deterministic corpus construction with explicit semantic assertions |
| `generator/section-model.mjs` | Reference schema helpers, tree derivation and per-node isolation (§14.2) |
| `generator/admission.mjs` | Reference admission (§14.1): rules A1–A5 and the readiness rule, per change against its causal history |
| `generator/verify-vectors.mjs` | Stored-byte replay, integrity checks and the optional independent-adapter interface |
| `schemas/section-vectors.schema.json` | JSON schema of the suite |
| `scripts/check-shared-sections-corpus.mjs` (repository root) | Schema, byte-for-byte regeneration and reference replay, in `validate.sh` |

## 3. Test identities and reproducibility

Resource bytes and Principal input bytes are SHA-256-derived deterministic fixture values. Actor IDs use the domain-separated derivation from the section profile. UUIDv7-shaped IDs are deterministically generated from labels with the required version/variant bits.

These fixtures do not provide signed Principal descriptors, a real Resource Genesis, invitations or key material. Treat their identities as raw application-profile inputs, not a ready-to-use secure LFCP session. Never use fixture identity generation as production identity generation.

Every authored Automerge change uses timestamp zero and a fixed message. Real change/save bytes come from Automerge, not invented hexadecimal. IDs are identities, not ordering clocks.

The generator records SHA-256 of the exact stored byte arrays separately from Automerge change hashes. Those are different identifiers and must not be substituted for one another.

## 4. JSON structure

Each case contains:

| Field | Meaning |
| --- | --- |
| id / title / coverage / notes | Stable case identity and evidence limits |
| base_snapshot | Complete reference save image before branches |
| base_changes | Actual history corresponding to that base |
| branches.A / branches.B | Changes authored independently from the shared base |
| after_merge | Optional resolution or follow-up by actor C |
| assertions | Human-authored required semantics |
| expected | Normalized reference state and diagnostics |
| expected_heads | Automerge heads after all changes |
| reference_snapshot | Full resulting reference save image |
| reference_snapshot_plaintext | Deterministic CBOR application Snapshot framing |

Byte records contain Base64, byte length and SHA-256. Change records additionally include the decoded Automerge hash, actor, sequence and dependencies, plus the application plaintext framing. A crafted Data Unit (SS42–SS46) also names its `signer`, the fixture Principal that signs it; otherwise the change's own actor signs it.

Schema files describe the JSON containers. The verifier additionally checks byte hashes, canonical framing, causal replay and semantic expectations. JSON-schema validity alone is not profile conformance.

## 5. What is exact and what is behavioral

| Comparison | Rule |
| --- | --- |
| Bytes supplied in this corpus | Verify their exact length/hash; they are fixed fixtures |
| Regeneration using the pinned generator and engine | Require byte-for-byte identical suite JSON |
| Deterministic CBOR [1, byte-string] framing | Exact byte-level check |
| Receiving a published Automerge change/save | Must load/apply valid supplied bytes correctly |
| Independently authoring equivalent logical state | Behavioral equivalence; identical save bytes are not generally required |
| Tree order, identities, text, retained state, conflicts | Compare specified normalized expectations |
| Internal diagnostic message strings in expected.errors | Reference debugging details, not a portable error-message contract |

The application framing is plaintext inside the LFCP security envelope. This suite does not replace Wire vectors for signatures, encryption, epochs, revocation or authorization.

## 6. Case catalog

| ID | Scenario | Required observation |
| --- | --- | --- |
| SS01 | Initial Task, child paragraph and sibling items | Correct schema, stable IDs and visible tree |
| SS02 | Concurrent sibling inserts | Both insertions survive in one converged list order |
| SS03 | Completion versus child-text edit | Both independent changes survive |
| SS04 | Concurrent moves to different parents | Placement conflict; no duplicated normal node |
| SS05 | Opposing moves form a cycle | Cycle members blocked; no arbitrary winner |
| SS06 | Delete parent versus edit child | Hidden subtree retains the concurrent edit |
| SS07 | Move child out versus delete parent | Child remains visible in its new location |
| SS08 | Delete versus explicit restore | Lifecycle conflict, including a fresh same-value restore |
| SS09 | Repeated moves | One identity, retained historical ordering slots |
| SS10 | Local detach | Empty shared delta; adapter action itself is not executed here |
| SS11 | Field edit from another projection | Same Task changes; child text is untouched |
| SS12 | Snapshot and later changes | Checkpoint plus tail equals full replay |
| SS13 | Mutate immutable placement parent | Refused at admission: `IMMUTABLE_FIELD_MUTATED` (A3) |
| SS14 | Concurrent Cyrillic/emoji text edits | Correct Unicode index conversion and converged text |
| SS15 | Resolve placement conflict | One selected location after causal resolution |
| SS16 | Split a paragraph | Original retains prefix identity; suffix gets a new node |
| SS17 | Join paragraphs | Target text updated; source text retained under tombstone |
| SS18 | Unknown extension | Preserved through unrelated edits and snapshots |
| SS19 | Duplicate a placement-list entry | Refused at admission: `PLACEMENT_NOT_ATOMIC` (A2) |
| SS20 | Replace Text with scalar | Refused at admission: `CONTAINER_REPLACED` (A4) |
| SS21 | Remove a historical slot | Refused at admission: `CHILDREN_LIST_MUTATED` (A1) |
| SS22 | Concurrent moves to the same parent | Distinct placement intents still conflict |
| SS23 | Large section | Exactly 200 Tasks, 200 paragraphs and two ordinary items |
| SS24 | Add child under concurrently deleted parent | Child retained and discoverable |
| SS25 | Restore parent with independently deleted child | Child remains hidden |
| SS26 | Resolve parent cycle | Valid tree after explicit placement resolution |
| SS27 | Resolve lifecycle conflict to active | Conflict removed through a fresh causal assignment |
| SS28 | Continue actor from a full snapshot | Actor sequence continues safely |
| SS29 | Import in three changes, ready last | Projected once ready is written (§12.1) |
| SS30 | Import without ready | `IMPORTING`, nothing projected |
| SS31 | Ready written by another actor | Refused: `IMMUTABLE_FIELD_MUTATED`; still `IMPORTING` |
| SS32 | Ready deleted | Refused: `IMMUTABLE_FIELD_MUTATED` |
| SS33 | Placement created but not inserted | Refused: `PLACEMENT_NOT_ATOMIC` (A2) |
| SS34 | Node kind changed | Refused: `IMMUTABLE_FIELD_MUTATED` (A3) |
| SS35 | Node children list replaced | Refused: `CONTAINER_REPLACED` (A4) |
| SS36 | Task title written as Text | Refused: `INVALID_FIELD_TYPE` (A5) |
| SS37 | A change depending on a refused change | Refused change plus one held dependent |
| SS38 | Task node whose Task is missing | Node `INVALID_REFERENCE`, child `BLOCKED_PARENT`, rest projected (§14.2) |
| SS39 | Item placed under a paragraph | Node `INVALID_REFERENCE`, rest projected |
| SS40 | 20,000-character insertion in three runs | Within the Text budget (§12.3, §16.2) |
| SS41 | 16,385 characters in one change | Refused: `INVALID_AUTOMERGE_BYTES` (SOP §11.1) |
| SS42 | A's change signed by B | Refused: `CHANGE_ACTOR_MISMATCH` (SOP §8, §11) |
| SS43 | A change skipping a sequence number | Refused: `INVALID_AUTOMERGE_BYTES` (SOP §14.1) |
| SS44 | A compressed change chunk | Refused: `INVALID_AUTOMERGE_BYTES` (SOP §11) |
| SS45 | A change whose checksum is wrong | Refused: `INVALID_AUTOMERGE_BYTES` (SOP §11) |
| SS46 | A change nesting an object 257 levels deep | Refused: `INVALID_AUTOMERGE_BYTES` (SOP §11.2) |
| SS47 | Concurrent splits of one paragraph | `VALID`: both new nodes kept; the prefix keeps the union of the deletions (§10) |
| SS48 | A split and a concurrent edit of the suffix | `VALID`: the edit stays in the original node (§10) |
| SS49 | A join and a concurrent edit of the second paragraph | The edit is retained under the tombstone: `EDIT_UNDER_DELETED_ANCESTOR` (§10) |
| SS50 | Concurrent joins of the same pair | `VALID`: the text appears twice; equal deletions are no lifecycle conflict (§14.3) |
| SS51 | A split and a concurrent join | `VALID`: both apply |
| SS52 | Two writers create one node ID | `STRUCTURAL_ATTENTION`: `OBJECT_ID_COLLISION`, the node is not projected (§14.2) |
| SS53 | Two writers create one Task ID, one with a child | The node is not projected, its child is `BLOCKED_PARENT` (§14.2) |
| SS54 | Two nodes claim one PlacementId | Neither node is projected (§14.2) |
| SS55 | 63 changes of 8,192 Text operations on one paragraph | `VALID`; 258,162 operation rows: the Snapshot is within the floor (SOP §13.1) |
| SS56 | 64 such changes | `VALID` from the units; 262,258 rows: a receiver with floor limits rejects the Snapshot (`INVALID_AUTOMERGE_BYTES`) |

SS14 is generated by two Automerge JS writers. It is suitable as a Rust consumer input but is not evidence of a Rust run. SS23 checks model load/state, not editor latency or a supported server payload limit.

## 7. Same-value lifecycle assignment clarification

Automerge JS 3.5.0 suppresses assignment of an already visible scalar value. Thus an explicit restore on an observed active object can disappear if implemented as a plain same-value set.

The profile now requires explicit lifecycle intents to produce fresh causal assignments. The reference helper writes the other valid lifecycle value and then the requested value in one atomic change where needed. SS08 and SS27 verify the consequence. This does not authorize automatic lifecycle rewrites on every render.

The clarification is incorporated into SHARED-SECTIONS-PROFILE-01, §9. A different binding may use a direct low-level fresh assignment if it produces the same semantics.

## 8. Run the reference checks

From the repository root, after `pnpm install --frozen-lockfile`:

    node scripts/check-shared-sections-corpus.mjs

Regenerate deliberately:

    node test-vectors/shared-sections-01/generator/generate-vectors.mjs

Inspect resulting diffs before accepting a new corpus. Do not regenerate expected values merely to make a broken implementation pass.

## 9. Independent implementation adapter

The optional JavaScript adapter module exports:

    async function runCase(input) { /* return normalized state */ }

Invoke it with:

    node test-vectors/shared-sections-01/generator/verify-vectors.mjs <directory holding the suite> --adapter /absolute/path/adapter.mjs

The runner supplies IDs, base bytes, branch changes and after-merge changes, but not expected results. A Rust harness may be invoked from this adapter or consume the JSON directly.

Return classification, tree, hidden IDs, invalid nodes with their diagnostic, recovery entries, the colliding IDs (`collisions`, present only when there are some), the Snapshot counts of SHARED-OBJECTS-PROFILE-01 §13.1 (`snapshot`: operation rows, the sum of the group columns (operations' successors and changes' dependencies) and whether both are within the floor; present only in SS55 and SS56), retainedConcurrentEdits, scalarConflicts, texts, tasks, slotCount, nodeCount, type checks, and the changes refused at admission (`refused`, with their diagnostic) and held behind them (`held`), in the JSON's normalized form. The reference verifier compares these fields; low-level expected.errors strings are excluded from the external-adapter comparison.

For negative cases, accepting bytes into Automerge is not acceptance by the LFCP profile. A change the profile refuses at admission (§14.1) never enters the document; the implementation reports it with its diagnostic and holds the changes that depend on it.

## 10. Coverage limits and next gates

The included inspector is reference test support, not a hardened SDK validator. Its checks target these cases. Independent implementation must still enforce the complete normative schema, immutable authorship fields, access checks and all relevant historical mutations.

Before freezing implementation tasks or claiming conformance:

1. Run actual sdk-ts and sdk-rs against the supplied corpus and each other's changes.
2. Run the secure Wire path, persistence/restart and real editor acceptance tests.

This corpus is the first reproducible test baseline for those steps, not completion of all MVP 0.2 release gates.
