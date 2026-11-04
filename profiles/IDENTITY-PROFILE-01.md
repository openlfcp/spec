# IDENTITY-PROFILE-01

**Title:** OpenLFCP Identity Resource Data Profile and device flows  
**Status:** Working Draft 0.1 for MVP 0.4; decisions of ADR 0011 (I1 to I6) applied; not in any implementation baseline yet (the baseline `mvp-0.4-baseline.1` follows with the identity corpora, task LFCP-04-403)  
**Date:** 2026-11-03  
**Profile identifier:** `org.openlfcp.identity.v1`  
**Dependencies:** LFCP-WIRE-01 with §7.2, §7.3, §17.4, §17.5, §80.1 and §100.1 (this repository, same revision); SHARED-OBJECTS-PROFILE-01 §§7–14 and §18 at `mvp-0.2-baseline.12`; ADR 0011  
**Companions:** `LFCP-IDENTITY-TEST-VECTORS-01` (wire identity vectors), `IDENTITY-PROFILE-TEST-VECTORS-01` (profile corpus) and `IDENTITY-FLOW-FIXTURES-01` (flow fixtures), to be published with LFCP-04-403 (§12)

> This document defines the Identity Resource, the Data Profile in which a human keeps the list of their devices and the roster of their Resources, and the client flows that use the device records of LFCP-WIRE-01: pairing a new installation, reaching every Resource of the human, reconciliation, invitations accepted by a device, Resources created from a device, revocation with key rotation, and the durable multi-record operations behind them. Nothing in this document confers authority: every authority decision is made by a Resource's own Control Chain under LFCP-WIRE-01 §80.1.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as in BCP 14 (LFCP-WIRE-01 §2). Text marked *Informative* is not normative. `W` cites `wire/LFCP-WIRE-01.md`; `SOP` cites `profiles/SHARED-OBJECTS-PROFILE-01.md`.

---

## 1. Contract and boundaries

An **Identity Resource** `I` is an ordinary Resource whose Genesis owner is a Root Identity `R` (W §7.2) and whose Data Profile is `org.openlfcp.identity.v1`. It is hosted on the human's default server, with its own DEK and epochs, Key Packages and Snapshots; servers do not recognise it. Its Control Chain carries the human's device records (W §17.4, §17.5): personal devices are registered there, service devices are **bound** there (their chains recorded, no authority, W §17.4 rule 8), and pairing devices are registered there for one session. That chain is the list that managing devices propagate to the human's other Resources (§7). One Identity Resource per root.

This profile defines:

- the document of the Identity Resource, its admission and state rules (§§2–4);
- the pairing link, the device fingerprint, and the two-phase pairing flow (§5);
- how a new device reaches every Resource of the human, and what it shows while it cannot (§6);
- reconciliation of device records and keys between the Identity Resource and every other Resource; invitations accepted by a device; Resources created from a device (§7);
- revocation of a device, the rotation policy, and what a revoked device shows (§8);
- the durable phases and states that make the multi-record operations above crash-safe and deterministic (§9);
- display rules for authorship, assignees, access lists and service devices (§10);
- compatibility and rollout (§11); the test corpora (§12).

It does not define (W §108.1): a root key kept off every device, root rotation, recovery after the loss of all devices, a per-device data cutoff without key rotation, passkeys, multi-owner governance, human-readable discovery.

Terms (root, device, kind, mask, scope, managing device, owner-acting device, bound, registered, active, suspended, exposing revocation, `holds`, `ownerAction`, `actsFor`, `rootOf`, `sameRoot`) are those of W §7.2, §17.5 and §80.1. `A` names the approving or managing installation of a flow, `B` the new installation, `J` a pairing device, `X` a Resource of the roster, `D_B` the Principal of `B`.

---

## 2. Document

The Data Plane of the Identity Resource follows SOP §§7–14 (Automerge 3.5.0 / automerge 0.12, one change per transaction, framing, expansion and depth limits, canonical change encoding, operation references, Snapshot equivalence and rebuilds) and SOP §18 for `extensions`. SOP §§15–17 do **not** apply: this profile has its own root keys and no `objects`. The Automerge actor of a writer is the one of SOP §8 unchanged, with its label `OPENLFCP-SHARED-OBJECTS-ACTOR-v1` and the Identity Resource's ID: this profile declares no actor domain of its own.

### 2.1 Structure

```text
root
├── profile      scalar string "org.openlfcp.identity.v1"; written by the initial change; immutable
├── identity     map { root: PrincipalRef }; written by the initial change; immutable
├── roster       map<ResourceRef, RosterEntry>
├── devices      map<PrincipalRef, DeviceEntry>       ; display metadata and key hints, never authority
├── requests     map<PrincipalRef, PairingRequest>    ; pending pairing requests
└── extensions   map<namespace, any>                  ; SOP §18

RosterEntry = {
  profile:      scalar string,               required; the Resource's data_profile
  endpoints:    list<scalar string>,         required, may be empty; route hints (W §89)
  coordinator:  scalar string,               required; last known coordinator URL, non-authoritative
  name?:        scalar string,
  archived?:    scalar bool
}
DeviceEntry = {
  label:        scalar string,               required
  kind:         0 / 1,                       required (pairing devices have no entry)
  platform?:    scalar string,
  added_at?:    timestamp,
  revoked?:     scalar bool,                 display only
  missing_keys?: map<ResourceRef, list<uint>> ; hint: epochs this device lacks the DEK of (§7.1), written only by the device itself (§3 AI5)
}
PairingRequest = {
  descriptor:   scalar string,               required; base64url of the deterministic CBOR principal-descriptor (W §7)
  pairing:      PrincipalRef,                required; the pairing device that wrote the request
  label:        scalar string,               required
  kind:         0 / 1,                       required; the requested kind
  scope?:       list<ResourceRef>,           required for kind 1 (1–64 entries, no repeats), absent for kind 0
  platform?:    scalar string,
  requested_at?: timestamp
}
ResourceRef  = unpadded base64url of the 32-byte Resource ID (43 characters)
PrincipalRef = "p:" + unpadded base64url of the 32-byte Principal ID            (SOP §27)
timestamp    = RFC 3339 UTC, the grammar of SOP §28
```

Every value is an Automerge scalar (`ImmutableString`, boolean, uint) or a map or list of such; collaborative Text is never used.

### 2.2 The initial change

The **initial change** of the document is the change that has no dependencies. It is identified by immutable facts of the change and of the Data Unit that carries it: it is authored by the Automerge actor of the Genesis owner (the root, SOP §8), it is that actor's change with Automerge sequence number `1`, its dependency list is empty, **and it is carried by the root's Data Unit with actor sequence `1`** (W §8). A change without dependencies that fails any of these conditions is refused at admission (§3, AI0), in whichever unit, epoch or order it arrives; a change whose bytes are malformed keeps its earlier diagnostic (SOP §11). It MUST create exactly the six root keys of §2.1: `profile` and `identity.root` with their final values, and `roster`, `devices`, `requests` and `extensions` as **empty** maps. Every other content, the roster and the device entries of a migrated installation included (§5.1), is written by later changes that depend on it.

A document therefore has exactly one accepted initial change:

- the eligibility check of AI0 runs when the change's bytes and its carrying unit are known, **before** the taken-`(actor, sequence)` hold of SOP §14.1: a change without dependencies in any Data Unit other than the root's actor sequence `1` is `INVALID_ROOT`, never held, so a different hash cannot become the initial change by arriving, or being decrypted, first;
- the root's Data Unit with actor sequence `1` is one unit (W §8, §26.2: a second unit at that sequence is equivocation and both are excluded), so its change is the only candidate. A change without dependencies that is not its actor's Automerge sequence `1` is refused by SOP §11.4 (R1) as `INVALID_AUTOMERGE_BYTES`;
- the writer persists the initial unit as exact bytes before sending it (§9.1) and retries those bytes; it never creates a second initial change in a later unit. A root whose actor sequence `1` unit is lost cannot initialise this Identity Resource and creates a new one (§5.1).

Delivery order and epochs therefore do not matter: a dependent change that arrives first waits for the initial change (SOP §14.1); a replica whose unit at actor sequence `1` is in `KEY_BLOCKED` (W §65) holds the whole document until it opens. A replica that loads the document from a Snapshot (SOP §14) takes the Snapshot's change without dependencies as the initial change only after it holds and has verified the root's Data Unit with actor sequence `1` and found that change in it; until then it fetches that unit and does not use the Snapshot's state.

### 2.3 Writer classes

Admission (§3) takes, besides the change bytes and the signer's actor, the signer's **class at the Data Unit's `control_ref`**, derived from the Identity Resource's own Control state (W §79): `root` (the signer is the Genesis owner), `personal` (bound with kind `0`), `pairing` (bound with kind `2`), `other` (anything else, a service device included, which is never registered in `I`). This is an input the SDK computes from the chain it has already validated, like the actor binding of SOP §8; it is deterministic (W §7.2, N3). The class is taken at `control_ref`, never at the current head, so the decision does not change when the pairing device is later revoked.

### 2.4 Reserved root keys

`recovery` and `succession` are reserved for recovery material pointers and root rotation state (W §108.1). A writer of this version MUST NOT create them; a reader preserves them. Admission has no rule for them: a change that is not the initial change and creates or writes them is admitted when §3 otherwise admits it, and the value is preserved as unknown data and never interpreted (the initial change that creates them is `INVALID_ROOT`, AI0). Unknown keys under the root, and unknown fields in entries, are preserved and ignored (SOP §17, §18 spirit).

---

## 3. Admission

As SHARED-SECTIONS-PROFILE-01 §14.1: when a change arrives, the checks of its bytes alone (SOP §11, §11.1, §11.3 and `CHANGE_ACTOR_MISMATCH`); once every dependency is present, SOP §11.2, §11.4 and the sequence checks of SOP §14.1 (a change at a taken `(actor, seq)` is held, §2.2); then these rules, decided from the change's operations, the objects they write into (in the change's causal history) and the writer class (§2.3):

| Rule | The change … | Diagnostic |
|---|---|---|
| AI0 | has no dependencies and is not authored by the root's actor, is not that actor's Automerge sequence `1`, or is not carried by the root's Data Unit with actor sequence `1` (§2.2; checked before the sequence hold of SOP §14.1); or has no dependencies and does not create exactly the six root keys of §2.1, with `profile` and `identity.root` set and the four containers empty | `INVALID_ROOT` |
| AI1 | writes or deletes `profile` or anything under `identity`, and is not the initial change | `IMMUTABLE_FIELD_MUTATED` |
| AI2 | replaces or deletes `roster`, `devices`, `requests` or `extensions`, or replaces an entry map or an entry's list with a scalar | `CONTAINER_REPLACED` |
| AI3 | creates collaborative Text anywhere, or writes a value that is not a scalar, map or list of scalars where this profile defines a field | `INVALID_FIELD_TYPE` |
| AI4 | is signed by a writer `J` of class `pairing` or `other`, and contains any operation that is not the creation of, or a write into, **one** entry `requests[k]` that `J` owns; or deletes anything; or replaces an entry map. `J` owns `requests[k]` when, in the change's causal history, `k` is absent from `requests` (the change creates the map and sets `pairing` to `J`'s `PrincipalRef`), or `requests[k]` is a map that a change of `J` created and whose `pairing` is unambiguously `J`'s `PrincipalRef` (one value, no conflict). After the change `pairing` equals `J`'s `PrincipalRef` as before; the ownership test on the history before the change is what refuses a takeover of another writer's entry, whether or not `pairing` is rewritten | `UNAUTHORIZED_WRITER` |
| AI5 | creates, writes, deletes or writes into `devices[k].missing_keys`, or anything inside it, and is not signed by the Principal whose `PrincipalRef` is `k` (decision I8: the hint is written only by the device itself; the root counts as the device of its own entry `devices[p:<R>]`). A `missing_keys` written into an entry map that the change creates counts; deleting the entry `devices[k]`, or replacing it with a map without `missing_keys`, is not a write of `missing_keys`. AI5 admits nothing that AI4 refuses | `UNAUTHORIZED_WRITER` |

For AI5, an entry map is any map created as a value of `devices[k]` in the change's causal history or earlier in the change, including conflicting values that the engine does not select and maps that have since been replaced or deleted. Creating, writing or deleting its `missing_keys` field, or writing into or deleting from any object created under that field at any depth, is subject to AI5 even when that map or object is no longer visible. Object membership is determined from the operations that created the objects, not from the engine's current projection. This does not restrict writes to other fields of the entry or change the exception for deleting or replacing the entry itself.

Two writers that create `requests[k]` concurrently, neither having seen the other's entry, each pass AI4; the merged entry then holds two concurrent maps under one key and is a **conflicted request**: invalid under §4 rule 2, never approved, neither map chosen. A change that breaks a rule is `PROFILE_INVALID` with that diagnostic, is not merged, and blocks its dependants (SOP §14.1). When several apply, the first in the order `INVALID_AUTOMERGE_BYTES`, `CHANGE_ACTOR_MISMATCH`, `INVALID_ROOT`, `CONTAINER_REPLACED`, `IMMUTABLE_FIELD_MUTATED`, `UNAUTHORIZED_WRITER` (AI4 and AI5), `INVALID_FIELD_TYPE` is reported. AI4 is what makes "nothing a pairing device writes is trusted outside its own request" an algorithm: such a change never reaches the engine, so a pairing device cannot delete or archive roster entries, relabel devices or touch another request. AI5 makes `missing_keys` a statement of its device alone: no other writer, a managing device or the root included, adds epochs to another device's hint or clears it. When the device and another writer write `devices[k].missing_keys` concurrently, each change is decided by itself: the device's is admitted, the other is `PROFILE_INVALID` (`UNAUTHORIZED_WRITER`) and blocks its dependants, so no admitted document holds values of one `missing_keys` from two writers. §4 rule 2 still reads concurrent values in a merged state as their union.

*Informative.* A change by the root or a personal device that depends on a pairing device's change is excluded together with it if that change is later excluded (an equivocation of the pairing device, W §26.2, SOP §14.1); nothing of authority is lost, and the display data it carried is rewritten by reconciliation (§7.1).

---

## 4. State validation (per entry, on the merged document)

| Diagnostic | Meaning |
|---|---|
| `INVALID_ROOT` | `profile` differs; a root container is missing or not a map; `identity.root` is not the `PrincipalRef` of the Genesis owner |
| `MISSING_REQUIRED_FIELD` | a required entry field is absent (`scope` counts as required for `kind = 1`) |
| `INVALID_FIELD_TYPE` | a field has the wrong type; `scope` present for `kind = 0`, empty, longer than 64 or with a repeat |
| `INVALID_RESOURCE_REF` | a `roster` key, `missing_keys` key or `scope` element is not 43 unpadded base64url characters decoding to 32 bytes |
| `INVALID_PRINCIPAL_REF` | a `devices` or `requests` key, `identity.root` or `pairing` is not `p:` + 43 characters decoding to 32 bytes |
| `INVALID_DESCRIPTOR` | `descriptor` is not the deterministic CBOR of a valid W §7 descriptor, or its ID is not the entry's key |
| `INVALID_ENUM_VALUE` | `kind` is not `0` or `1` |
| `INVALID_TIMESTAMP` | `added_at` or `requested_at` is not RFC 3339 UTC |
| `INVALID_EXTENSION_NAMESPACE` | an `extensions` key does not match SOP §18 |

Rules:

1. Validation is per entry. An invalid `roster`, `devices` or `requests` entry is ignored by readers (never shown, never reconciled, never approved); the rest of the document stays usable (SOP §77). An invalid root is `INVALID_ROOT` and the document is unusable.
2. A field with concurrent values (SOP §45: distinct values only) is valid only if every value is valid. For `requests` a conflicted field makes the entry invalid, an unknown field included, and so do two concurrent maps under one key. For `roster` and `devices`, `endpoints`, `coordinator`, `name`, `label`, `platform`, `revoked` and `archived` are display or hint fields and a reader MAY show any value; `missing_keys` is read as the union of its concurrent values; a `kind` conflict makes the entry invalid. An entry that a conflict makes invalid reports the diagnostic of its first invalid value in table order, and `INVALID_FIELD_TYPE` when every concurrent value is valid by itself.
3. Unknown keys under the root, and unknown fields in entries, are preserved and otherwise ignored (rule 2 still applies to a conflicted unknown field of a request).
4. The diagnostics above are profile-level codes reported to the application (SOP §74.1 model), not wire codes. When one value breaks several rules, the first in table order is reported.
5. Nothing in the document confers authority (W §7.2, N7). `devices` entries are metadata; authority in any Resource, the Identity Resource included, comes from that Resource's Control Chain, and the certificates of service devices are read from `I`'s Control state, never from the document. On disagreement the chain is right.
6. Deleting a `roster` entry or setting `archived` never revokes anything.
7. Secrets (DEKs, private keys, pairing secrets) MUST NOT be written into the document.

*Informative.* Tens of Resources and a handful of devices: a few kilobytes. Snapshots follow SOP §13.

---

## 5. Pairing a new installation

### 5.1 Creating the identity: migrating an existing installation

Precondition: an installation with Principal `P`, member or owner of Resources `X_1..X_n`. `P` is a root without devices (W §7.2, N1). Nothing is committed anywhere until the human adds a device. On the first "Add my other device…":

1. The client checks that its default server's `READY` lists `identity-01` (W §37); otherwise it stops with "this server does not support devices yet" (§6).
2. It creates the Identity Resource `I`: Genesis with owner `P` (no field `5`), profile `org.openlfcp.identity.v1`, routes and coordinator = the default server; `RESOURCE_HOST`; then two changes: the initial change of §2.2 (six root keys, four empty containers), and a second change, depending on it, that fills `roster` from the local Resource list and writes `devices[p:<P>] = {label: <this installation>, kind: 0}`.
3. It records `I`'s ID locally as the installation's identity (W §86).

`P` keeps writing as itself in every Resource (N6). Existing Resources change only when a device is registered in them (§5.3 step 10). Migration is zero-cost for humans who never add a device.

### 5.2 Pairing link and fingerprint

A pairing link carries the keys of a **pairing device** `J` (kind `2`) that a managing installation registered in the Identity Resource `I` (§5.3):

```text
lfcp://pair/<identity-resource-b64url>?endpoint=<escaped-wss-url>&device=<pairing-device-id-b64url>#secret=<secret-b64url>
```

`device` is `J`'s Principal ID; `secret` is the W §18.2 `invite-secret` structure holding `J`'s Ed25519 seed and X25519 private key (the codec is reused; `J` is not an Invitation Principal in the W §18 sense: no grant, no claim). W §18.2 rules apply: percent-encoding, several `endpoint` parameters, unknown query parameters ignored, the fragment never logged, stored in history or sent to a server. A receiver of invitation URIs that does not implement pairing rejects the link as not starting with `lfcp://join/`, and a pairing parser rejects a `lfcp://join/` link. The receiving client MUST recompute `J`'s descriptor from the secret, verify that its ID equals `device`, open `I` as `J`, verify that `I`'s Genesis profile is `org.openlfcp.identity.v1`, and verify that `J` is a registered, active kind-2 device of `I`'s owner in `I`'s chain, before using the secret for anything else. A link that fails any of these checks is **rejected**: a client-local outcome with no wire code (W §62), reported to the human, after which the client makes no further use of the link: it writes no request and sends nothing more as `J`. The corpora of §12 name this outcome `PAIRING_LINK_REJECTED`, a test convention like the profile diagnostics of §4 rule 4, never sent on the wire.

The **device fingerprint** shown to humans during pairing is derived identically by every client:

```text
fp = base32-lower-nopad( SHA-256( ASCII("LFCP-DEVICE-FP-v1") || principal_id )[0..10] )
```

rendered as four groups of four characters separated by `-` (16 characters, 80 bits; RFC 4648 base32 alphabet in lower case, no padding). It is computed from the descriptor in the request after §4 has checked that the descriptor's ID equals the request key. A display convention of this profile, not a wire object.

### 5.3 The flow

Roles: `A` = an installation that is the root `R` or an active managing device of `R` (`12` in its mask, hence `1` and `2` by W §7.3 rule 4, and a chain of at most three certificates by W §7.3 c7) and holds `I`; `B` = the new installation. Every step `A` performs needs only `12` (or being the root): pairing uses device records and same-root Key Packages (W §25.2), never Capability Grants. Transport for the link is outside the protocol (shown on screen, a file transfer, a messenger, typed); the link is a bearer secret with the W §18.2 hygiene. Every Control Plane step goes through `CONTROL_PUT` with compare-and-swap (W §47) and follows the durable phases of §9.

1. **A creates a pairing device.** `A` generates a key pair `J`, signs a certificate for `J` (kind `2`, mask `{1, 2}`, scope `[I]`, fresh serial; signer `R` or `A`'s device key) and commits `DEVICE_GRANT {0: R, 1: [cert_J(, chain_A…)]}` in `I`. Before creating the session `A` MUST hold, verified, the root's Data Unit with actor sequence `1` (the carrier of the initial change, §2.2) and the DEK of every epoch of `I`; otherwise it offers no link and reports the missing material. When the `DEVICE_GRANT` of `J` is refused by W §17.4 rule 8 (`R` already has `32` live devices in `I`), `A` offers no link and asks the human to revoke a device first (§8). On `ACK`, it seals to `J` the DEK of **every** epoch of `I` it holds (same root, W §25.2; `J` holds `data/read` through W §80.1 because `R` owns `I` and `1` is in its mask), the epoch of that unit and the current epoch among them, and makes that unit retrievable on an advertised route (re-supplying it as W §68.1 allows) before showing the link, so that `B` can verify the initial change whether it loads a Snapshot or replays the units. It journals the session (`J`, the record ID, the IDs of these packages) and shows the link of §5.2; after a crash before the link is shown, `A` completes the packages and the unit's availability from the journal before showing it, or cancels the session. A session that is not completed is cancelled with `DEVICE_REVOKE {R, J, 0}` (step 9).
2. **B receives the link.** `B` is a fresh installation with its own Principal `D_B`. `B` parses the link, recomputes `J`'s descriptor and checks it against `device`, opens `I` as `J` (allowed: `holds(J, 1)`), fetches the Control Chain, verifies `I`'s Genesis profile and that `J` is an active kind-2 device of `I`'s owner (§5.2), opens the Key Packages, validates the DEK commitments, fetches and verifies the root's Data Unit with actor sequence `1`, and loads the document (§2.2: a Snapshot's state is used only after that unit is held).
3. **B persists its candidates and writes a pairing request.** Before the request is sent, `B` persists (§9) the pairing session (`I`, `J`, its own `D_B`) and, for every Resource it may be registered in, the roster entry it read (endpoints, coordinator, profile, name): for a personal `B` every roster Resource not archived, for a service `B` the Resources its human chose from that roster, the Identity Resource `I` itself excluded (a service device is bound in `I`, never registered there). That is all `B` needs later (step 8), whatever happens to `J` or to `I`. Then, as actor `J` (`holds(J, 2)` at the head; §3 AI4 admits only this write): `requests[p:<D_B>] = {descriptor: <D_B>, pairing: p:<J>, label, kind: 0 or 1, scope (kind 1 only), platform}`. `B` shows the fingerprint of `D_B` (§5.2) and waits, subscribed to `I`'s Control and Data pushes as `J`.
4. **A validates the request and checks the future certificate.** On a live push or the next open of `I`: the entry passes §4, the `pairing` field names a kind-2 device `J` that is active and that `A`'s own session journal knows, and the Data Unit that wrote the entry was signed by that `J` (the client knows each change's signer). An entry that fails any of this is ignored. `A` shows label, platform, kind, the fingerprint computed from `descriptor`, and the preset choice (§5.4); for kind `1` the requested scope, from which `A` MAY remove Resources and MUST NOT add any, and from which `A` MUST remove `I` if present: a service scope never lists the Identity Resource. The human compares the fingerprint with `B`'s screen.

   Before anything is committed, and for every preset it offers, `A` MUST build the **complete future certificate chain** for `B` (`[cert_B]` or `[cert_B, chain_A…]`, with the leaf's payload fully determined: root, descriptor, kind, mask, scope, a fresh serial; the leaf unsigned) and check it as W §7.3 verification steps 1 and 4 and W §17.4 rules 4 to 6 and 8 would check the `DEVICE_GRANT` of step 6 against `I`'s current state (for rule 8 with `J` counted as revoked, as it is after step 5, so a session whose `J` fits always leaves a place for `D_B`), with the leaf's signature taken as given: structure (kind, mask and scope rules, c1, c5, c7: a Full leaf under a chain of three certificates is one certificate too many), (c3) and (c4) against `A`'s own mask, roles, bindings, revocations, and `A`'s own standing and activity. A preset whose chain fails is not offered; when `A`'s chain or mask admits no managing preset, `A` offers the non-managing presets only and says why. A service request whose scope is empty after trimming, `I` removed, is not approvable: `A` either keeps at least one Resource or rejects the request (step 9). A request the human does not confirm is rejected: `A` deletes the entry and cancels the session (step 9).

   `A` records in its approval journal (§9) the exact descriptor bytes, the request change hash, `J`, the kind, the chosen mask and scope, the fingerprint shown, **and the complete certificate payload it will sign**, with that payload's digest (W §7.3 rule 6). If the entry changes before the human confirms, the tuple differs and the confirmation is asked again.
5. **A consumes the session (phase 1).** `DEVICE_REVOKE {0: R, 1: J, 2: 3, 4: digest}` in `I`, issued by `A`. Nothing has been signed for `D_B` yet (N9): a proposal that loses the compare-and-swap carries only a digest, from which no certificate can be made. On `ACK` the session is consumed: no second `DEVICE_REVOKE` of `J` can succeed (W §17.5 rule 5), whichever manager proposes it, so **a pairing session yields at most one approved payload**. A proposer that meets `CONTROL_HEAD_MISMATCH` synchronises, re-runs the check of step 4 on the new head (its own authority may have changed), and classifies the phase as §9.2 says: `committed-own` when `revoked[(R, J)].approval` equals its own digest, `superseded` when `J` is revoked with another digest or another reason, in which case the operation ends and `A` signs nothing.
6. **A signs the certificate (phase 2)** exactly from the journaled payload and commits `DEVICE_GRANT {0: R, 1: chain_B, 2: J}` in `I`, issued by `A`. W §17.4 rule 7 accepts it only when the leaf's payload digest equals the consumed approval. If rule 8 refuses it (another binding took the last place after step 5), `A` reports it and, once a device of `R` is revoked, proposes the same chain again on the new head; the approval stays consumed and nothing else is signed. For a personal `B` this registers `B` in `I`; for a service `B` (`I` is not in its scope) it binds `B` in `I` without registering it, which is what later reconciliation reads (§7.1). On `ACK`, `A` writes `devices[p:<D_B>] = {label, kind, platform, added_at}` and deletes `requests[p:<D_B>]`.
7. **A seals I's keys to B** (kind `0` only): a Key Package of every epoch DEK of `I` it holds, recipient `D_B`, at the head after step 6 (W §25.2), and records each package it sent (§9.5).
8. **B learns its result.** `B` is subscribed as `J` until the revocation of `J` ends its pushes (W §69); from then on `J` reads only through the revoked-reader prefix (W §41), which tells `B` whether the session was consumed (reason `3`) or cancelled (reason `0`). A cancelled session is **rejected**, a final state. A consumed session is **approved**, and `B` then needs its certificate, which only a Resource's chain carries:
   - a personal `B` opens `I` as `D_B` with resumable retries (§9) until its registration appears, verifies that the leaf names its own descriptor and that `cert_B`'s root is `I`'s owner, checks it against the approval `d` as below, persists its chain, and requests `I`'s Key Packages as `D_B`;
   - a service `B` opens each candidate Resource of step 3 as `D_B` with resumable retries until its registration appears there, and verifies the same facts from that Resource's chain.

   The **first verified certificate** `B` obtains, from any Resource, decides the rest. Only the approval proves a result: `B` takes as its result the certificate naming `D_B` whose payload digest equals the approval `d` read from the consumed record, found as the leaf of an accepted `DEVICE_GRANT` in the chain of `I` (personal) or of a candidate (service), whether that leaf is still current or was since re-certified. In each Resource `B` then uses its current leaf only when kind, mask and scope equal the result's (N8). A certificate for `D_B` with another digest proves nothing, whoever signed it: it is reported and not used. A candidate where `B` is registered but whose chain never carried a leaf with digest `d` (for example a service re-certified before its first registration anywhere) is **unproven**: `B` does not use it, keeps trying the other candidates and shows "approval not provable here"; the human may instead pair the installation again with a new session, after which a managing device revokes the old `D_B` (§8). The certificate's signed scope is the approved scope (for kind `0`, every roster Resource). A candidate absent from the scope is **not granted** (final). A candidate in the scope where `B`'s registration has not appeared yet is **pending registration**, and `B` keeps trying it (§6; §7.1 registers it eventually). Until `B` holds a certificate, no candidate's outcome is known: `B` shows "approved, waiting for registration" and keeps trying every candidate. **A timeout is never a decision**: an unreachable coordinator or an exhausted retry budget leaves the candidate **unreachable, retrying**, and the retries resume after a restart from the persisted candidates. Neither path depends on `J` after its revocation.
9. **A closes the session.** When `J` is not yet revoked (rejection, timeout, cancel): `DEVICE_REVOKE {R, J, 0}`. A consumed or cancelled `J` was a reader of `I`, so the revocation is exposing (W §17.5) and the rotation policy of §8.4 applies to `I`: `A` rotates `I` when it is the rotator of §8.1 (`7` is enough while every reader of `I` is of the root); otherwise `I` is marked `awaiting rotation` for the root or an owner-acting device. Until the rotation a leaked link together with a dishonest server lets the link holder decrypt `I`'s new units.
10. **A registers B in its Resources.** For a personal `B`: for each `X` in `roster` (not archived) whose coordinator advertises `identity-01` and where `A` is `R`, or active in `X` with `12`, or active in `X` with `13` when `R` owns `X`: `DEVICE_GRANT {0: R, 1: chain_B}` on `X`; on `ACK`, a Key Package of every epoch DEK of `X` that `A` holds, to `D_B`, at the new head, each recorded in the ledger. For a service `B`: the same for the Resources of the approved scope only. Resources `A` cannot reach are left to reconciliation (§7.1) and listed to the human.
11. **B completes.** `B` opens every Resource it is registered in, requests Key Packages (`KEY_PACKAGE_GET`, at most 256 epochs per request, W §52), synchronises Control, Snapshots and Data (W §66), and shows the per-Resource status of §6. A personal `B` MAY write `devices[p:<D_B>].missing_keys` as a hint (§7.1) once it can read and write `I`.

**Concurrency and failure.** Two installations given one link both write requests as `J`: the second sees the first's unit and writes sequence `2` (no equivocation), or they equivocate when both start from sequence `1`, in which case both units are excluded (W §26.2) and `A` sees no request. Two managers approving the same session propose two phase-1 records; one wins, the other is `superseded` and signs nothing. A late equivocating unit of `J` that arrives after approval removes the request entry from the document (both units excluded, with the dependants of SOP §14.1) but does not touch the records already in the chain; `A` keeps the approval journal, not the entry, and reconciliation rewrites the `devices` entry (§7.1). If `A` crashes after step 5, §9 resumes from the journaled payload; after step 6, it resumes steps 7 to 10; if `B` crashes, it resumes from the persisted candidates, the chain and the keys it holds, or from the link alone while `J` is still active.

**Headless installation** (bridge, bot): the same steps without UI; the request label and the requested Resources (by roster name) are command-line arguments and the fingerprint is printed. The managing device shows "<label> (service) asks to join <sections>; access: read and write".

### 5.4 Mask presets (decision I6)

| Preset | Kind | Mask | Scope | Intended for |
|---|---|---|---|---|
| Full | 0 | `{1,2,3,4,5,6,7,8,10,12,13}` | — | another desktop; manages devices, acts as owner, rotates and distributes keys; default for a desktop request |
| Edit | 0 | `{1,2,3}` | — | a phone (writes once mobile write is allowed); default for a mobile request |
| Read | 0 | `{1}` | — | a read-only installation |
| Service | 1 | `{1,2}` | the approved subset of the requested Resources | a bridge or bot |

Codes `9` and `11` are never listed. A mask is restricted by the issuer's own mask when the issuer is a device (W §7.3 c4): a Full device certified by a Full device is Full, an Edit device cannot issue at all (`12` is not in its mask), and a Full leaf needs an issuing chain of at most two certificates (c7). The feasibility check of §5.3 step 4 decides which presets are offered. Because kind, mask and scope are immutable (N8), changing a device's preset or a service device's Resources means revoking it (§8) and pairing a new Principal.

---

## 6. A new device reaching every Resource of the human

A device learns the human's Resources from the roster (§2), never from a server lookup. For each roster Resource it needs three things, checked independently: registration in that Resource's chain (W §17.4), `data/read` through its root (W §80.1), and a Key Package for each epoch it must decrypt (W §25.2). Registration and packages come from the approving device (§5.3 step 10) or from reconciliation (§7.1); the device opens the Resource as itself and synchronises as any member. It receives the whole history its root may read (every epoch DEK the sender holds), as today's members do; a Snapshot alone is a partial state and is reported as such.

Per-Resource status shown to the human, from the device's own observations only:

| Status | Condition |
|---|---|
| ready | registered, active, every epoch's DEK held |
| waiting for keys | registered and active; a DEK is missing (the device MAY write `missing_keys`, §7.1) |
| pending registration | in the approved scope (§5.3 step 8), not yet registered there; retried |
| not granted | absent from the signed scope of the device's certificate |
| approved, waiting for registration | the session was consumed and no certificate has been obtained yet from any Resource |
| rejected | the session was cancelled with reason `0` |
| unreachable, retrying | the coordinator did not answer, or the retry budget of the current run is spent; resumed after restart |
| on a server without device support | the coordinator's `READY` does not list `identity-01` (W §37); the device gets access when the server is updated and a managing device reconciles |
| access refused / revocation proven | §8.6 |

A status moves to a final one (`ready`, `not granted`, `rejected`, `revocation proven`) only on evidence from a chain or a certificate; never on elapsed time.

---

## 7. Reconciliation, invitations, Resources created from a device

### 7.1 Reconciliation

A managing installation (the root, or an active personal device with `12` in its mask) reconciles whenever it opens the Identity Resource `I` or a roster Resource `X` with Control synchronisation complete and the Resource's coordinator advertises `identity-01`. The **targets** of reconciliation are the Identity Resource itself and every roster Resource: `{I} ∪ roster`. `I` is a target without being listed in its own roster. The input is `I`'s Control state (never the document) and the target's Control state. Registration and key delivery are reconciled **independently**: an equal leaf certificate ID says nothing about packages. The order below is normative; for the target `I` itself, steps 1 and 2 are vacuous (its own chain is the source) and step 3 applies in full.

**1. Revocations first.** For every pair `(R, D)` in `I`'s `revoked` and not in `X`'s: propose `DEVICE_REVOKE {R, D, reason}` on `X` (reason `3` is propagated as `0`; the approval travels nowhere). This precedes every registration, so that a device whose issuer `I` has revoked is never registered in `X` before the cascade reaches `X`.

**2. Registrations.** From `I`'s `devices`:

- for every personal device `D` of `R` that is active in `I`, registration in `X` is needed when `devices_X[D]` is absent, when `devices_X[D].registered` is false (an intermediate-only or out-of-scope binding is not a completed registration), or when its leaf certificate ID differs from `I`'s leaf certificate ID for `D`: propose `DEVICE_GRANT` with `I`'s chain for `D`, subject to `X`'s revocations and the reconciler's authority there (W §17.4 rules 4 to 6); a proposal `X` refuses is reported, not repeated as such;
- for every kind-1 device `S` bound in `I` with a chain, whose scope lists `X`, with `(R, S)` not in `I`'s `revoked` and no issuer of its chain in it, and that is absent from `X`: propose `DEVICE_GRANT` with that chain (`X`'s own `verifyChain` decides, with its own revocations);
- for a suspended device in `X` whose `I` chain avoids the revoked issuer: propose the re-certifying `DEVICE_GRANT`.

**3. Keys.** For every device `D` active in the target whose root is `R` (service devices included; in `I`, every active personal and pairing device: every `P` with `holds(P, 1)`): for every epoch of the target whose DEK the reconciler holds and for which its own ledger (§9.5) records no sent package to `D`: seal it to `D` at the current head and record it. This is unconditional: it needs no complaint, no `data/write` and no DEK of `I` on the recipient's side, so a Read device, a device registered in `I` whose approver crashed before its first package, and a device that never received its first package in any Resource are served by the next reconciling manager. `devices[p:<D>].missing_keys` is a hint only: a reconciler that reads it also re-seals the listed epochs even when its ledger shows a sent package (the package may be lost), and the device clears its hint when the packages arrive. A human MAY clear a managing device's ledger for one device ("Re-send keys") to force a full re-send.

**4. Display data.** The reconciler restores `devices[p:<D>]` entries for devices it finds in `I`'s chain without a valid entry (labels default to the fingerprint).

Reconciliation is idempotent and conflicts only through compare-and-swap; it is the mechanism that carries revocations into Resources the revoking device could not reach, new Resources into every device, and missing keys to devices whose packages were lost. It is suspended while `I` or the target is in `CONTROL_CONFLICT` (§9.7).

### 7.2 Invitations: the human is invited, a device accepts

- **Inviting** is unchanged for the inviter (W §18, §73): a grant to an Invitation Principal, a Key Package, a `lfcp://join/…` link. The inviter does not know whether the invitee has devices.
- **Accepting** on an installation `B` that is a device `D_B` of root `R`: before submitting the claim, `B` MUST verify that it can write the roster entry in `I` (`holds(D_B, 2)` in `I`, which a Read device lacks); otherwise it leaves the invitation unclaimed and asks the human to complete it on a personal installation that can write `I` (the link is handed over as it was received), so that no accepted Resource is ever absent from the roster. Then `B` opens as the Invitation Principal, fetches the chain, opens the invitation Key Package, and submits `CAPABILITY_CLAIM` with **claimant = `R`'s descriptor** (known to `B` from `I`'s Genesis), signed by the Invitation Principal (W §18.1 rule 5). The claim creates a grant to `R` (`R` is `non-device`, W §80.1). Then `B`, as one durable operation (§9):
  1. registers itself: `DEVICE_GRANT {0: R, 1: chain_B}` issued by `D_B` (self-registration, W §17.4 rule 6; `B` holds the chain and the head because it opened as the Invitation Principal);
  2. seals the DEK of every epoch it holds to `R` (same root; `R` holds `data/read` from the claim) and records the packages;
  3. if `12` is in `B`'s mask, registers every other active personal device of `R` (chains from `I`) and seals the DEKs to each; otherwise leaves the rest to reconciliation;
  4. adds the Resource to the roster.
  When `B` is the root itself, the claim names `R` as today and steps 1 to 3 reduce to registering and keying the human's other devices, if any.
- **Presets** stay `Read` = `{data/read, invite/claim}` and `Read + write` = `{+ data/write}`; they are granted to the root and reach devices through W §80.1. `capability/grant` and `key/distribute` are not needed for a human's own devices (W §25.2).
- **Removing a human** is unchanged: the owner revokes the root's grants and rotates (W §17.3, §75); every device of that root loses standing at once (N4, W §17.5).
- A human who received an invitation on one device and wants it on another does nothing: reconciliation (§7.1) and the roster carry it over.

### 7.3 Creating a Resource from a device

A personal device with `13` in its mask creates Resources owned by its root: Genesis field `1` = `R`'s descriptor, field `5` = the device's chain, signed by the device (W §15); the server records the owner `R` as host (W §39). The creating device is registered from Genesis. As one durable operation (§9) it then: seals the epoch-0 DEK to `R` (the recipient holds `data/read` as owner) and records the package; if `12` is in its mask, registers the root's other active personal devices and seals the DEK to each (else reconciliation does); adds the roster entry. The root therefore can open the Resource even if the creating device goes offline right after creation. A device without `13` cannot create a Resource for its root; the UI offers to create it from a Full device.

---

## 8. Revoking a device (decision I4)

From a managing installation `A` (root or `12` in its mask), for device `D` with reason `r` (`0`, `1` or `2`):

### 8.1 Preview and post-state

`A` computes the state of `I` and of each reachable `X` **after** the revocation: the devices that would be suspended by the cascade (W §17.5), and whether `A` itself stays active (its own chain MUST NOT pass through `D`; a revoker whose chain passes through `D` first obtains a fresh chain from the root or from a managing device whose chain avoids `D`, by re-certification, and only then revokes; it cannot re-certify itself). For each Resource it then decides who rotates. `A` is the **rotator** of a Resource only when, in the post-state, `holds(A, 7)` **and** `A` can seal the new DEK to every reader of the new head: `holds(A, 6)`, or every reader is of `A`'s root (W §25.2). Otherwise the Resource is marked `awaiting rotation` and the rotator is the root or an owner-acting device of `R` (own Resources) or the owner (other Resources). `A` offers to re-certify the affected devices with a chain through `A` or the root, states what revocation does not do (W §98.1), and names the rotator of each Resource.

### 8.2 Identity Resource

`DEVICE_REVOKE {0: R, 1: D, 2: r}` on `I`, then, when `A` is the rotator of `I` by §8.1 (`7` alone suffices while every reader of `I` is of the root), `KEY_EPOCH` on `I` (reason `2`; final frontier per §8.3), then Key Packages of the new DEK to **every Principal `P` with `holds(P, 1)` at the new head** (W §19, §25.2): the root, every remaining active personal device, every still-active pairing device of an open session (its request continues with the new key), and any other reader `I`'s chain admits; the revoked device, a consumed or cancelled pairing device and suspended devices receive nothing. The same reader-set rule governs key delivery by reconciliation (§7.1 step 3); no assumption that every reader of `I` is a personal device, or of one root, replaces the rotator test of §8.1. `devices[p:<D>].revoked = true` for display. A self-retiring device (`D = A`, reason `0`) commits the `DEVICE_REVOKE` only; rotation is left to another installation.

### 8.3 Frontier

The final frontier of a `KEY_EPOCH` is computed from the revoker's locally verified accepted set after a Control and Data synchronisation of that Resource, as W §19 requires: a server's Have Vector is a fetch hint; a sequence the revoker could not fetch and verify stays outside the frontier; units covered by a verified Snapshot count as accepted (W §29.3).

### 8.4 Each roster Resource and the rotation policy (decision I6, automatic)

For each roster Resource `X` where `A` may act: `DEVICE_REVOKE` on `X`, then the rotation when `A` is the rotator by §8.1, else the `awaiting rotation` mark.

**Rotation policy.** An installation that, when it validates a chain, finds an **exposing** revocation (W §17.5) committed after the current epoch's `KEY_EPOCH` (or Genesis), and that is a rotator for that Resource by the test of §8.1, rotates once (reason `2`), covering every exposing revocation since the last rotation; it then seals the new DEK to every reader. A revocation that is not exposing (one that removes no registered reader, directly or through the cascade) never triggers a rotation; a Principal without standing cannot issue one (W §17.5 rule 4). The policy runs in own Resources (root or owner-acting device) and, for Resources the human does not own, at the owner's client; the UI of `A` says who closes the window. The mark `awaiting rotation` clears when a `KEY_EPOCH` is committed at a sequence greater than the revocation's.

**Rotation of the Identity Resource after a pairing session** (§5.3 step 9) is a SHOULD for the rotator; an installation without `7` reports "rotation pending".

### 8.5 Unreachable Resources

Resources with an offline coordinator, a server without `identity-01`, or where `A` is not active are reconciled later (§7.1) and listed to the human. Revocation is a Control Plane action and needs the coordinator (W §3.5): an offline "Remove device…" is refused.

### 8.6 The revoked device

After the record is committed the server stops the device's pushes before pushing the record (W §69) and refuses its reads (W §41); its uploads are still checked by object (W §84). The device distinguishes two states: **access refused** (a `NACK(AUTHORIZATION_FAILED)` alone: shown as "This device no longer has access to this section; it may have been removed from your identity"; the local replica stays readable, unsent work is exportable, nothing is deleted) and **revocation proven** (the Control prefix through the revoking record, obtained through the revoked-reader read of W §41 when the device was a reader: shown as "This device was removed from your identity on <date of the record>"). Without such a server, or for a device that never read, the device stays in "access refused". In both states the device MUST NOT create Data Units for that Resource, and it is never re-paired under the same Principal (N5); a replacement is a new installation.

Deterministic consequence (W §19.1): Data Units of `D` with `control_ref` at or after the `DEVICE_REVOKE` are refused everywhere (`AUTHORIZATION_FAILED`); units referencing an older head are acceptable until the closing `KEY_EPOCH`, after which units beyond the recorded frontier are refused (`STALE_DATA_EPOCH`) and quarantined, and a replica that had merged such a unit rebuilds without it (W §19.1, SOP §14.1). Honest work of `D` caught beyond the frontier is re-applied by the human from another device as a new unit.

---

## 9. Durable multi-record operations

Pairing (§5), accepting an invitation (§7.2), creating a Resource (§7.3), revocation with rotation (§8) and reconciliation (§7.1) each commit several records and packages, possibly on several Resources. The following rules make them crash-safe and deterministic. A re-proposal after `CONTROL_HEAD_MISMATCH` follows W §47; a `KEY_EPOCH` is never re-proposed as it was, it is rebuilt (§9.3).

### 9.1 Phases and exact bytes

Before any record or package is sent, the client persists the operation's intent (which device, which Resources, which epochs; for a pairing approval the complete certificate payload and its digest; for a pairing request the candidates of §5.3 step 3) and the exact signed bytes of the next record. After each `ACK` it persists the committed record ID (and, for a `KEY_EPOCH`, the DEK, persisted before the record is sent). A phase is repeated only by re-sending the same exact bytes: a coordinator answers a record it already committed with the same `ACK` (W §47, §70).

### 9.2 Phase states

After a `CONTROL_HEAD_MISMATCH` or a restart the client synchronises Control and Data for the Resource and classifies each phase against the accepted chain. The states are `pending` (propose, or propose again on the new head), `committed-own` (the chain holds this installation's own record: continue with the next phase), `complete` (the phase's effect exists by someone else's hand and the phase is idempotent: skip it, continue), `superseded` (the chain makes the phase impossible: the operation ends; the client signs and registers nothing further and reports it; a same effect produced by another installation is never taken as success of this installation's intent), `awaiting rotation` and `awaiting key holder`. For each kind of phase exactly one rule below applies; the rules of one kind are evaluated in order and the first that matches decides:

| Phase | Decision, first match wins |
|---|---|
| **Consume** `J` with digest `d` (`DEVICE_REVOKE` reason `3`) | `(R, J)` not revoked: `pending`. Revoked with reason `3` and approval `= d`: `committed-own`. Anything else (reason `3` with another digest; reason `0`, `1`, `2` or unknown): `superseded`. |
| **Register or re-certify** leaf `D` with certificate `c` (`DEVICE_GRANT`) | `(R, D)` revoked, or an issuer of `c`'s chain revoked: `superseded`. `devices[D]` holds leaf certificate ID `= id(c)` (the binding exists with that chain, and `registered` agrees with `c`'s scope in this Resource: an out-of-scope service leaf is bound with `registered = false`): `committed-own` when this installation's record produced the effect, else `complete`; a matching bind-only effect is never re-proposed as a new transition. `devices[D]` holds a chain with another leaf certificate ID, and the phase is a pairing phase 2: `superseded`. Otherwise (no binding, or a binding without a chain, or re-certification): `pending`. |
| **Cancel** `J` (`DEVICE_REVOKE` reason `0` of a pairing device) | `(R, J)` not revoked: `pending`. Revoked with reason `3`: `superseded` (the session was consumed, not cancelled). Revoked with any other reason: `complete`. |
| **Revoke** `(R, D)` with reason `r` in `{0, 1, 2}` | `(R, D)` not revoked: `pending`. Revoked with reason `3`: `superseded`. Revoked with any other reason, by anyone: `complete`; the operation continues with the rotation test. |
| **Rotate** after a revocation at sequence `s` (`KEY_EPOCH`) | a `KEY_EPOCH` accepted at a sequence `> s`: `complete`. The rotator test of §8.1 fails on the current head: `awaiting rotation` (the mark stays until a `KEY_EPOCH` after `s` appears). Otherwise: `pending`, rebuilt as §9.3 says. |
| **Package** `(resource, epoch, recipient)` | never `superseded`; `complete` when the ledger (§9.5) records it, else `pending`. A recipient that is no longer a reader at the current head is skipped and the DEK rule of §9.4 applies. |

The reason of a revocation changes nothing in these rules except the distinction between `3` and the rest; a different reason recorded by another installation is `complete`, not `superseded`.

**Awaiting key holder.** A `KEY_EPOCH` is committed whose DEK this client does not hold (the rotator crashed before any package): readers hold that epoch's units in `KEY_BLOCKED` (W §65) until the rotator returns and distributes; another rotator MAY, after a bounded wait, commit the next `KEY_EPOCH` with a fresh DEK so that writing resumes, which leaves the stranded epoch's units unreadable until its holder returns. No installation ever reconstructs a DEK it does not hold.

### 9.3 Re-evaluation, not re-proposal

A `KEY_EPOCH` is always rebuilt on the current head with the current epoch number, the frontier of §8.3 and the current reader set, after the rotator test of §8.1 has passed on that head; when another writer has already closed the epoch after the revocation, the rotation is `complete`.

### 9.4 DEK hygiene

A DEK that was sealed to any Principal that is not in the reader set of the head the `KEY_EPOCH` will be committed on MUST NOT be used for that `KEY_EPOCH`; a fresh DEK is generated. A DEK generated but never sent may be reused in the rebuilt record.

### 9.5 Package ledger

A client records every Key Package it sent: `(resource, epoch, recipient, package ID)`. The ledger drives §7.1 step 3; it never infers delivery from the absence of a complaint, and a cleared ledger entry causes a re-send.

### 9.6 Takeover

A phase is executed by the installation that started the operation; another managing installation that finds the operation half done completes only what §7.1 defines (registrations, revocations, packages for DEKs it holds, display data) and what the rotation policy allows (§8.4). It never completes a phase that needs a secret it does not hold.

### 9.7 Control conflict

While `I` is in `CONTROL_CONFLICT` (W §13.2, §42), approval, reconciliation and automatic rotation that take `I`'s state as input are suspended, and no branch is treated as the device list; the same holds per Resource for `X`. An honest coordinator prevents accidental forks with compare-and-swap; a malicious one can equivocate with valid competing proposals (W §98.1), and clients detect it once both branches are known. No branch is chosen by time, order or `ACK`.

### 9.8 Journals hold no secrets

Beyond the DEK slot in the secret store, a bearer link, a pairing device's keys and a DEK never appear in journal rows, logs or diagnostics.

---

## 10. Display: authorship, assignees, access lists, service devices, mobile

- **Attribution.** `created_by` (SOP §27) and the actor of every change stay the writing device's Principal; nothing is rewritten. A reader displays the author as `rootOf(actor)` (W §80.1, computed from the Resource's own chain, including revoked devices so that history keeps its author) and the device as detail ("from <label>", from the Identity Resource label when it is the reader's own identity, else the device fingerprint). A Principal known only through a `DEVICE_REVOKE` (never bound) is displayed as itself.
- **Assignees** (SOP §42, `PrincipalRef` set; decision I6): an identity-aware writer assigns `p:<rootOf(P)>`, never a device; a reader treats `p:<D>` and `p:<R>` with `rootOf(D) = R` as the same human for display and filtering. The CRDT set is unchanged; two keys for one human are two members of the set and are merged in display only. Legacy data needs no change.
- **Access list**: one row per root, with its devices expandable; "You" for the reader's root and all its devices; "Remove access…" acts on the root (W §17.3) and "Remove device…" on a device (§8).
- **Aliases** stay local labels, keyed by root ID rather than by Principal.
- **Import readiness** (SHARED-SECTIONS-PROFILE-01 §12.1): unchanged; `ready` is written by the actor of `section.created_by`, which is the device that started the import.
- **Service devices** (decision I6): a standalone bridge or bot is a service device: its own Principal and secret store, certificate kind `1`, mask `{1,2}`, scope = the Resources its human chose at request time, as approved (§5.3). It is registered only in scoped Resources, by a managing device (W §17.4 rule 6; it cannot register itself), is bound but never registered in `I`, so it never reads the roster or the device list, and it learns its result from the scoped Resources themselves (§5.3 step 8). It cannot invite, revoke, rotate, publish Snapshots, add devices or create Resources; its edits are attributed to the human with "via <label>" as detail; it is revoked with reason `0` like any device, and widening its scope means pairing a new Principal (N8). A bridge embedded in an application needs no Principal of its own: it writes as the application's actor.
- **Mobile.** A phone paired with the Edit preset holds `data/write` and uses it only where the application allows writing; a copied installation is a new installation and is paired as a new device; keys are never copied.

---

## 11. Compatibility and rollout

- Resources without devices are byte-for-byte unchanged (W §100.1). The barrier, the client generations and the behaviour of a blocked client are defined there.
- Negotiation: a client treats a missing `identity-01` in `READY` (W §37) as "do not propose identity records here" and tells the human which Resources are affected (§6).
- Rollout order (decision I6): the specification, CDDL, corpora, this profile and ADR 0011 (tag `mvp-0.4-baseline.1`); the reference SDKs and the server (advertising `identity-01`), the public server deployed first; the herald client release, at least one release and at least two weeks before the release that pairs; the release that pairs, which warns before the first pairing that collaborators on older versions stop syncing the affected Resources until they update.
- Existing Resources change only when a device is bound in them (§5.1), by the approving device or reconciliation, only on servers with `identity-01`. Existing groups see one new row per device under a human once their client is identity-aware; no re-invitation, no re-claim, no ownership change. The public server keys every new hosting row by the Genesis owner, with or without Genesis field `5`, and keeps existing rows as recorded (W §39).
- Implementations move their `spec.lock` from `mvp-0.2-baseline.12` to `mvp-0.4-baseline.1` deliberately.
- SHARED-SECTIONS-PROFILE-01 §12.2 and ADR 0009 are reworded editorially: a Principal has exactly one writing installation (W §7.1); key material copied to a second installation is a misconfiguration; a human's other installations are other Principals tied to the human by this profile.

---

## 12. Test vectors, flow fixtures, end-to-end scenarios

### 12.1 Corpora and conventions

Three corpora, each with its own independent implementer in both reference SDKs (task LFCP-04-403):

| Corpus | File | Covers |
|---|---|---|
| Wire identity vectors | `test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.{md,json}`, generated by an extension of `generate_lfcp_test_vectors_01.py` | §12.2 ID-01 to ID-04: bytes and validation of certificates, chains, records, units, packages, Snapshots, messages |
| Identity profile corpus | `test-vectors/identity-01/IDENTITY-PROFILE-TEST-VECTORS-01.{md,json}` (Automerge reference corpus convention) | §12.2 ID-05: documents, admission, state validation, links, fingerprints |
| Flow fixtures | `test-vectors/identity-01/IDENTITY-FLOW-FIXTURES-01.json` | §12.3 state-machine and durable-operation fixtures |

All in `lfcp-vector-format/1` (`schemas/README.md`). The existing `LFCP-TEST-VECTORS-01.json` is not evidence for the new model; it changes only as `migrations/mvp-0.4-baseline.1` records. Fixtures use the existing derivation `h('LFCP-TV-' + label + '-ED25519')`, the existing `OWNER`, `BOB`, `CAROL`, `INVITE`, and new Resource IDs from the labels `LFCP-TV-IDENTITY-RESOURCE-X`, `…-Y`, `…-I` (the existing Resource is not reused: ownership moves to `BOB` at `C4` of the old chain).

**Conventions.** Every byte-exact case gives input fields, canonical CBOR hex, protected header hex, signature hex, object hex, object ID and expected result (W §106). Every validation case names its Resource, the exact ordered context records, the head it is proposed on, the expected code or `accept`, the rule that decides it, and for `accept` the post-state facts (`roles`, `devices`, `revoked`, `issuer_root`, activity, exposure) that an implementation must reproduce. Each negative case carries an assertion naming the deciding rule, and a case that violates two rules names the class and rule W §62 selects. **Every validation case is generated fresh on the head it names**: its `control_seq` and `prev_control_id` are those of that head, so that the case reaches the rule it claims to test and not chain placement first; a case meant to show an exact-byte replay says so and is the only kind that re-sends committed bytes. A transfer case after an additional record re-creates offer, accept and commit on the head after that record. `Full` below is `{1,2,3,4,5,6,7,8,10,12,13}`.

**Fixture Principals and certificates.**

| Label | Role | Certificate (root, kind, mask, scope; issuer) |
|---|---|---|
| `DAVE` | plain Principal (grant subject) | — |
| `DEV_A`, `DEV_A2` | personal devices of `OWNER` | `CERT_A`, `CERT_A2`: Full, `[]`; issuer `OWNER` |
| `DEV_B` | personal device of `OWNER` | `CERT_B`: Edit `{1,2,3}`; issuer `DEV_A`. `CERT_B2`: same fields; issuer `OWNER`. `CERT_B'`: same fields, another serial; issuer `DEV_A` |
| `DEV_R` | personal device of `OWNER` | `CERT_R`: Read `{1}`; issuer `OWNER` |
| `DEV_W` | personal device of `OWNER` | `CERT_W`: `{2}` (writes, never reads); issuer `OWNER` |
| `DEV_X` | personal device of `OWNER` | `CERT_X`: Full; issuer `DEV_B` (negative: `DEV_B` lacks `12`) |
| `PAIR_J` | pairing device of `OWNER` | `CERT_J`: kind 2, `{1,2}`, `[I]`; issuer `DEV_A` |
| `BRIDGE_O` | service device of `OWNER` | `CERT_SO`: kind 1, `{1,2}`, `[X]`; issuer `DEV_A` |
| `DEV_C` | personal device of `BOB` | `CERT_C`: `{1,2,4,5,12}`, `[]`; issuer `BOB` |
| `DEV_E` | personal device of `BOB` | `CERT_E`: `{1,2,5,12}`, `[]`; issuer `DEV_C` |
| `DEV_F` | personal device of `BOB` | `CERT_F`: Full; issuer `BOB` |
| `BRIDGE` | service device of `BOB` | `CERT_S`: kind 1, `{1,2}`, `[X]`; issuer `BOB`. `CERT_S2`: kind 1, `{1,2}`, `[Y]`; issuer `DEV_C` |

**Context chain of `X`** (owner `OWNER`): `J0_genesis` (profile `org.lfcp.test.raw.v1`); `J1_grant_bob` (`BOB`: `{1,2,3,4,5,6,7}`, delegable `{1,2,6,11}`); `J2_grant_carol` (`CAROL`: `{1,2,5}`, delegable `[]`). Then, each on the previous:

| Record | Body | Decided by | Expected post-state |
|---|---|---|---|
| `I1_device_grant_dev_a` | `DEVICE_GRANT {OWNER, [CERT_A]}` by `OWNER` | W §17.4 (issuer `R`, owner standing) | `DEV_A` bound, registered, active; `roles[DEV_A] = device` |
| `I2_device_grant_self_dev_b` | `DEVICE_GRANT {OWNER, [CERT_B, CERT_A]}` by `DEV_B` | W §17.4 rule 6 (kind-0 self-registration); c2 to c4 | `DEV_B` registered, `issuers = [DEV_A]`, active |
| `I3_owner_action_by_dev_a` | `CAPABILITY_GRANT` to `DAVE` `{1}`, delegable `[]`, no parent, by `DEV_A` | `ownerAction(DEV_A)` (root owns, `13`) | `issuer_root = OWNER`; `roles[DAVE] = non-device` |
| `I4_device_grant_dev_c_bob` | `DEVICE_GRANT {BOB, [CERT_C]}` by `BOB` | standing through `J1` | `DEV_C` active |
| `I5_device_grant_dev_e_by_dev_c` | `DEVICE_GRANT {BOB, [CERT_E, CERT_C]}` by `DEV_C` | c3, c4, c7 (leaf lists 12, two certificates); chain issuer | `DEV_E` active, `issuers = [DEV_C]` |
| `I6_grant_by_member_device` | `CAPABILITY_GRANT` by `DEV_C` to `CAROL` `{2}`, delegable `[]`, parent `J1` | `holds(DEV_C, 4)`; `actsFor = BOB = J1.subject`; `{2}` within mask and `J1.delegable` | `issuer_root = BOB` |
| `I7_revoke_covered_by_sibling` | `CAPABILITY_REVOKE` of `I6` by `DEV_E` | `holds(DEV_E, 5)`; coverage `actsFor(DEV_E) = BOB = I6.issuer_root` | `I6` revoked |
| `I8_bridge_grant` | `DEVICE_GRANT {BOB, [CERT_S]}` by `DEV_C` | kind 1 in scope; issuer active managing | `BRIDGE` registered, active |
| `I9_device_revoke_dev_a` | `DEVICE_REVOKE {OWNER, DEV_A, 1}` by `OWNER` | W §17.5 (issuer `R` with standing) | `(OWNER, DEV_A)` revoked; `DEV_B` suspended; exposing (`DEV_A` and `DEV_B` lose `data/read`) |
| `I10_recertify_dev_b` | `DEVICE_GRANT {OWNER, [CERT_B2]}` by `OWNER` | W §7.3 step 4.3 (same fields), §17.4 rule 5 (new leaf ID) | `DEV_B` active, `issuers = []` |
| `I11_revoke_root_grant_bob` | `CAPABILITY_REVOKE` of `J1` by `OWNER` | owner | `BOB` without standing: `DEV_C`, `DEV_E`, `BRIDGE` registered, inactive |
| `I12_regrant_bob` | `CAPABILITY_GRANT` to `BOB` as `J1` by `OWNER` | owner | `DEV_C`, `DEV_E`, `BRIDGE` active again, no new device record |
| `I13_owner_expels_dev_c` | `DEVICE_REVOKE {BOB, DEV_C, 2}` by `OWNER` | W §17.5 rule 4 (owner) | `(BOB, DEV_C)` revoked; `DEV_E` suspended; `BRIDGE` active; exposing |

**Branches.** `Y` (owner `OWNER`): `G1_genesis_by_dev_a` (Genesis of `Y`, field 5 `[CERT_A]`, `kid = DEV_A`) → `DEV_A` registered at sequence 0; `G2_grant_bob_y` (`BOB`: `{1,2}`, delegable `[]`, by `DEV_A`, `ownerAction`); `Yb1_bridge_out_of_scope` (`DEVICE_GRANT {BOB, [CERT_S]}` by `BOB`) → accept: `BRIDGE` bound in `Y`, `registered = false` (W §17.4 rule 8). `I` (owner `OWNER`, profile `org.openlfcp.identity.v1`): `P0_genesis_i`; `P1_device_grant_dev_a_i` (`[CERT_A]` by `OWNER`); `P2_pairing_device` (`DEVICE_GRANT {OWNER, [CERT_J, CERT_A]}` by `DEV_A`) → `PAIR_J` registered, active; `P3_consume_for_dev_b` (`DEVICE_REVOKE {OWNER, PAIR_J, 3, 4: digest(CERT_B payload)}` by `DEV_A`) → `revoked[(OWNER, PAIR_J)] = {3, digest}`, exposing; `P4_register_dev_b_approved` (`DEVICE_GRANT {OWNER, [CERT_B, CERT_A], 2: PAIR_J}` by `DEV_A`) → `DEV_B` registered in `I`. Service variant from `P2`: `P3s_consume_for_bridge_o` (digest of `CERT_SO` payload) and `P4s_bind_bridge_o` (`DEVICE_GRANT {OWNER, [CERT_SO, CERT_A], 2: PAIR_J}`) → `BRIDGE_O` bound in `I`, `registered = false`. `T` (transfer, from `I8`): `T1_offer` (by `OWNER`, new owner `BOB`, head `I8`), `T1_accept` (by `DEV_F`, field 2 `BOB`), `T1_commit` (field 2 `[CERT_F]`, by `DEV_F`) → owner `BOB`; `DEV_F` bound and registered with `[CERT_F]`. `K` (cutoff, from `I9`): `K1_key_epoch` (`KEY_EPOCH` by `OWNER`, epoch 1, frontier `DEV_A ≤ 1`, `DEV_B ≤ 1`, others as accepted). `V` (intermediate-only, from `J2`): `V1_bind_dev_c_as_intermediate` (`DEVICE_GRANT {BOB, [CERT_E, CERT_C]}` by `BOB`) → `DEV_E` registered and reading, `DEV_C` bound only; `V2_revoke_dev_c` (`DEVICE_REVOKE {BOB, DEV_C, 1}` by `BOB`) → `DEV_E` suspended; **exposing** (`DEV_E` held `data/read` before and not after, W §17.5). `Vu` (unbound tombstone without descendants, from `J2`): `Vu1_revoke_unbound` (`DEVICE_REVOKE {BOB, DEV_X, 1}` by `BOB`) → not exposing. `Rd` (read-only device, from `I1`): `Rd1` (`DEVICE_GRANT {OWNER, [CERT_R]}` by `OWNER`). `W` (never-reading device, from `I1`): `W1` (`DEVICE_GRANT {OWNER, [CERT_W]}` by `OWNER`), `W2` (`DEVICE_REVOKE {OWNER, DEV_W, 1}` by `OWNER`; not exposing: `DEV_W` never held `data/read` and has no descendants).

### 12.2 Vectors

**ID-01 Device Certificate (bytes and structure)**, decided by W §7.3: `cert_a_by_root`, `cert_b_by_device`, `cert_service_scoped`, `cert_pairing_j` (exact bytes, IDs, payload digests); `cert_bad_signature`; `cert_payload_map`, `cert_wrong_label`, `cert_six_elements` (rule 1); `cert_mask_repeat`, `cert_mask_empty`, `cert_mask_33`, `cert_mask_32` (accepted), `cert_mask_unknown_u64` (accepted, confers nothing), `cert_manage_without_write`, `cert_manage_without_read` (rule 4); `cert_service_with_manage`, `cert_service_empty_scope`, `cert_personal_with_scope`, `cert_scope_65`, `cert_scope_64` (accepted), `cert_scope_repeat`, `cert_pairing_bad_mask`, `cert_pairing_two_scopes`, `cert_pairing_no_scope` (rule 5); `cert_kind_3` (rule 3); `cert_device_is_root`, `cert_descriptor_bad_id`, `cert_descriptor_extra_field` (rule 2); `cert_noncanonical_payload`, `cert_tagged_cose` (W §5.2, §10). The must-fail CDDL fixtures `wire/fixtures/invalid-device-*.diag` mirror the structural ones until these bytes exist.

**ID-02 Chains**, `verifyChain` against the named state (W §7.3): `chain_a`, `chain_b_a`, `chain_e_c`, `chain_j_a` (positives at `J2` / `I1` / `I4` / `P1`); `chain_empty`, `chain_length_5`, `chain_managing_leaf_length_4` (c7) and `chain_managing_leaf_length_3`, `chain_non_managing_leaf_length_4` (accepted), `chain_repeated_device` (c5), `chain_mixed_roots` (c1), `chain_bad_sig_and_repeat` (structure before signatures); `chain_not_root_terminated`, `chain_kid_mismatch_inner` (c2, `INVALID_SIGNATURE`); `chain_root_unknown` (`MISSING_DEPENDENCY`); `chain_mask_exceeds_issuer` (c4), `chain_issuer_without_manage`, `chain_issuer_service`, `chain_issuer_pairing` (c3), `chain_pairing_in_x` (c6), `chain_service_out_of_scope_is_not_failure` (`in_scope = false`), `chain_root_is_device` (step 4.2), `chain_leaf_is_owner`, `chain_leaf_is_member`, `chain_leaf_is_invitation`, `chain_intermediate_two_roots` (step 4.3), `chain_mask_changed`, `chain_kind_changed`, `chain_scope_changed` (N8), `chain_old_intermediate_cert_reused`, `chain_through_revoked_issuer`, `chain_revoked_leaf` (step 4.4).

**ID-03 Control Records**, the context chain plus these cases, each generated on the stated head (W §17.4, §17.5, §15, §23.3, §80.1): `device_grant_root_without_standing` (`I11`, rule 4), `device_grant_root_unknown` (`J2`, `MISSING_DEPENDENCY`), `device_grant_root_invitation_only`, `device_grant_standing_and_bad_sig` (class 4 before 5), `device_grant_replay_exact_bytes` (the exact bytes of `I1` sent again: the coordinator answers the same `ACK`; a validator reports the record as already in the chain), `device_grant_repeat_same_leaf_fresh` (a fresh record on `I1` with chain `[CERT_A]` and correct `prev`/`seq`: `AUTHORIZATION_FAILED`, rule 5), `device_grant_revoked_pair` (`I9`), `device_grant_issuer_unrelated`, `device_grant_issuer_edit_device`, `device_grant_issuer_unknown`, `device_grant_service_self`, `device_grant_service_by_unregistered_issuer`, `device_grant_service_out_of_scope_bind_only`, `device_grant_pairing_self`, `device_grant_pairing_leaf_with_field_2`, `device_grant_body_extra_key`, `device_grant_approval_without_consume` (a fresh `P4`-shaped record on `P2`, rule 7), `device_grant_approval_mismatch` (`P3`, `CERT_B'`), `device_grant_approval_after_cancel`, `device_grant_field2_personal`, `device_grant_approved_without_field_2` (accept), `device_grant_feasibility_full_depth_4` (a Full leaf issued by a manager whose chain has three certificates: `MALFORMED_MESSAGE`, c7; the approver never proposes it, §5.3 step 4), `device_grant_feasibility_mask_exceeds_issuer` (a kind-0 issuer with mask `{1,2,12}`, Edit leaf `{1,2,3}`, structure and c3 pass: `AUTHORIZATION_FAILED`, c4), `device_grant_feasibility_edit_issuer` (an Edit-issued chain: `AUTHORIZATION_FAILED`, c3), `device_grant_self_recertify_suspended` (on `I9`, `DEVICE_GRANT {OWNER, [CERT_B2]}` by `DEV_B`: `AUTHORIZATION_FAILED`, rule 6; the same record by `OWNER` is `I10`), `device_grant_binding_limit` (a 33rd live Principal bound to `BOB` in `X`: `AUTHORIZATION_FAILED`, rule 8; the 32nd accepted; after one of them is revoked, a new binding accepted), `device_grant_recertification_limit` (a ninth `DEVICE_GRANT` for one pair: `AUTHORIZATION_FAILED`, rule 8), `device_revoke_tombstone_limit` (a 65th revoked unbound pair for one root: `AUTHORIZATION_FAILED`, §17.5 rule 5), `device_revoke_bound_after_tombstone_limit` (64 unbound pairs revoked by a managing device `M`, then the root revokes `M` with reason `2`, and cancels an open pairing device: both accepted), `transfer_offer_unknown_signer` (offer signed by a Principal no record describes, no field 2: `AUTHORIZATION_FAILED`, W §23.3 item 1, not `MISSING_DEPENDENCY`), `device_revoke_consume_twice` (rule 5), `device_revoke_reason3_without_field4`, `device_revoke_field4_with_reason_0`, `device_revoke_reason3_personal_target`, `claim_against_pairing_device`, `grant_subject_bound`, `claim_by_bound_claimant`, `legacy_two_grants_either_order`, `legacy_claim_with_delegated_11`, `legacy_transfer_to_former_invitation_subject`, `grant_exceeds_device_mask`, `grant_delegable_exceeds_device_mask`, `grant_within_mask_and_parent`, `invitation_grant_by_device_within_mask`, `grant_exceeds_parent_delegable`, `revoke_not_covered_unrelated`, `owner_action_by_edit_device`, `device_revoke_twice` (a fresh record on `I9`), `device_revoke_by_member_device`, `device_revoke_self` (accept; exposing), `device_revoke_self_reason_1`, `device_revoke_unbound` (accept; not exposing), `device_revoke_by_invitation_only_root`, `device_revoke_by_former_member`, `device_revoke_foreign_root_of_intermediate`, `device_revoke_foreign_unbound_no_effect`, `device_revoke_intermediate_with_reading_descendant` (`V2`: accept; `DEV_E` suspended; **exposing**), `device_revoke_unbound_without_descendants` (`Vu1`: accept; not exposing), `device_revoke_root_target`, `device_revoke_with_field_3`, `device_revoke_wrong_root`, `genesis_device_without_owner_act`, `genesis_device_service`, `genesis_device_pairing`, `genesis_device_foreign_root` (c1), `genesis_device_kid_owner` (field 5 present, `kid = OWNER`: `INVALID_SIGNATURE`, W §15), `genesis_after_revocation_elsewhere` (accept), `transfer_commit_via_dev_f` (`T1_commit` on `I8`), `transfer_commit_revoked_leaf` (offer, accept and commit re-created on the head after `DEVICE_REVOKE {BOB, DEV_F, 1}`), `transfer_commit_leaf_without_owner_act`, `transfer_commit_leaf_other_root` (c1), `transfer_commit_new_owner_bound`, `transfer_commit_kid_mismatch`, `transfer_commit_malformed_offer_bad_placement` and `transfer_commit_malformed_offer_unknown_issuer` (no field 2, offer = COSE of `null`, wrong `prev`/`seq` or unknown issuer: `MALFORMED_MESSAGE`, W §62 class 1), `key_epoch_by_dev_a`, `key_epoch_by_dev_f`, `key_epoch_by_dev_c`, `key_epoch_by_bridge`, `key_epoch_wrong_number` and `key_epoch_repeats_current_number` (`INVALID_CONTROL_CHAIN`, W §19), `key_epoch_wrong_number_and_bad_sig`, `key_epoch_wrong_number_unknown_issuer`, `key_epoch_wrong_number_without_key_rotate` (still `INVALID_CONTROL_CHAIN`: the epoch number is class 2, before classes 3 to 5, decision I9), `key_epoch_wrong_number_noncanonical_frontier` (`MALFORMED_MESSAGE`, class 1 first), `KP_to_device_with_mask_11` (an active device of `BOB` with mask `{1,2,11}`, `BOB` holding an ordinary grant and an invitation grant: `holds(D, 11)` false, a package to it is authorized only through `data/read`), `KP_to_owner_acting_device_with_mask_11` (an active device of `OWNER` with mask `{1,2,11,13}` in a Resource `OWNER` owns, after its `data/read` grant is irrelevant: `holds(D, 11)` false; `direct(OWNER, 11)` true and consumed by nothing, W §80.1), `transfer_accept_field2_mismatch_valid_signers` (offer, accept and commit signed by their required signers, accept field 2 differs from offer field 3: `AUTHORIZATION_FAILED`), `transfer_accept_wrong_signer_before_acceptor_mismatch` (an acceptance signed by a third Principal whose field 2 also differs from the offer's field 3, no field 2: `INVALID_SIGNATURE`, W §23.3 and §62 class 4 before 5), `type_11_reserved` (`INVALID_CONTROL_CHAIN`), `ability_12_in_grant_confers_nothing` (with its control).

**ID-04 Data Units, Key Packages, Snapshots, session**, decided by W §80.1, §25.2, §26.3, §41 and §84: `D_dev_a_seq1`, `D_dev_b_seq1`; `D_dev_a_before_registration`, `D_dev_b_at_i1` (`MISSING_DEPENDENCY`); `D_dev_a_after_revoke`; `D_dev_a_old_head_after_revoke` (accept); `D_dev_a_beyond_epoch_cutoff` (`STALE_DATA_EPOCH`); `D_dev_b_suspended`, `D_dev_b_recertified`; `D_read_only_device_writes`; `D_bridge_writes_x`, `D_bridge_in_y`; `D_dev_c_without_standing`, `D_dev_c_regranted`; `D_pairing_j_in_i`; `D_bridge_o_in_i`; `KP_owner_to_dev_b`, `KP_dev_a_to_dev_b`, `KP_dev_b_to_owner`, `KP_dev_b_to_dev_a`, `KP_dev_a_to_carol`, `KP_dev_b_to_carol`, `KP_dev_c_to_carol`, `KP_bob_to_carol`, `KP_dev_c_to_bridge`, `KP_bridge_to_dev_c`, `KP_dev_e_to_dev_c`, `KP_bridge_to_carol`, `KP_owner_to_dev_a_revoked`, `KP_owner_to_dev_b_suspended`, `KP_dev_b_suspended_to_owner`, `KP_dev_c_to_dev_e_no_standing`, `KP_owner_to_dev_c_no_standing`, `KP_owner_to_bob_no_read`, `KP_at_old_head`, `KP_epoch_unknown_at_head`, `KP_matrix` (every sender and recipient pair at `I8`, `I9`, `I11`, `I13`); `SNAP_by_dev_a`, `SNAP_by_bridge`; `OPEN_as_dev_b` (at `I2`, `I9`, `I10`: allowed, refused, allowed); `CONTROL_GET_by_revoked_reader` (session `DEV_A`, latest `I10`: records `J0` to `I9`, `CONTROL_HAVE` head `I9`); `CONTROL_GET_by_consumed_pairing` (`P0` to `P3`); `CONTROL_GET_by_intermediate_only`, `CONTROL_GET_by_unbound_tombstoned`, `CONTROL_GET_by_never_reader`, `CONTROL_GET_by_root_without_standing` (`AUTHORIZATION_FAILED`); `DATA_PUT_by_revoked_session_foreign_unit` (session `DEV_A` after `I9` uploads a valid unit of `DEV_B` at `I10`: accepted), `KEY_PACKAGE_PUT_by_revoked_session_foreign_package` (session `DEV_A` uploads `KP_owner_to_dev_b`: accepted), `DATA_PUT_by_revoked_session_own_old_head_within_cutoff` (accepted) and `DATA_PUT_by_revoked_session_own_beyond_cutoff` (`STALE_DATA_EPOCH`), `DATA_GET_by_revoked_session` (`AUTHORIZATION_FAILED`); `READY_identity_01` (exact bytes).

**ID-05 Profile and links**, decided by §§2–5: `identity_doc_initial` (canonical change bytes; valid); `identity_doc_initial_by_device`, `identity_doc_initial_extra_key`, `identity_doc_initial_filled_roster` (an initial change whose `roster` is not empty: `INVALID_ROOT`, AI0); `identity_doc_second_initial_other_unit` (two different root changes without dependencies, Automerge sequence 1, in Data Units with actor sequences 1 and 2, a fill change depending on the second: in both plaintext orders, `KEY_BLOCKED` of one epoch included, the unit-1 change is the initial change, the other is `INVALID_ROOT` and never held, the fill waits; the same choice from a Snapshot after the unit-1 unit is fetched), `identity_doc_initial_without_unit_1` (a Snapshot whose dependency-free change is not in the root's unit 1: not used); `identity_doc_initial_seq_2` (no dependencies, Automerge actor sequence 2: `INVALID_AUTOMERGE_BYTES`, SOP §11.4, reported before `INVALID_ROOT`); `identity_doc_initial_in_unit_2` (a well-formed change without dependencies, Automerge sequence 1, carried by the root's Data Unit with actor sequence `2`: `INVALID_ROOT`, AI0, before the sequence hold); `identity_doc_initial_then_fill` (the two changes of §5.1, both orders, and the same state from a Snapshot); `identity_doc_bad_root`, `identity_doc_profile_mutated`, `identity_doc_container_replaced`, `identity_doc_text_field`; `pairing_writes_own_request` (admitted), `pairing_writes_roster`, `pairing_deletes_roster`, `pairing_writes_devices`, `pairing_writes_other_request`, `pairing_wrong_pairing_field`, `pairing_edits_foreign_request_label`, `pairing_takes_over_foreign_request` (rewrites `pairing` and `label` in one change), `pairing_replaces_foreign_request_map` (`UNAUTHORIZED_WRITER`), `pairing_continues_own_request` (admitted), `pairing_concurrent_same_key` (two creations of one key, neither seen by the other: both admitted, the entry conflicted and invalid), `pairing_class_at_control_ref` (admitted after `P3`); `request_valid`, `request_service_valid`, `request_service_without_scope`, `request_personal_with_scope`, `request_scope_bad_ref`, `request_key_descriptor_mismatch`, `request_bad_descriptor`, `request_missing_label`, `request_kind_2`, `request_bad_timestamp`, `request_conflicted_kind`, `request_conflicted_valid_invalid`, `request_conflicted_maps`; `roster_bad_ref`, `roster_conflicted_name`; `device_entry_missing_keys_union` (the reading of §4 rule 2 on a merged state; its root-written changes are refused at admission by AI5, as `missing_keys_root_creates_entry_with_hint` shows); `missing_keys_entry_without_hint`, `missing_keys_device_writes_own`, `missing_keys_device_appends_own`, `missing_keys_device_clears_own`, `missing_keys_root_writes_own_entry`, `missing_keys_root_deletes_device_entry`, `missing_keys_root_replaces_device_entry` (admitted), `missing_keys_root_writes_device_hint`, `missing_keys_root_creates_entry_with_hint`, `missing_keys_root_clears_device_hint`, `missing_keys_root_appends_device_hint`, `missing_keys_manager_writes_device_hint`, `missing_keys_root_relabels_and_writes_hint` (`UNAUTHORIZED_WRITER`, AI5), `missing_keys_service_writes_own` (`UNAUTHORIZED_WRITER`, AI4), `missing_keys_concurrent_device_and_root` (the device's change admitted, the root's concurrent one refused and its dependant pending, in both orders; decision I8); `missing_keys_root_writes_hidden_device_hint`, `missing_keys_root_appends_hidden_hint`, `missing_keys_root_appends_deleted_entry_hint` (`UNAUTHORIZED_WRITER`, AI5, including hidden and deleted entry objects); `missing_keys_device_writes_hidden_own_hint`, `missing_keys_device_appends_hidden_hint`, `missing_keys_device_appends_deleted_entry_hint` (admitted); `missing_keys_hidden_entry_resolution` (a foreign hidden hint is refused and blocks its dependent conflict resolution; the device's own hidden hint is admitted and becomes visible after resolution); `identity_snapshot_equivalence`; `pair_uri_roundtrip`, `pair_uri_rejected_by_join_parser`, `join_uri_rejected_by_pair_parser`, `pair_uri_device_mismatch`; `fingerprint_dev_b`; `approval_digest_cert_b` (equal to `P3`'s field 4); `root_of_corpus` (`rootOf`, `actsFor`, `bound`, `active` tables at `I2`, `I9`, `I11`, `I13`); `assignee_root_ref`.

### 12.3 Flow fixtures (W §107 style)

1. register → write → revoke → old-head unit accepted → `KEY_EPOCH` → unit beyond frontier quarantined → rebuild (replicas that saw the unit before and after the revoke converge).
2. cascade: revoke `DEV_A` → `DEV_B` suspended → re-certify → active; interleaved units of `DEV_B` at each head.
3. self-registration on a stale head → `CONTROL_HEAD_MISMATCH` → re-evaluation; the same `DEVICE_GRANT` proposed twice → second `complete`.
4. owner revokes the root's grant → all devices inactive → re-grant → active without new records.
5. reconciliation: `I` state against `X` state, revocations before registrations (a service device whose issuer `I` revoked is never registered in `X`), the registration cases and the ledger-driven key case of §7.1; a device bound in `X` only as an intermediate (`B` self-registered with `[cert_B, cert_A]`) is registered by the next reconciliation and receives keys, and a second run proposes nothing; the Identity Resource as its own target; idempotence on a second run; two reconcilers racing.
6. two managing devices revoke the same device concurrently with different reasons → one record; the other classifies its revoke phase as `complete` (not `superseded`) and continues with the rotation test (§9.2).
7. invitation accepted by a device: claim names the root; self-registration; packages to the root and siblings; the root opens and reads.
8. pairing, personal: `I` created in epoch 0 and rotated to epoch 1, then a new session: `J` receives the DEKs of both epochs and the root's unit 1 is retrievable, `B` verifies the initial change from a Snapshot of epoch 1 and from a replay without a Snapshot, and writes its request without `A` reopening `I`; a managing installation that lacks a DEK or that unit offers no link; 40 sessions created and cancelled one after the other, then a session completed (revoked pairing devices free their places, W §17.4 rule 8); `R` at 31 live devices: `J` takes the 32nd place, the consume frees it and `D_B` is registered; `R` at 32 live devices: no link until one is revoked; phases 1 and 2; one link, two installations (sequential reuse and concurrent equivocation); two managers approving different requests of one session → one `committed-own`, one `superseded`, no certificate signed by the loser; lost `ACK` and exact-byte retry; identical intent retried; crash between phase 1 and phase 2 resumed from the journaled payload.
9. pairing, service, with the states of §5.3 step 8: requested scope, `A` removes one Resource; `B` approved with certificate `C0` (digest `d`) and bound in `I`, every candidate offline, then `C0`'s issuer revoked and `B` re-certified by the root as `C1` with the same kind, mask and scope, `B` restarted, then the candidates reachable: reconciliation carries the revocation and registers `C1`, `C0` never accepted in any candidate: every candidate is unproven, `B` uses none and shows "approval not provable here", and a new session completes; `C0` registered in a candidate and re-certified there as `C1`: `B` takes `C0` as its result from that chain's history and uses `C1` (equal kind, mask and scope); requested `{X, Y}`, approved `{X}`, another issuer of `R` registers `C*` for `D_B` with scope `{X, Y}` and another digest in `X`: not used, `Y` never shown as granted; every candidate temporarily unreachable after approval → "approved, waiting for registration", no `not granted`; `B` restarts and resumes from its persisted candidates; the first certificate arrives from one Resource → the removed Resource becomes `not granted`, the others `pending registration` until a late reconciliation registers them; crash at the consuming `ACK` on either side; `A` crashes after the bind-only `DEVICE_GRANT` of a service `B` was accepted but before its `ACK` was persisted → on restart the register phase is `committed-own` (not `pending`), no new record is proposed, and registration in `X` and its packages follow; a certificate for `B` with another digest is not taken as the result; `B` resumes after `J`'s revocation using the revoked-reader prefix.
10. pairing request validation and feasibility: descriptor or kind changed between display and confirmation → re-confirmation; a request written by another pairing device → ignored; a manager with a chain of three certificates offered Full, Edit and Read → Full is not offered and no consume is proposed for it; a service scope trimmed to nothing → no consume, the session is cancelled; the manager's own authority re-checked after a head change.
11. revocation by a device whose chain passes through the target: pre-check refuses; after re-certification by the root the revocation proceeds; self-retirement leaves rotation to another installation.
12. rotation of `I` with an open session: a `DEVICE_REVOKE` of another device while a pairing device `J` is active → the rotation seals the new DEK to `J` too and its request continues; two active sessions, one closed → the other continues; a consumed or cancelled `J` receives nothing; a foreign reader in `I` → a rotator without `6` fails the post-state test. Rotation feasibility: a revoker with `7` but not `6` in a Resource with a foreign reader marks `awaiting rotation` and does not commit; with `6` but not `7` likewise; with both it rotates and seals to every reader; in `I` (all readers of the root) `7` alone suffices.
13. durable phases: crash before and after each `ACK` of pairing approval and of revoke+rotate; a concurrent rotation by another writer (`complete`); a reader revoked between planning and sending packages (fresh DEK); partial package delivery repaired by the ledger rule; a rotator that crashes after the `KEY_EPOCH` `ACK` and before any package → `awaiting key holder`, readers `KEY_BLOCKED`, a second rotator's next epoch after the bound.
14. frontier: server advertises `D 1..100`, only `1..2` fetchable → frontier `D ≤ 2`; holes; a unit the server advertises that fails authorization is not counted.
15. rotation policy by exposure: an exposing revocation → one rotation; three exposing revocations in one epoch → one rotation; an unbound tombstone without descendants, an out-of-scope binding, an already suspended device and a never-reading device revoked → no rotation; an intermediate-only device with a reading descendant revoked → one rotation, and the suspended descendant receives no package of the new epoch; a former member cannot issue the tombstone at all.
16. forks: two valid competing `DEVICE_GRANT`s on one `prev` delivered to two managers → both branches known → `CONTROL_CONFLICT`; approval and reconciliation suspended; no branch chosen by time, order or `ACK`.
17. revoked device: offline during revocation, reconnects → "access refused"; with an `identity-01` server and a reader history → proof prefix → "revocation proven"; never-reader → stays "access refused"; online unsubscribe-before-push case; the revoked session re-supplies a valid foreign Key Package the server lost → accepted.
18. barrier: each of the four barrier entries against a pre-identity validator (code per W §100.1), a herald validator (blocked state and message) and an identity-aware one; old-head writes of a blocked client accepted until the epoch closes.
19. key bootstrap: a Read device in `X`, a device registered in `I` whose approver crashed before its first package, and a service device bound in `I` and registered in `X` whose approver sent no package, none of them in any roster entry's `missing_keys` and none able to write a hint, all receive every epoch from the next reconciling manager without any request, `I` included as a target.

### 12.4 End-to-end scenarios (reference client against the reference server)

1. **First desktop → second desktop**: pair with Full; every section opens; edits from both show one author with one alias; access lists show one human with two devices.
2. **Desktop → phone**: pair with Edit; read-only on the phone where writing is not allowed; request and approve with fingerprint comparison.
3. **Bridge CLI**: headless pair as a service device requesting two sections; an edit from the bridge is attributed to the human "via bridge"; an invitation from the bridge is refused; the bridge cannot open a third section and cannot open `I`.
4. **Lost device**: revoke from a Full device; owned sections rotate at once and the lost device's later units are refused; a section owned by a colleague rotates when the colleague's client sees the exposing revoke; status shows which sections are closed and which await rotation.
5. **Offline device caught by revocation**: it wrote offline, is revoked, reconnects: units within the frontier accepted, beyond it quarantined and exported; re-applied from another device; three replicas converge; the device shows "access refused" and, against the reference server, "revocation proven".
6. **Legacy human**: an existing installation upgrades, no change in any Resource; "Add my other device…" creates `I` with the two changes of §5.1; the compatibility warning is shown before the first pairing.
7. **Three generations**: a pre-identity client opens a section after its barrier and its actual behaviour is recorded (expected: blocked with a generic chain error); a herald client: blocked with the update message, surviving a restart; after the update it syncs.
8. **Old server**: a coordinator without `identity-01`: pairing skips that section and lists it; after the server update, reconciliation registers the device and delivers keys.
9. **Human invited on one device, works on all**: the device claims as the root; the root and the other devices get the section through packages, the roster and reconciliation.
10. **Managing device lost with cascade**: preview shows the dependent device and the revoker's own dependency; re-certify, then revoke; the dependent device keeps working.
11. **Resource created from a device**: Genesis with field 5 on a Full device, the device goes offline immediately; the first installation (root) opens and reads it from the package sent at creation.
12. **Installation copied to a new machine**: the copy starts as a new installation; "Pair this device" leads through §5; no key is copied.
13. **Leaked link and double approval**: a third installation uses the link first; the human sees a foreign fingerprint, rejects; the session is cancelled and `I` rotated; the third installation holds nothing. Then: two Full devices approve two requests of one session; exactly one device is registered, the other manager reports "superseded".
14. **Access change**: a device paired as Read is removed and paired again as Full; history keeps its author.
15. **Edit device revokes**: a device with `12` but without `7` revokes a lost phone; sections show "awaiting rotation" until the Full device opens them and rotates.
