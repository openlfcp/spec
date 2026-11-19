# SERVICE-CONTROL-PROFILE-01

**Title:** OpenLFCP Service Control Resource Data Profile  
**Status:** Working Draft 0.1 for MVP 0.6; not in an implementation baseline yet; version 1 is frozen minimal for the Apple Reminders bridge (§1)  
**Date:** 2026-11-19  
**Profile identifier:** `org.openlfcp.service-control.v1`  
**Dependencies:** LFCP-WIRE-01 (this repository, same revision); SHARED-OBJECTS-PROFILE-01 §§7–14 at `mvp-0.2-baseline.12`; IDENTITY-PROFILE-01 (this repository, same revision), in particular §2.3, §5.2, §5.3, §7.1, §8, §9 and §10  
**Companions:** `SERVICE-CONTROL-TEST-VECTORS-01` (admission and replica transitions, §12), to be published with the next MVP 0.6 tag

> This document defines the **control Resource** `C`: the end-to-end encrypted channel through which the devices of one human manage one service installation (a bridge) that works for that human: status, section bindings, questions and answers, requests and their events, approval records, and section pairing. The server does not interpret it. Nothing in this document confers authority: every authority decision is made by `C`'s own Control Chain under LFCP-WIRE-01 §80.1; the writer classes of §2.3 only restrict which admitted writers may change which parts of the document.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as in BCP 14 (LFCP-WIRE-01 §2). Text marked *Informative* is not normative. `W` cites `wire/LFCP-WIRE-01.md`, `SOP` `profiles/SHARED-OBJECTS-PROFILE-01.md`, `IDENTITY` `profiles/IDENTITY-PROFILE-01.md`.

---

## 1. Contract and boundaries

A control Resource `C` is an ordinary Resource whose Genesis owner is a Root Identity `R` (W §7.2) and whose Data Profile is `org.openlfcp.service-control.v1`. There is one `C` per pair *(service installation, root)*. A managing client of `R` creates it (it needs `13`, IDENTITY §7.3) and adds it to the roster of `R`'s Identity Resource `I` (IDENTITY §2.1, `roster[C].profile` = this profile). Its readers are the personal devices of `R` that hold `C` (registered by the creating client or by reconciliation, IDENTITY §7.1) and the **base installation** of the service: a service device of `R` (kind `1`, preset Service, scope exactly `[C]`, IDENTITY §5.4, §10) paired through IDENTITY §5.3 with human fingerprint comparison. The service's **section installations** are further service devices, one per section Resource `X` it synchronises, each with scope exactly `[X]`; they never read `C`.

Version 1 is **frozen minimal**: it carries exactly what an Apple Reminders bridge needs (status, bindings, questions, the ten requests of §6.1, section pairing). It is not a general control plane: a future integration that needs more uses a new profile identifier (§11), not new keys of version 1.

This profile defines the document and its admission (§§2–4), state validation (§5), requests, events and cancellation (§6), approval records and the revocations they permit (§7), section pairing through `C` (§8), status, readers and deletion (§9), the execution obligations of the service (§10), version compatibility (§11) and the test corpus (§12). It does not define the service's internal storage, its synchronisation algorithm or its user interface texts other than those of §11.

Terms of IDENTITY §1 and W §7.2, §17.5, §80.1 apply. `B` names the base installation, `D_X` the section installation of `X`, `J_X` a pairing device created for `D_X`, `A` a managing client of `R`.

---

## 2. Document

The Data Plane follows SOP §§7–14 (Automerge, one change per transaction, framing, limits, canonical change encoding, operation references, Snapshots) exactly as IDENTITY §2 adopts them; SOP §§15–18 do not apply (no `objects`, no `extensions`). The Automerge actor of a writer is that of SOP §8 with `C`'s Resource ID.

### 2.1 Structure

```text
root                                   ; exactly these thirteen keys (§4 SC3)
├── profile     scalar string "org.openlfcp.service-control.v1"
├── meta        { attemptId: string, createdAt: timestamp }
├── approvals   map<PrincipalRef, Approval>
├── service     ServiceInfo                         ; a map, filled by the service
├── status      Status                              ; a map, filled by the service
├── bindings    map<ResourceRef, Binding>
├── pairing     map<Uuid, PairingDescriptor>
├── questions   map<Uuid, Question>
├── requests    map<Uuid, Request>
├── answers     map<Uuid, Answer>
├── cancels     map<Uuid, Cancel>                   ; key = the rid of the cancelled request
├── events      map<Uuid, Event>                    ; key = a rid or an aid
└── lifecycle   Lifecycle                           ; a map, filled by the service

Approval = { role: "base" / "section", resource: ResourceRef, principal: PrincipalRef, certDigest: Hash32,
             certId: Hash32, generation: uint, origin: string, at: timestamp, revoked?: { at: timestamp } }
ServiceInfo = { instance: string, kind: string, label: string, platform: string, app: string,
             protocol: { v: uint, ops: list<string>, questionKinds: list<string> },
             artifactSliceId: string, macos: string,
             cert: { state: string, manifestSeq: uint, certTestMode: bool },
             capacity: { sections: uint, max: uint, devicesFree: uint } }
Status    = { state: string, since: timestamp, heartbeatAt: timestamp, message?: string }
Binding   = { state: string, generation: uint, list: string, filter: string, lastCompleteCheckAt?: timestamp,
             pending: { toApple: uint, toLfcp: uint }, refused: uint, unconfirmed: uint,
             preview?: { id: string, planHash: string, filter: string, list: string, items?: list<Example>, counts?: map<string, uint> },
             needsAttention?: { code: string }, lifecycle?: string }
PairingDescriptor = { descriptor: string, principal: PrincipalRef, fp: string }
Question  = { binding: ResourceRef, generation: uint, kind: string, anomalyId: string, snapshotHash: string,
             items: list<Example> (0–5), counts: map<string, uint>, actor?: string, options: list<string>, at: timestamp,
             resolved?: { answerId: Uuid, choice: string, at: timestamp }, superseded?: { by: string } }
Request   = { op: Op, binding?: ResourceRef, generation?: uint, args: map, client: { app: string, protocol: uint }, at: timestamp }
Answer    = { qid: Uuid, snapshotHash: string, choice: string, at: timestamp }
Cancel    = { reason: "user" / "mismatch" / "expired", at: timestamp }
Event     = { state: EventState, code?: string, detail?: string, at: timestamp }
Lifecycle = { op?: "remove" / "uninstall", bindings?: list<{ binding: ResourceRef, generation: uint }>, at?: timestamp }

Uuid      = a UUIDv7 (RFC 9562) in lower-case hyphenated text form, 36 characters, created by the writer of the entry
Op        = 1 to 32 characters of [a-z-]
EventState = "received" / "executing" / "request-ready" / "ready" / "applied" / "failed" / "rejected" / "stale" / "cancelled"
Example   = a string of at most 80 Unicode scalar values (a task title)
Hash32    = unpadded base64url of 32 bytes (43 characters)
ResourceRef, PrincipalRef, timestamp  as IDENTITY §2.1
```

Every value is an Automerge scalar (`ImmutableString`, boolean, uint), a map or a list of such; collaborative Text is never used. `string` is an `ImmutableString`. A field marked `?` is optional; every other field of an entry is required. `certDigest` is the certificate payload digest of W §7.3 rule 6 of the leaf the approval committed to; `certId` that certificate's ID. `generation` of a base approval is `0`.

**Unknown fields.** An entry or a map named above MAY hold fields this version does not name. Readers ignore them, writers never delete a field they did not write, and admission does not refuse them (§4 SC4 and the size limit still apply). This is the forward-compatibility rule of §11.

### 2.2 The initial change

The initial change is identified as in IDENTITY §2.2, with "the root" read as **the Principal that signed `C`'s Genesis** (`R`, or the device whose chain is Genesis field `5`, W §15): the change without dependencies authored by that Principal's actor, its Automerge sequence `1`, carried by that Principal's Data Unit with actor sequence `1`. It MUST create exactly the thirteen root keys of §2.1: `profile` with its value; `meta` as a map with `attemptId` and `createdAt`; the other eleven as **empty** maps. Every rule of IDENTITY §2.2 on one accepted initial change, Snapshots and delivery order applies unchanged.

### 2.3 Writer classes

Admission (§4) takes, besides the change and its signer, the signer's **class**. It is derived from `C`'s Control state at the Data Unit's `control_ref`, as in IDENTITY §2.3, and for `service` also from the document in the change's causal history:

- `root`: the signer is the Genesis owner `R`;
- `personal`: the signer is bound in `C` with kind `0` and its chain's root is `R`;
- `service`: the signer `P` is bound and active in `C` with kind `1` and root `R`, **and** in the change's **pre-state** (§3) `approvals` holds exactly one entry with `role = "base"` that is valid (§5) and has no `revoked`, and that entry's key is `p:<P>`. Two such entries give the class `service` to nobody until `root` or `personal` revokes one (the conflict is shown to the human, §7.3);
- `other`: anything else — a service device without that approval, a section installation of the same service, a pairing device (kind `2`), another root's Principal, a non-device member.

A change by `other` is refused whole (§4 SC5). The class is taken at `control_ref` and on the causal history, never at the current head or the merged state, so a later revocation does not change a decision already made.

### 2.4 Attribution

No field records who wrote an entry. The author of an entry is the signer of the change that created it (`personal` and `root` are displayed as the human by `rootOf`, IDENTITY §10; `service` as the service's label). A reader that needs the author — the service executing a request (§10), a client checking an approval (§7.2) — takes it from the change, never from a field.

---

## 3. The mutation table

Each row lists the only mutations admitted at its position; every other operation at that position is refused (§4 SC5 for a writer outside the row, SC6 for a mutation the row does not allow).

**Pre-state and post-state.** The **pre-state** of a change is the document of its causal history **without** the change (its dependencies and their history); the **post-state** is that document with the change applied. Every condition of a row — "present", "absent", "final", "holds neither", "without any `revoked` value", "never held a value" (no operation of that history ever set the key, deleted values included) — is evaluated on the pre-state, except the conditions marked "after the change", which are evaluated on the post-state; SC4 and SC7 of §4 are also post-state checks. One change MAY contain several operations, at several positions: each operation is judged against the same pre-state, an operation that writes into an entry the same change creates is part of that creation (it is not "a write into an existing entry"), and a change that creates and deletes the same entry, or creates one key twice, is refused (SC6). For example, the service deletes `requests[rid]`, `events[rid]`, `cancels[rid]` and `pairing[rid]` in one change: `events[rid]` is final in the pre-state, and `requests[rid]` is absent in the post-state.

| Position | Writer | Admitted mutations |
|---|---|---|
| the root keys of §2.1, `profile`, `meta` and below | the Genesis signer, in the initial change | exactly the creations of §2.2, checked by SC0; nothing after the initial change (SC1, SC2) |
| `approvals[P]` | `root`, `personal` | create the entry when `P` never held a value; create `revoked` = `{at}` in an entry without any `revoked` value. Nothing else; never deleted |
| `service`, `status`, `lifecycle` (below the root key) | `service` | any write or deletion of fields and of values below them |
| `bindings[X]` | `service` | create, write into, delete |
| `pairing[rid]` | `service` | create when `rid` never held a value and `requests[rid]` is present with `op = "pair-section"`; delete when `requests[rid]` is absent after the change and, in the pre-state, `approvals[principal]` is present or `events[rid]` is final with state `cancelled` or `rejected` (the entry is what lets a reconciler repair a missing approval, §7.4) |
| `questions[qid]` | `service` | create when `qid` never held a value; create `resolved` or `superseded` once, when the entry holds neither; delete when it holds one of them |
| `requests[rid]` | `root`, `personal` | create when `rid` never held a value |
|  | `service` | delete when `events[rid]` is final |
| `answers[aid]` | `root`, `personal` | create when `aid` never held a value |
|  | `service` | delete when `questions[qid]` (its `qid`) is absent or holds `resolved` or `superseded` |
| `cancels[rid]` | `root`, `personal` | create when `rid` never held a value and `requests[rid]` is present |
|  | `service` | delete when `requests[rid]` is absent after the change |
| `events[id]` | `service` | create when `id` never held a value and `requests[id]` or `answers[id]` is present; write `state` to the same or a later value of §6.2, together with `code`, `detail` and `at`, and delete `code` or `detail` (a retryable code does not outlive its state); nothing once the event is final; delete when final and `requests[id]` and `answers[id]` are absent after the change |

An entry is **created** by one change as a whole map: the change that creates `approvals[P]`, `requests[rid]`, `answers[aid]`, `cancels[rid]`, `pairing[rid]`, `questions[qid]` or `events[id]` writes all its fields; later changes write only what the row allows. The root key and its container are never replaced or deleted (SC2).

---

## 4. Admission

As IDENTITY §3: when a change arrives, the checks of its bytes alone, then, once every dependency is present, SOP §11.2, §11.4 and the sequence checks of SOP §14.1, then these rules. A position is located by the operations that created the objects on its path, in the change's causal history or earlier in the change, hidden, replaced and deleted objects included, never by the engine's projection (IDENTITY §3, AI2 and AI3).

| Rule | The change … | Diagnostic |
|---|---|---|
| SC0 | breaks §2.2 (a change without dependencies that is not the initial change, or an initial change that does not create exactly the thirteen root keys with `profile`, `meta` and eleven empty maps) | `INVALID_ROOT` |
| SC1 | writes or deletes `profile` or anything under `meta`, and is not the initial change | `IMMUTABLE_FIELD_MUTATED` |
| SC2 | replaces or deletes a root key of §2.1 other than `profile` and `meta`, or replaces an entry map with a scalar | `CONTAINER_REPLACED` |
| SC3 | creates a root key that §2.1 does not name (version 1 is closed at the root, §11) | `UNKNOWN_ROOT_KEY` |
| SC4 | creates collaborative Text anywhere; or leaves an entry it creates or writes (or `service`, `status`, `lifecycle`) invalid by §5 in the state of its causal history and the change, conflicts aside | `INVALID_FIELD_TYPE` (or the §5 diagnostic) |
| SC5 | is signed by a writer of class `other`; or contains an operation at a position whose row in §3 does not name the writer's class | `UNAUTHORIZED_WRITER` |
| SC6 | contains an operation the row of its position does not admit for that writer: a second creation, a write into an entry other than the one the row allows, a deletion before its condition holds, a backward or post-final `events` write | `FORBIDDEN_MUTATION` |
| SC7 | leaves, after the change in its causal history, an entry it creates or writes (or `service`, `status`, `lifecycle`) larger than its limit, with an `Example` longer than 80 Unicode scalar values or with more than 5 `items`; or creates a request and leaves more than 32 open requests, or more than one open `pair-section` request | `LIMIT_EXCEEDED` |

**Sizes.** The size of an entry (and of `service`, `status`, `lifecycle` as wholes) is the sum, over every value present in it after the change in its causal history (concurrent values of a field included), of: the UTF-8 length of every map key and every string, and 8 bytes for every other scalar. The limit is 4096 bytes, and 8192 for a `pairing` entry. A request is **open** when it is present and `events[rid]` is absent or not final; a `pair-section` request likewise. Concurrent creations can exceed the counts; a change that creates no request is never refused for them, so the service can still write its events and heartbeat, and the clients can still cancel.

**The initial change.** A change that SC0 identifies as the initial change and admits is exempt from SC1, SC5 and SC6: its writer is the Genesis signer, whatever its class at `control_ref`, and it is the only change that creates root keys or writes `profile` and `meta`. Any other change that creates a root key of §2.1 breaks SC2 (it replaces a container), and one that creates another root key breaks SC3.

A change that breaks a rule is `PROFILE_INVALID` with that diagnostic, is not merged, and blocks its dependants (SOP §14.1). When several apply, the first in the order `INVALID_AUTOMERGE_BYTES`, `CHANGE_ACTOR_MISMATCH`, `INVALID_ROOT`, `CONTAINER_REPLACED`, `IMMUTABLE_FIELD_MUTATED`, `UNKNOWN_ROOT_KEY`, `UNAUTHORIZED_WRITER`, `FORBIDDEN_MUTATION`, `INVALID_FIELD_TYPE` (and the other §5 diagnostics), `LIMIT_EXCEEDED` is reported. A client whose own change would be refused does not send it; it shows "Couldn't send" (§11). An unknown `op` is **not** refused (§6.1).

*Informative.* Two `personal` writers that create the same `rid` concurrently each pass §3; the merged entry is conflicted and invalid (§5). UUIDv7 keys make this an error case only.

---

## 5. State validation

| Diagnostic | Meaning |
|---|---|
| `INVALID_ROOT` | `profile` differs, a root key is missing or not of its §2.1 kind |
| `MISSING_REQUIRED_FIELD` | a required field of §2.1 is absent |
| `INVALID_FIELD_TYPE` | a field has the wrong type |
| `INVALID_RESOURCE_REF`, `INVALID_PRINCIPAL_REF` | as IDENTITY §4 |
| `INVALID_KEY` | a key of `pairing`, `questions`, `requests`, `answers`, `cancels` or `events` is not a `Uuid`; a key of `approvals` differs from `principal` |
| `INVALID_ENUM_VALUE` | `role`, `cancels.reason`, `lifecycle.op` or `events.state` is not a value of §2.1; `op` does not match `Op`; `approvals.role = "base"` with `resource` other than `C` |
| `INVALID_TIMESTAMP` | a timestamp is not RFC 3339 UTC (SOP §28) |
| `INVALID_DESCRIPTOR` | `pairing[rid].descriptor` is not the base64url of a valid W §7 descriptor whose ID is `principal`, or `fp` is not its fingerprint (IDENTITY §5.2) |
| `LIMIT_EXCEEDED` | an `Example` longer than 80 Unicode scalar values; more than 5 `items`; an entry larger than its limit (§4 Sizes) |

Rules:

1. Validation is per entry; an invalid entry is ignored by readers (never shown, never executed, never used as an approval) and the rest stays usable. An invalid root is `INVALID_ROOT` and `C` is unusable. An empty `service`, `status` or `lifecycle` (as the initial change creates them) is valid and means "not reported yet"; the service's first write fills every required field of `service` and `status` in one change (§4 SC4).
2. Open-set strings are not validated against a list: `service.kind`, `status.state`, `bindings[X].state`, `needsAttention.code`, `questions[q].kind`, `choice`, `options[]`, `events.code`, `events.detail`, `requests.op` within `Op` (§11).
3. Concurrent values (SOP §45): an entry created by `root` or `personal` (`approvals` except `revoked`, `requests`, `answers`, `cancels`) with two concurrent maps under one key, or a conflicted field, is invalid; concurrent `revoked` values mean revoked. Concurrent maps of one `approvals[P]` whose `role`, `resource`, `principal`, `certDigest`, `certId` and `generation` are equal are valid and read as one approval (two clients may write the same A3, §7.4); any difference makes the entry invalid. In entries written by `service`, a display field MAY be shown with any value; `events.state` is read as its highest value in the order of §6.2, and two distinct final values make the event invalid but **final** for §3 and §4; `questions` with both `resolved` and `superseded` is read as resolved.
4. Nothing in `C` confers authority. Principals are taken only from `approvals` written by `root` or `personal` (§7), never from a field written by `service` (`pairing`, `lifecycle`, `service`).
5. Secrets MUST NOT be written into `C`, with the single exception of the pairing link of a `pair-section` request (§8.3).

---

## 6. Requests, events and cancellation

### 6.1 Requests

A request is written by `root` or `personal` with a fresh `rid`. `binding` and `generation` name the section binding a request acts on (required for the binding-scoped operations below); `args` holds operation arguments, `{}` when there are none; `client` the writer's application version and the version of this profile's operation set it implements (`1`).

On the wire `op` is any `Op` string: admission never refuses an unknown one. Version 1 defines, and a version-1 service executes, exactly:

| `op` | Scope | `args` |
|---|---|---|
| `preview`, `turn-on`, `turn-off`, `resume-binding`, `remove`, `retry-helper` | a binding | `turn-on`: `{previewId, planHash}` |
| `pause`, `resume`, `check` | the service | — |
| `pair-section` | a section `X` to connect (`binding`) | `{link}`: the pairing link of `J_X` (§8) |

A request whose `op` the service does not execute gets `events[rid] = rejected{code: "unsupported_op"}` and **no effect** (§11).

### 6.2 Event states

`events[id]` reports a request (`id = rid`) or an answer (`id = aid`). States, in order: `received` → `executing` → (`pair-section` only: `request-ready` → `ready`) → one **final** state: `applied`, `failed`, `rejected`, `stale`, `cancelled`. A write MAY skip states; it never moves back; a final event is immutable until it is deleted.

- **Retryable codes** (the event stays `executing`): `network`, `helper_unavailable`, `server_429`.
- **Final codes**, with `failed` or `rejected`: `stale_generation`, `snapshot_changed`, `too_large`, `capacity`, `uncertified`, `not_permitted`, `unresolved_work`, `unsupported_op`, `already_answered`; `stale` carries `stale_generation` or none; `applied` MAY carry `late_cancel`.
- The set of codes is open (§11): a reader shows an unknown code as the generic row of §11.

### 6.3 Cancellation

A cancel `cancels[rid]` is written by `root` or `personal`. The service checks for it before each effect of the request:

| When the cancel is seen | Outcome |
|---|---|
| before `received` (with the request or earlier) | `cancelled`; nothing done |
| after `received`, before the first effect | `cancelled`; effects not started are dropped |
| an effect has started | the request completes by the service's recovery rules; `applied` with `late_cancel` |
| the event is final | ignored |
| the service crashed | on recovery, the same rules from its durable execution record (§10) and `cancels` |
| `pair-section` before the consume of `J_X` | the cancelling client revokes `J_X` itself (`DEVICE_REVOKE` reason `0`, IDENTITY §5.3 step 9) and writes the cancel with `reason` `user`, `mismatch` or `expired`; the service forgets its unapproved `D_X` |
| `pair-section` after the consume | no cancellation (IDENTITY §9): the section is removed afterwards (`remove`, §7.2) |

---

## 7. Approval records

### 7.1 Writing

An approval record `approvals[P]` is written by the managing client `A` that approved `P`'s pairing, as phase **A3** of that pairing, after the consume (A1, IDENTITY §5.3 step 5) and the grant (A2, step 6) and **before** registration (A4, step 10 for `C` or `X`). Its `certDigest` is the consumed approval digest, `certId` the leaf certificate's ID, `origin` the `attemptId` of the base connection or the `rid` of the `pair-section` request, `generation` the binding's generation (`0` for the base). A3 is journaled like the other phases (IDENTITY §9.1); after a crash, an entry already present with the same `certDigest` is `complete`, and the same entry is written again otherwise. Because A3 precedes A4, the base installation gets the class `service` only once its approval exists (§2.3). The order A3 before A4 holds for every client that implements this profile, the approving one and any reconciler (§7.4).

### 7.2 The only revocations it permits

A client revokes a service Principal `P` (IDENTITY §8) because of `C` only when **every** condition holds:

1. `C` holds a valid `approvals[P]` without `revoked`, created by `root` or `personal` (§2.4);
2. in the verified chain of `I`, `P` is bound with kind `1` and root `R`, and the leaf payload digest equals `certDigest`; `P` has issued no certificate;
3. the cause is either (a) the human pressed Remove or Disconnect in this client, or (b) `lifecycle`, written by `service` of this same `C`, names `{binding: X, generation: g}` and `approvals[P]` is a section approval of this `C` with `resource = X` and `generation = g`; for `lifecycle.op = "uninstall"`, every approval of this `C` without `revoked`, the base last.

Never: a Principal read from a field written by `service`; a device of kind `0` or `2`; an approval of another control Resource; a `generation` mismatch; another root. After the revocation the client writes `approvals[P].revoked` and rotates as IDENTITY §8.4 says. A service device of `R` without an approval in any `C` is revoked only by the human's explicit choice (IDENTITY §8).

### 7.3 Two base approvals

Two valid base approvals without `revoked` mean no `service` class (§2.3): the service's writes are refused until `root` or `personal` revokes one, and clients show the conflict with the two installations' labels and fingerprints.

### 7.4 Repair and reconciliation

The approval record is derivable from public state, so any client of class `root` or `personal` in `C` that implements this profile and holds `I`'s verified chain MAY write a missing A3 (a takeover, IDENTITY §9.6); it writes nothing that the chains do not prove:

- **Section.** The client writes `approvals[P] = {role: "section", resource: X, principal: p:<P>, certDigest: d, certId: <the leaf's ID>, generation: <requests[rid].generation>, origin: rid, at}` only when **all** of these hold, and writes nothing otherwise:
  1. a request `requests[rid]` of `C`, present or in `C`'s history, created by `root` or `personal`, with `op = "pair-section"` and `binding = X`, carries in `args.link` a pairing link whose `device` parameter gives the ID of a pairing device `J` (IDENTITY §5.2; the link's secret is not used, IDENTITY §9.8);
  2. in `I`'s verified chain, `J` is a kind-2 device of `R` revoked with reason `3` and approval digest `d` (the consume, IDENTITY §5.3 step 5);
  3. a `DEVICE_GRANT` of `I` with field `2` = `J` binds a leaf whose payload digest is `d`, of kind `1`, root `R`, the Service mask `{1, 2}` and scope exactly `[X]`; its descriptor gives `P`;
  4. `pairing[rid]` is valid and its `principal` is `p:<P>`. This is a consistency check only: `P` is taken from `I`'s chain through the `J` of the trusted request, never from a field written by `service` (§5 rule 4).
- **Base.** The client writes `approvals[P] = {role: "base", resource: C, principal: p:<P>, certDigest: d, certId: <the leaf's ID>, generation: 0, origin: meta.attemptId, at}` when `C` holds no approval for `P` and, in `I`'s verified chain, a `DEVICE_GRANT` whose field `2` names a pairing device of `R` revoked with reason `3` and approval digest `d` binds `P` with a leaf whose payload digest is `d`, of kind `1`, root `R`, the Service mask `{1, 2}` and scope exactly `[C]`. Two such devices give two base approvals, which §7.3 resolves.

**Reconciliation order (IDENTITY §7.1 step 2).** A control Resource `C` **names** a kind-1 device `P` only when conditions 1 to 3 of the Section rule prove `P` for some `requests[rid]` of `C`, or when `P`'s scope is exactly `[C]`. A `pairing[rid]` whose `principal` is not so proven is ignored for this purpose: it neither defers the registration of `P` nor produces an approval, and a client MAY show it as an error of that `C`'s service. A reconciler that implements this profile registers a kind-1 device `P` in a Resource `X` only after it has synchronised every control Resource of the roster, and, when one of them names `P`, only once `approvals[P]` is present there, writing it by the rules above first when it is missing. While a control Resource is unreachable, it defers the registrations of kind-1 devices and retries on its next run.

*Informative.* A client that does not implement this profile (one that does not open `C`, §11) reconciles as IDENTITY §7.1 says and may register such a `P` before A3. This follows from §11 and from IDENTITY §7.1 as already deployed, not from an exception to the order of §7.1: the rights of `P` in `C` still come only from the approval record (§2.3), and a section installation does not read `C`. The window closes when the approving client repeats A3 from its journal (§7.1), or when a client that implements this profile repairs it as above. Until then `P` has no `service` class (a base) and §7.2 offers no revocation through `C`: a Remove waits for the repair and is shown as "Finishing connection…", while the human can still revoke `P` explicitly (IDENTITY §8).

---

## 8. Section pairing through `C`

### 8.1 Flow

1. `A` checks capacity, creates the pairing device `J_X` in `I` (IDENTITY §5.3 step 1) and writes `requests[rid] = {op: "pair-section", binding: X, args: {link: <link of J_X>}, …}`.
2. The service executes it only when the request's author is `root` or `personal` (§2.4): it creates `D_X`, writes the pairing request into `I` as `J_X` with kind `1` and scope exactly `[X]` (IDENTITY §5.3 steps 2 and 3), then writes `pairing[rid] = {descriptor, principal: p:<D_X>, fp}` with `descriptor` the exact string it wrote in `I`, and `events[rid] = request-ready`.
3. `A` approves without a human comparison only under the conditions of IDENTITY §5.3 *pre-authorised approval*. While the request in `I` or `pairing[rid]` in `C` has not reached `A`'s replicas, `A` waits and re-checks on each push or open of `I` and `C`; it cancels `J_X` and writes `cancels[rid] = {reason: "mismatch"}` only on an established mismatch, and `{reason: "expired"}` when its local deadline passes.
4. Phases A1 to A4 (§7.1); the service writes `events[rid] = ready`, then `applied` once the section is bound.

### 8.2 One session

At most one open `pair-section` request per `C` (§4 SC7). `A` journals its session (IDENTITY §9); after a restart it completes or cancels it from the journal. A request left open by a client that never returns is shown to every managing client as "Pending connection" with [Cancel], which performs the cancel of §6.3.

### 8.3 Exposure of the link

The link in `args.link` lets its holder read `I` as `J_X` until `I` is rotated (IDENTITY §5.3 step 9). It is readable by every reader of `C` — the personal devices of `R` and the base installation, which thereby gets **temporary read access to `I`** for each section connection — and stays in `C`'s history. It is carried only in the encrypted plaintext of `C` (IDENTITY §5.2, W §18.2); it MUST NOT appear in journals, logs or diagnostics (IDENTITY §9.8). Only the client that created `J_X` cancels it before the consume.

---

## 9. Status, readers, deletion

- **Heartbeat.** The service writes `status.heartbeatAt` at least every 30 minutes, and state transitions at once but at most once a minute per binding. Clients display "last heard" from `heartbeatAt`. A binding is "Up to date" only when `lastCompleteCheckAt` is at most 75 minutes old, `pending.toApple`, `pending.toLfcp`, `refused` and `unconfirmed` are `0`, and `needsAttention` is absent.
- **Readers** (*informative* summary of §1): the personal devices of `R` that hold `C`, and the base installation. Content: the Mac's status and versions, section and list names, at most five task titles per question or preview, and section pairing links (§8.3).
- **Deletion for display.** The service SHOULD delete a final request with its `events`, `cancels` and `pairing`, an answered question and its answers, 7 days after they became final. Deletion removes nothing from history (SOP §56) and is never the service's deduplication boundary (§10).
- **Snapshots** follow SOP §13 and are published by the human's clients; the service does not publish them.

---

## 10. Execution by the service

1. For a new request or answer the service checks the author class (§2.4), the binding's current `generation` and, for an answer, `snapshotHash` and the question it names.
2. Before any effect it commits, in one durable transaction, an execution record `(id, kind, binding, generation, choice, effects, state = accepted, author)`.
3. It executes with its ordinary mechanisms and recovery, then writes `events` and, for an answer, `questions[qid].resolved`. The first answer it accepts wins; a later one gets `rejected{already_answered}`.
4. Execution records are never deleted: an `id` seen again is ignored, also after the entry was deleted from `C`. A `generation` below the binding's current one gives `stale`.

A client shows a request as *queued* (local), *sent* (the server acknowledged the unit), *received* (`events.received`), then the final state.

---

## 11. Version compatibility

The service writes `service.app` (its version) and `service.protocol = {v: 1, ops, questionKinds}`: the operations of §6.1 it executes and the question kinds it can ask. A client writes its own version in `requests[].client`. These rules are normative for every version-1 reader and writer:

| Case | Behaviour |
|---|---|
| unknown field in an entry | readers ignore it; writers never delete another writer's field; admission admits it (§2.1), within the limits of §4 |
| unknown root key | admission refuses it (SC3): version 1 is closed at the root |
| unknown `op` at the service | `events[rid] = rejected{code: "unsupported_op"}`, no effect; the client shows "Update LFCP Bridge on <label> to use this (menu → Check for Updates…)" |
| an `op` absent from `service.protocol.ops` | the client does not offer it: the control is disabled with the same text |
| unknown `questions[q].kind`, `bindings[X].state` or `needsAttention.code` at the client | a generic card or row: "Update Shared Tasks to see this. You can also answer in LFCP Bridge on your Mac." |
| a change admission refuses | the client shows "Couldn't send — update Shared Tasks" and does not retry it |
| a client whose SDK does not implement this profile (`profile-unsupported`) | it does not open `C`; the roster name the creating client writes, "Reminders bridge · <Mac> (needs Shared Tasks 0.8)", explains the entry; a client that implements this profile displays `service.label` instead |
| a Genesis profile `org.openlfcp.service-control.vN`, `N` greater than the reader's | the client does not interpret `C` (as `profile-unsupported`): from the roster only, it shows "Reminders bridge · <Mac> — update Shared Tasks" with [Update…] and reads no `status`; a service executes no request and shows "Update LFCP Bridge" |

`<label>` is `service.label`. Version-1 values: `service.protocol.ops` ⊆ the ten operations of §6.1; `bindings[X].state` in `connecting`, `preview`, `turning-on`, `on`, `needs-answer`, `needs-attention`, `partly-synced`, `off`, `removing`; `status.state` adds `paused` and `stopped`. Mixed client and service versions are tested before automatic updates are enabled by default.

A change of the root keys, of the mutation table or of the meaning of an existing field is a new profile identifier, never a new value of `service.protocol.v`; `v` names the set of `op` values only.

---

## 12. Test vectors

`SERVICE-CONTROL-TEST-VECTORS-01` (in `lfcp-vector-format/1`, the conventions of the identity profile corpus, IDENTITY §12.1) covers at least one admitted and one refused case for each cell of §3 — `root`, `personal`, `service` by approval, a section installation, a pairing device, another root —, insertion, rewrite and deletion; `events` only forward; concurrent `resolved` and `superseded`; deletion of a request before and after its final event; two base approvals; a service change without the approval in its causal history; the limits of §4; and an unknown `op`: admitted, `rejected{unsupported_op}`, no effect. Until it is published, claim "implements Working Draft SERVICE-CONTROL-PROFILE-01 at revision …", not interoperability.
