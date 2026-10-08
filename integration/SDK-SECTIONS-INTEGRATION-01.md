# SDK-SECTIONS-INTEGRATION-01

**Title:** SDK Receipt, Status and Parser Integration Contracts for OpenLFCP Shared Sections  
**Status:** Working Draft for MVP 0.2, not in any implementation baseline  
**Date:** 2026-10-08  
**Contract version:** `sections-integration/1`  
**Profile:** `org.openlfcp.shared-sections.v1`  
**Dependencies:** LFCP-WIRE-01 (`mvp-0.1-baseline.9`); SHARED-OBJECTS-PROFILE-01; SHARED-SECTIONS-PROFILE-01; MARKDOWN-SECTIONS-01; ADR 0008; ADR 0009

## 1. Purpose and scope

This document fixes what an SDK tells an editor adapter about a local edit of a shared section, and what the adapter's Markdown parser hands to the code that turns source edits into intents. Its goal is that no editor code invents durable or synchronization evidence: every "saved" or "accepted" an adapter shows comes from a fact defined here.

It defines:

- the local commit of a batch of intents and its receipt (§3);
- the status of a local batch, and the facts about received units (§4);
- the event stream and its gap recovery (§5);
- write access and its freshness (§6);
- the boundaries between parser, source map, projection base, candidates, journal and patches (§7);
- contract examples that a provider and a consumer test against (§8).

It defines no LFCP Wire message. Server acceptance is the existing `ACK` of LFCP-WIRE-01 §59 at the durability of §37. The names below are this contract's; a language binding may adapt their case and form (for example `operation_id` in Rust), but not their semantics. An SDK that does not provide a fact reports it as unknown (§2); an adapter never derives it from something else, such as a sent WebSocket frame.

## 2. Versions and unknown evidence

An SDK reports the contract versions it implements, here `sections-integration/1`. An adapter states the minimum it requires and refuses to open shared sections in write mode with an SDK below it, keeping the Markdown readable.

| Requirement | Minimum |
| --- | --- |
| Profile | SHARED-SECTIONS-PROFILE-01 Working Draft 0.3, its corpus at the SDK's pin |
| Wire | LFCP-WIRE-01 `mvp-0.1-baseline.9`: `UNKNOWN_PREVIOUS` (§51.1), bidirectional anti-entropy (§68.1), re-hosting (§41.1) |
| Server, for "accepted by the server" | `READY` durability 2 or higher (§37) |

A fact the SDK cannot establish is `unknown`, never a default value. A newer contract version may add facts and event types; a consumer ignores event types it does not know and treats the facts they would carry as unknown.

## 3. Local commit and receipt

### 3.1 Commit

```text
commit(resource, intents, { operationId }) -> Receipt
```

- `intents` are the intents of SHARED-SECTIONS-PROFILE-01 §11 and the Task intents it reuses, as one batch. The caller allocates every new ID (UUIDv7) and the SDK uses those IDs; it never substitutes its own.
- `operationId` is chosen by the caller, unique per Resource, and stable across the caller's retries of the same operation.
- The batch is validated as a whole. One refused intent refuses the batch with a typed code (§3.6); nothing is written and there is no receipt.
- A batch within the authoring budgets of SHARED-SECTIONS-PROFILE-01 §16.2 and the admission limits of §16.1 becomes one Automerge change and one Data Unit. A larger batch, such as an import, becomes several changes in order (§12, §12.3), and for an import the last one writes `ready` (§12.1).
- The commit is atomic, whatever the number of changes: the Data Units of every change, the model and actor state, the outbound queue entries and the receipt are written in one local transaction. After a crash either all of them exist or none does.
- The call returns only after that transaction is durable. A changed editor buffer, a successful parse or an in-memory Automerge change is not a commit.

An import is therefore one operation with one receipt. A provider whose storage cannot hold an import in one transaction does not split it silently: it refuses the batch, and the adapter imports in several operations, each with its own receipt, the last one writing `ready`.

### 3.2 Receipt

| Field | Meaning |
| --- | --- |
| `operationId` | The caller's operation ID |
| `unitIds` | The Data Unit IDs of the batch, in the order of their changes |
| `affectedNodeIds` | The nodes whose fields, Text, placement or lifecycle the batch writes, and the section when it writes the title |
| `modelRevision` | The local document's heads after the commit, sorted, as one opaque string; the same value and name as the revision of the section snapshot |
| `durable` | Always `true`: a receipt exists only for a durable commit |

`modelRevision` is the base an adapter records for the projection it reconciles with this commit (§7.3).

### 3.3 Idempotency

- `commit` with an `operationId` that already has a receipt and the same intents returns that receipt and writes nothing.
- `commit` with an `operationId` that already has a receipt and different intents fails with `OPERATION_ID_REUSED`, a local SDK error, not a Wire code. Intents are the same when their canonical forms are equal.
- An adapter that is unsure whether a commit happened asks `receiptOf` (§3.4); it never repeats the intents under a new `operationId`.

### 3.4 Query after a crash

```text
receiptOf(resource, operationId) -> Receipt | none
```

The answer is definitive and survives a restart. Because the receipt is written in the commit's transaction (§3.1), `none` means that no part of the batch was committed, and the adapter may submit the operation again with the same `operationId` and the same IDs.

### 3.5 Retention

A receipt is kept until the adapter releases it:

```text
releaseReceipt(resource, operationId)
```

An adapter releases a receipt when its journal finishes the operation (§7.7). An SDK MAY also drop a receipt after a ceiling counted from the batch's final status, accepted or rejected (§4.1); the default ceiling is 30 days. That number is a default of the SDK, not a protocol rule. A batch that is still pending, including one pending again (§4.2), never loses its receipt to the ceiling.

### 3.6 Refusals before commit

A refused batch reports a code and, where it applies, the intent and node it concerns. The codes are those of SHARED-SECTIONS-PROFILE-01 (§6, §8, §10, §14) and SHARED-OBJECTS-PROFILE-01, plus:

| Code | Meaning |
| --- | --- |
| `STALE_BASE` | A `text.edit` names a base revision the SDK cannot rebase onto the current Text (§7.5) |
| `OPERATION_ID_REUSED` | §3.3 |
| `NOT_WRITABLE` | The validated access state does not allow writing (§6) |
| `SECTION_IMPORTING` | The section has no `ready` and the batch is not the creator's continuation of the import (SHARED-SECTIONS-PROFILE-01 §12.1) |

An adapter shows a code by its own words; it does not show raw SDK text.

## 4. Status

### 4.1 A local batch

The status of a local batch, from its receipt onwards:

| Status | Meaning | May be shown as |
| --- | --- | --- |
| `saved` | A receipt exists (§3) | Saved locally |
| `pending` | Saved; at least one of its units is not accepted | Waiting to sync |
| `accepted` | Every unit of the batch is accepted by the server (below) | Accepted by the server |
| `evidence-unavailable` | The route's server does not promise durability 2 (LFCP-WIRE-01 §37), so no ACK can establish acceptance | Server confirmation unavailable |
| `rejected` | A unit of the batch received a terminal `NACK` | Not accepted, with the code |

A unit is accepted when an `ACK` correlated with the `DATA_PUT` that carried it names its Data Unit ID with `durable: true`, from a server whose `READY` advertised durability 2 or higher, on a route of the Resource's current route set (LFCP-WIRE-01 §37, §59). A send, an open socket, a heartbeat or the removal of an outbound entry is not acceptance.

A batch of several units reports `acceptedUnitIds`, the accepted subset of `unitIds`. It is `accepted` only when the subset is all of them; a consumer counts it as one pending batch until then, however many of its units are accepted.

"Accepted by the server" is a fact about the store of that server, not about other participants: an `ACK` does not mean another replica has the unit, and a server whose store is replaced by an older copy may have lost it (LFCP-WIRE-01 §37, §59, ADR 0008). §4.2 handles the loss.

A rejected batch carries its `operationId`, the unit IDs and the code. Its content stays in the local model and the adapter's source; the SDK never sends it again under a new identity.

### 4.2 Pending again

A lost `ACK` changes nothing: the unit stays queued, the same bytes are sent again, and the server acknowledges the duplicate (LFCP-WIRE-01 §70). The batch goes from `pending` to `accepted` once.

A server that loses a unit it had acknowledged is detected only after the unit left the outbound queue, by one of three signals:

| Reason | Signal |
| --- | --- |
| `unknown-previous` | A later unit is refused with `NACK(UNKNOWN_PREVIOUS)` naming the lost unit as its `previous` (LFCP-WIRE-01 §51.1) |
| `have-gap` | Anti-entropy finds the unit missing from the server's Have Vector and offers it again (§68.1) |
| `rehost` | The route answered `RESOURCE_NOT_HOSTED` and the client re-hosted the Resource (§41.1) |

The SDK then reports the units as `reoffered` with the reason (§5). Every local batch holding one of them returns to `pending`, and becomes `accepted` again by a new correlated `ACK` for those units. Returning to pending is not an error: the units are re-supplied automatically, and an adapter shows the batch as waiting to sync.

### 4.3 Received units and section state

These facts concern units received from others, never a local batch:

| Fact | Meaning |
| --- | --- |
| `held` | A change whose actor and sequence number another change holds (SHARED-OBJECTS-PROFILE-01 §14.1) |
| `waiting` | A change whose dependency has not arrived |
| `refused` | A change refused at admission, with its diagnostic (SHARED-SECTIONS-PROFILE-01 §14.1); the changes that depend on it are held behind it |

A section without `ready` is `importing` (SHARED-SECTIONS-PROFILE-01 §12.1). The adapter projects none of its content and creates no content in it. The creator's import is one operation (§3.1), so on the creator's device the section is `ready` from the moment that receipt exists; other participants see `importing` until the unit carrying `ready` arrives.

Model problems (structural and lifecycle conflicts, isolated nodes, colliding IDs, retained concurrent edits; SHARED-SECTIONS-PROFILE-01 §14.2, §14.3) are reported with the section snapshot. An `ACK` never clears one.

## 5. Events

The SDK reports facts as one event stream per Resource. Every event carries `revision`, an integer that increases by one with each event of that Resource in the SDK's session. It is a local sequence, not a shared clock.

| Event | Fields |
| --- | --- |
| `nodes-changed` | `nodeIds`, `origin`: `local`, `remote` or `rebuild`; `modelRevision` |
| `section-state` | `ready` or `importing` |
| `batch` | `operationId`, `status` (§4.1), `unitIds`, `acceptedUnitIds`, and `rejection: {code, unitIds}` when rejected |
| `reoffered` | `unitIds`, `reason`: `unknown-previous`, `have-gap` or `rehost` (§4.2) |
| `received` | `fact`: `held`, `waiting` or `refused`; the change or unit IDs; the diagnostic when refused |
| `rehost` | The route on which the Resource was hosted again |
| `access` | The new access state (§6) |

A consumer that sees a revision other than the next one has missed events. It asks for a complete state:

```text
statusSnapshot(resource) -> { revision, batches, received, section, access }
```

and until it has one, shows the affected status as unknown, never as current. Events whose revision is not above the snapshot's are ignored. Events of a Resource session the consumer no longer follows are ignored.

## 6. Write access

```text
canWrite(resource) -> { allowed, reason, controlHead, verifiedAt }
```

`allowed` comes from the validated Control state only, never from a cache of UI lists. `controlHead` is the Control Head it was validated at and `verifiedAt` the local time of that validation; together they are its freshness. `reason`, when not allowed, is one of `not-member`, `read-only`, `key-unavailable`, `revoked` or `unknown`. A batch submitted while not allowed is refused with `NOT_WRITABLE` (§3.6); the adapter keeps the edit as a local candidate.

## 7. Parser and adapter boundaries

The parser, source map, projection base, candidates, journal and patch writer are parts of the adapter. Only the intents and the receipt cross into the SDK. The names in this section are the shapes the contract needs; they are not existing SDK APIs.

### 7.1 Parser output

The parser is pure: source text in, the following out, with no network, model or file access.

| Output | Content |
| --- | --- |
| `sections[]` | Per section: its reference, the heading line, the start and end marker lines, and `nodes` |
| `SectionNode` | `kind` (`task`, `paragraph`, `item`, `raw`), `id` (or null when unbound), `lines` (its line range), `column` (its content column), `children`; sibling order is array order |
| `claimed` | The line ranges owned by section boundaries, valid or damaged: other parsers (such as the standalone Task ref parser of MARKDOWN-REFS-01) skip them |
| `localBlocks` | Comments kept local (MARKDOWN-SECTIONS-01 §4.5) |
| `privateTail` | Private text between an end marker and the next heading (MARKDOWN-SECTIONS-01 §3) |
| `diagnostics` | `{code, severity, line, detail}`, codes of MARKDOWN-SECTIONS-01 §14 |

A bound node is a node whose `id` is not null. A Task node's fields come from the Task line parser of MARKDOWN-REFS-01, and its ref placement from the ref scanner; the section parser does not repeat them.

### 7.2 Source map

The source map gives each node's Text as source segments, and translates between editor offsets (UTF-16) and the SDK's Text indices (Unicode scalar values) against a given source revision. It never carries an offset from one revision to another; a stale offset is rebased by the adapter or refused by the SDK (§7.5).

### 7.3 Projection base

A projection base is the last reconciled state of one projection: the `modelRevision` of the receipt or snapshot it was reconciled with, the source hash, and the tree with its node mapping. It is local and is never inferred from markers alone (MARKDOWN-SECTIONS-01 §11).

### 7.4 Candidates

An unbound node is a candidate:

```text
UnboundNode { kind, parent, after, text?, line }
```

`parent` is the bound parent, `after` the preceding bound sibling or null. A candidate gets an ID only inside a section that is ready, healthy and writable, and only when the editor transaction or the base shows it was inserted (MARKDOWN-SECTIONS-01 §7). The adapter allocates the ID and records it in its journal before the commit, so that a retry reuses it.

### 7.5 Intents

Intents are computed from the difference between the parsed source and the projection base, never from the source alone. A `text.edit` carries the base `modelRevision` its indices were computed against. The SDK rebases the edit onto the current Text when the Text changed only by known concurrent edits; otherwise it refuses with `STALE_BASE`, and the adapter recomputes from a new snapshot. It never applies old indices to different Text (SHARED-SECTIONS-PROFILE-01 §10).

### 7.6 Patches

The patch writer applies minimal source patches checked against the source revision they were computed for. A guard keyed by the `operationId` recognizes the adapter's own writes, so that they produce no intent; every other change, including another plugin's write, is reconciled as an edit.

### 7.7 Journal

The adapter's journal records each operation through its phases, for example:

```text
captured -> ids-allocated -> committed -> projected -> done | abandoned
```

An operation reaches `committed` with its receipt, and records the receipt's `modelRevision` as its new base. After a crash, an operation found before `committed` asks `receiptOf` (§3.4): a receipt moves it to `committed`; `none` lets it submit again with the same `operationId` and IDs. A `rejected` batch (§4.1) turns its operation into a rejected local candidate. `held`, `reoffered`, `rehost` and `importing` are inputs to status, not journal phases.

## 8. Contract examples

A provider (SDK) and a consumer (adapter) each test these cases against this contract.

| Case | Given | Expected |
| --- | --- | --- |
| Crash ambiguity | The process stops between `commit` and the journal's `committed` | After restart `receiptOf` returns the receipt; the adapter moves the operation to `committed` and projects the allocated IDs; no second change |
| Crash before commit | The process stops before the commit's transaction | `receiptOf` returns none; the adapter submits again with the same `operationId` and IDs; one change results |
| Retry with different intents | `commit` again with a used `operationId` and changed intents | `OPERATION_ID_REUSED`; nothing written |
| Lost ACK | The `ACK` for a batch's unit never arrives | The same bytes are sent again; the duplicate is acknowledged; the batch becomes `accepted` once |
| Stale revision | A `text.edit` against a base the SDK cannot rebase onto | `STALE_BASE`; no change; the adapter recomputes |
| Partial acceptance | An import of three units; the server acknowledges two | `pending` with two `acceptedUnitIds`; counted as one pending batch; `accepted` after the third |
| Server loss | An accepted unit is missing after a server restore | `reoffered` (`have-gap`, `unknown-previous` or `rehost`); the batch returns to `pending`, then `accepted` on the new `ACK`; no error shown |
| No durable server | The route's `READY` advertises durability below 2 | `evidence-unavailable`; never `accepted` |
| Event gap | The consumer receives revision 12 after 10 | It shows unknown, calls `statusSnapshot`, and continues from the snapshot's revision |
| Importing | A section without `ready` arrives from its creator | `section-state: importing`; nothing projected or created until the unit with `ready` arrives |
