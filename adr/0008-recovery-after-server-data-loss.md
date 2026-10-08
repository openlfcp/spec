# ADR 0008: Recovery after server data loss

- **Status:** Accepted by the project owner on 2026-10-08: option (c),
  with (d) deferred (see Decision). Applied in `mvp-0.1-baseline.9`
  (SPEC-PATCH-09), together with POST-001.
- **Proposed by:** Worker2 for the orchestrator, 2026-10-06 (POST-013 in
  `.github: docs/BACKLOG-MVP-0.1.md` §6).
- **Supersedes:** nothing. **Related:** POST-001 (hold and retry of
  Automerge (actor, seq) collisions,
  `.github: docs/release/open-decision-actor-seq-collision.md`).

Citations: `W` is `wire/LFCP-WIRE-01.md`, `P` is
`profiles/SHARED-OBJECTS-PROFILE-01.md` (this repository); `TS` is
`sdk-ts@98519b5`, `RS` is `sdk-rs@c9132b1`, `SV` is `server@d6cd820`
(`crates/lfcp-server/src/`).

## Context

### The drill

A restore drill of the public sync server (2026-10-06, recorded in
`devbox-asstnt: stacks/openlfcp/README.md` and
`.github: docs/operations/sync-server-runbook.md`) restored the server's
SQLite store from a backup taken while it ran:

1. Alice (lfcp-todo over sdk-ts) wrote units 1–3; the backup was taken; she
   wrote unit 4, which the server acknowledged.
2. The server was destroyed and restored: units 1–3 came back, 4 did not.
3. Alice synced: nothing was re-sent. She wrote unit 5 (`previous` = 4); the
   server accepted it. The server then held Alice's 1, 2, 3, 5.
4. Bob joined and stopped at Alice's unit 5 with `NO_PROGRESS` on every
   round, seeing neither 4 nor anything Alice writes later.

A restore from a daily backup therefore loses recent writes **and** can
stop other replicas permanently. The public server's terms already say
data may be lost; the stall is the part no user can work around.

### What the server loses

Everything stored after the backup, kind by kind (`SV store/schema.rs`):

| Lost | Effect today |
| --- | --- |
| Data Units | The writer still holds them as accepted; readers that fetched them before the loss hold them too. Nobody re-sends them (below). A later unit of the same actor is accepted over the gap, and every replica that lacks the lost unit holds the later ones forever: the wedge |
| Control Records | Clients that fetched them hold a longer chain than the server. sdk-ts classifies the server as `peer-behind` and ignores it (`TS packages/wire/src/control-sync.ts:29-30, 66-74`; `packages/client/src/sync-client.ts:751-752`). If someone then proposes a new record at the lost sequence, the server's chain and the holders' chain diverge: holders see `DIVERGED`, store a conflict and enter `FORK` (`control-sync.ts:64-71`, `sync-client.ts:764-770, 821-826`) — indistinguishable from a malicious server's rollback (W §94) |
| Key Packages | The sender dequeued them on ACK. A reader that has not fetched its package yet stays `KEY_BLOCKED` for that epoch, retrying forever (`sync-client.ts:911-983`) |
| Snapshots | Harmless: clients fall back to the units (`sync-client.ts:739-741`) |
| Hosting rows, whole Resources | A Resource hosted after the backup is gone with its Genesis; its clients get `RESOURCE_NOT_HOSTED`. Whether a client re-hosts by itself is not established (open question 4) |

The server's durability promise (W §37, level 2 "durable local
persistence") does not survive a restore of an older store; an ACK
(W §59, line 2239) means only that the receiver accepted the object.

### Why nothing re-sends today

- **sdk-ts drops own objects from the outbound queue on ACK** and never
  sends them again (`TS packages/client/src/outbound.ts:49-52, 468-490`).
  The only memory of acknowledged objects is a 256-entry `recentlyAcked`
  list that nothing compares with the server (`outbound.ts:491-506, 724`).
  This matches W §86, which requires a client to persist only "local Data
  Units not yet acknowledged by any route" (line 2923), and W §88, whose
  reconnect uploads only queued units (line 2961).
- **Anti-entropy is pull-only.** `RESOURCE_OPENED` and `DATA_HAVE` set the
  remote Have (`sync-client.ts:638, 686-687`), and its only use is
  "the units the remote holds that the local replica does not"
  (`TS packages/wire/src/have.ts:313-327`; `sync-client.ts:1173, 1224`).
  The opposite difference is never computed. W §68 has both peers exchange
  Have Vectors, but its example and §69 (line 2470) describe pulling.
- **sdk-rs has no sync client** (`RS crates/lfcp/src/lib.rs:7-30`). Its
  `have::difference` already returns the `offer` side ("ranges we hold and
  the peer does not", `RS wire/have.rs:235-252`) and `control_sync` a
  `PeerBehind` ("we could offer records with CONTROL_BATCH",
  `RS wire/have.rs:276-327`); nothing uses either for pushing.
- **The server checks no sequence or `previous` link on DATA_PUT**: "actor
  hash chain gaps (§26.2) are the sync engine's" (`SV ingest.rs:18-21`;
  the store inserts `previous_id` unchecked, `SV store.rs:476-508`).

### Why the reader stalls

Bob fetches unit 5. Its `previous` names unit 4, which Bob has not
accepted, so §26.2 holds it "until it links" (W line 1212; `TS
packages/wire/src/data-unit.ts:582-641`, status `GAP`). A held unit is not
a holding (W §70), so the next round asks for the same range and reports
`NO_PROGRESS` (`sync-client.ts:1181-1196`). The profile would block it too:
the change in 5 depends on the change in 4 (P §14.1). §26.2's allowance for
holes (W line 1204, 1208) does not apply: it covers a writer that abandons a
sequence and names its latest *accepted* unit, not a predecessor that
existed and vanished.

### Facts that make recovery possible

- **Any session may upload another Principal's objects.** The server
  validates the object, not the uploader: DATA_PUT checks the actor's
  signature, `data/write` at the referenced head and the cutoff, never the
  session Principal (`SV session.rs:783-871`, `ingest.rs:45-63`); the same
  holds for CONTROL_PUT, which must extend the head and be authorized for
  its issuer (`SV coordinator.rs:380-444`), KEY_PACKAGE_PUT (sender holds
  `key/distribute`) and SNAPSHOT_PUT (`SV session.rs:935-994`,
  `ingest.rs:66-89`). W does not restrict uploads to the author (§51 lists
  checks on the actor, not the uploader) and explicitly lets a client
  "seed or mirror another server" with historical Control Records (W §46,
  line 1967).
- **Re-uploading identical bytes is idempotent everywhere.** The server
  stores with `INSERT OR IGNORE` and ACKs a duplicate like a new object
  (`SV store.rs:90-98, 490-503`; `session.rs:927-931`); it pushes only new
  units live (`session.rs:914-926`). Clients classify the same unit ID as
  `duplicate` (`TS data-unit.ts:542-544`). Equivocation needs a
  *different* ID at the same (actor, seq) (`TS data-unit.ts:166-177, 385-399`;
  `RS wire/data_unit.rs:425-434`; `SV session.rs:873-909`).
- **Every replica keeps what it accepted.** Clients store accepted units,
  the Control Chain and their own Key Packages' DEKs locally (W §86).

## Options

### (a) Client push: reconcile in both directions

On every (re)connect, and whenever the server's Have arrives, a client
computes **local minus remote** as well as remote minus local, and uploads
what the server lacks:

- **Data:** for each actor, the accepted units the client holds that the
  server's Have lacks (`have::difference`'s `offer`), in sequence order,
  oldest first, before any newly queued unit. The client pushes its own
  units **and other actors' accepted units** (relay); it never pushes held,
  quarantined or excluded units.
- **Control:** when the server is `peer-behind`, the client sends the
  missing records in order (CONTROL_PUT, or CONTROL_BATCH per §46), before
  proposing anything new.
- **Key Packages:** a client that holds a package addressed to it, or that
  sent one, re-uploads it when a `KEY_PACKAGE_GET` for that epoch comes back
  empty for anyone. Simplest: the sender keeps its packages and re-puts
  them on `peer-behind`/missing-data detection; recipients keep theirs.
- **Snapshots:** not needed; optional re-put by the publisher.

Wire: no new message. Spec: §68–§70 (anti-entropy is bidirectional and
includes upload), §86 (keep accepted units and own Key Packages after ACK;
they already are, as replica state), §88 (step: "offer what the route
lacks"), §46 (relay of Control Records is the general rule), §51/§84 (any
session may upload validly signed objects).

- **Cost on reconnect:** the Have comparison already happens; the extra is
  one set difference per actor. In normal operation the server lacks
  nothing and nothing is sent.
- **Privacy:** none new. The server sees only objects it already held, and
  their metadata is visible anyway (actor, seq, epoch).
- **Abuse and quotas:** re-uploads count against the hosting Principal's
  quota and the per-connection message rate (POST-003). A relay cannot
  forge (signatures) or amplify beyond what the server lacks; a duplicate
  costs one ACK. Batching into one DATA_PUT per round keeps it within
  `ws_messages_per_second`.
- **Coverage:** heals data, Control Records and Key Packages that **any**
  connected client still holds, including those of an author who is
  offline or gone. Does not prevent the wedge forming before the healing
  client connects.
- **Equivocation (POST-001):** relaying identical bytes cannot create
  equivocation. Relaying a *second* unit for a slot (equivocation evidence
  the client holds) is refused by the server with `ACTOR_EQUIVOCATION`; for
  a relayed unit that NACK is expected, not an alarm (today the queue
  treats it as one, `TS outbound.ts:584-588`). Held units (POST-001 B) are
  not holdings and are never relayed.

### (b) The server refuses a dangling `previous`

A server rejects a Data Unit whose `previous` is neither `null`, nor a unit
it stores for that actor, nor covered by a Snapshot frontier it stores,
with a defined error. The writer reacts by uploading its own units from the
named predecessor onwards, then retrying.

- **Wire:** reuse `MISSING_DEPENDENCY` (15), extending its definition (W
  §26.3, line 1238) to "a Data Unit whose `previous` the receiver does not
  hold"; or a new code from the reserved 23–127 (W §62). Reuse is cheaper;
  a new code is more precise for clients that already treat 15 as "fetch
  the Control Head".
- **What the server sees:** actor, sequence and `previous` are plaintext
  metadata it already indexes (`SV store/schema.rs:49-58`); no privacy
  change.
- **Legitimate gaps stay legal.** The rule is about the *link*, not
  sequence contiguity:
  - an abandoned or equivocating sequence N (W line 1204): N+1 names N−1,
    which the server holds;
  - equivocation: the server stores both units as evidence, so either can
    be a predecessor;
  - a cutoff (W §19.1): units beyond the final frontier are already refused
    with `STALE_DATA_EPOCH`, and re-issued work names a unit the server
    holds;
  - a writer bootstrapped from a Snapshot names its own units, which the
    server holds; units covered by a stored Snapshot are accepted without
    their link, as receivers do (W §29.3).
  A server that pruned units would have to keep their IDs; this server
  prunes nothing.
- **Cost:** one indexed lookup per unit. **Abuse:** none new; a refused
  unit costs the sender a round trip.
- **Coverage:** prevents the wedge from forming whenever the writer is the
  one who writes next, and makes the writer heal its own history. Does not
  recover units whose writer never writes again, nor Control Records or
  Key Packages.

### (c) Both

(b) stops the server from accepting a broken chain; (a) heals from any
holder. Together: the writer's next unit cannot wedge readers, and any
client that connects re-supplies what the server lost, for all object
kinds.

### (d) A store generation (restore marker)

The server announces a store generation in `READY` (a new optional field,
W §37): a random value created with the store and replaced by the operator
when restoring (`lfcp-server --mark-restored`). A client that sees a new
generation for a server runs a full upload reconciliation (a) at once, and
treats a `peer-behind` Control Chain as the expected effect of a restore,
not as a rollback attack; before proposing new Control Records it first
pushes what it holds.

- **Wire:** one optional READY field; §37, §88, §94 (what a client may
  conclude from a rollback).
- **What it cannot do:** the server cannot detect its own rollback; the
  marker depends on the operator. Clients can detect lost data without it
  (the server's Have lacks units it once acknowledged), so for data (a)
  suffices; the marker matters for Control Records, where "server behind"
  is otherwise ambiguous, and for telling users.
- **The Control race remains:** if a client that never saw a lost record
  proposes a new one before any holder reconnects, the chain forks. Fork
  handling (coordinator recovery, W record types 7/8) is refused in MVP 0.1
  (`SV coordinator.rs:13`). A server in a fresh generation could refuse new
  CONTROL_PUT proposals (not re-uploads of records it can validate as the
  continuation of its head) for a grace period, but it cannot tell a
  re-upload of a lost record from a new proposal by bytes alone; any rule
  here needs its own design.

### Not chosen

- **Clients keep their outbound queue after ACK, forever.** Equivalent to
  (a) for own objects only, without relay, at the cost of unbounded queues.
- **Servers never lose data.** Continuous replication of the store
  (Litestream-style streaming of the SQLite WAL to object storage) shrinks
  the loss window from a day to seconds and is worth doing operationally,
  but it is not a protocol guarantee and does not help a server that loses
  its replica too.

## Decision

The project owner accepted the recommendation below on 2026-10-08. The
open questions were answered by the orchestrator, as the owner delegated:

1. **(c), with (d) deferred.** Yes.
2. **Code.** A new code, 23 `UNKNOWN_PREVIOUS` (W §62), not
   `MISSING_DEPENDENCY`. A 0.1.1 sdk-ts client parks a unit refused with
   `MISSING_DEPENDENCY` until its next Control sync and then sends it
   again, every round (`TS packages/client/src/outbound.ts:616`); an
   unknown code takes its retry-with-backoff path instead. Both SDKs
   decode any error code. The `NACK` details are the 32-byte `previous`
   (W §51.1, §60).
3. **Relay.** Any authenticated session may upload a validly signed
   object; the server authorizes the object, not the uploader (W §84).
   This is the server's behaviour already. Restricting relay to members
   with `data/read` would fail exactly after a loss, when the server may
   not know the relaying member's grant until the Control Records come
   back. Because a put is all-or-nothing, a client uploads each actor's
   units in ascending order and an equivocating unit only on its own
   (W §68.1).
4. **Re-host.** Automatic, in the SDK, with no user command: a client
   that holds the Genesis re-hosts a Resource when a route of its current
   route set, which it has seen host the Resource, answers
   `RESOURCE_NOT_HOSTED` (W §41.1). A refusal (`HOSTING_DENIED` and the
   like) is shown to the user and not retried automatically.
5. **Launching the public server as a POC with this limitation** stays
   with the project owner (`.github: docs/BACKLOG-MVP-0.1.md`,
   LAUNCH-003).

**Known limitation (open).** Neither the server nor `lfcp-admin` can
remove a hosted Resource today. If an operator removal is added, it must
leave a lasting refusal (`RESOURCE_TOMBSTONED`, or a denylist the
server answers with `HOSTING_DENIED`): a missing Resource is otherwise
indistinguishable from a lost one, and clients re-host it.

### The recommendation

**Adopt (c): bidirectional reconciliation with relay (a), plus the server
refusing a dangling `previous` (b). Defer (d) to a separate design together
with Control Chain fork recovery.**

- (a) heals every object kind from whichever client still holds it, with no
  new message, and costs nothing when nothing is lost.
- (b) is one lookup on the server and closes the window in which the wedge
  forms.
- Control Record loss stays fail-safe without (d): holders push the missing
  records on connect; a fork that still happens blocks security-sensitive
  actions instead of silently diverging. Fork recovery is its own problem.
- (d) is cheap on the wire but only useful with a Control-race rule, which
  needs its own design.

### Spec work (SPEC-PATCH-09, applied in `mvp-0.1-baseline.9`)

- W §68–§70: anti-entropy is bidirectional; a peer offers what the other
  lacks, own and relayed, oldest first per actor; relayed units are
  accepted units only.
- W §86: a client keeps its accepted units, Control Chain and the Key
  Packages it sent or received as long as it keeps the Resource (state it
  already holds), and may re-upload them.
- W §88: after "upload locally queued valid Data Units", "offer what the
  route lacks".
- W §51 and §84: any authenticated session may upload a validly signed
  object; the server authorizes the object, not the uploader. W §46's relay
  sentence generalizes to all persistent objects.
- W §26.3 / §62: the dangling-`previous` rejection and its code.
- W §37: an ACK's durability holds for the store that gave it; a restored
  store may have lost acknowledged objects, which peers re-supply.
- A note in W §94: a server that is behind is not necessarily malicious;
  clients re-supply before concluding anything.

### Vectors and tests

- **Wire vectors:** a DATA_PUT whose `previous` the receiver does not hold →
  the chosen NACK; one whose `previous` is an equivocation-evidence unit →
  accepted; one covered by a stored Snapshot frontier → accepted.
- **Have vectors:** `offer` (local minus remote) for contiguous and ranged
  Have Vectors, including holes, in both SDKs.
- **Live interop test reproducing the drill** (sdk-ts client, the real
  server process, its state directory copied with SQLite's online backup):
  1. A hosts a Resource and writes units 1–3; B joins; back up the store.
  2. A writes 4; A also grants C (a Control Record) and sends C its Key
     Package; B fetches 4.
  3. Stop the server, restore the backup, start it.
  4. Expected, case by case:
     - A reconnects first and writes 5: the server refuses 5 until A has
       re-uploaded 4 (b), then holds 1–5; B converges.
     - A stays offline; B reconnects: B relays A's unit 4 (a); a new
       reader D converges on 1–4 without A.
     - The grant to C and C's Key Package come back from whichever of A, C
       reconnects first; C is not `KEY_BLOCKED`.
     - No `NO_PROGRESS` loop and no `FORK` in any case.
  5. Variant: the Resource itself was hosted after the backup → its owner
     re-hosts it with its Genesis and re-uploads the rest.
- sdk-rs gains the same `offer` use when it gets a sync client; until then,
  its vectors cover the Have difference and the server rule (sdk-rs is the
  server's validation library).

### Also applied in `mvp-0.1-baseline.9`: POST-001

The same baseline applies the project owner's decision of 2026-10-06 on
two Automerge changes with the same actor and sequence number, option B,
hold and retry (`.github: docs/release/open-decision-actor-seq-collision.md`,
POST-001 in `.github: docs/BACKLOG-MVP-0.1.md` §6). It concerns the same
actor history as this ADR, so it ships with it rather than in an ADR of
its own:

- P §14.1: a replica never merges two different changes with one actor
  and sequence number. It holds the later one (not merged, not
  profile-invalid, its Data Unit still accepted) and retries it after
  every rebuild that removes changes. P §9 points to it.
- Vectors: the Automerge reference corpus `collision` section.

A unit whose change is held this way is LFCP-accepted, so it is a
holding and may be relayed (W §68.1); a unit held for its `previous`
link (W §26.2) is not.

## Interim guidance (until this ships)

For the operator of a server that restores a store:

1. **Restore only for a lost machine**, not to undo a mistake: a restore
   loses every write after the backup and, with the 0.1.0 SDK clients, can
   stop collaborators for good.
2. **Shorten the window.** Back up more often than daily, or stream the
   SQLite WAL off the machine continuously, so that less is lost.
3. **Announce it** to users with the backup's time T: changes made after T
   may be missing on the server; a collaboration edited after T may stop
   syncing for some members ("no progress"), and new edits to it make that
   worse for the others.
4. **What users can do today:** keep their vaults (they hold the full
   data). For a collaboration that stalls, the owner creates a new
   collaboration and shares the tasks into it again, and members join the
   new one; the old one is abandoned. There is no client command that
   re-sends acknowledged units.
5. **Record** the restore (time, backup used, Resources affected if known)
   for later diagnosis.

## Consequences

- If adopted: both SDKs gain an upload side to anti-entropy and relay;
  the server gains one rule and one NACK; the reconnect procedure grows a
  step. Normal operation is unchanged in cost.
- The public server can leave POC/beta status only after this ships (the
  orchestrator's recommendation; the decision is the project owner's).
- Until then, a server restore is a known limitation, stated in the
  server's terms ("data may be deleted") and its runbook.

## Open questions for the project owner

1. Accept the recommendation (c), with (d) deferred?
2. `MISSING_DEPENDENCY` reused, or a new code for a dangling `previous`?
3. Relay: allow any session to upload another Principal's objects as a
   rule of the protocol (it is the server's behaviour today), or restrict
   relay to members with `data/read` on the Resource?
4. Does a client re-host a Resource whose Genesis the server lost, or does
   it need a command? (Not established from the code; the live test will
   tell.)
5. Launch the public server as a POC with this limitation (the
   orchestrator's recommendation), and invest operationally in continuous
   WAL streaming meanwhile?
