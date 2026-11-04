# ADR 0011: Human root identity and device Principals

- **Status:** Accepted. Decisions I1 to I6 taken by the project owner on
  2026-11-03, the clarifications I8 and I9 on 2026-11-04; the normative
  details by the orchestrator, after three independent reviews of the
  specification draft. Applied in this text
  (LFCP-WIRE-01 §7.2, §7.3, §17.4, §17.5, §80.1, §100.1 and
  IDENTITY-PROFILE-01); in no implementation baseline yet (the baseline
  `mvp-0.4-baseline.1` follows with the identity corpora, LFCP-04-403).
- **Proposed by:** the orchestrator for MVP 0.4 (task LFCP-04-401).
- **Supersedes:** nothing. **Resolves:** LFCP-WIRE-01 §108.1 (multi-device
  root identity, deferred since WIRE-01). **Reworded:** ADR 0009 and
  SHARED-SECTIONS-PROFILE-01 §12.2 ("several devices of one Principal").

Citations: `W` is `wire/LFCP-WIRE-01.md`, `IP` is
`profiles/IDENTITY-PROFILE-01.md` (this repository, this revision).

## Context

A Principal is one installation (W §7.1): its keys and its actor sequence
state live in one vault, one headless process or one browser profile, and
two installations writing as one Principal equivocate (W §26.2). A human
with a desktop, a laptop, a phone and a bridge process is therefore four
Principals that collaborators see as four members, that are invited and
removed one by one, and that cannot share Resource keys without
`key/distribute`. The next planned bridge (a standalone process with its
own store) made the gap concrete: it needs a Principal of its own, scoped
to a few Resources, that is still the human's.

Two proposals were merged into one draft, reviewed three times. The
decisions below settle what the owner chose; the sections cited say how.

## Decisions

| ID | Decision | Where |
| --- | --- | --- |
| I1 | The full model now: a Root Identity (an ordinary Principal) and Device Principals tied to it by signed Device Certificates, authority inside each Resource's own Control Chain. No self-invitation step first; the bridge adapter itself is the next MVP. | W §7.2, §7.3, §17.4, §17.5, §80.1 |
| I2 | The root key lives on the first installation; a root key kept off every device is deferred. | W §7.2 N6, §108.1 |
| I3 | Any managing device (`device/manage`, ability `12`) adds devices, not only the root; chains of at most four certificates, managing chains of at most three; revoking a managing device suspends what it certified (cascade), and re-certification restores it. | W §7.3 c3, c4, c7; §17.5 |
| I4 | Revocation is `DEVICE_REVOKE` plus an epoch rotation by whoever can rotate and distribute; a terminal cut of a revoked device's exact units, which would change W §26.2, is not done. | W §17.5, §19, §108.1; IP §8 |
| I5 | No recovery kit, recovery codes or key backups in this MVP; the formats keep room for them. | W §7.3 reserved values, §108.1; IP §2.4 |
| I6 | Service devices (kind `1`) and headless pairing are in; a herald client release at least one release and two weeks before the release that pairs, the public server updated first; the presets Full, Edit, Read and Service; automatic rotation by the owner's client on an exposing revocation; server hosting quotas keyed by the Genesis owner; assignees as references to the root. | W §37, §39, §100.1; IP §5.4, §8.4, §10, §11 |
| I8 | `missing_keys` in a device entry of the Identity Resource is written only by that device; a write by any other writer is refused at admission (`UNAUTHORIZED_WRITER`), not only avoided by honest writers. | IP §2.1, §3 AI5 |
| I9 | The new epoch number of a `KEY_EPOCH` is a chain placement check (`INVALID_CONTROL_CHAIN`, class 2), run before dependencies, signatures and authority. | W §19, §62 |

Orchestrator decisions inside those (one line each): a certificate is a
seven-element array under the label `LFCP-DEVICE-CERT-v1` with kind, mask,
scope and a random serial; kind, mask and scope never change for a pair
`(root, device)` (N8), so a change of access is a new Principal; a mask
with `12` lists `1` and `2`; a kind-2 pairing device, scoped to the
Identity Resource, is consumed by a `DEVICE_REVOKE` with reason `3` that
carries the digest of the certificate payload before that certificate is
signed (N9), and the `DEVICE_GRANT` that follows proves the digest; a
service device is bound in the Identity Resource but never registered
there, and reconciliation reads its chain from that Control state; roles
`device` and `non-device` are exclusive in every transition; every device
of an accepted chain is bound, the leaf registered when its scope admits
the Resource; `rootOf` attributes history to the human, revoked devices
included; the Key Package rule admits a sender of the same root; a
revocation is exposing when it removes a registered reader, directly or
through the cascade, and only an exposing revocation rotates; an
`identity-01` server lets a revoked reader read the chain prefix through
its revocation, and checks uploads by object; the validation classes are
ordered (structure, placement, dependencies, signatures, authority) for
every record; no new error code, `24` kept free; the Identity Resource's
initial change creates six root keys and is identified by actor, sequence
`1` and empty dependencies.

## Alternatives considered

- **Self-invitation first** (invite one's own second installation as a
  separate member, the full model later): cheaper, but collaborators keep
  seeing several members per human and the bridge still cannot be scoped;
  rejected by I1.
- **A root key kept off every device, with a recovery code** from the
  start: safer against the loss of the first installation, but needs
  recovery material and a "harden identity" flow; deferred by I2 and I5
  with the label, key and HKDF reservations that keep it possible.
- **Only the root adds devices**: simpler cascade, but every pairing needs
  the first installation present; rejected by I3.
- **A terminal cut** of a revoked device's exact units (a cutoff frontier
  in `DEVICE_REVOKE` field `3`, changing W §26.2): closes the historical
  equivocation window, but adds a validation input and a new error code;
  deferred by I4 with field `3` and code `24` reserved and rejected.
- **An identity chain outside the Resources**, with checkpoints imported
  into each Resource: one place to revoke, but validation would fetch
  another Resource (against W §3.3) and would need a global cut; rejected
  for N3.
- **A separate human identifier** distinct from the root Principal ID:
  rejected; the root is a Principal, and type `11` is reserved for
  succession.
- **A service device's scope as profile data** rather than a signed
  certificate field: rejected after review, since a scope must be
  cryptographic, not data a manager could edit.
- **A new wire profile identifier** (`LFCP-WIRE-02`): rejected; the
  additions use reserved core space and old clients fail closed at the
  barrier (W §100.1).
- **Bidirectional pairing with a relay channel and proof of possession**:
  rejected for a one-way link that carries a throwaway pairing device,
  with the fingerprint compared by the human and a two-phase approval that
  never lets a certificate travel in a proposal that can lose.
- **A minimal device ceiling unlocked by the root** instead of presets:
  rejected by I6.

## Consequences

- Both reference SDKs implement the derived state `roles`, `devices`,
  `revoked` and `issuer_root`, the chain verification, the device records,
  `holds`/`ownerAction`/`actsFor`/`rootOf`, the same-root Key Package rule
  and the Identity Resource profile; the reference server advertises
  `identity-01`, keys hosting by the Genesis owner and serves the
  revoked-reader prefix.
- Pre-identity clients are blocked whole at the first device record of a
  Resource (W §14, §100.1); the rollout order of I6 limits that to humans
  who pair.
- Two legacy rejection outcomes are reclassified, by the registry change
  and by the class ordering; one published vector changes, in three
  recorded values (`unknown_core_type_C1`, type `9` to `31`), and no
  published baseline vector covers the malformed transfer case.
  `migrations/mvp-0.4-baseline.1` records both.
- Revocation is per Resource (N3): a certificate stays verifiable where
  the revocation has not been seen, which W §98.1 states as a limit. A
  stolen first installation is identity compromise, as owner compromise is
  today (W §98).

## Value changes

`migrations/mvp-0.4-baseline.1/value-changes.json`: three values of
`unknown_core_type_C1` (description, mutation target, signed bytes), with
the decision. The identity corpora are new suites.

## Open items

- The three corpora of IP §12 with their generators (LFCP-04-403) and the
  third independent review of text and corpus before implementation
  starts.
- Whether `IDENTITY_SUCCESSION` (type `11`) and the cold root (W §108.1)
  come together in one later MVP.
