# MVP-0.4-BASELINE

**OpenLFCP MVP 0.4 implementation baseline — NOT Stable LFCP-WIRE-01, NOT
full WIRE-01 conformance, documents remain Working Drafts.**

This file answers one question: *what exactly do I implement against for
MVP 0.4?* The answer is every file listed below, at the Git tag
`mvp-0.4-baseline.2` of this repository.

| Tag | Status |
| --- | --- |
| mvp-0.4-baseline.2 | **To be tagged.** `mvp-0.4-baseline.1` with clarified identity rules and added vectors (tasks LFCP-04-403b and LFCP-04-403c): LFCP-WIRE-01 §19 and §62 (the new epoch number of a `KEY_EPOCH` is a chain placement check, class 2; decision I9), §39 and §41.1 (every new hosting row is keyed by the Genesis owner, with or without field `5`; rows recorded before keep their host; decision I12), §41 (the revoked-reader replies to `RESOURCE_OPEN`, `CONTROL_GET` and presence) and §62 (a rejected pairing link is client-local); IDENTITY-PROFILE-01 §3 (admission rule AI5: `missing_keys` is written only by its device, decision I8; AI2 and AI5 decided on the causal history, hidden values included) and §5.2. Three published values change: the description of IDENTITY-PROFILE-TEST-VECTORS-01, and `READY_identity_01`, which was not a `READY` message (`migrations/mvp-0.4-baseline.2/value-changes.json`). |
| mvp-0.4-baseline.1 | Superseded by `mvp-0.4-baseline.2`, because the clarifications of LFCP-WIRE-01 §19, §39, §41 and IDENTITY-PROFILE-01 §3 change normative rules and `READY_identity_01` was not a `READY` message. Never moved. `mvp-0.2-baseline.12` plus multi-device root identity (ADR 0011, decisions I1 to I6): LFCP-WIRE-01 §7.1 to §7.3 (Root Identity, Device Principals, Device Certificates and certificate chains), §14 (Control Record types `9` `DEVICE_GRANT` and `10` `DEVICE_REVOKE`), §15 (Genesis field `5`), §17.1, §17.4 and §17.5, §23.3 (transfer commit field `2`), §25.2 (the same-root Key Package rule), §37 (the server extension `identity-01`), §41 (the Control read for a revoked reader), §62 (the ordering of the validation classes, normative for every Control Record), §79, §80.1 and §100.1; the profile IDENTITY-PROFILE-01 (`org.openlfcp.identity.v1`); and the three identity corpora of IDENTITY-PROFILE-01 §12 (task LFCP-04-403). One published value moves: `unknown_core_type_C1` uses the reserved type `31` instead of `9` (`migrations/mvp-0.4-baseline.1/value-changes.json`). |

- The listed specifications are Working Drafts. They keep their identifiers;
  nothing is renamed or declared Stable.
- Every file of `mvp-0.2-baseline.12` is part of this baseline, byte for
  byte, except the files that the Changes sections below list as changed.
  MVP-0.1-BASELINE.md and MVP-0.2-BASELINE.md keep describing their tags.
- A chain without device records keeps its authority semantics and
  encodings (LFCP-WIRE-01 §7.2 N1); the registry assignment of types `9`
  and `10` and the ordering of §62 are the only changes to how such a chain
  is checked, and they are recorded in `migrations/mvp-0.4-baseline.1/`.
- Software built on this baseline may say "Implements the OpenLFCP MVP 0.4
  subset of LFCP-WIRE-01". It must not claim full LFCP-WIRE-01 conformance.
- The decisions applied are those of `mvp-0.2-baseline.12` (ADR 0001 to
  ADR 0010) and [ADR 0011](adr/0011-human-root-identity.md).

## Pinning

Implementations pin the tag `mvp-0.4-baseline.2` of `openlfcp/spec`, never
a branch, in their `spec.lock`, and move to it from `mvp-0.4-baseline.1` or
`mvp-0.2-baseline.12` deliberately (IDENTITY-PROFILE-01 §11). An
implementation pinned to an earlier tag answers the codes recorded there.

A later approved Working Draft correction does not move the tag. It
produces a new tag, such as `mvp-0.4-baseline.3`, with an updated copy of
this file and a `migrations/mvp-0.4-baseline.N/` entry. Implementations
move to it deliberately.

## Canonical files

`./scripts/validate.sh` checks that every file listed here exists, and that
every file under `wire/`, `profiles/`, `integration/`, `test-vectors/`,
`schemas/` and `adr/` is listed (a path ending in `/` covers its whole
directory).

### Normative prose

| File | Role |
| --- | --- |
| `wire/LFCP-WIRE-01.md` | LFCP Wire protocol (Working Draft), with multi-device root identity (§7.1 to §7.3, §17.4, §17.5, §80.1, §100.1) |
| `profiles/SHARED-OBJECTS-PROFILE-01.md` | Shared Objects application profile `org.openlfcp.shared-objects.v1` (Working Draft) |
| `profiles/SHARED-SECTIONS-PROFILE-01.md` | Shared sections application profile `org.openlfcp.shared-sections.v1` (Working Draft 0.3, ADR 0009) |
| `profiles/IDENTITY-PROFILE-01.md` | Identity Resource profile `org.openlfcp.identity.v1` (Working Draft, ADR 0011): document, admission, pairing, reconciliation, revocation, durable operations, vectors |
| `integration/MARKDOWN-REFS-01.md` | Markdown projection reference grammar: inline and child-line placements (Working Draft) |
| `integration/MARKDOWN-SECTIONS-01.md` | Markdown bindings of shared sections (Working Draft) |
| `integration/SDK-SECTIONS-INTEGRATION-01.md` | SDK receipt, status and parser integration contracts for shared sections, `sections-integration/1` (Working Draft) |

### Test vectors

| File | Role |
| --- | --- |
| `test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json` | Wire vectors, machine-readable (`lfcp-vector-format/1`): byte-exact positives and negatives; not evidence for the identity model (IDENTITY-PROFILE-01 §12.1) |
| `test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.md` | Wire vectors, human-readable, with derivations |
| `test-vectors/lfcp-wire-01/generate_lfcp_test_vectors_01.py` | Generator; reproduces both Wire vector files byte for byte |
| `test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.json` | Wire identity vectors (IDENTITY-PROFILE-01 §12.2 ID-01 to ID-04), machine-readable: Device Certificates, chains, identity Control Records with their context chains and post-states, Data Units, Key Packages, Snapshots and reads |
| `test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.md` | Wire identity vectors, human-readable: fixtures, case tables with deciding rules, the Key Package matrix |
| `test-vectors/lfcp-wire-01/generate_lfcp_identity_test_vectors_01.py` | Generator, an extension of `generate_lfcp_test_vectors_01.py`; reproduces both identity vector files byte for byte |
| `test-vectors/lfcp-wire-01/identity_model.py` | The generator's reference model of LFCP-WIRE-01 identity validation; every verdict and post-state is computed by it and checked against the expectation written from the specification |
| `test-vectors/identity-01/IDENTITY-PROFILE-TEST-VECTORS-01.json` | Identity profile corpus (§12.2 ID-05), machine-readable: exact Automerge changes of the Identity Resource, admission AI0 to AI5, per-entry validation, pairing links, fingerprint, approval digest, rootOf tables |
| `test-vectors/identity-01/IDENTITY-PROFILE-TEST-VECTORS-01.md` | Identity profile corpus, human-readable |
| `test-vectors/identity-01/generate_identity_profile_vectors_01.mjs` | Corpus generator with its reference admission and validation; with the pinned `@automerge/automerge` 3.5.0 it reproduces both files byte for byte |
| `test-vectors/identity-01/IDENTITY-FLOW-FIXTURES-01.json` | Flow fixtures (§12.3; LFCP-WIRE-01 §107 style), machine-readable: 22 state-machine and durable-operation fixtures (the 19 of §12.3, F08 in three parts) whose steps name the cases of the two identity suites and form one Control history per Resource and branch |
| `test-vectors/identity-01/IDENTITY-FLOW-FIXTURES-01.md` | Flow fixtures, human-readable |
| `test-vectors/identity-01/generate_identity_flow_fixtures_01.py` | Fixture generator (Python standard library); reproduces both files byte for byte and checks every step outcome against the case it names |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json` | Shared Objects vectors, machine-readable: deterministic, validation and behavioral cases |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.md` | Shared Objects vectors, human-readable |
| `test-vectors/shared-objects-01/generate_shared_objects_test_vectors_01.py` | Generator; reproduces both Shared Objects vector files byte for byte |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json` | Automerge reference corpus for S01–S16 and its `validations`, `expansion`, `depth`, `collision`, `canonical` and `references` sections |
| `test-vectors/shared-objects-01/generate_automerge_reference_01.mjs` | Corpus generator; with the pinned `@automerge/automerge` 3.5.0 it reproduces the corpus byte for byte |
| `test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json` | Shared sections corpus, machine-readable |
| `test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.md` | Shared sections corpus, human-readable |
| `test-vectors/shared-sections-01/MARKDOWN-SECTIONS-FIXTURES-01.json` | Markdown fixtures of MARKDOWN-SECTIONS-01, machine-readable: before, event and after files |
| `test-vectors/shared-sections-01/MARKDOWN-SECTIONS-FIXTURES-01.md` | Markdown fixtures, human-readable |
| `test-vectors/shared-sections-01/markdown-files/` | The fixtures' files, extracted byte for byte |
| `test-vectors/shared-sections-01/generator/` | Corpus and fixture generators and reference verifiers; with the pinned `@automerge/automerge` 3.5.0 they reproduce both suites byte for byte |
| `test-vectors/shared-sections-01/schemas/` | JSON Schema of the Markdown fixtures (the corpus uses `lfcp-vector-format/1`) |

### Wire CDDL

| File | Role |
| --- | --- |
| `wire/LFCP-WIRE-01.cddl` | CDDL extracted from the body of `LFCP-WIRE-01.md` (generated) |
| `wire/LFCP-WIRE-01.summary.cddl` | CDDL of the Part XXVIII summary (generated; checked against the body) |
| `wire/LFCP-WIRE-01.supplement.cddl` | Typed signed-object, Control Record and message rules |
| `wire/README.md` | What the CDDL proves and what it leaves to validators |
| `wire/fixtures/` | CDDL fixture manifest and must-fail structural fixtures, among them the `invalid-device-*` fixtures of Device Certificates, `DEVICE_GRANT` and `DEVICE_REVOKE` |

### Schemas

| File | Role |
| --- | --- |
| `schemas/lfcp-vector-format-1.schema.json` | JSON Schema of the vector format every suite uses, with the optional deciding `rule` and `expected.post_state` |
| `schemas/README.md` | Vector format description, validator rules, conflict convention |
| `schemas/fixtures/` | Format examples and validator self-tests (not normative vectors) |
| `profiles/shared-objects-01/schema/shared-objects-state.schema.json` | Structural contract for Shared Objects logical state |
| `profiles/shared-objects-01/schema/README.md` | Contract coverage and enforcement table |
| `profiles/shared-objects-01/schema/fixtures/` | Valid and invalid state fixtures (not normative vectors) |

### Decisions

| File | Role |
| --- | --- |
| `adr/0001-mvp-0.1-protocol-decisions.md` | Project-owner decisions of 2026-10-05 applied to the Working Drafts |
| `adr/0002-mvp-0.1-protocol-decisions-2.md` | Second batch of project-owner decisions of 2026-10-05 (SPEC-PATCH-03) |
| `adr/0003-mvp-0.1-protocol-decisions-3.md` | Third batch of project-owner decisions of 2026-10-05 (SPEC-PATCH-04) |
| `adr/0004-mvp-0.1-protocol-decisions-4.md` | Fourth batch (SPEC-PATCH-05): G-DP1-GAP approved by the project owner; the other items are orchestrator decisions approved by the project owner on 2026-10-06 |
| `adr/0005-mvp-0.1-protocol-decisions-5.md` | Fifth batch (SPEC-PATCH-06): orchestrator decisions approved by the project owner on 2026-10-06 |
| `adr/0006-mvp-0.1-protocol-decisions-6.md` | Sixth batch (SPEC-PATCH-07): Automerge expansion limits, value nesting, the client receive limit |
| `adr/0007-mvp-0.1-protocol-decisions-7.md` | Seventh batch (SPEC-PATCH-08): the document depth bound |
| `adr/0008-recovery-after-server-data-loss.md` | SPEC-PATCH-09: recovery after server data loss (POST-013) and POST-001 |
| `adr/0009-shared-sections-profile.md` | The shared sections profile: decisions P1, P2, P3 and P5 |
| `adr/0010-canonical-changes-and-operation-references.md` | SPEC-PATCH-10: canonical change encoding and operation references (findings F2 to F4) |
| `adr/0011-human-root-identity.md` | Human root identity and device Principals: decisions I1 to I6 of the project owner (2026-11-03) and the clarifications I8 and I9 (2026-11-04), applied in this baseline |

## Validation

From a clean checkout with full history and tags:

```sh
pnpm install --frozen-lockfile
bundle install
./scripts/validate.sh
```

The checks are those of MVP-0.2-BASELINE.md, plus:

- vector values against the previous baseline tag, from the newest
  `migrations/mvp-0.M-baseline.N/value-changes.json`: for this baseline,
  `migrations/mvp-0.4-baseline.2/`, against `mvp-0.4-baseline.1`, every
  suite listed (for `mvp-0.4-baseline.1`, against `mvp-0.2-baseline.12`,
  with the three identity suites new);
- the identity suites, including `IDENTITY-FLOW-FIXTURES-01.json`:
  schema-valid, every hash recomputed (`scripts/validate-vectors.mjs`), and
  regenerated byte for byte (`scripts/check-identity-corpora.mjs`; the wire
  identity suite when `LFCP_PYTHON` names a Python with `cryptography`, as
  for the generator of LFCP-TEST-VECTORS-01; CI installs it and sets
  `LFCP_REQUIRE_ALL_CORPORA`, so the suite is never skipped there);
- this manifest's file list, as for MVP-0.1-BASELINE.md.

## Changes from `mvp-0.4-baseline.1` (`mvp-0.4-baseline.2`)

| Kind | Files |
| --- | --- |
| Changed, normative | `wire/LFCP-WIRE-01.md` §19 and §62: the new epoch number of a `KEY_EPOCH` is checked in class 2 (chain placement), after structure and before dependencies, signatures and authority (decision I9); §39, §41.1 and the §37 row of `identity-01`: a server that advertises `identity-01` keys every new hosting row by the Genesis owner, with or without Genesis field `5`, the session Principal never being the host of a new row; rows recorded before keep their host, the quota of a Principal counts every row whose recorded host or Genesis owner it is, each once, and a re-hosted Resource gets a new owner-keyed row (decision I12); §41: a revoked reader's `RESOURCE_OPENED` omits fields `4` and `5`, its `CONTROL_GET` returns accepted records only, trimmed at the revoking record and refused after it, and a server without `presence` answers it `PROTOCOL_UNSUPPORTED` like every session; §62: a rejected pairing link is a client-local outcome. `profiles/IDENTITY-PROFILE-01.md` §2.1 and §3: admission rule AI5, `devices[k].missing_keys` written only by the Principal `k` names (`UNAUTHORIZED_WRITER`, decision I8), decided like AI2 on the objects of the causal history, hidden, replaced and deleted values included; §5.2: a rejected pairing link has no wire code (`PAIRING_LINK_REJECTED` is a test convention); §11: the hosting key of W §39 |
| Changed, decisions | `adr/0011-human-root-identity.md`: the clarifications I8 and I9 |
| Changed, vectors | `test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.*`, its generator and `identity_model.py`: six `KEY_EPOCH` cases on the class of the epoch number; `READY_identity_01` re-encoded as a `READY` message (type `3`, profile `LFCP-WIRE-01`; two values change). `test-vectors/identity-01/IDENTITY-PROFILE-TEST-VECTORS-01.*` and its generator: the AI5 cases and scenarios (own, foreign, concurrent, hidden, deleted and replaced entry maps), the AI2 cases on a hidden entry value, and the suite description (AI0 to AI5; one value changes) |
| Added, migration | `migrations/mvp-0.4-baseline.2/` |

## Changes from `mvp-0.2-baseline.12` (`mvp-0.4-baseline.1`)

| Kind | Files |
| --- | --- |
| Changed, normative | `wire/LFCP-WIRE-01.md` §7.1 to §7.3, §14, §15, §17.1, §17.2, §17.3, §17.4, §17.5, §18.1, §19, §23.1, §23.3, §25.2, §26.3, §37, §41, §62, §79, §80.1, §84, §100.1, §107, §108.1: multi-device root identity; `wire/LFCP-WIRE-01.cddl`, `wire/LFCP-WIRE-01.summary.cddl` and `wire/LFCP-WIRE-01.supplement.cddl` with the device certificate, chain, `DEVICE_GRANT` and `DEVICE_REVOKE` rules |
| Added, normative | `profiles/IDENTITY-PROFILE-01.md`, `adr/0011-human-root-identity.md` |
| Changed, editorial | `profiles/SHARED-SECTIONS-PROFILE-01.md` §12.2 and `adr/0009-shared-sections-profile.md`: a Principal has exactly one writing installation (IDENTITY-PROFILE-01 §11) |
| Changed, vectors | `test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.*` and its generator: `unknown_core_type_C1` uses type `31` (the one value change); `wire/fixtures/` gains the `invalid-device-*` must-fail fixtures |
| Added, vectors | `test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.{json,md}`, `generate_lfcp_identity_test_vectors_01.py`, `identity_model.py`; `test-vectors/identity-01/` (IDENTITY-PROFILE-TEST-VECTORS-01, IDENTITY-FLOW-FIXTURES-01 and their generators) |
| Changed, format | `schemas/lfcp-vector-format-1.schema.json` and `schemas/README.md`: an optional deciding `rule` on every case and an optional `expected.post_state` on a validation case; `scripts/validate-vectors.mjs` also checks `*-FLOW-FIXTURES-*.json` suites and recomputes certificate IDs, payload digests and the IDs of validation cases' objects |
| Added, checks | `scripts/check-identity-corpora.mjs` (run by `scripts/validate.sh`); `.github/workflows/ci.yml` installs `cryptography` for it |
| Added, migration | `migrations/mvp-0.4-baseline.1/` |
