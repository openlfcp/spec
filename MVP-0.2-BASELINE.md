# MVP-0.2-BASELINE

**OpenLFCP MVP 0.2 implementation baseline — NOT Stable LFCP-WIRE-01, NOT
full WIRE-01 conformance, documents remain Working Drafts.**

This file answers one question: *what exactly do I implement against for
MVP 0.2?* The answer is every file listed below, at the Git tag
`mvp-0.2-baseline.5` of this repository.

| Tag | Status |
| --- | --- |
| mvp-0.2-baseline.6 | **Prepared, not tagged.** `mvp-0.2-baseline.5` with SHARED-OBJECTS-PROFILE-01 §11.3 rule 2 bounding header numbers: the sequence number is below 2^53 and the time between -2^53 and 2^53 (finding D2); §14.1 and SHARED-SECTIONS-PROFILE-01 §14.1 check a change's bytes when it arrives, before its actor and whether or not its dependencies are present. SHARED-OBJECTS-PROFILE-01 §14.1 also allows an Automerge author only in an actor's first change (finding D5), and SHARED-SECTIONS-PROFILE-01 A5 refuses Text in every field of the section, a node (but its `text`) and a placement, and anywhere in a Task (finding D3). The Automerge reference corpus gains five `canonical` cases, the shared sections corpus SS66 to SS75; no vector value changes (`migrations/mvp-0.2-baseline.6/value-changes.json` lists no change). |
| mvp-0.2-baseline.5 | **Current.** `mvp-0.2-baseline.4` with SHARED-OBJECTS-PROFILE-01 §11.3 rule 8 clarified: the start op is below 2^32 even for a change without operations; and §11.4 R8 to R10: an increment names only the counter puts it adds to, no operation is a mark and none makes a table (finding D1). The Automerge reference corpus gains `CAN-8-start-op-empty` and eight references cases; the shared sections corpus gains SS64 (a table, refused) and SS65 (a section created with `ready = false`, refused: SHARED-SECTIONS-PROFILE-01 §12.1 binds the creating change, finding D4). SDK-SECTIONS-INTEGRATION-01 §5 says which nodes a `nodes-changed` event lists: those of the `affectedNodeIds` rule, for every origin; no vector value changes (`migrations/mvp-0.2-baseline.5/value-changes.json` lists no change). |
| mvp-0.2-baseline.4 | Superseded by `mvp-0.2-baseline.5`, because SHARED-OBJECTS-PROFILE-01 §11.3 rule 8 and §11.4 R8 to R10 and SDK-SECTIONS-INTEGRATION-01 §5 change normative rules, and vectors are added. Never moved. `mvp-0.2-baseline.3` with SDK-SECTIONS-INTEGRATION-01 §3.4, §3.5 and §7.7 clarified: releasing a receipt ends the adapter's use of the operation ID, and a batch released before its status is final is still reported until it is final. The shared sections corpus gains SS61 to SS63, hostile changes above the SHARED-OBJECTS-PROFILE-01 §11.1 expansion limits on the section receive path. SHARED-SECTIONS-PROFILE-01 §14.1 says how a refused change is named: by its hash only when it is a type 1 change chunk, so SS44's refused compressed chunk is no longer named, the one value change (`migrations/mvp-0.2-baseline.4/value-changes.json`). |
| mvp-0.2-baseline.3 | Superseded by `mvp-0.2-baseline.4`, because SDK-SECTIONS-INTEGRATION-01 §3.5 (a released batch is reported until it is final) and SHARED-SECTIONS-PROFILE-01 §14.1 (how a refused change is named) change normative rules, SS44's refusal is no longer named and SS61 to SS63 are added. Never moved. `mvp-0.2-baseline.2` with SHARED-SECTIONS-PROFILE-01 §7.6 clarified: a node in lifecycle conflict is blocked, not hidden, and an edit under it is not under a deleted ancestor. The shared sections corpus gains SS60; no vector value changes (`migrations/mvp-0.2-baseline.3/value-changes.json`). |
| mvp-0.2-baseline.2 | Superseded by `mvp-0.2-baseline.3`, because the §7.6 clarification changes a normative rule and adds a vector. Never moved. The MVP 0.1 baseline `mvp-0.1-baseline.10` unchanged, plus shared sections as in `mvp-0.2-baseline.1`. Applies SPEC-PATCH-10 (ADR 0010): canonical change encoding and operation references (SHARED-OBJECTS-PROFILE-01 §11.3, §11.4), which shared sections inherit unchanged (SHARED-SECTIONS-PROFILE-01 §2). No vector value changes (`migrations/mvp-0.2-baseline.2/value-changes.json` lists no change); the Automerge reference corpus gains the `canonical` and `references` sections, the shared sections corpus the cases SS57 to SS59. |
| mvp-0.2-baseline.1 | Superseded by `mvp-0.2-baseline.2`, because SPEC-PATCH-10 changes normative rules and adds vectors. Never moved. The MVP 0.1 baseline `mvp-0.1-baseline.9` unchanged, plus shared sections: the profile `org.openlfcp.shared-sections.v1` (SHARED-SECTIONS-PROFILE-01, ADR 0009), its Markdown bindings (MARKDOWN-SECTIONS-01), the SDK integration contracts (SDK-SECTIONS-INTEGRATION-01), the corpus and the Markdown fixtures. No published value of MVP 0.1 changes (`migrations/mvp-0.2-baseline.1/value-changes.json` lists no change); the two shared sections suites are new. |

- The listed specifications are Working Drafts. They keep their identifiers;
  nothing is renamed or declared Stable.
- Every file of `mvp-0.1-baseline.10` is part of this baseline, byte for
  byte: a Resource of the profile `org.openlfcp.shared-objects.v1` behaves
  exactly as in MVP 0.1. MVP-0.1-BASELINE.md keeps describing the MVP 0.1
  tags.
- Software built on this baseline may say "Implements the OpenLFCP MVP 0.2
  subset of LFCP-WIRE-01". It must not claim full LFCP-WIRE-01 conformance
  (`.github: docs/MVP-0.1-PROTOCOL-SCOPE.md` §5; MVP 0.2 adds no Wire
  feature).
- The decisions applied are those of MVP 0.1 (ADR 0001 to ADR 0008 and
  [ADR 0010](adr/0010-canonical-changes-and-operation-references.md)) and
  [ADR 0009](adr/0009-shared-sections-profile.md).

## Pinning

Implementations pin the current tag, `mvp-0.2-baseline.5`, of
`openlfcp/spec`, never a branch, in their `spec.lock`. A development pin of
the shared sections files before this tag (`spec-sections.lock`) is retired
when an implementation moves to the tag.

A later approved Working Draft correction does not move the tag. It
produces a new tag, such as `mvp-0.2-baseline.6`, with an updated copy of
this file and a `migrations/mvp-0.2-baseline.N/` entry. Implementations
move to it deliberately.

## Canonical files

`./scripts/validate.sh` checks that every file listed here exists, and that
every file under `wire/`, `profiles/`, `integration/`, `test-vectors/`,
`schemas/` and `adr/` is listed (a path ending in `/` covers its whole
directory).

### Normative prose

| File | Role |
| --- | --- |
| `wire/LFCP-WIRE-01.md` | LFCP Wire protocol (Working Draft) |
| `profiles/SHARED-OBJECTS-PROFILE-01.md` | Shared Objects application profile `org.openlfcp.shared-objects.v1` (Working Draft) |
| `profiles/SHARED-SECTIONS-PROFILE-01.md` | Shared sections application profile `org.openlfcp.shared-sections.v1` (Working Draft 0.3, ADR 0009) |
| `integration/MARKDOWN-REFS-01.md` | Markdown projection reference grammar: inline and child-line placements (Working Draft) |
| `integration/MARKDOWN-SECTIONS-01.md` | Markdown bindings of shared sections (Working Draft) |
| `integration/SDK-SECTIONS-INTEGRATION-01.md` | SDK receipt, status and parser integration contracts for shared sections, `sections-integration/1` (Working Draft) |

### Test vectors

| File | Role |
| --- | --- |
| `test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json` | Wire vectors, machine-readable (`lfcp-vector-format/1`): byte-exact positives and negatives |
| `test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.md` | Wire vectors, human-readable, with derivations |
| `test-vectors/lfcp-wire-01/generate_lfcp_test_vectors_01.py` | Generator; reproduces both Wire vector files byte for byte |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json` | Shared Objects vectors, machine-readable: deterministic, validation and behavioral cases |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.md` | Shared Objects vectors, human-readable |
| `test-vectors/shared-objects-01/generate_shared_objects_test_vectors_01.py` | Generator; reproduces both Shared Objects vector files byte for byte |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json` | Automerge reference corpus for S01–S16: exact changes, save images, logical states and conflict sets, plus `validations` (save images with the expected profile problems) `expansion` (chunks at and past the §11.1 and §13.1 limits), `depth` (change sequences and Snapshots at and past the §11.2 depth bound) `collision` (a change held for a taken actor sequence until a rebuild, §14.1), `canonical` (changes in and out of the canonical encoding, §11.3) and `references` (changes whose operations refer inside and outside their history, §11.4) (supplementary; bytes not normative) |
| `test-vectors/shared-objects-01/generate_automerge_reference_01.mjs` | Corpus generator; with the pinned `@automerge/automerge` 3.5.0 it reproduces the corpus byte for byte |
| `test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json` | Shared sections corpus, machine-readable: 59 cases of Automerge changes, admission, isolation, budgets and the Snapshot floor |
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
| `wire/fixtures/` | CDDL fixture manifest and must-fail structural fixtures |

### Schemas

| File | Role |
| --- | --- |
| `schemas/lfcp-vector-format-1.schema.json` | JSON Schema of the vector format both suites use |
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
| `adr/0006-mvp-0.1-protocol-decisions-6.md` | Sixth batch (SPEC-PATCH-07): Automerge expansion limits, value nesting, the client receive limit; orchestrator decisions approved by the project owner on 2026-10-06 |
| `adr/0007-mvp-0.1-protocol-decisions-7.md` | Seventh batch (SPEC-PATCH-08): the document depth bound; an orchestrator decision approved by the project owner on 2026-10-06 |
| `adr/0008-recovery-after-server-data-loss.md` | SPEC-PATCH-09: recovery after server data loss (POST-013), accepted by the project owner on 2026-10-08, and POST-001 (hold and retry of a taken actor sequence), decided by the project owner on 2026-10-06 |
| `adr/0009-shared-sections-profile.md` | The shared sections profile: decisions P1, P2, P3 and P5 approved by the project owner, applied in this baseline |
| `adr/0010-canonical-changes-and-operation-references.md` | SPEC-PATCH-10: canonical change encoding and operation references (findings F2 to F4); orchestrator decisions of 2026-10-09, applied in `mvp-0.1-baseline.10` and this baseline |

## Validation

From a clean checkout with full history and tags:

```sh
pnpm install --frozen-lockfile
bundle install
./scripts/validate.sh
```

The checks are those of MVP-0.1-BASELINE.md, plus:

- vector values against the previous baseline tag, from the newest
  `migrations/mvp-0.M-baseline.N/value-changes.json`: for this baseline,
  against `mvp-0.2-baseline.4`;
- the shared sections corpus and the Markdown fixtures: schema-valid,
  regenerated byte for byte with the pinned `@automerge/automerge` and
  replayed by the reference verifiers (`scripts/check-shared-sections-corpus.mjs`);
- this manifest's file list, as for MVP-0.1-BASELINE.md.

## Changes from `mvp-0.2-baseline.5` (`mvp-0.2-baseline.6`, prepared)

| Kind | Files |
| --- | --- |
| Changed, normative | `profiles/SHARED-OBJECTS-PROFILE-01.md` §11.3 rule 2: the sequence number is below 2^53, the time between -2^53 and 2^53; §14.1: the checks of a change's bytes (§11, §11.1, §11.3, then the actor) are made when it arrives, whether or not its dependencies are present; an Automerge author only in an actor's first change |
| Changed, normative | `profiles/SHARED-SECTIONS-PROFILE-01.md` §14.1: admission in two steps, the bytes when a change arrives, the rest when its dependencies are present; A5 covers every field of the section, a node and a placement, and all of a Task, defined or not |
| Changed, vectors | `test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json` (`CAN-2-time-largest`, `CAN-2-time-smallest`, admitted; `CAN-2-time-2pow53`, `CAN-2-time-minus-2pow53`, `CAN-2-seq-2pow53`, refused), appended after the earlier cases; `test-vectors/shared-sections-01/` (SS66 to SS69: header numbers beyond 2^53, refused when they arrive, also with a missing dependency or signed by another Principal; SS70: an author in a later change, refused; SS71 to SS74: Text in fields the profile does not define, refused; SS75: a table made as a node, refused for R10 before A2); the sections reference admission checks a change's bytes before its dependencies, the author rule and A5 on every field |
| Added, migration | `migrations/mvp-0.2-baseline.6/` |
| Changed, MVP 0.1 files | `profiles/SHARED-OBJECTS-PROFILE-01.md` (§11.3 rule 2, §14.1, the author rule) and the Automerge reference corpus, both also part of the MVP 0.1 baseline: they apply to it, and reach the MVP 0.1 line only with a 0.1 patch, which the owner decides |

## Changes from `mvp-0.2-baseline.4` (`mvp-0.2-baseline.5`)

| Kind | Files |
| --- | --- |
| Changed, normative | `profiles/SHARED-OBJECTS-PROFILE-01.md` §11.3 rule 8: the start op is below 2^32, even for a change without operations; §11.4 R8 (increments), R9 (no marks) and R10 (no tables), which Shared Sections inherits |
| Changed, normative | `integration/SDK-SECTIONS-INTEGRATION-01.md` §3.2, §5: the `nodeIds` of `nodes-changed` follow the `affectedNodeIds` rule for every origin (a Task's fields are its task node's, the title is the section's); an SDK may list more nodes, never fewer |
| Changed, vectors | `test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json` (`CAN-8-start-op-empty`, refused; `REF-control-increment`, `REF-control-increment-two-counters`, `REF-R8-increment-not-counter`, `REF-R8-increment-no-pred`, `REF-R8-increment-pred-increment`, `REF-R9-mark`, `REF-R10-make-table`, `REF-R10-write-into-table-D1`), appended after the earlier cases; `test-vectors/shared-sections-01/` (SS64: a table made and written into, refused; SS65: a section created with `ready = false`, refused, and the sections reference admission checks §12.1 on the creating change); the sections reference admission checks R8 to R10 |
| Added, migration | `migrations/mvp-0.2-baseline.5/` |
| Changed, MVP 0.1 files | `profiles/SHARED-OBJECTS-PROFILE-01.md` (§11.3 rule 8, §11.4 R8 to R10) and the Automerge reference corpus, both also part of the MVP 0.1 baseline: they apply to it, and reach the MVP 0.1 line only with a 0.1 patch; for R10 (an engine abort, finding D1) the owner approved the patch releases sdk-ts 0.1.5 and Shared Tasks 0.3.4 on 2026-10-10 |

## Changes from `mvp-0.2-baseline.3` (`mvp-0.2-baseline.4`)

| Kind | Files |
| --- | --- |
| Changed, normative | `integration/SDK-SECTIONS-INTEGRATION-01.md` §3.4, §3.5, §7.7: a released batch is reported until its status is final |
| Changed, normative | `profiles/SHARED-SECTIONS-PROFILE-01.md` §14.1: a refused change is named by its hash only when it is one type 1 change chunk; a compressed or unreadable chunk is not named |
| Changed, vectors | `test-vectors/shared-sections-01/` (SS61 to SS63: changes above the §11.1 expansion limits, refused before they are decoded; the reference admission checks §11.1 on the raw bytes, `generator/expansion.mjs`; SS44's refused compressed chunk is no longer named) |
| Added, migration | `migrations/mvp-0.2-baseline.4/`; `migrations/vector-format-1/shared-sections-01.mapping.json` lists SS44's removed name |
| Changed, tooling | `scripts/check-vector-migration.mjs`: an approved change whose new value is null is a removal |
| Changed, MVP 0.1 files | None |

## Changes from `mvp-0.2-baseline.2` (`mvp-0.2-baseline.3`)

| Kind | Files |
| --- | --- |
| Changed, normative | `profiles/SHARED-SECTIONS-PROFILE-01.md` §7.6: a lifecycle conflict blocks its branch and hides nothing |
| Changed, vectors | `test-vectors/shared-sections-01/` (SS60; the reference model's hidden rule; the verifier's `notHidden` and `notRetained` requirements) |
| Added, migration | `migrations/mvp-0.2-baseline.3/` |
| Changed, MVP 0.1 files | None |

## Changes from `mvp-0.2-baseline.1`

| Kind | Files |
| --- | --- |
| Changed, normative | `profiles/SHARED-OBJECTS-PROFILE-01.md` (§11, §11.3, §11.4, §13, §74.1; the same text as `mvp-0.1-baseline.10`) |
| Changed, normative (reference) | `profiles/SHARED-SECTIONS-PROFILE-01.md` §2, §14.1: the inherited checks list §11.3 and §11.4 (no new rule) |
| Changed, vectors | `test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json` and its generator (sections `canonical`, `references`), `test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.md`; `test-vectors/shared-sections-01/` (SS57 to SS59, the reference admission checks §11.3 and §11.4) |
| Added, decision | `adr/0010-canonical-changes-and-operation-references.md` |
| Changed, tooling | `scripts/check-baseline-changes.mjs`: reads suites of several MiB, and compares a suite moved to `lfcp-vector-format/1` after the previous baseline through the migration check (`"previous": "migrated"`) |
| Added, migration | `migrations/mvp-0.2-baseline.2/`, `migrations/mvp-0.1-baseline.10/` |
| Changed, MVP 0.1 files | Those of `mvp-0.1-baseline.10` |

## Changes from `mvp-0.1-baseline.9` (`mvp-0.2-baseline.1`)

| Kind | Files |
| --- | --- |
| Added, normative | `profiles/SHARED-SECTIONS-PROFILE-01.md`, `integration/MARKDOWN-SECTIONS-01.md`, `integration/SDK-SECTIONS-INTEGRATION-01.md` |
| Added, vectors | `test-vectors/shared-sections-01/` |
| Added, decision | `adr/0009-shared-sections-profile.md` |
| Added, migration | `migrations/mvp-0.2-baseline.1/` |
| Changed, tooling | `scripts/check-shared-sections-corpus.mjs` (new), `scripts/validate-vectors.mjs` (skips the sections suites, which have their own format), `scripts/check-baseline.mjs` and `scripts/check-baseline-changes.mjs` (two baseline series), `package.json` |
| Changed, MVP 0.1 files | None |
