# MVP-0.1-BASELINE

**OpenLFCP MVP 0.1 implementation baseline — NOT Stable LFCP-WIRE-01, NOT
full WIRE-01 conformance, documents remain Working Drafts.**

This file answers one question: *what exactly do I implement against for
MVP 0.1?* The answer is every file listed below, at the Git tag
`mvp-0.1-baseline.8` of this repository.

| Tag | Status |
| --- | --- |
| mvp-0.1-baseline.8 | **Current.** Applies the seventh batch of decisions (SPEC-PATCH-08, ADR 0007), an orchestrator decision approved by the project owner on 2026-10-06: no object of a document may be deeper than 256 levels below the root (§11.2). A receiver rejects, before its Automerge engine, a change or Snapshot that would create one: deep nesting traps Automerge JS and terminates its wasm module. No vector value changes (`migrations/mvp-0.1-baseline.8/value-changes.json` lists no change); the corpus gains the `depth` section. |
| mvp-0.1-baseline.7 | Superseded by `mvp-0.1-baseline.8`, because SPEC-PATCH-08 changes normative rules and adds vectors. Never moved. Applies the sixth batch of decisions (SPEC-PATCH-07, ADR 0006), all orchestrator decisions approved by the project owner on 2026-10-06, from the pre-release security review. Receivers check every Automerge chunk before their engine: changes against exact expansion limits and structural rules (§11.1); Snapshots against local limits with a floor, with capped inflation (§13.1). Changes are uncompressed chunks, values nest at most 64 levels (§30), KEY_PACKAGE_GET lists at most 256 epochs (§52), and a client bounds its receive limit (§31). No vector value changes (`migrations/mvp-0.1-baseline.7/value-changes.json` lists no change); the corpus gains `expansion` cases, `SO-DEPTH` validations and the `SO-UNKNOWN-ACTOR` negative. |
| mvp-0.1-baseline.6 | Superseded by `mvp-0.1-baseline.7`, because SPEC-PATCH-07 changes normative rules and adds vectors. Never moved. Applied the fifth batch of decisions (SPEC-PATCH-06, ADR 0005), all orchestrator decisions approved by the project owner on 2026-10-06: a writer names its latest own unit still accepted as `previous` (§26.2), clients retransmit after a request timeout (§70), the invitation read rule uses the §25.2 active grant (§41), a writer keeps writing after a rebuild removes its own changes (Shared Objects §9, §14.1), scalar conflicts stay profile-valid (Shared Objects scenarios S15 and S16) and Collaborative Text is rejected at its own pointer (Automerge corpus `validations`). No vector value changes (`migrations/mvp-0.1-baseline.6/value-changes.json` lists no change). |
| mvp-0.1-baseline.5 | Superseded by `mvp-0.1-baseline.6`, because SPEC-PATCH-06 changes normative rules and adds vectors. Never moved. Applied the fourth batch of decisions (SPEC-PATCH-05, ADR 0004): actor chains link across abandoned sequences (G-DP1-GAP, approved by the project owner), and, as orchestrator decisions approved by the project owner on 2026-10-06, the Snapshot cutoff rebuild (SNAP-EP), forward-compatible invitation query parameters, claimant Key Packages, server and message clarifications, per-value profile diagnostics and `INVALID_AUTOMERGE_BYTES`. No vector value changes; new `actor_chain` and `invite_uri` validation cases and two Automerge corpus negatives are added (`migrations/mvp-0.1-baseline.5/value-changes.json` lists no change). |
| mvp-0.1-baseline.4 | Superseded by `mvp-0.1-baseline.5`, because SPEC-PATCH-05 changes normative rules and adds vectors. Never moved. Applied the third batch of project-owner decisions (SPEC-PATCH-04, ADR 0003): the Data Epoch rules G-EP1 to G-EP7, the general error-code rule, connection limits, Shared Objects validation (SO-SEC1, SOG-1, SOG-2) and the Markdown reference grammar. Adds the Automerge reference corpus (SPEC-CORPUS) and shared strict-Ed25519 vectors. `hpke_recipient_mismatch_KP0` is rebuilt (KP-1), four negatives now name a code and the Shared Objects intent names follow §59 (G-SC5); every changed value is listed in `migrations/mvp-0.1-baseline.4/value-changes.json`. |
| mvp-0.1-baseline.3 | Superseded by `mvp-0.1-baseline.4`, because the approved SPEC-PATCH-04 decisions change normative rules and vector values. Never moved. Applied the second batch of project-owner decisions (SPEC-PATCH-03, ADR 0002): strict Ed25519, capability authority and revocation rules, named error codes, message and state-machine edges. The Key Package vectors are regenerated from published `ikmE` (G-KP2) and `descriptor_extra_field` now names `MALFORMED_MESSAGE` (V2); every changed value is listed in `migrations/mvp-0.1-baseline.3/value-changes.json`. New positive and negative vectors are added. |
| mvp-0.1-baseline.2 | Superseded by `mvp-0.1-baseline.3`, because the approved SPEC-PATCH-03 decisions change normative rules and the Key Package vector values. Never moved. |
| mvp-0.1-baseline | Superseded by `mvp-0.1-baseline.2`. Never moved. |

- The listed specifications are Working Drafts. They keep their identifiers
  (`LFCP-WIRE-01`, `SHARED-OBJECTS-PROFILE-01`, …); nothing is renamed or
  declared Stable.
- Software built on this baseline may say "Implements the OpenLFCP MVP 0.1
  subset of LFCP-WIRE-01". It must not claim full LFCP-WIRE-01 conformance
  (`.github: docs/MVP-0.1-PROTOCOL-SCOPE.md` §5).
- The protocol decisions applied for this baseline are recorded in
  [ADR 0001](adr/0001-mvp-0.1-protocol-decisions.md),
  [ADR 0002](adr/0002-mvp-0.1-protocol-decisions-2.md),
  [ADR 0003](adr/0003-mvp-0.1-protocol-decisions-3.md),
  [ADR 0004](adr/0004-mvp-0.1-protocol-decisions-4.md),
  [ADR 0005](adr/0005-mvp-0.1-protocol-decisions-5.md),
  [ADR 0006](adr/0006-mvp-0.1-protocol-decisions-6.md) and
  [ADR 0007](adr/0007-mvp-0.1-protocol-decisions-7.md).

## Pinning

Implementations pin the current tag, `mvp-0.1-baseline.8`, of
`openlfcp/spec`, never a branch. sdk-ts consumes the vectors at this tag (LFCP-017); other
implementations do the same.

A later approved Working Draft correction does not move the tag. It
produces a new tag, such as `mvp-0.1-baseline.9`, with an updated copy of
this file. Implementations move to it deliberately.

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
| `integration/MARKDOWN-REFS-01.md` | Markdown projection reference grammar: inline and child-line placements (Working Draft) |

### Test vectors

| File | Role |
| --- | --- |
| `test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json` | Wire vectors, machine-readable (`lfcp-vector-format/1`): byte-exact positives and negatives |
| `test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.md` | Wire vectors, human-readable, with derivations |
| `test-vectors/lfcp-wire-01/generate_lfcp_test_vectors_01.py` | Generator; reproduces both Wire vector files byte for byte |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json` | Shared Objects vectors, machine-readable: deterministic, validation and behavioral cases |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.md` | Shared Objects vectors, human-readable |
| `test-vectors/shared-objects-01/generate_shared_objects_test_vectors_01.py` | Generator; reproduces both Shared Objects vector files byte for byte |
| `test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json` | Automerge reference corpus for S01–S16: exact changes, save images, logical states and conflict sets, plus `validations` (save images with the expected profile problems) `expansion` (chunks at and past the §11.1 and §13.1 limits) and `depth` (change sequences and Snapshots at and past the §11.2 depth bound) (supplementary; bytes not normative) |
| `test-vectors/shared-objects-01/generate_automerge_reference_01.mjs` | Corpus generator; with the pinned `@automerge/automerge` 3.5.0 it reproduces the corpus byte for byte |

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

## Project documents in `openlfcp/.github`

These belong to the baseline at commit `.github@eda4a80` (tag
`mvp-0.1-baseline.8` in that repository; `mvp-0.1-baseline.7` there marks
`c7e8a30`, `mvp-0.1-baseline.6` marks `6ae515a`, `mvp-0.1-baseline.5` marks `125c4e6`, `mvp-0.1-baseline.4` marks `1a8ab67`, `mvp-0.1-baseline.3` marks
`0cfa217`, `mvp-0.1-baseline.2` marks `174e6e4` and `mvp-0.1-baseline`
marks `89c0b01`):

- `docs/MVP-0.1-PROTOCOL-SCOPE.md`: the required MVP 0.1 subset of
  LFCP-WIRE-01, the deferred features and the completion gate;
- `docs/BACKLOG-MVP-0.1.md`: the authoritative implementation plan;
- `docs/AGENT-OPERATING-GUIDE.md`: source-of-truth rules and repository
  boundaries.

Obsidian-specific architecture (`obsidian: docs/OBSIDIAN-ARCHITECTURE-01.md`)
guides the editor adapter. It is subordinate to the documents above.

## Validation

From a clean checkout with full history:

```sh
pnpm install --frozen-lockfile
bundle install
./scripts/validate.sh
```

The checks:

- vector schema and validator;
- vector migration;
- vector values against the previous baseline tag (the newest
  `migrations/mvp-0.1-baseline.N/value-changes.json`);
- the Automerge reference corpus, regenerated with the pinned
  `@automerge/automerge`;
- CDDL extraction and fixtures;
- Shared Objects contract;
- this manifest's file list.

Both vector generators must reproduce the committed vector files byte for
byte, and the corpus generator the committed corpus.
