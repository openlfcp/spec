# MVP-0.1-BASELINE

**OpenLFCP MVP 0.1 implementation baseline — NOT Stable LFCP-WIRE-01, NOT
full WIRE-01 conformance, documents remain Working Drafts.**

This file answers one question: *what exactly do I implement against for
MVP 0.1?* The answer is every file listed below, at the Git tag
`mvp-0.1-baseline.2` of this repository.

| Tag | Status |
| --- | --- |
| mvp-0.1-baseline.2 | **Current.** Adds the editorial clarifications CB1–CB3, P1, P2 and K1 (ADR 0001). No published vector value changed; one negative vector was added. |
| mvp-0.1-baseline | Superseded by `mvp-0.1-baseline.2`. Never moved. |

- The listed specifications are Working Drafts. They keep their identifiers
  (`LFCP-WIRE-01`, `SHARED-OBJECTS-PROFILE-01`, …); nothing is renamed or
  declared Stable.
- Software built on this baseline may say "Implements the OpenLFCP MVP 0.1
  subset of LFCP-WIRE-01". It must not claim full LFCP-WIRE-01 conformance
  (`.github: docs/MVP-0.1-PROTOCOL-SCOPE.md` §5).
- The protocol decisions applied for this baseline are recorded in
  [ADR 0001](adr/0001-mvp-0.1-protocol-decisions.md).

## Pinning

Implementations pin the current tag, `mvp-0.1-baseline.2`, of
`openlfcp/spec`, never a branch. sdk-ts consumes the vectors at this tag (LFCP-017); other
implementations do the same.

A later approved Working Draft correction does not move the tag. It
produces a new tag, such as `mvp-0.1-baseline.3`, with an updated copy of
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
| `test-vectors/shared-objects-01/generate_automerge_reference_01.mjs` | Supplementary Automerge reference-corpus generator (not normative bytes) |

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

## Project documents in `openlfcp/.github`

These belong to the baseline at commit `.github@174e6e4` (tag
`mvp-0.1-baseline.2` in that repository; `mvp-0.1-baseline` there marks
`89c0b01`):

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
- CDDL extraction and fixtures;
- Shared Objects contract;
- this manifest's file list.

Both generators must reproduce the committed vector files byte for byte.
