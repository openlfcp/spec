# openlfcp/spec

Normative specifications, profiles, interoperability vectors, registries,
and ADR/RFC material for OpenLFCP.

This repository contains no production application logic.

## Source of truth

Higher entries win. A lower artifact never overrides a higher one; a
conflict between them is a specification gap to report, not something to
resolve in code.

| # | Artifact | Location | Status |
| --- | --- | --- | --- |
| 1 | LFCP protocol architecture | `.github: docs/PROJECT-NARRATIVE.md`, `.github: docs/AGENT-OPERATING-GUIDE.md` | Context |
| 2 | LFCP Wire | [wire/LFCP-WIRE-01.md](wire/LFCP-WIRE-01.md) | Normative, Working Draft |
| 3 | LFCP Wire test vectors | [test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.md](test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.md), [.json](test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json) | Test vectors |
| 4 | Shared Objects Profile | [profiles/SHARED-OBJECTS-PROFILE-01.md](profiles/SHARED-OBJECTS-PROFILE-01.md) | Normative, Working Draft |
| 5 | Shared Objects test vectors | [test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.md](test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.md), [.json](test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json) | Test vectors |
| 6 | Markdown projection refs | [integration/MARKDOWN-REFS-01.md](integration/MARKDOWN-REFS-01.md) | Normative, Working Draft |
| 6 | Obsidian architecture | `obsidian: docs/OBSIDIAN-ARCHITECTURE-01.md` | Architecture |
| 7 | Implementation code | `sdk-ts`, `sdk-rs`, `server`, `obsidian` | |
| 8 | UI behavior | `obsidian` | |

Other repositories are referenced as `repository: path` within the
`openlfcp` organization.

MVP scope is defined in `.github: docs/MVP-0.1-PROTOCOL-SCOPE.md`. The
authoritative implementation plan is `.github: docs/BACKLOG-MVP-0.1.md`;
it does not override the normative documents above.

### Working Drafts

The documents marked Working Draft are mutable in place. Corrections go
into the canonical document (and its vectors) and are tracked by Git
history. There are no separate errata files for Working Drafts: the former
`LFCP-WIRE-01.1` errata are already incorporated into `LFCP-WIRE-01`.

### Vector generators

Each vector directory also holds the generator that produced it:

- [test-vectors/lfcp-wire-01/generate_lfcp_test_vectors_01.py](test-vectors/lfcp-wire-01/generate_lfcp_test_vectors_01.py)
- [test-vectors/shared-objects-01/generate_shared_objects_test_vectors_01.py](test-vectors/shared-objects-01/generate_shared_objects_test_vectors_01.py)
- [test-vectors/shared-objects-01/generate_automerge_reference_01.mjs](test-vectors/shared-objects-01/generate_automerge_reference_01.mjs)

## Layout

```text
wire/          LFCP Wire specification
profiles/      Shared Objects Profile and other application profiles
integration/   Editor-integration formats (Markdown refs)
test-vectors/  Interoperability vectors and their generators
```

`registries/`, `rfcs/` and `adr/` will be added when they first have content.

## Validate from a clean checkout

```sh
./scripts/validate.sh
```

Requires Node.js 24 or later. The script is a placeholder: today it only
checks that every JSON file parses. Schema and vector checks arrive with
LFCP-004.

## License

Apache License 2.0. See [LICENSE](LICENSE).
