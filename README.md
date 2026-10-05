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
| 2 | LFCP Wire | [wire/LFCP-WIRE-01.md](wire/LFCP-WIRE-01.md); CDDL extracted from it in [wire/](wire/README.md) | Normative, Working Draft |
| 3 | LFCP Wire test vectors | [test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.md](test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.md), [.json](test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json) | Test vectors |
| 4 | Shared Objects Profile | [profiles/SHARED-OBJECTS-PROFILE-01.md](profiles/SHARED-OBJECTS-PROFILE-01.md); structural contract in [profiles/shared-objects-01/schema/](profiles/shared-objects-01/schema/README.md) | Normative, Working Draft |
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
wire/          LFCP Wire specification, its extracted CDDL and CDDL fixtures
profiles/      Shared Objects Profile and other application profiles, with structural contracts
integration/   Editor-integration formats (Markdown refs)
test-vectors/  Interoperability vectors and their generators
schemas/       lfcp-vector-format/1 schema for the vector suites, with fixtures
migrations/    Value-preservation proofs for format migrations
scripts/       Validation entry point and checks
```

`registries/`, `rfcs/` and `adr/` will be added when they first have content.

## Validate from a clean checkout

```sh
pnpm install --frozen-lockfile
bundle install
./scripts/validate.sh
```

Requires Node.js 24 or later, pnpm 10, Ruby 4.0 and Bundler. Gems install
into the project-local, gitignored `vendor/bundle` (set in `.bundle/config`).
The script checks that every JSON file parses and that both vector suites
and the format fixtures match the
[`lfcp-vector-format/1`](schemas/README.md) schema. It also proves that the
migration to that format changed no vector value (see
[migrations/vector-format-1/](migrations/vector-format-1/)); that check reads
the pre-migration files from Git, so it needs the full history, not a shallow
clone.

It also checks the LFCP Wire CDDL: the extracted `.cddl` files must match
the prose, the schema must compile with the cddl tool, and every fixture
must validate as listed. See [wire/README.md](wire/README.md) for what the
CDDL does and does not prove.

## Regenerate the vectors

Both generators write next to themselves by default (`--out-dir` overrides)
and reproduce the committed `.json` and `.md` files byte-for-byte.

```sh
# Shared Objects suite: Python 3 standard library only
python3 test-vectors/shared-objects-01/generate_shared_objects_test_vectors_01.py

# LFCP Wire suite: needs the `cryptography` package, e.g. in a local venv
uv venv .venv && uv pip install --python .venv/bin/python cryptography
.venv/bin/python test-vectors/lfcp-wire-01/generate_lfcp_test_vectors_01.py
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
