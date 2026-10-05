# openlfcp/spec

Normative specifications, profiles, interoperability vectors, registries,
and ADR/RFC material for OpenLFCP.

This repository contains no production application logic.

## Layout

Normative documents are imported in LFCP-003. The intended layout is:

```text
wire/          LFCP Wire specification
profiles/      Shared Objects Profile and other profiles
test-vectors/  Machine-readable interoperability vectors
registries/    Protocol registries
rfcs/          Change proposals
adr/           Architecture decision records
```

## Validate from a clean checkout

```sh
./scripts/validate.sh
```

Requires Node.js 24 or later. The script is a placeholder: today it only
checks that every JSON file parses. Schema and vector checks arrive with
LFCP-004.

## License

Apache License 2.0. See [LICENSE](LICENSE).
