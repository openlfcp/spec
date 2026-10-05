# Vector format: `lfcp-vector-format/1`

[`lfcp-vector-format-1.schema.json`](lfcp-vector-format-1.schema.json) is the
JSON Schema (draft 2020-12) for every machine-readable vector suite in
`test-vectors/`. The LFCP Wire suite and the Shared Objects Profile suite both
use it.

## Suite

```json
{
  "format": "lfcp-vector-format/1",
  "suite": {
    "id": "LFCP-TEST-VECTORS-01",
    "version": "01",
    "specification": { "id": "LFCP-WIRE-01", "revision": "working-draft" },
    "description": "…",
    "depends_on": ["…"],
    "conventions": { "…": "…" },
    "warning": "…",
    "conformance": { "…": "…" }
  },
  "fixtures": { "…": "…" },
  "cases": [ … ]
}
```

- `suite.specification` names the specification the suite tests. Application
  profiles also give their `profile` identifier. Working Drafts use the
  revision `working-draft`; their exact state is the Git commit.
- `suite.conformance` holds suite-wide obligations, including the
  cross-implementation acceptance rules for behavioral cases.
- `fixtures` holds named inputs that several cases share, such as the test
  Resource ID. Its layout is suite-specific.

## Byte values

Bytes are always wrapped so the encoding is explicit:

| Form | Meaning |
| --- | --- |
| `{"hex": "0a1b"}` | lowercase hexadecimal, two digits per byte |
| `{"b64url": "Chs"}` | unpadded base64url (RFC 4648 §5) |

A bare JSON string inside `inputs` or `expected` is an exact text value (for
example a PrincipalRef or a URI), never encoded bytes.

## Cases

Every case has a stable `id` (unique within the suite), a `kind` naming what
it exercises (`control_record`, `actor_id`, …), and one of three `type`s. The
types are separate schema branches: a field that belongs to one type is
rejected on another.

### `bytes`: byte-exact

The same `inputs` (plus suite `fixtures`) MUST produce exactly the `expected`
values in every implementation. Used for deterministic CBOR, Principal IDs,
COSE, hashes, signed object IDs, wire framing and profile framing.

```json
{
  "id": "D01-actor-andrey-resource-a",
  "type": "bytes",
  "kind": "actor_id",
  "inputs": { "resource_hex": { "hex": "1081…" }, "principal_hex": { "hex": "bd07…" } },
  "expected": { "actor_id": { "hex": "6c9e…" } }
}
```

### `validation`: accept or reject

`expected.valid` says whether the input must be accepted. A rejection may give
`expected.error`:

- `code`: the machine-readable category or code from the specification (for
  example `STALE_DATA_EPOCH` from the LFCP-WIRE-01 error registry, or
  `PROFILE_INVALID`);
- `diagnostic`: an optional finer machine-readable code;
- `detail`: optional human-readable text. Test runners never compare it.

A case with `valid: true` must not carry `error`.

### `behavioral`: logical state

For Automerge/profile scenarios where independent implementations may produce
different bytes. `inputs` gives the starting state and the operations;
`expected` gives the logical state, conflict sets and acceptance after
convergence; `assertions` adds prose checks. Independent implementations are
never required to emit identical changes.

## Checks

`./scripts/validate.sh` validates every suite against the schema. It also
checks the fixtures in [`fixtures/`](fixtures/): every `valid-*.json` must
validate and every `invalid-*.json` must be rejected.

Checks beyond the schema, such as recomputing hashes or cross-checking
references, belong to the protocol vector validator (LFCP-007).
