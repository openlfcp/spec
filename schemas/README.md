# Vector format: `lfcp-vector-format/1`

[`lfcp-vector-format-1.schema.json`](lfcp-vector-format-1.schema.json) is the
JSON Schema (draft 2020-12) for every machine-readable vector suite in
`test-vectors/`. The LFCP Wire suite, the Shared Objects Profile suite and the
shared sections suite use it.

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

Optional fields for negative cases:

- `expected.disposition`: what the specification says happens to the
  input. The values are `reject`, `quarantine` (kept out of the merge and
  surfaced), `conflict` (enter a conflict state; choose neither) and
  `report` (report to the sync engine). It is given only where the
  specification states it.
- `context`: the state the outcome depends on, such as the current Control
  Head, the epoch cutoff record or the recipient key. Values are literals or
  references `{"case": <id>, "field": <name>}` to another case's `expected`
  values (`"in": "inputs"` for its inputs). A negative case must be decidable
  from its inputs, its context and the cases it references.
- `derivation`: how the case was derived from a positive one. It records the
  `base_case`, the single `mutation` (`field`, `from`, `to`), the violated
  `rule` (`section` and exact `text`) and `why` acceptance would break the
  protocol.

### `behavioral`: logical state

For Automerge/profile scenarios where independent implementations may produce
different bytes. `inputs` gives the starting state and the operations;
`expected` gives the logical state, conflict sets and acceptance after
convergence; `assertions` adds prose checks. Independent implementations are
never required to emit identical changes.

#### Conflict convention

A behavioral `expected` object states a conflicted field as
`<field>_conflict_set`: the list of concurrent values that must remain
discoverable (for example `"status_conflict_set": ["cancelled", "done"]`),
usually together with `must_report_conflict`. `<field>_values_may_include`
lists values that may appear among them. This is a test convention of the
vector format, not part of any profile's logical state (decision SO-G4,
spec: adr/0001-mvp-0.1-protocol-decisions.md). Each listed value must still
be a valid value of its field; `scripts/validate-shared-objects.mjs` checks
that.

## Checks

`./scripts/validate.sh` runs `scripts/validate-vectors.mjs`, the protocol
vector validator. It checks every published suite against the schema and
then runs the checks in
[`scripts/lib/vector-checks.mjs`](../scripts/lib/vector-checks.mjs). It also
checks the format excerpts in [`fixtures/`](fixtures/) against the schema:
every `valid-*.json` must validate and every `invalid-*.json` must be
rejected.

### Problem lines

Each problem is printed on one line:

```text
<suite> <case-id|-> <json-pointer> <reason>
```

`<reason>` starts with a stable code:

- `schema/<keyword>`: a schema violation, reported against the case's own
  type branch;
- `duplicate-key`, `duplicate-id`, `bad-hex`, `bad-b64url`, `hash-mismatch`,
  `encoding-mismatch`, `unresolved-ref`, `no-op-mutation`: the checks beyond
  the schema.

### Coverage

Each requirement is enforced in exactly one place.

| Requirement | Enforced by |
| --- | --- |
| Conforms to the vector schema | schema |
| Required suite metadata | schema (`suite` required fields) |
| Required per-case fields by type | schema (type branches) |
| Hex: lowercase, even length, no `0x` | schema (`{"hex"}` pattern); validator `bad-hex` for free-form `*_hex` fixture strings |
| Base64url structurally valid | schema (character set); validator `bad-b64url` (decodes, unpadded, re-encodes identically) |
| Unique case IDs | validator `duplicate-id` |
| Unique keys, including fixture keys | validator `duplicate-key` (JSON.parse would hide repeats) |
| Expected hashes reproduced | validator `hash-mismatch` (table below) |
| Deterministic encodings reproduced | validator `encoding-mismatch` |
| References resolve (including negative `derivation.base_case` and `context` references) | validator `unresolved-ref` |
| A negative's mutation changes something | validator `no-op-mutation` |
| Behavioral cases not forced into byte shape | schema (`behavioral` branch has no byte requirements) |
| Byte-exact cases carry expected bytes | schema (`bytes` branch: `expected` with at least one value) |
| Wire, Shared Objects and shared sections suites accepted | the suites validate in CI |

### Hash recomputation

Only plain SHA-256 hashes over bytes present in the vector are recomputed,
and only where the formula is stated in the specification. Run
`node scripts/validate-vectors.mjs --report` for the table: each formula with
its section, verified counts per suite, and every hash-like field that is
deliberately not verified, with the reason. Signatures, AEAD, HPKE and key
derivation are implementation work, not spec-repository checks.

### Validator self-tests

[`fixtures/validator/`](fixtures/validator/) holds deliberately invalid
suites. They are not part of the normative corpus. Each must produce exactly
the problem lines listed in
[`fixtures/validator/expected.json`](fixtures/validator/expected.json). They
cover:

- malformed hex (inside a wrapper and in a free-form fixture);
- malformed base64url;
- a missing required field;
- a duplicate case ID;
- a duplicate key;
- a wrong hash;
- an unknown case type;
- an unresolved reference;
- a negative case with a missing base case, a no-op mutation, or an
  unresolved context reference.
