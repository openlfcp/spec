# LFCP Wire

[`LFCP-WIRE-01.md`](LFCP-WIRE-01.md) is the normative LFCP Wire specification
(Working Draft) and the single source of truth. The CDDL files in this
directory make its structural grammar machine-checkable.

## Files

| File | What it is |
| --- | --- |
| `LFCP-WIRE-01.cddl` | **Generated.** Every ```` ```cddl ```` block of the body (Parts I–XXVII), in document order. Unnamed blocks appear as comments. |
| `LFCP-WIRE-01.summary.cddl` | **Generated.** The Part XXVIII "Full CDDL Summary" block. It restates body rules, so it is kept out of the main schema and checked for agreement instead. |
| `LFCP-WIRE-01.supplement.cddl` | Hand-maintained complements, each citing the WIRE-01 sentence it encodes (see below). |
| `fixtures/manifest.json` | Table of fixtures: rule → published vector value or hand-built file → expected pass/fail. |
| `fixtures/*.diag` | Hand-built, **non-normative** CBOR diagnostic-notation fixtures for structural mismatches that must fail. Snapshots are checked with the real SNAPSHOT-01 and SNAPSHOT-02 bytes. |

Never edit the generated files. Change the prose and run:

```sh
node scripts/extract-cddl.mjs
```

`./scripts/validate.sh` fails when they are out of date.

## The supplement

The extracted blocks do not compile on their own. The supplement adds only
what the prose states but the blocks omit:

- `hash32`, which is used throughout but defined only in §5.3 prose (and
  Part XXVIII);
- names for the five unnamed blocks: the unprotected header (§10.2),
  `Sig_structure` (§10.5), HPKE `info` and AAD (§25.1) and the Data Unit
  AAD (§26.1);
- signed-object rules (`control-record`, `data-unit`, `key-package`,
  `snapshot`, `owner-transfer-offer`, `owner-transfer-accept`,
  `auth-proof`). These use `.cbor` to decode the protected header (§10.1) and
  the payload (§10.3) instead of treating them as opaque bytes;
- `typed-control-record-payload`, which binds each §14 Control Record type to
  its body rule, with Genesis fixed to `control_seq = 0` and
  `prev_control_id = null` (§13.1);
- `typed-lfcp-message`, which binds each §33 message type to its body rule.

## What the CDDL proves

Validating an item against a rule proves its **structure**:

- CBOR major types and map keys;
- required and optional fields;
- byte-string sizes (32-byte IDs, 64-byte signatures, 16-byte nonces and
  message IDs);
- registry codes tied to the matching body (Control Record and message
  types);
- the untagged four-element COSE_Sign1 array with an empty unprotected
  header;
- protected header and payload contents of signed objects.

## What it does not prove

These rules are semantic. They belong to the protocol validator (LFCP-007)
and the Wire decoder (LFCP-016), not to CDDL:

- **Deterministic encoding** (§5.2): shortest integer and length forms, map
  key order, no indefinite lengths. CDDL validates decoded data, so a
  non-canonical encoding of a valid structure passes.
- **Signatures** (§10.5): Ed25519 over the exact `Sig_structure`, and `kid`
  equal to the signer's Principal ID. A tampered object still validates
  structurally; see the `tampered_D1` fixture.
- **Hashes and IDs** (§10.6, §6, §7): object IDs, Principal IDs and DEK
  commitments as SHA-256 of exact bytes.
- **Control Chain validity** (§13): sequence continuity, `prev_control_id`
  linkage, forks, signer authority.
- **Authorization** (§17, §25.2, §26.3, §29.2): abilities at the referenced
  Control Head.
- **AEAD and HPKE** (§12, §25, §29.1): decryption, AAD reconstruction, key
  derivation, nonce construction.
- **Monotonicity and uniqueness** (§8, §29): actor and Snapshot sequences,
  no reuse of `(resource, principal, seq)`, equivocation; see the
  `actor_equivocation` fixture.
- **Canonical Have Vectors and frontiers** (§28.1, §28.2): sorted,
  non-overlapping, non-adjacent ranges above `contiguous`; key `2` omitted
  when empty; frontier sorted by Principal ID with no duplicates.
- **Value constraints stated only in prose**: `wss://` endpoint URLs (§16),
  text limits of 256 UTF-8 bytes (§22, §24), `flags` currently 0 (§32),
  extension and reserved code ranges (§14, §33).
- **Envelope extensibility** (§32): keys above 15 MAY be ignored, but
  `lfcp-message` as written is a closed map. This is listed as a
  specification gap.

## Checks

`./scripts/validate.sh` runs:

1. `scripts/extract-cddl.mjs --check`, which compares the generated files
   with the prose;
2. `scripts/check-cddl.rb`, using the reference
   [cddl](https://github.com/cabo/cddl) tool, which:
   - compiles the extracted CDDL plus the supplement with no undefined names;
   - checks that every Part XXVIII rule agrees with the body (instances
     generated from each side validate against the other);
   - runs every fixture in the manifest.
