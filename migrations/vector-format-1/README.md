# Migration to `lfcp-vector-format/1`

LFCP-004 moved the Wire and Shared Objects vector suites into the
[`lfcp-vector-format/1`](../../schemas/README.md) layout in place. No vector
value changed.

Each `*.mapping.json` file lists, for one suite:

- `baseline_commit`: the commit holding the suite before migration;
- `moves`: where every old value now lives (`old path` → `new path`);
- `structural`: old values the new format expresses as structure instead
  (for example `deterministic_bytes: true` became the case type);
- `changed`: later, explicitly approved changes to a migrated value, with old
  value, new value and approval (the `suite.warning` wording, the SPEC-PATCH-01
  error-code moves, and the SPEC-PATCH-03 / G-KP2 Key Package values);
- `added`: every new value, with its source. These are the format metadata,
  case IDs taken from old object keys, and the error codes mapped from
  LFCP-WIRE-01 §62.

`scripts/check-vector-migration.mjs` (run by `scripts/validate.sh`) reads the
baseline file from Git and checks the following:

- every old value is present and unchanged at its mapped location;
- no two old values share a location, so the multisets of old and new values
  are equal;
- every other value in a migrated case is explained by `added`.

Run it with `--verbose` to list the added values.

LFCP-02-107 moved the shared sections corpus SHARED-SECTIONS-TEST-VECTORS-01
the same way, from its own format at `mvp-0.2-baseline.1`
(`shared-sections-01.mapping.json`). Its mapping names its old id lists
(`old_id_lists`) and re-encodes the bytes: a move with the encoding
`base64url` takes a standard base64 value to the same bytes as unpadded
base64url, and the check compares the bytes. No value changed.
Because the paths changed, the value check of the next MVP 0.2 baseline
(`scripts/check-baseline-changes.mjs` against `mvp-0.2-baseline.1`) has to
read this suite through the mapping, or list it as moved; prepare that with
`mvp-0.2-baseline.2`.

