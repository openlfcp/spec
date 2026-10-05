# Migration to `lfcp-vector-format/1`

LFCP-004 moved both vector suites into the
[`lfcp-vector-format/1`](../../schemas/README.md) layout in place. No vector
value changed.

Each `*.mapping.json` file lists, for one suite:

- `baseline_commit`: the commit holding the suite before migration;
- `moves`: where every old value now lives (`old path` → `new path`);
- `structural`: old values the new format expresses as structure instead
  (for example `deterministic_bytes: true` became the case type);
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
