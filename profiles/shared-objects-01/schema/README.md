# Shared Objects structural contract

Machine-checkable structure for the **logical state** of
[SHARED-OBJECTS-PROFILE-01](../../SHARED-OBJECTS-PROFILE-01.md): the JSON an
Automerge document of profile `org.openlfcp.shared-objects.v1` materializes
to. It does not describe Automerge bytes or change history. Conflict
resolution, add-wins collections and tombstone causality are behavioral and
belong to the profile interoperability runners (LFCP-032, LFCP-037).

| File | Role |
| --- | --- |
| [`shared-objects-state.schema.json`](shared-objects-state.schema.json) | JSON Schema 2020-12. Each rule has a `$comment` citing its profile section. |
| [`../../../scripts/lib/shared-objects-checks.mjs`](../../../scripts/lib/shared-objects-checks.mjs) | Rules the schema cannot express. |
| [`fixtures/`](fixtures/) | `valid-*.json` states must pass. Each `invalid-*.json` must fail at exactly the pointers in `fixtures/expected.json`. |
| [`../../../scripts/validate-shared-objects.mjs`](../../../scripts/validate-shared-objects.mjs) | Runs the fixtures and the vector consistency checks; part of `./scripts/validate.sh`. |

Unknown data is accepted (§70–§72). The contract does not reject unknown
Task fields, unknown extension namespaces, unknown object types, or custom
`x/…/…` statuses and priorities.

## Constraints

| Field | Rule | Profile | Enforced by |
| --- | --- | --- | --- |
| root `profile` | equals `org.openlfcp.shared-objects.v1` | §6, §15, §74 | schema |
| root `objects` | map keyed by Object ID | §15, §20 | schema |
| root `extensions` | map | §15, §18 | schema |
| `objects` key / `id` | UUIDv7: lowercase, hyphenated, version 7, variant `10` | §19 | schema (pattern) |
| `id` | equals its key in `objects` | §20, §24 | validator `id-mismatch` |
| `id`, `type`, `created_by` | unchanged between two states of the same object | §24, §25, §27, §75 | validator `immutable` |
| `type` | non-empty text; `task` selects the Task rules | §25, §74, §93 | schema |
| base fields | `id`, `type`, `lifecycle`, `created_by`, `extensions` required on Tasks | §23, §74 | schema |
| `lifecycle` | text (standard values `active`, `deleted`) | §26, §74 | schema (text only, gap SO-G1) |
| `created_by` | `p:` + unpadded base64url of exactly 32 bytes | §27 | schema (43 characters, canonical last character) |
| `created_at` | optional RFC 3339 UTC timestamp ending in `Z` | §28 | schema (shape) + validator `bad-timestamp` (real date and time) |
| `extensions` | map; contents unconstrained | §18, §29 | schema |
| Task required fields | `title`, `status`, `priority`, `tags`, `assignees` (plus base) | §30, §31 | schema |
| `title` | string; empty allowed | §32 | schema |
| `status` | `todo`, `in_progress`, `done`, `cancelled`, or `x/<…>/<…>` | §33 | schema |
| `priority` | `lowest`, `low`, `normal`, `high`, `highest`, or `x/<…>/<…>` | §38 | schema |
| `due`, `scheduled`, `completion_date` | optional; `YYYY-MM-DD` or `null` | §30, §35, §36 | schema (shape) + validator `bad-date` (real Gregorian date) |
| `tags` | map; keys non-empty, no leading `#`; values `true` | §39, §40 | schema |
| `assignees` | map; keys are PrincipalRefs; values `true` | §42, §43 | schema |

Not checked, and why:

- `status`/`completion_date` consistency: §37 permits temporary
  inconsistency.
- Tag NFC normalization: §40 makes it a SHOULD only.
- Case-sensitive tag duplicates: §40 says they are allowed.
- Collision detection: §21 needs history.

## Vector consistency

`validate-shared-objects.mjs` also checks SHARED-OBJECTS-TEST-VECTORS-01:

- **S01–S14** must satisfy the contract wherever a scenario states or writes
  a value. That covers base-state and expected Tasks and object maps, created
  objects, field writes, and expected field values: `tags` and `assignees`
  lists, `*_conflict_set` and `*_values_may_include` arrays.
- **I01–I07** must be invalid at the mutated field. The scenario field
  (mutation of the S01 Task) is checked, but not the diagnostic name, which is
  undecided (gaps G2/G3). I07 (`type` changed) is valid as a state; it is
  caught only by the immutable-field check across states.
- **D06–D08** Object IDs are classified as the vectors say.

Profile framing (D04, D05) is byte-verified by the vector validator
(`scripts/lib/vector-checks.mjs`) and not repeated here. The profile defines
no other framing.

## Spec gaps

- **SO-G1** `lifecycle`: §26 lists *standard* values `active`/`deleted`, while
  §30 types it as exactly `"active" | "deleted"`. It is unclear whether other
  values are invalid or must be preserved.
- **SO-G2** The grammar of `x/<reverse-domain>/<value>` is undefined, and §38
  writes `x/<domain>/<value>`. Only the `x/<part>/<part>` shape is checked.
- **SO-G3** Extension namespace keys must be "reverse-domain names" (§18), but
  no grammar is given. Not checked.
- **SO-G4** How a conflicted scalar appears in logical state is not defined.
  The vectors use their own `<field>_conflict_set` arrays.
- **SO-G5** It is not stated whether the §23 base fields are required for
  non-standardized (namespaced) object types. Only `id` and `type` are
  required for them.
- **SO-G6** §17 forbids creating unrelated root keys, yet future reserved keys
  must be preserved by older clients. Unknown root keys are accepted.
- **SO-G7** No maximum `title` length is stated. None is enforced.
- **SO-G8** §39 makes `true` the only tag value. §42/§43 only imply the same
  for `assignees`, which the contract also requires.
- **SO-G9** The §87 "Tombstoned Task" example omits required fields
  (`created_by`, `priority`, `tags`, `assignees`, `extensions`) without saying
  "only relevant fields are shown" as §86 does.
