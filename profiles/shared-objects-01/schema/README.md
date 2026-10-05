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
| root `extensions` | map keyed by `reverse-domain` namespaces | §15, §18 | schema |
| `objects` key / `id` | UUIDv7: lowercase, hyphenated, version 7, variant `10` | §19 | schema (pattern) |
| `id` | equals its key in `objects` | §20, §24 | validator `id-mismatch` |
| `id`, `type`, `created_by` | unchanged between two states of the same object | §24, §25, §27, §75 | validator `immutable` |
| `type` | non-empty text; `task` selects the Task rules | §25, §74, §93 | schema |
| base fields | `id`, `type`, `lifecycle`, `created_by`, `extensions` required on every object, namespaced types included | §23, §74 | schema |
| `lifecycle` | `active` or `deleted` (closed set in version 1) | §26, §74 | schema |
| `created_by` | `p:` + unpadded base64url of exactly 32 bytes | §27 | schema (43 characters, canonical last character) |
| `created_at` | optional RFC 3339 UTC timestamp ending in `Z`, on every object type | §28 | schema (shape) + validator `bad-timestamp` (real date and time, every object type: SPEC-PATCH-04 / SOG-1) |
| `extensions` | map keyed by `reverse-domain` namespaces; contents unconstrained | §18, §29 | schema |
| Task required fields | `title`, `status`, `priority`, `tags`, `assignees` (plus base) | §30, §31 | schema |
| `title` | string; empty allowed | §32 | schema |
| `status` | `todo`, `in_progress`, `done`, `cancelled`, or `x/<reverse-domain>/<value>` (§33 ABNF) | §33 | schema |
| `priority` | `lowest`, `low`, `normal`, `high`, `highest`, or `x/<reverse-domain>/<value>` | §38 | schema |
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
- **I01–I07** must be invalid at the mutated field (a mutation of the S01
  Task). The vectors also name the `PROFILE_INVALID` diagnostic; the contract
  checks the field, not the diagnostic name. I07 (`type` changed) is valid as
  a state; it is caught only by the immutable-field check across states.
- **D06–D08** Object IDs are classified as the vectors say.

Profile framing (D04, D05) is byte-verified by the vector validator
(`scripts/lib/vector-checks.mjs`) and not repeated here. The profile defines
no other framing.

## Spec decisions

The gaps this contract first found (SO-G1 to SO-G9) were decided by the
project owner and applied by SPEC-PATCH-01; see
`adr/0001-mvp-0.1-protocol-decisions.md`. Every failure reported here
corresponds to a §74.1 diagnostic, listed per fixture in
`fixtures/expected.json`. The contract asserts the failing field, not the
diagnostic name.
