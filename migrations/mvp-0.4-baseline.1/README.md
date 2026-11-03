# Value changes for `mvp-0.4-baseline.1`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.12`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

MVP 0.4 adds multi-device root identity (ADR 0011): LFCP-WIRE-01 §7.2, §7.3,
§17.4, §17.5, §80.1 and §100.1, the profile IDENTITY-PROFILE-01 and, with
task LFCP-04-403, the identity corpora. The Control Record type `9` becomes
`DEVICE_GRANT` and `10` becomes `DEVICE_REVOKE` (§14).

One published value follows from the registry change:

- `unknown_core_type_C1` mutated C1's type to `9` to show an unknown core
  type (`INVALID_CONTROL_CHAIN`, §14). An identity-aware receiver now
  rejects those bytes earlier, as `MALFORMED_MESSAGE`, because a type-9
  body that is a capability-grant-body is not a device-grant-body (§62,
  class 1 before class 2). The case moves to type `31`, the last reserved
  core code, so that it keeps showing an unknown core type for as long as
  possible; its base case, rule, expected code and the generator's
  derivation are otherwise unchanged. The description, the mutation target
  and the signed bytes change (the record is re-signed).

No other published value of `mvp-0.2-baseline.12` changes. The identity
vector suites (`LFCP-IDENTITY-TEST-VECTORS-01`,
`IDENTITY-PROFILE-TEST-VECTORS-01`, `IDENTITY-FLOW-FIXTURES-01`) are new
and are listed here as absent at the previous baseline when they are added.
