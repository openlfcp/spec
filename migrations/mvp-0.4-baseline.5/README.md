# Value changes for `mvp-0.4-baseline.5`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.4-baseline.4`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.4-baseline.5` states the positions of admission rule AI3 (task
LFCP-04-417, decision I27, from findings P2-1 and P3-1 of the cross-SDK
review of MVP 0.4). Every suite of `mvp-0.4-baseline.4` is listed and
compared value by value. No wire rule changes.

## Changed values

None. The reference admission of the profile generator now decides AI3 by
position; every published case keeps its verdict and its bytes.

## Added, with no published value changed

- `IDENTITY-PROFILE-TEST-VECTORS-01`: the AI3 position cases
  `identity_doc_extension_int_value`, `identity_doc_extension_f64_value`,
  `identity_doc_extension_null_value`,
  `identity_doc_unknown_field_int_value` (with `.entry`),
  `identity_doc_int_below_scalar_field` (with `.entry`) and
  `identity_doc_f64_below_map_in_list_field` (with `.entry`), admitted;
  `identity_doc_map_in_endpoints`, `identity_doc_map_in_scope`,
  `identity_doc_map_in_hint_list`, `identity_doc_f64_in_named_field` and
  `identity_doc_null_in_named_field`, `INVALID_FIELD_TYPE`; the changes
  they reference (`change.T1_*`); and the pairing-link endpoint cases
  `pair_uri_endpoint_ws_loopback` and
  `pair_uri_endpoint_upper_case_scheme` (accepted on parse),
  `pair_uri_endpoint_https` and `pair_uri_endpoint_without_authority`
  (`PAIRING_LINK_REJECTED`), `pair_uri_endpoint_at_in_path` and
  `pair_uri_endpoint_at_in_query` (an `@` outside the authority, accepted
  on parse), and `pair_uri_prefix_upper_case` (the prefix
  `LFCP://PAIR/`, accepted on parse; IDENTITY-PROFILE-01 §5.2, decision I32).
