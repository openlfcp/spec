# Value changes for `mvp-0.4-baseline.4`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.4-baseline.3`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

`mvp-0.4-baseline.4` applies the ten findings of the final review of
`mvp-0.4-baseline.3` (task LFCP-04-415). Every suite of
`mvp-0.4-baseline.3` is listed and compared value by value. No wire rule
changes.

## Changed values (28), all from finding 1

IDENTITY-PROFILE-01 §7.1 step 1 now propagates a revoked pair of `I` into a
roster Resource `X` only when it is relevant there: the device is bound in
`X`, or it is bound in `I` with kind `0`, or with kind `1` and `X` in its
scope, or `I` holds no binding of it. A pairing device is never bound
outside `I`, so the consume or cancellation of a pairing session is no
longer propagated.

- `LFCP-IDENTITY-TEST-VECTORS-01` (9 values): the cases
  `flow.reconcile_revoke_pairing_in_x`, `flow.f09a_revoke_pair_j` and
  `flow.f09b_revoke_pair_j` keep their bytes and verdicts (the wire accepts
  them); their `description`, `rule.section` and `rule.text` now state the
  wire decision and that IP §7.1 no longer proposes them.
- `IDENTITY-FLOW-FIXTURES-01` (19 values): in `F05_reconciliation` step 3
  and in `F09_pairing_service` steps 7 and 11, the step that revoked
  `PAIR_J` in `X` is now the client step `not propagated` (its `case` and
  the `exposing` fact are removed, its `action` and `outcome` change), and
  the following steps name the histories without that tombstone
  (`flow.reconcile_register_dev_a_in_x`, `flow.f09a_reconcile_*`,
  `flow.f09b_reconcile_*`). Step counts and every other fact are unchanged.

The cases built on the old histories (`flow.reconcile_register_dev_a`,
`flow.f09{a,b}_revoke_dev_a`, `flow.f09{a,b}_register_c1`,
`flow.f09b_kp_owner_to_bridge_o`) are unchanged and gain a `note` naming
their replacements.

## Added, with no published value changed

- `LFCP-IDENTITY-TEST-VECTORS-01`: the Principals `DEV_P`, `PAIR_Z`,
  `PAIR_B` and `PAIR_T_01..65` with their certificates; the record set
  `sixty_five_cancelled_sessions_in_i` and the `flow.p65_*` cases
  (finding 1); the corrected F05 and F09 histories; the revoked reader's
  `RESOURCE_OPENED`, `CONTROL_GET` ranges and presence cases, the Key
  Package uploads to a server without `identity-01`, and the states of the
  link and claim cases (finding 8).
- `IDENTITY-PROFILE-TEST-VECTORS-01`: initial changes with a container as
  an empty list, and their Snapshot states (finding 2); descriptors with a
  small-order, non-canonical or off-curve Ed25519 key (finding 3); wrong
  types of `platform` and `revoked`, with valid and conflicting controls
  (finding 4); an extension namespace value replaced by a scalar, admitted,
  and the `extensions` container replaced, refused (finding 5); one case
  per pairing-link check of §5.2 (finding 8).
- `IDENTITY-FLOW-FIXTURES-01`: `F05.sixty_five_sessions` (finding 1),
  `F05.display_data` (finding 7), `F13.issuer_revoked_before_resume`
  (finding 6), `F07.read_device_cannot_claim`, `F08.link_rejected`,
  `F08.missing_material` and appended steps of `F17` and `F18` (finding 8);
  every Register phase's `phase_input` gains its planned `chain`
  (finding 6).
