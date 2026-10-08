# Value changes for `mvp-0.2-baseline.2`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.1`, with the
SPEC-PATCH-10 decision that approved it (ADR 0010).
`scripts/check-baseline-changes.mjs` always checks the newest
`mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SPEC-PATCH-10 changes no published value. It only adds cases: the
Automerge reference corpus gains the `canonical` and `references` sections
(SHARED-OBJECTS-PROFILE-01 §11.3, §11.4), as in `mvp-0.1-baseline.10`, which
is on the same commit; the shared sections corpus gains SS57 to SS59, the
same rules in its own domain. No existing case of either corpus changes:
every published change is canonical and refers only to its history, and
the reference admission of the shared sections corpus, which now checks
§11.3 and §11.4, decides every earlier case as before.
