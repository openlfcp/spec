# Value changes for `mvp-0.1-baseline.10`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.1-baseline.9`, with the
SPEC-PATCH-10 decision that approved it (ADR 0010).
`scripts/check-baseline-changes.mjs` always checks the newest
`mvp-0.M-baseline.N` directory, which for this commit is
[`../mvp-0.2-baseline.2/`](../mvp-0.2-baseline.2/README.md): the two tags
are on one commit, and the MVP 0.1 suites are the same in both. See
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SPEC-PATCH-10 changes no published value. It only adds cases: the
Automerge reference corpus gains the `canonical` section (SHARED-OBJECTS-
PROFILE-01 §11.3) and the `references` section (§11.4). Every change
already published is canonical and refers only to its history.
