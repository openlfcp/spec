# Value changes for `mvp-0.2-baseline.7`

[`value-changes.json`](value-changes.json) lists every vector value that
differs from the previous baseline, `mvp-0.2-baseline.6`, with the decision
that approved it. `scripts/check-baseline-changes.mjs` always checks the
newest `mvp-0.M-baseline.N` directory; see
[`../mvp-0.1-baseline.3/`](../mvp-0.1-baseline.3/README.md) for how the
check works.

SHARED-SECTIONS-PROFILE-01 §14.1 now names a refused change only when its
chunk's checksum matches. The name is the SHA-256 of the chunk from its
type byte on, which leaves out the checksum, so a copy with a wrong
checksum was named by the hash of its intact copy. sdk-rs remembered the
refusal by that name and refused the intact copy when the same Principal
sent it, and every change that depended on it; sdk-ts checked the intact
copy and applied it (finding C1 of the differential fuzzing). The checksum
is the first four bytes of the same hash, so checking it needs no
decoding; a name then stands for exactly one sequence of bytes, and a
receiver may refuse later bytes with a refused name again. A change that
depends on an unnamed refusal waits, as for any missing dependency.

One value changes: SS45's refused change, whose checksum is wrong, loses
its `change` field, as SS44's compressed chunk did in
`mvp-0.2-baseline.4`. `migrations/vector-format-1/shared-sections-01.mapping.json`
lists the removal too.

The shared sections corpus gains SS76 to SS78. SS76: A's change with a
wrong checksum, the same change intact, then A's change after it; the
broken copy is refused without a name, the other two are applied. SS77:
the broken copy and the change after it, without the intact copy; the
dependent waits. SS78: the broken copy, then the intact copy in a Data
Unit signed by B; the intact copy is refused with `CHANGE_ACTOR_MISMATCH`
(finding C2: one SDK answered with the remembered `INVALID_AUTOMERGE_BYTES`).
The reference admission lists refusals in a fixed order, the named ones
by change hash, then the unnamed ones, so that SS78's two refusals do not
depend on the order the changes arrive in.

For an implementation the change is: name refused bytes only when they are
one type 1 change chunk of exact length whose checksum matches; never
remember a refusal by the hash of bytes whose checksum does not match.
