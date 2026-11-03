"""Reference model of LFCP-WIRE-01 multi-device identity, for the vector generators.

An independent, deliberately literal reading of LFCP-WIRE-01 §7.2, §7.3, §13,
§15, §17.2 to §17.5, §18.1, §19, §23, §25.2, §26.3, §29.2, §41, §62, §79 and
§80.1. The identity vector generator computes every verdict and post-state
with it and checks the result against the expectation written next to each
case from the specification text; a disagreement stops the generator.

It is test tooling, not an implementation: no I/O, no clocks, no network.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from generate_lfcp_test_vectors_01 import cbor, ed_encode, ed_small_order, ed_try_decode, sha256

FULL = [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13]
STANDARD = set(range(1, 11))

MALFORMED = 'MALFORMED_MESSAGE'
PLACEMENT = 'INVALID_CONTROL_CHAIN'
MISSING = 'MISSING_DEPENDENCY'
BAD_SIG = 'INVALID_SIGNATURE'
DENIED = 'AUTHORIZATION_FAILED'
STALE = 'STALE_DATA_EPOCH'
CONFLICT = 'CONTROL_CONFLICT'

GENESIS, GRANT, REVOKE, CLAIM, KEY_EPOCH, ROUTE, COMMIT, RECOVERY, TOMBSTONE, DEVICE_GRANT, DEVICE_REVOKE = range(11)
KNOWN_TYPES = {GENESIS, GRANT, REVOKE, CLAIM, KEY_EPOCH, COMMIT, DEVICE_GRANT, DEVICE_REVOKE}


class Reject(Exception):
    """A rejection with its wire code and the rule that decided it."""

    def __init__(self, code: str, rule: str):
        super().__init__(f'{code}: {rule}')
        self.code = code
        self.rule = rule


# -----------------------------------------------------------------------------
# Strict decoding (W §5.2, §10): canonical bytes, untagged COSE_Sign1.
# -----------------------------------------------------------------------------

def _decode(b: bytes, i: int):
    major, info = b[i] >> 5, b[i] & 0x1f
    i += 1
    if info < 24:
        n = info
    elif info in (24, 25, 26, 27):
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        if i + size > len(b):
            raise ValueError('truncated')
        n, i = int.from_bytes(b[i:i + size], 'big'), i + size
    else:
        raise ValueError('indefinite or reserved length')
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(b):
            raise ValueError('truncated')
        raw = b[i:i + n]
        return (raw if major == 2 else raw.decode('utf-8')), i + n
    if major == 4:
        out = []
        for _ in range(n):
            v, i = _decode(b, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = _decode(b, i)
            if isinstance(k, (list, dict)):
                raise ValueError('composite map key')
            v, i = _decode(b, i)
            out[k] = v
        return out, i
    if major == 6:
        raise ValueError('tagged item')
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], i
    raise ValueError('unsupported item')


def decode_canonical(b: bytes):
    """Decode one deterministic CBOR item that must be all of `b` and re-encode identically."""
    try:
        v, i = _decode(b, 0)
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        raise Reject(MALFORMED, f'W §5.2: not decodable ({e})')
    if i != len(b) or cbor(v) != b:
        raise Reject(MALFORMED, 'W §5.2: not the deterministic encoding')
    return v


@dataclass
class Signed:
    cose: bytes
    protected: bytes
    payload: bytes
    obj: Any
    signature: bytes
    kid: bytes

    @property
    def id(self) -> bytes:
        return sha256(self.cose)

    def verifies(self, ed_pk: bytes) -> bool:
        sig_structure = cbor(['Signature1', self.protected, b'', self.payload])
        try:
            Ed25519PublicKey.from_public_bytes(ed_pk).verify(self.signature, sig_structure)
            return True
        except (InvalidSignature, ValueError):
            return False


def parse_signed(cose: Any, what: str) -> Signed:
    """W §10: untagged four-element COSE_Sign1, protected {1: -8, 4: kid}, empty unprotected."""
    if not isinstance(cose, bytes) or not cose:
        raise Reject(MALFORMED, f'W §10: {what} is not a byte string')
    if cose[0] >> 5 == 6:
        raise Reject(MALFORMED, f'W §10: {what} is a tagged COSE_Sign1')
    arr = decode_canonical(cose)
    if not (isinstance(arr, list) and len(arr) == 4 and isinstance(arr[0], bytes) and arr[1] == {}
            and isinstance(arr[2], bytes) and isinstance(arr[3], bytes) and len(arr[3]) == 64):
        raise Reject(MALFORMED, f'W §10: {what} is not a COSE_Sign1 array')
    prot = decode_canonical(arr[0])
    if not (isinstance(prot, dict) and set(prot) == {1, 4} and prot[1] == -8
            and isinstance(prot[4], bytes) and len(prot[4]) == 32):
        raise Reject(MALFORMED, f'W §10: {what} protected header is not {{1: -8, 4: kid}}')
    obj = decode_canonical(arr[2])
    return Signed(cose, arr[0], arr[2], obj, arr[3], prot[4])


def is_h32(v) -> bool:
    return isinstance(v, bytes) and len(v) == 32


def is_uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def check_descriptor(d: Any, what: str) -> dict:
    """W §7: closed map {0, 1, 2}, recomputed ID, canonical non-small-order Ed25519 key."""
    if not (isinstance(d, dict) and set(d) == {0, 1, 2} and all(is_h32(d[k]) for k in (0, 1, 2))):
        raise Reject(MALFORMED, f'W §7: {what} is not a closed principal-descriptor')
    if sha256(b'LFCP-PRINCIPAL-v1' + d[1] + d[2]) != d[0]:
        raise Reject(MALFORMED, f'W §7: {what} ID is not the recomputed ID')
    point = ed_try_decode(d[1])
    if point is None or ed_encode(point) != d[1] or ed_small_order(point):
        raise Reject(MALFORMED, f'W §7: {what} Ed25519 key is not canonical')
    return d


def uint_list(v: Any, lo: int, hi: int | None, what: str, rule: str) -> list[int]:
    if not (isinstance(v, list) and all(is_uint(x) for x in v)):
        raise Reject(MALFORMED, f'{rule}: {what} is not a list of uint')
    if len(set(v)) != len(v):
        raise Reject(MALFORMED, f'{rule}: {what} repeats a code')
    if len(v) < lo or (hi is not None and len(v) > hi):
        raise Reject(MALFORMED, f'{rule}: {what} has {len(v)} entries')
    return v


# -----------------------------------------------------------------------------
# Device Certificates and chains (W §7.3).
# -----------------------------------------------------------------------------

@dataclass
class Cert:
    signed: Signed
    root: bytes
    device: dict
    kind: int
    mask: list[int]
    scope: list[bytes]
    serial: bytes

    @property
    def id(self) -> bytes:
        return self.signed.id

    @property
    def digest(self) -> bytes:
        return sha256(self.signed.payload)

    @property
    def device_id(self) -> bytes:
        return self.device[0]


def parse_cert(cose: Any) -> Cert:
    """Structural rules 1 to 5 of W §7.3 and the §5.2 canonical-bytes check."""
    s = parse_signed(cose, 'certificate')
    p = s.obj
    if not (isinstance(p, list) and len(p) == 7 and p[0] == 'LFCP-DEVICE-CERT-v1'):
        raise Reject(MALFORMED, 'W §7.3 rule 1: payload is not the seven-element LFCP-DEVICE-CERT-v1 array')
    if not is_h32(p[1]):
        raise Reject(MALFORMED, 'W §7.3 rule 1: field 1 is not a principal-id')
    check_descriptor(p[2], 'certificate field 2')
    if p[2][0] == p[1]:
        raise Reject(MALFORMED, 'W §7.3 rule 2: the device ID equals the root ID')
    if not is_uint(p[3]) or p[3] > 2:
        raise Reject(MALFORMED, 'W §7.3 rule 3: kind is not 0, 1 or 2')
    mask = uint_list(p[4], 1, 32, 'mask', 'W §7.3 rule 4')
    if 12 in mask and not {1, 2} <= set(mask):
        raise Reject(MALFORMED, 'W §7.3 rule 4: a mask that lists 12 lists 1 and 2')
    scope = p[5]
    if not (isinstance(scope, list) and all(is_h32(r) for r in scope)):
        raise Reject(MALFORMED, 'W §7.3 rule 5: scope is not a list of resource-id')
    if len(scope) > 64:
        raise Reject(MALFORMED, 'W §7.3: resource-scope has at most 64 entries')
    if len(set(scope)) != len(scope):
        raise Reject(MALFORMED, 'W §7.3 rule 5: scope repeats a Resource ID')
    if p[3] == 0 and scope:
        raise Reject(MALFORMED, 'W §7.3 rule 5: kind 0 has an empty scope')
    if p[3] == 1 and (not scope or 12 in mask or 13 in mask):
        raise Reject(MALFORMED, 'W §7.3 rule 5: kind 1 has 1 to 64 Resources and no 12 or 13')
    if p[3] == 2 and (len(scope) != 1 or not set(mask) <= {1, 2}):
        raise Reject(MALFORMED, 'W §7.3 rule 5: kind 2 has exactly one Resource and a mask within {1, 2}')
    if not (isinstance(p[6], bytes) and len(p[6]) == 16):
        raise Reject(MALFORMED, 'W §7.3: serial is not bstr .size 16')
    return Cert(s, p[1], p[2], p[3], mask, scope, p[6])


def parse_chain(chain: Any, root: bytes) -> list[Cert]:
    """verifyChain step 1 (structure): c1, c5, c7."""
    if not (isinstance(chain, list) and 1 <= len(chain) <= 4 and all(isinstance(c, bytes) for c in chain)):
        raise Reject(MALFORMED, 'W §7.3 (c1): a chain has one to four certificates')
    certs = [parse_cert(c) for c in chain]
    if any(c.root != root for c in certs):
        raise Reject(MALFORMED, 'W §7.3 (c1): every certificate names root R')
    ids = [c.device_id for c in certs]
    if len(set(ids)) != len(ids) or root in ids:
        raise Reject(MALFORMED, 'W §7.3 (c5): no device twice, no certificate naming R as its device')
    if 12 in certs[0].mask and len(certs) > 3:
        raise Reject(MALFORMED, 'W §7.3 (c7): a managing leaf has at most three certificates')
    return certs


def chain_signatures(certs: list[Cert], root_desc: dict) -> None:
    """verifyChain step 3 (c2), leaf first."""
    for i, c in enumerate(certs):
        signer = certs[i + 1].device if i + 1 < len(certs) else root_desc
        if c.signed.kid != signer[0]:
            raise Reject(BAD_SIG, 'W §7.3 (c2): certificate kid is not its issuer')
        if not c.signed.verifies(signer[1]):
            raise Reject(BAD_SIG, 'W §7.3 (c2): certificate signature does not verify')


# -----------------------------------------------------------------------------
# Derived Control state (W §79) and evaluation (W §80.1).
# -----------------------------------------------------------------------------

@dataclass
class Grant:
    subject: bytes
    abilities: list[int]
    delegable: list[int]
    parent: bytes | None
    claim_limit: int | None
    issuer_root: bytes
    claims: int = 0
    revoked: bool = False


@dataclass
class Binding:
    root: bytes
    kind: int
    mask: frozenset
    scope: frozenset
    registered: bool = False
    chain: list[bytes] | None = None
    leaf_id: bytes | None = None
    issuers: list[bytes] = field(default_factory=list)


@dataclass
class State:
    resource: bytes
    profile: str
    owner: bytes
    descriptors: dict
    seq: int = 0
    head: bytes | None = None
    ids: list[bytes] = field(default_factory=list)
    epoch: int = 0
    commitments: dict = field(default_factory=dict)
    cutoffs: dict = field(default_factory=dict)
    grants: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)
    devices: dict = field(default_factory=dict)
    revoked: dict = field(default_factory=dict)
    grant_counts: dict = field(default_factory=dict)
    device_revokes: list = field(default_factory=list)  # (index in ids, root, device)

    def clone(self) -> 'State':
        return copy.deepcopy(self)

    # ---- grants (W §17.2, §18) ----
    def grant_active(self, gid: bytes) -> bool:
        g = self.grants[gid]
        return not g.revoked and (g.parent is None or self.grant_active(g.parent))

    def confers(self, g: Grant, a: int) -> bool:
        if a not in g.abilities:
            return False
        if a == 11 and g.claim_limit is not None and g.claims >= g.claim_limit:
            return False  # §18.1: an invitation grant whose claims are used up confers no invite/claim
        return True

    def direct(self, p: bytes, a: int) -> bool:
        """W §80 steps 2 to 7."""
        if p == self.owner:
            return True
        return any(g.subject == p and self.grant_active(gid) and self.confers(g, a) for gid, g in self.grants.items())

    def invitation_subject(self, p: bytes) -> bool:
        """Subject of an active grant that includes and still confers invite/claim (§25.2, §41)."""
        if p in self.devices:
            return False
        return any(g.subject == p and self.grant_active(gid) and self.confers(g, 11) for gid, g in self.grants.items())

    def standing(self, r: bytes) -> bool:
        """rootStanding (W §17.5)."""
        if r == self.owner:
            return True
        return any(g.subject == r and self.grant_active(gid) and 11 not in g.abilities for gid, g in self.grants.items())

    # ---- devices (W §17.5, §80.1) ----
    def active(self, d: bytes) -> bool:
        b = self.devices.get(d)
        if b is None or not b.registered:
            return False
        if (b.root, d) in self.revoked or any((b.root, e) in self.revoked for e in b.issuers):
            return False
        return self.standing(b.root)

    def suspended(self, d: bytes) -> bool:
        b = self.devices.get(d)
        return (b is not None and b.registered and (b.root, d) not in self.revoked
                and any((b.root, e) in self.revoked for e in b.issuers))

    def bound(self, p: bytes) -> bool:
        return p in self.devices

    def acts_for(self, p: bytes) -> bytes:
        return self.devices[p].root if self.active(p) else p

    def root_of(self, p: bytes) -> bytes:
        return self.devices[p].root if p in self.devices else p

    def holds(self, p: bytes, a: int) -> bool:
        if p in self.devices:
            if not self.active(p) or a not in STANDARD:
                return False
            d = self.devices[p]
            if self.owner == d.root and 13 in d.mask:
                return True
            return a in d.mask and self.direct(d.root, a)
        return self.direct(p, a)

    def owner_action(self, p: bytes) -> bool:
        if p in self.devices:
            d = self.devices[p]
            return self.active(p) and d.root == self.owner and 13 in d.mask
        return self.owner == p

    def same_root(self, s: bytes, r: bytes) -> bool:
        return self.acts_for(s) == self.acts_for(r) and (self.active(s) or self.active(r))

    def readers(self) -> set:
        return {p for p, b in self.devices.items() if b.registered and self.holds(p, 1)}

    # ---- chain verification step 4 (W §7.3) ----
    def chain_state(self, certs: list[Cert], root: bytes) -> None:
        for i in range(len(certs) - 1):
            issuer = certs[i + 1]
            if issuer.kind != 0 or 12 not in issuer.mask:
                raise Reject(DENIED, 'W §7.3 (c3): an issuer is a personal device with 12 in its mask')
            if not set(certs[i].mask) <= set(issuer.mask):
                raise Reject(DENIED, 'W §7.3 (c4): a mask is within its issuer\'s mask')
        if certs[0].kind == 2 and self.resource not in certs[0].scope:
            raise Reject(DENIED, 'W §7.3 (c6): a pairing leaf lists this Resource')
        if self.roles.get(root, 'non-device') != 'non-device':
            raise Reject(DENIED, 'W §7.3 step 4.2: roles[R] is non-device')
        for c in certs:
            e = c.device_id
            if self.roles.get(e, 'device') != 'device':
                raise Reject(DENIED, 'W §7.3 step 4.3: a chain device has the non-device role')
            b = self.devices.get(e)
            if b is not None and (b.root != root or b.kind != c.kind or b.mask != frozenset(c.mask)
                                  or b.scope != frozenset(c.scope)):
                raise Reject(DENIED, 'W §7.3 step 4.3: a bound device keeps its root, kind, mask and scope (N8)')
        for c in certs:
            if (root, c.device_id) in self.revoked:
                raise Reject(DENIED, 'W §7.3 step 4.4: no device of the chain is revoked')

    def in_scope(self, leaf: Cert) -> bool:
        return not (leaf.kind == 1 and self.resource not in leaf.scope)

    def bind(self, certs: list[Cert], root: bytes) -> list[bytes]:
        """Effect of an accepted chain (§17.4 rule 9, §15, §23.3); returns the new bindings."""
        new = []
        for c in certs:
            self.descriptors[c.device_id] = c.device
            if c.device_id not in self.devices:
                self.devices[c.device_id] = Binding(root, c.kind, frozenset(c.mask), frozenset(c.scope))
                self.roles[c.device_id] = 'device'
                new.append(c.device_id)
        leaf = self.devices[certs[0].device_id]
        leaf.chain = [c.signed.cose for c in certs]
        leaf.leaf_id = certs[0].id
        leaf.issuers = [c.device_id for c in certs[1:]]
        if self.in_scope(certs[0]):
            leaf.registered = True
        return new

    def live_bound(self, root: bytes) -> int:
        return sum(1 for e, b in self.devices.items() if b.root == root and (root, e) not in self.revoked)

    def unbound_tombstones(self, root: bytes) -> int:
        return sum(1 for (r, e) in self.revoked if r == root and e not in self.devices)


def placement(s: State | None, payload: dict, typ: int) -> None:
    """Class 2 (W §13.1, §14)."""
    if typ == GENESIS:
        if payload[1] != 0 or payload[2] is not None:
            raise Reject(PLACEMENT, 'W §13.1: Genesis is at control_seq 0 with a null prev_control_id')
        if s is not None:
            raise Reject(PLACEMENT, 'W §13.1: a Genesis after the first record')
        return
    if s is None:
        raise Reject(PLACEMENT, 'W §13.1: the first record is a Genesis')
    if payload[0] != s.resource or payload[1] != s.seq + 1 or payload[2] != s.head:
        raise Reject(PLACEMENT, 'W §13.1: control_seq is previous + 1 and prev_control_id is the previous record ID')
    if typ not in KNOWN_TYPES and typ < 32:
        raise Reject(PLACEMENT, 'W §14: an unknown core Control Record type fails validation')


def outer_signature(rec: Signed, payload: dict, desc: dict | None) -> None:
    if rec.kid != payload[4]:
        raise Reject(BAD_SIG, 'W §13: the protected-header kid equals field 4')
    if desc is None or not rec.verifies(desc[1]):
        raise Reject(BAD_SIG, 'W §10.5: the record signature verifies under the issuer')


def apply_record(s: State | None, cose: bytes) -> tuple[State, dict]:
    """Validate one Control Record at state `s` (None before Genesis); return the next state and effects.

    The classes of W §62 run in order across the record and every embedded object.
    """
    rec = parse_signed(cose, 'record')
    p = rec.obj
    if not (isinstance(p, dict) and set(p) == {0, 1, 2, 3, 4, 5} and is_h32(p[0]) and is_uint(p[1])
            and (p[2] is None or is_h32(p[2])) and is_uint(p[3]) and is_h32(p[4])):
        raise Reject(MALFORMED, 'W §13: control-record-payload is a closed map of the stated types')
    typ, body = p[3], p[5]
    parsed = structure(typ, body)            # class 1
    placement(s, p, typ)                     # class 2
    handler = {GENESIS: _genesis, GRANT: _grant, REVOKE: _revoke, CLAIM: _claim, KEY_EPOCH: _key_epoch,
               COMMIT: _commit, DEVICE_GRANT: _device_grant, DEVICE_REVOKE: _device_revoke}[typ]
    nxt, effects = handler(s, rec, p, parsed)
    nxt.seq = p[1]
    nxt.head = rec.id
    nxt.ids = list(nxt.ids) + [rec.id]
    return nxt, effects


# ---- class 1 per type ----

def structure(typ: int, body: Any) -> dict:
    if typ == GENESIS:
        if not (isinstance(body, dict) and {0, 1, 2, 3, 4} <= set(body) <= {0, 1, 2, 3, 4, 5}
                and isinstance(body[0], str) and is_h32(body[2]) and isinstance(body[3], list) and body[3]
                and isinstance(body[4], str)):
            raise Reject(MALFORMED, 'W §15: genesis-body is a closed map of the stated types')
        owner = check_descriptor(body[1], 'Genesis owner')
        certs = parse_chain(body[5], owner[0]) if 5 in body else None
        return {'owner': owner, 'certs': certs}
    if typ == GRANT:
        if not (isinstance(body, dict) and {0, 1, 2} <= set(body) <= {0, 1, 2, 3, 4}):
            raise Reject(MALFORMED, 'W §17.2: capability-grant-body is a closed map')
        subject = check_descriptor(body[0], 'grant subject')
        ab = uint_list(body[1], 1, None, 'abilities', 'W §17.1')
        dl = uint_list(body[2], 0, None, 'delegable abilities', 'W §17.1')
        if (3 in body and not is_h32(body[3])) or (4 in body and not is_uint(body[4])):
            raise Reject(MALFORMED, 'W §17.2: parent is hash32, claim_limit is uint')
        return {'subject': subject, 'abilities': ab, 'delegable': dl, 'parent': body.get(3), 'limit': body.get(4)}
    if typ == REVOKE:
        if not (isinstance(body, dict) and set(body) == {0} and is_h32(body[0])):
            raise Reject(MALFORMED, 'W §17.3: capability-revoke-body is {0: hash32}')
        return {'target': body[0]}
    if typ == CLAIM:
        if not (isinstance(body, dict) and set(body) == {0, 1, 2} and is_h32(body[0])):
            raise Reject(MALFORMED, 'W §18.1: capability-claim-body is a closed map')
        claimant = check_descriptor(body[1], 'claimant')
        return {'grant': body[0], 'claimant': claimant, 'abilities': uint_list(body[2], 1, None, 'abilities', 'W §17.1')}
    if typ == KEY_EPOCH:
        if not (isinstance(body, dict) and set(body) == {0, 1, 2, 3} and is_uint(body[0]) and is_h32(body[1])
                and isinstance(body[2], list) and is_uint(body[3])):
            raise Reject(MALFORMED, 'W §19: key-epoch-body is a closed map')
        pids = []
        for e in body[2]:
            if not (isinstance(e, dict) and set(e) <= {0, 1, 2} and {0, 1} <= set(e) and is_h32(e[0]) and is_uint(e[1])):
                raise Reject(MALFORMED, 'W §28.1: actor-have entry')
            prev_end = e[1]
            if 2 in e and not isinstance(e[2], list):
                raise Reject(MALFORMED, 'W §28.1: the extra ranges of an actor-have are a list')
            for r in e.get(2, []):
                # rules 2 to 8: a present key 2 is a non-empty list of sorted, non-overlapping,
                # non-adjacent ranges strictly above contiguous + 1.
                if not (isinstance(r, list) and len(r) == 2 and all(is_uint(x) for x in r) and r[0] <= r[1] and r[0] >= prev_end + 2):
                    raise Reject(MALFORMED, 'W §28.1: the extra ranges of an actor-have are canonical')
                prev_end = r[1]
            if 2 in e and not e[2]:
                raise Reject(MALFORMED, 'W §28.1 rule 2: key 2 is omitted when there are no extra ranges')
            pids.append(e[0])
        if pids != sorted(pids) or len(set(pids)) != len(pids):
            raise Reject(MALFORMED, 'W §19: the final frontier is canonical')
        return {'epoch': body[0], 'commitment': body[1], 'frontier': {e[0]: (e[1], [tuple(r) for r in e.get(2, [])]) for e in body[2]}}
    if typ == COMMIT:
        if not (isinstance(body, dict) and {0, 1} <= set(body) <= {0, 1, 2}):
            raise Reject(MALFORMED, 'W §23.3: owner-transfer-commit-body is a closed map')
        offer = parse_signed(body[0], 'transfer offer')
        o = offer.obj
        if not (isinstance(o, dict) and set(o) == {0, 1, 2, 3, 4} and is_h32(o[0]) and is_h32(o[1]) and is_uint(o[2])
                and isinstance(o[4], bytes) and len(o[4]) == 16):
            raise Reject(MALFORMED, 'W §23.1: owner-transfer-offer-payload is a closed map of the stated types')
        new_owner = check_descriptor(o[3], 'offer new owner')
        accept = parse_signed(body[1], 'transfer accept')
        a = accept.obj
        if not (isinstance(a, dict) and set(a) == {0, 1, 2} and all(is_h32(a[k]) for k in (0, 1, 2))):
            raise Reject(MALFORMED, 'W §23.2: owner-transfer-accept-payload is a closed map')
        certs = parse_chain(body[2], new_owner[0]) if 2 in body else None
        return {'offer': offer, 'accept': accept, 'new_owner': new_owner, 'certs': certs}
    if typ == DEVICE_GRANT:
        if not (isinstance(body, dict) and {0, 1} <= set(body) <= {0, 1, 2} and is_h32(body[0])
                and (2 not in body or is_h32(body[2]))):
            raise Reject(MALFORMED, 'W §17.4 rule 1: device-grant-body is a closed map {0, 1, ?2}')
        certs = parse_chain(body[1], body[0])
        if certs[0].kind == 2 and 2 in body:
            raise Reject(MALFORMED, 'W §17.4 rule 1: a pairing leaf carries no field 2')
        return {'root': body[0], 'certs': certs, 'pairing': body.get(2)}
    if typ == DEVICE_REVOKE:
        if not (isinstance(body, dict) and {0, 1, 2} <= set(body) and set(body) <= {0, 1, 2, 4}
                and is_h32(body[0]) and is_h32(body[1]) and is_uint(body[2]) and (4 not in body or is_h32(body[4]))):
            raise Reject(MALFORMED, 'W §17.5 rule 1: device-revoke-body is a closed map {0, 1, 2, ?4}; field 3 is reserved')
        if body[0] == body[1]:
            raise Reject(MALFORMED, 'W §17.5 rule 1: D differs from R')
        if (4 in body) != (body[2] == 3):
            raise Reject(MALFORMED, 'W §17.5 rule 1: field 4 is present if and only if the reason is 3')
        return {'root': body[0], 'device': body[1], 'reason': body[2], 'approval': body.get(4)}
    return {}


# ---- classes 3 to 5 per type ----

def _known(s: State, pid: bytes) -> dict | None:
    return s.descriptors.get(pid)


def _genesis(s, rec, p, b):
    owner, certs = b['owner'], b['certs']
    if certs is None:
        if rec.kid != owner[0] or p[4] != owner[0]:
            raise Reject(BAD_SIG, 'W §15: Genesis is signed by the owner of field 1')
        outer_signature(rec, p, owner)
    else:
        leaf = certs[0]
        if rec.kid != leaf.device_id or p[4] != leaf.device_id:
            raise Reject(BAD_SIG, 'W §15: a Genesis with field 5 is signed by the leaf device')
        outer_signature(rec, p, leaf.device)
        chain_signatures(certs, owner)
    n = State(resource=p[0], profile=p[5][0], owner=owner[0], descriptors={owner[0]: owner})
    n.commitments[0] = p[5][2]
    n.roles[owner[0]] = 'non-device'
    if certs is not None:
        n.chain_state(certs, owner[0])
        if certs[0].kind != 0 or 13 not in certs[0].mask:
            raise Reject(DENIED, 'W §15: the Genesis leaf is of kind 0 with 13 in its mask')
        n.bind(certs, owner[0])
    return n, {}


def _issuer_checks(s, rec, p, extra: dict | None = None):
    desc = _known(s, p[4]) or (extra or {}).get(p[4])
    if desc is None:
        raise Reject(MISSING, 'W §13.1: the issuer resolves to a Principal Descriptor')
    outer_signature(rec, p, desc)


def _grant(s, rec, p, b):
    _issuer_checks(s, rec, p)
    kid, subj = p[4], b['subject'][0]
    if s.bound(subj):
        raise Reject(DENIED, 'W §17.2, §80.1: the subject is not bound as a device')
    if not s.owner_action(kid):
        if not s.holds(kid, 4):
            raise Reject(DENIED, 'W §17.2, §80.1: a non-owner issuer holds capability/grant')
        par = b['parent']
        if par is None or par not in s.grants:
            raise Reject(DENIED, 'W §17.2: a non-owner issuer references a parent grant')
        g = s.grants[par]
        if not s.grant_active(par):
            raise Reject(DENIED, 'W §17.2: the parent grant is active')
        if s.acts_for(kid) != g.subject:
            raise Reject(DENIED, 'W §17.2, §80.1: actsFor(issuer) is the subject of the parent grant')
        if not set(b['abilities']) <= set(g.delegable) or not set(b['delegable']) <= set(g.delegable):
            raise Reject(DENIED, "W §17.2: granted and delegable abilities are within the parent's delegable abilities")
        if s.bound(kid):
            mask = s.devices[kid].mask
            listed = (set(b['abilities']) | set(b['delegable'])) & STANDARD
            if not listed <= mask:
                raise Reject(DENIED, "W §17.2 delegation bound: codes 1 to 10 are within the issuer's certificate mask")
    n = s.clone()
    n.grants[rec.id] = Grant(subj, b['abilities'], b['delegable'], b['parent'], b['limit'], s.acts_for(kid))
    n.roles[subj] = 'non-device'
    n.descriptors[subj] = b['subject']
    return n, {'issuer_root': s.acts_for(kid)}


def _revoke(s, rec, p, b):
    _issuer_checks(s, rec, p)
    kid, t = p[4], b['target']
    if t not in s.grants:
        raise Reject(DENIED, 'W §17.3 check 1: the target names a grant of this chain')
    if not s.owner_action(kid):
        covers = False
        g = t
        while g is not None:
            if s.grants[g].issuer_root == s.acts_for(kid):
                covers = True
            g = s.grants[g].parent
        if not (s.holds(kid, 5) and covers):
            raise Reject(DENIED, 'W §17.3 check 2: the issuer is the owner or holds capability/revoke that covers the target')
    if s.grants[t].revoked:
        raise Reject(DENIED, 'W §17.3 check 3: the target is not already revoked')
    n = s.clone()
    n.grants[t].revoked = True
    return n, {}


def _claim(s, rec, p, b):
    _issuer_checks(s, rec, p)
    gid = b['grant']
    if gid not in s.grants or not s.grant_active(gid):
        raise Reject(DENIED, 'W §18.1 rule 1: the invitation grant is active')
    g = s.grants[gid]
    if 11 not in g.abilities:
        raise Reject(DENIED, 'W §18.1 rule 2: the grant grants invite/claim')
    if g.claim_limit is None or g.claims >= g.claim_limit:
        raise Reject(DENIED, 'W §18.1 rule 3: claims remain')
    allowed = (set(g.abilities) - {11}) | ({11} if 11 in g.delegable else set())
    if not set(b['abilities']) <= allowed:
        raise Reject(DENIED, 'W §18.1 rule 4: claimed abilities are within the invitation grant')
    if p[4] != g.subject:
        raise Reject(DENIED, 'W §18.1 rule 5: the claim is signed by the Invitation Principal')
    claimant = b['claimant'][0]
    if s.bound(claimant):
        raise Reject(DENIED, 'W §18.1, §80.1: the claimant is not bound as a device')
    n = s.clone()
    n.grants[gid].claims += 1
    n.grants[rec.id] = Grant(claimant, b['abilities'], [], None, None, s.acts_for(p[4]))
    n.roles[claimant] = 'non-device'
    n.descriptors[claimant] = b['claimant']
    return n, {}


def _key_epoch(s, rec, p, b):
    if b['epoch'] != s.epoch + 1:
        raise Reject(PLACEMENT, 'W §19: the new epoch is the previous Data Epoch plus one')
    _issuer_checks(s, rec, p)
    if not s.holds(p[4], 7):
        raise Reject(DENIED, 'W §19, §80.1: the issuer holds key/rotate')
    n = s.clone()
    n.cutoffs[s.epoch] = b['frontier']
    n.epoch = b['epoch']
    n.commitments[b['epoch']] = b['commitment']
    return n, {}


def _commit(s, rec, p, b):
    offer, accept, new_owner, certs = b['offer'], b['accept'], b['new_owner'], b['certs']
    o, a = offer.obj, accept.obj
    r2 = new_owner[0]
    # class 3: the referenced head; the root descriptor is in the offer.
    if o[1] not in s.ids:
        raise Reject(MISSING, 'W §23.3: the offer references a Control Head the receiver has')
    chain_descs = {c.device_id: c.device for c in certs} if certs else {}
    required = certs[0].device if certs else new_owner
    issuer_desc = _known(s, p[4]) or ({r2: new_owner} | chain_descs).get(p[4])
    if issuer_desc is None:
        raise Reject(MISSING, 'W §13.1: the issuer resolves to a Principal Descriptor')
    # class 4
    ok_kid = offer.kid == s.owner or (offer.kid in s.devices and s.devices[offer.kid].root == s.owner)
    if ok_kid and not offer.verifies(s.descriptors[offer.kid][1]):
        raise Reject(BAD_SIG, 'W §23.3, §62 class 4: the offer verifies under its kid')
    if accept.kid != required[0] or not accept.verifies(required[1]):
        raise Reject(BAD_SIG, 'W §23.3 item 4, §62 class 4: the acceptance is signed by its required signer')
    if certs and p[4] != required[0]:
        raise Reject(BAD_SIG, 'W §23.3: with field 2 the commit is signed by the leaf device')
    outer_signature(rec, p, issuer_desc)
    if certs:
        chain_signatures(certs, new_owner)
    # class 5
    if not ok_kid or not s.owner_action(offer.kid):
        raise Reject(DENIED, 'W §23.3 item 1: the offer is signed by the current owner or its owner-acting device')
    if certs:
        s.chain_state(certs, r2)
        if certs[0].kind != 0 or 13 not in certs[0].mask:
            raise Reject(DENIED, 'W §23.3: the accepting leaf is of kind 0 with 13 in its mask')
    if not certs and p[4] != r2:
        raise Reject(DENIED, 'W §23.3 item 5: without field 2 the commit is issued by the new owner')
    if s.bound(r2):
        raise Reject(DENIED, 'W §23.3, §80.1: the new owner is not bound as a device')
    if o[0] != s.resource or o[1] != s.head:
        raise Reject(DENIED, 'W §23.3 item 2: the offer references the current Control Head')
    if a[0] != s.resource or a[1] != offer.id or a[2] != r2:
        raise Reject(DENIED, 'W §23.3 item 3: the offer names the accepting Principal')
    if o[2] != p[1]:
        raise Reject(DENIED, 'W §23.3 item 6: the expected next Control Sequence matches the commit')
    n = s.clone()
    n.owner = r2
    n.roles[r2] = 'non-device'
    n.descriptors[r2] = new_owner
    if certs:
        leaf = n.devices.get(certs[0].device_id)
        if leaf is not None and leaf.registered and leaf.leaf_id == certs[0].id:
            for c in certs[1:]:
                n.descriptors[c.device_id] = c.device
        else:
            n.bind(certs, r2)
    return n, {}


def _device_grant(s, rec, p, b):
    r, certs, j = b['root'], b['certs'], b['pairing']
    leaf = certs[0]
    d = leaf.device_id
    # rule 2
    r_desc = _known(s, r)
    if r_desc is None:
        raise Reject(MISSING, "W §17.4 rule 2: R's descriptor is known")
    _issuer_checks(s, rec, p, {c.device_id: c.device for c in certs})
    # rule 3 (chain part)
    chain_signatures(certs, r_desc)
    # rule 4
    if not s.standing(r):
        raise Reject(DENIED, 'W §17.4 rule 4: rootStanding(R)')
    # rule 5
    s.chain_state(certs, r)
    if d in s.devices and s.devices[d].chain is not None and s.devices[d].leaf_id == leaf.id:
        raise Reject(DENIED, "W §17.4 rule 5: the new leaf certificate ID differs from devices[D].leaf_id")
    # rule 6
    kid = p[4]
    m = s.devices.get(kid)
    if kid == d:
        # D itself only for a first registration: "a device that was registered never re-certifies
        # itself", even when it is an active managing or owner-acting device (the parenthesis of rule 6).
        allowed = leaf.kind == 0 and (d not in s.devices or s.devices[d].chain is None)
    else:
        allowed = (
            kid == r
            or (leaf.kind == 0 and kid in [c.device_id for c in certs[1:]])
            or (m is not None and s.active(kid) and m.root == r and 12 in m.mask)
            or (r == s.owner and m is not None and s.active(kid) and m.root == r and 13 in m.mask)
        )
    if not allowed:
        raise Reject(DENIED, 'W §17.4 rule 6: the issuer is R, D itself, a chain issuer, an active managing device or an owner-acting device')
    # rule 7
    if j is not None:
        rv = s.revoked.get((r, j))
        bj = s.devices.get(j)
        if not (rv and rv[0] == 3 and bj and bj.kind == 2 and bj.root == r and rv[1] == leaf.digest):
            raise Reject(DENIED, 'W §17.4 rule 7: the consumed approval of J names this leaf')
    # rule 8
    new = [c.device_id for c in certs if c.device_id not in s.devices]
    if s.live_bound(r) + len(new) > 32:
        raise Reject(DENIED, 'W §17.4 rule 8: at most 32 live Principals bound to R')
    if s.grant_counts.get((r, d), 0) >= 8:
        raise Reject(DENIED, 'W §17.4 rule 8: at most 8 accepted DEVICE_GRANTs per (R, D)')
    n = s.clone()
    n.bind(certs, r)
    n.grant_counts[(r, d)] = s.grant_counts.get((r, d), 0) + 1
    return n, {'in_scope': s.in_scope(leaf)}


def _device_revoke(s, rec, p, b):
    r, d, reason, approval = b['root'], b['device'], b['reason'], b['approval']
    _issuer_checks(s, rec, p)
    # rule 3
    bd = s.devices.get(d)
    if bd is not None and bd.root != r:
        raise Reject(DENIED, 'W §17.5 rule 3: devices[D].root is R')
    if s.roles.get(d, 'device') != 'device':
        raise Reject(DENIED, 'W §17.5 rule 3: roles[D] is device')
    if s.roles.get(r, 'non-device') != 'non-device':
        raise Reject(DENIED, 'W §17.5 rule 3: roles[R] is non-device')
    if reason == 3 and (bd is None or bd.kind != 2):
        raise Reject(DENIED, 'W §17.5 rule 3: reason 3 names a pairing device')
    # rule 4
    kid = p[4]
    m = s.devices.get(kid)
    owner_dev = m is not None and s.active(kid) and m.root == s.owner and 13 in m.mask
    allowed = (
        (kid == r and s.standing(r))
        or (m is not None and s.active(kid) and m.root == r and 12 in m.mask)
        or kid == s.owner or owner_dev
        or (kid == d and bd is not None and bd.registered and (r, d) not in s.revoked and reason == 0)
    )
    if not allowed:
        raise Reject(DENIED, 'W §17.5 rule 4: the issuer is R with standing, an active managing device, the owner or its owner-acting device, or D retiring itself')
    # rule 5
    if (r, d) in s.revoked:
        raise Reject(DENIED, 'W §17.5 rule 5: (R, D) is not already revoked')
    if bd is None and s.unbound_tombstones(r) + 1 > 64:
        raise Reject(DENIED, 'W §17.5 rule 5: at most 64 revoked pairs of R without a binding')
    n = s.clone()
    n.revoked[(r, d)] = (reason, approval)
    n.device_revokes.append((len(s.ids), r, d))
    before = s.readers()
    exposing = any(not n.holds(x, 1) for x in before)
    return n, {'exposing': exposing}


# -----------------------------------------------------------------------------
# Data Plane objects (W §25.2, §26.3, §29.2) and reads (W §41).
# -----------------------------------------------------------------------------

def check_unit(at: State, latest: State, cose: bytes, known_heads: dict) -> None:
    u = parse_signed(cose, 'Data Unit')
    q = u.obj
    if not (isinstance(q, dict) and set(q) == {0, 1, 2, 3, 4, 5, 6} and is_uint(q[3]) and q[3] >= 1):
        raise Reject(MALFORMED, 'W §26: data-unit-payload')
    if q[5] not in known_heads:
        raise Reject(MISSING, 'W §26.3: the referenced Control Head is known')
    at = known_heads[q[5]]
    desc = at.descriptors.get(q[2])
    if desc is None:
        raise Reject(MISSING, 'W §26.3: the chain through the head describes the actor')
    if q[1] > at.epoch:
        raise Reject(MISSING, 'W §26.3: the Data Epoch is known at the head')
    if u.kid != q[2] or not u.verifies(desc[1]):
        raise Reject(BAD_SIG, 'W §26.3 rule 1: the signature is valid for the actor')
    if not at.holds(q[2], 2):
        raise Reject(DENIED, 'W §26.3 rule 2, §80.1: holds(actor, 2) at the referenced head')
    if q[1] < latest.epoch:
        fr = latest.cutoffs[q[1]]
        if not within_frontier(fr, q[2], q[3]):
            raise Reject(STALE, 'W §19.1: a closed-epoch unit is within the final frontier')


def within_frontier(fr: dict, actor: bytes, seq: int) -> bool:
    """W §19.1 with W §28.1: within the contiguous prefix or inside one of the extra ranges."""
    if actor not in fr:
        return False
    contiguous, extras = fr[actor]
    return seq <= contiguous or any(a <= seq <= b for a, b in extras)


def check_package(cose: bytes, known_heads: dict) -> None:
    k = parse_signed(cose, 'Key Package')
    q = k.obj
    if not (isinstance(q, dict) and set(q) == {0, 1, 2, 3, 4, 5, 6}):
        raise Reject(MALFORMED, 'W §25: key-package-payload')
    if q[3] not in known_heads:
        raise Reject(MISSING, 'W §25.2: the referenced Control Head is known')
    at = known_heads[q[3]]
    if q[1] > at.epoch:
        raise Reject(MISSING, 'W §25.2: the Data Epoch is known at the referenced head')
    desc = at.descriptors.get(q[4])
    if desc is None:
        raise Reject(MISSING, 'W §25: the sender resolves to a Principal Descriptor')
    if k.kid != q[4] or not k.verifies(desc[1]):
        raise Reject(BAD_SIG, 'W §25: the package is signed by its sender')
    decide_package(at, q[4], q[2])


def decide_package(at: State, sender: bytes, recipient: bytes) -> None:
    if not (at.holds(sender, 6) or at.same_root(sender, recipient)):
        raise Reject(DENIED, 'W §25.2: holds(sender, 6) or sameRoot(sender, recipient)')
    if not (at.holds(recipient, 1) or at.invitation_subject(recipient)):
        raise Reject(DENIED, 'W §25.2: holds(recipient, 1) or the invitation exception')


def check_snapshot(cose: bytes, known_heads: dict) -> None:
    sn = parse_signed(cose, 'Snapshot')
    q = sn.obj
    if q[4] not in known_heads:
        raise Reject(MISSING, 'W §29: the Snapshot Control Head is known')
    at = known_heads[q[4]]
    desc = at.descriptors.get(q[2])
    if desc is None:
        raise Reject(MISSING, 'W §29: the publisher resolves to a Principal Descriptor')
    if sn.kid != q[2] or not sn.verifies(desc[1]):
        raise Reject(BAD_SIG, 'W §29: the Snapshot is signed by its publisher')
    if not at.holds(q[2], 3):
        raise Reject(DENIED, 'W §29.2, §80.1: holds(publisher, 3) at the Snapshot head')


def read_access(latest: State, history: list[State], p: bytes) -> tuple[str, int | None]:
    """W §41 on an identity-01 server: ('full', None), ('prefix', index of the revoking record) or Reject."""
    if latest.holds(p, 1) or latest.invitation_subject(p):
        return 'full', None
    b = latest.devices.get(p)
    if b is not None and b.registered:
        for idx, r, d in latest.device_revokes:
            if d == p and r == b.root:
                before = history[idx - 1]
                if before.holds(p, 1):
                    return 'prefix', idx
                break
    raise Reject(DENIED, 'W §41, §84: holds(session, 1) at the accepted head, or the Control read for a revoked reader')
