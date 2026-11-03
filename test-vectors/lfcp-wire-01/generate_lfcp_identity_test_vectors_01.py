#!/usr/bin/env python3
"""Generate deterministic LFCP-IDENTITY-TEST-VECTORS-01 (IDENTITY-PROFILE-01 §12.2, ID-01 to ID-04).

An extension of generate_lfcp_test_vectors_01.py: it reuses that generator's
deterministic CBOR, Principals, key derivations and HPKE, and adds Device
Certificates, certificate chains, the identity Control Records, and the Data
Units, Key Packages, Snapshots and reads that depend on them.

Every verdict and post-state is computed by identity_model.py, an independent
reading of LFCP-WIRE-01, and checked against the expectation written next to
each case from IDENTITY-PROFILE-01 §12 and LFCP-WIRE-01; a disagreement stops
the generator. The flow fixtures (IDENTITY-FLOW-FIXTURES-01) are generated from
the same corpus by generate_identity_flow_fixtures_01.py.

DO NOT reuse any test private keys in production.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))

import generate_lfcp_test_vectors_01 as base  # noqa: E402
from generate_lfcp_test_vectors_01 import (  # noqa: E402
    COORD_A, ENDPOINT_A, ChaCha20Poly1305, actor_key, cbor, h, hpke_derive_key_pair_x25519,
    hpke_open, hpke_seal_with_ephemeral, lfcp_nonce, principal, sha256, snapshot_key, u64,
)
import identity_model as M  # noqa: E402
from identity_model import FULL, Reject  # noqa: E402

SUITE_ID = 'LFCP-IDENTITY-TEST-VECTORS-01'
OUT_JSON = HERE / f'{SUITE_ID}.json'
OUT_MD = HERE / f'{SUITE_ID}.md'
RAW_PROFILE = 'org.lfcp.test.raw.v1'
IDENTITY_PROFILE = 'org.openlfcp.identity.v1'
EDIT = [1, 2, 3]

# -----------------------------------------------------------------------------
# Fixture Principals (IDENTITY-PROFILE-01 §12.1) and the additions this corpus needs.
# -----------------------------------------------------------------------------

PRINCIPAL_ROLES = {
    'OWNER': 'root; owner of X, Y and I',
    'BOB': 'root; member of X (J1)',
    'CAROL': 'root; member of X (J2)',
    'INVITE': 'Invitation Principal',
    'DAVE': 'plain Principal (grant subject)',
    'DEV_A': 'personal device of OWNER (CERT_A, Full)',
    'DEV_A2': 'personal device of OWNER (CERT_A2, Full)',
    'DEV_B': 'personal device of OWNER (CERT_B, Edit, by DEV_A; CERT_B2 by OWNER)',
    'DEV_R': 'personal device of OWNER (CERT_R, Read)',
    'DEV_W': 'personal device of OWNER (CERT_W, {2})',
    'DEV_X': 'personal device of OWNER (CERT_X, Full, by DEV_B: negative)',
    'PAIR_J': 'pairing device of OWNER (CERT_J)',
    'BRIDGE_O': 'service device of OWNER (CERT_SO, scope [X])',
    'DEV_C': 'personal device of BOB (CERT_C)',
    'DEV_E': 'personal device of BOB (CERT_E, by DEV_C)',
    'DEV_F': 'personal device of BOB (CERT_F, Full)',
    'BRIDGE': 'service device of BOB (CERT_S, scope [X]; CERT_S2, scope [Y], by DEV_C)',
    # Additions of this corpus (not in the §12.1 table).
    'INVITE2': 'a fresh Invitation Principal (invitation_grant_by_device_within_mask)',
    'STRANGER': 'a Principal no record or chain describes',
    'DEV_D': 'personal device of DAVE (CERT_D)',
    'DEV_N': 'personal device of INVITE (CERT_N)',
    'DEV_L': 'a leaf device used by chain cases',
    'DEV_M2': 'managing device of OWNER at level 2 (CERT_M2, Full, by DEV_A)',
    'DEV_M3': 'managing device of OWNER at level 3 (CERT_M3, Full, by DEV_M2)',
    'DEV_M4': 'managing device of OWNER at level 4 (CERT_M4, Full, by DEV_M3: negative)',
    'DEV_G': 'personal device of OWNER with mask {1,2,12} (CERT_G)',
    'DEV_H': 'a leaf device used by feasibility cases',
    'DEV_K11': 'personal device of BOB with mask {1,2,11} (CERT_K11)',
    'DEV_K11W': 'personal device of BOB with mask {2,11} (CERT_K11W)',
    'DEV_K13': 'personal device of OWNER with mask {1,2,11,13} (CERT_K13)',
    'PAIR_K': 'a second pairing device of OWNER (CERT_JK), for the profile corpus',
    'PAIR_L': 'a pairing device of OWNER in I after the rotation to epoch 1 (CERT_JL), for flow F08',
    'PAIR_M': 'a pairing device of OWNER at the live-binding limit of I (CERT_JM), for flow F08',
    'PAIR_M2': 'a further pairing device of OWNER refused at the limit (CERT_JM2), for flow F08',
    'DEV_R7': 'personal device of BOB with mask {1,2,7} (CERT_R7), for the rotator test',
    'DEV_R6': 'personal device of BOB with mask {1,2,6} (CERT_R6), for the rotator test',
    'DEV_R7O': 'personal device of OWNER with mask {1,2,7} (CERT_R7O), for the rotator test in I',
}
P = {label: principal(label) for label in PRINCIPAL_ROLES}
LIMIT = [f'LIMIT_BOB_{k:02d}' for k in range(1, 31)]
TOMB_X = [f'TOMB_X_{k:03d}' for k in range(1, 66)]
TOMB_I = [f'TOMB_I_{k:03d}' for k in range(1, 65)]
LIMIT_OWNER = [f'LIMIT_OWNER_{k:02d}' for k in range(1, 31)]
PAIR_S = [f'PAIR_S_{k:02d}' for k in range(1, 41)]
for label in LIMIT + TOMB_X + TOMB_I + LIMIT_OWNER + PAIR_S:
    P[label] = principal(label)

RES = {name: h(f'LFCP-TV-IDENTITY-RESOURCE-{name}') for name in ('X', 'Y', 'I', 'U', 'Z')}
RES_PROFILE = {'X': RAW_PROFILE, 'Y': RAW_PROFILE, 'I': IDENTITY_PROFILE, 'U': RAW_PROFILE, 'Z': RAW_PROFILE}
SCOPE_FILL = [h(f'LFCP-TV-IDENTITY-SCOPE-{k:02d}') for k in range(1, 66)]


def dek(res: str, epoch: int) -> bytes:
    return h(f'LFCP-TV-IDENTITY-DEK-{res}-EPOCH-{epoch}')


def commitment(res: str, epoch: int) -> bytes:
    return sha256(b'LFCP-DEK-v1' + RES[res] + u64(epoch) + dek(res, epoch))


LABEL = {p.pid: label for label, p in P.items()}
RES_LABEL = {rid: name for name, rid in RES.items()}

# -----------------------------------------------------------------------------
# Signed objects.
# -----------------------------------------------------------------------------


def sign(payload: bytes, signer, kid: bytes | None = None, flip: bool = False) -> dict:
    protected = cbor({1: -8, 4: kid if kid is not None else signer.pid})
    sig_structure = cbor(['Signature1', protected, b'', payload])
    signature = signer.ed_sk.sign(sig_structure)
    if flip:
        signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
    cose = cbor([protected, {}, payload, signature])
    return {'protected': protected, 'payload': payload, 'sig_structure': sig_structure, 'signature': signature,
            'cose': cose, 'id': sha256(cose)}


CERTS: dict[str, dict] = {}
CERT_LABEL: dict[bytes, str] = {}


def cert(label: str, root: str, device: str, kind: int, mask: list[int], scope: list[str] | list[bytes], issuer: str,
         *, register: bool = True, payload: bytes | None = None, flip: bool = False, descriptor: dict | None = None,
         wrap=None) -> dict:
    serial = h('LFCP-TV-SERIAL-' + label)[:16]
    scope_ids = [RES[s] if isinstance(s, str) else s for s in scope]
    obj = ['LFCP-DEVICE-CERT-v1', P[root].pid, descriptor if descriptor is not None else P[device].descriptor(),
           kind, mask, scope_ids, serial]
    pb = payload if payload is not None else cbor(obj)
    s = sign(pb, P[issuer], flip=flip)
    if wrap is not None:
        s['cose'] = wrap(s['cose'])
        s['id'] = sha256(s['cose'])
    c = {'label': label, 'root': root, 'device': device, 'kind': kind, 'mask': mask, 'scope': scope,
         'issuer': issuer, 'serial': serial, **s, 'digest': sha256(pb)}
    if register:
        CERTS[label] = c
        CERT_LABEL[c['id']] = label
    return c


def C(*labels: str) -> list[bytes]:
    return [CERTS[label]['cose'] for label in labels]


# The fixture certificates of IDENTITY-PROFILE-01 §12.1.
cert('CERT_A', 'OWNER', 'DEV_A', 0, FULL, [], 'OWNER')
cert('CERT_A2', 'OWNER', 'DEV_A2', 0, FULL, [], 'OWNER')
cert('CERT_B', 'OWNER', 'DEV_B', 0, EDIT, [], 'DEV_A')
cert('CERT_B2', 'OWNER', 'DEV_B', 0, EDIT, [], 'OWNER')
cert("CERT_B'", 'OWNER', 'DEV_B', 0, EDIT, [], 'DEV_A')
cert('CERT_R', 'OWNER', 'DEV_R', 0, [1], [], 'OWNER')
cert('CERT_W', 'OWNER', 'DEV_W', 0, [2], [], 'OWNER')
cert('CERT_X', 'OWNER', 'DEV_X', 0, FULL, [], 'DEV_B')
cert('CERT_J', 'OWNER', 'PAIR_J', 2, [1, 2], ['I'], 'DEV_A')
cert('CERT_SO', 'OWNER', 'BRIDGE_O', 1, [1, 2], ['X'], 'DEV_A')
cert('CERT_JK', 'OWNER', 'PAIR_K', 2, [1, 2], ['I'], 'DEV_A')
cert('CERT_C', 'BOB', 'DEV_C', 0, [1, 2, 4, 5, 12], [], 'BOB')
cert('CERT_E', 'BOB', 'DEV_E', 0, [1, 2, 5, 12], [], 'DEV_C')
cert('CERT_F', 'BOB', 'DEV_F', 0, FULL, [], 'BOB')
cert('CERT_S', 'BOB', 'BRIDGE', 1, [1, 2], ['X'], 'BOB')
cert('CERT_S2', 'BOB', 'BRIDGE', 1, [1, 2], ['Y'], 'DEV_C')
# Certificates this corpus adds.
cert("CERT_A'", 'OWNER', 'DEV_A', 0, FULL, [], 'OWNER')
for k in range(2, 10):
    cert(f'CERT_A#{k}', 'OWNER', 'DEV_A', 0, FULL, [], 'OWNER')
cert("CERT_B''", 'OWNER', 'DEV_B', 0, [1], [], 'OWNER')
cert("CERT_S''", 'BOB', 'BRIDGE', 0, [1, 2], [], 'BOB')
cert("CERT_S'''", 'BOB', 'BRIDGE', 1, [1, 2], ['X', 'Y'], 'BOB')
cert('CERT_D', 'DAVE', 'DEV_D', 0, FULL, [], 'DAVE')
cert('CERT_N', 'INVITE', 'DEV_N', 0, FULL, [], 'INVITE')
cert('CERT_M2', 'OWNER', 'DEV_M2', 0, FULL, [], 'DEV_A')
cert('CERT_M3', 'OWNER', 'DEV_M3', 0, FULL, [], 'DEV_M2')
cert('CERT_M4', 'OWNER', 'DEV_M4', 0, FULL, [], 'DEV_M3')
cert('CERT_L_BY_M4', 'OWNER', 'DEV_L', 0, EDIT, [], 'DEV_M4')
cert('CERT_L_BY_M3', 'OWNER', 'DEV_L', 0, EDIT, [], 'DEV_M3')
cert('CERT_H_FULL_BY_M3', 'OWNER', 'DEV_H', 0, FULL, [], 'DEV_M3')
cert('CERT_A_SELF', 'OWNER', 'DEV_A', 0, FULL, [], 'DEV_A')
cert('CERT_A_SELF_BADSIG', 'OWNER', 'DEV_A', 0, FULL, [], 'DEV_A', flip=True)
cert('CERT_E_ROTATE', 'BOB', 'DEV_E', 0, [1, 2, 7], [], 'DEV_C')
cert('CERT_L_BY_BRIDGE', 'BOB', 'DEV_L', 0, [1], [], 'BRIDGE')
cert('CERT_L_BY_J', 'OWNER', 'DEV_L', 0, [1], [], 'PAIR_J')
cert('CERT_L_ROOT_DEV_A', 'DEV_A', 'DEV_L', 0, [1], [], 'DEV_A')
cert('CERT_OWNER_AS_DEVICE', 'BOB', 'OWNER', 0, [1], [], 'BOB')
cert('CERT_CAROL_AS_DEVICE', 'OWNER', 'CAROL', 0, [1], [], 'OWNER')
cert('CERT_INVITE_AS_DEVICE', 'OWNER', 'INVITE', 0, [1], [], 'OWNER')
cert('CERT_C_FOR_OWNER', 'OWNER', 'DEV_C', 0, FULL, [], 'OWNER')
cert('CERT_L_BY_C_FOR_OWNER', 'OWNER', 'DEV_L', 0, [1], [], 'DEV_C')
cert('CERT_G', 'OWNER', 'DEV_G', 0, [1, 2, 12], [], 'OWNER')
cert('CERT_H_EDIT_BY_G', 'OWNER', 'DEV_H', 0, EDIT, [], 'DEV_G')
cert('CERT_X_READ_BY_B', 'OWNER', 'DEV_X', 0, [1], [], 'DEV_B')
cert('CERT_K11', 'BOB', 'DEV_K11', 0, [1, 2, 11], [], 'BOB')
cert('CERT_K11W', 'BOB', 'DEV_K11W', 0, [2, 11], [], 'BOB')
cert('CERT_K13', 'OWNER', 'DEV_K13', 0, [1, 2, 11, 13], [], 'OWNER')
cert("CERT_K13'", 'OWNER', 'DEV_K13', 0, [1, 2, 11, 13], [], 'OWNER')
for label in LIMIT:
    cert(f'CERT_{label}', 'BOB', label, 0, [1], [], 'BOB')
for label in LIMIT_OWNER:
    cert(f'CERT_{label}', 'OWNER', label, 0, [1], [], 'OWNER')
for label in PAIR_S:
    cert(f'CERT_{label}', 'OWNER', label, 2, [1, 2], ['I'], 'DEV_A')
cert('CERT_JL', 'OWNER', 'PAIR_L', 2, [1, 2], ['I'], 'DEV_A')
cert('CERT_JM', 'OWNER', 'PAIR_M', 2, [1, 2], ['I'], 'DEV_A')
cert('CERT_JM2', 'OWNER', 'PAIR_M2', 2, [1, 2], ['I'], 'DEV_A')
cert('CERT_E2', 'BOB', 'DEV_E', 0, [1, 2, 5, 12], [], 'BOB')
cert('CERT_SO_R', 'OWNER', 'BRIDGE_O', 1, [1, 2], ['X'], 'OWNER')
cert('CERT_SO_XY', 'OWNER', 'BRIDGE_O', 1, [1, 2], ['X', 'Y'], 'OWNER')
cert('CERT_R7', 'BOB', 'DEV_R7', 0, [1, 2, 7], [], 'BOB')
cert('CERT_R6', 'BOB', 'DEV_R6', 0, [1, 2, 6], [], 'BOB')
cert('CERT_R7O', 'OWNER', 'DEV_R7O', 0, [1, 2, 7], [], 'OWNER')

# -----------------------------------------------------------------------------
# Corpus: heads, cases and the checks against the expectations.
# -----------------------------------------------------------------------------


class Node:
    def __init__(self, resource: str, state: M.State, prefix: list[str], history: list[M.State], record_set: str | None,
                 set_at: int | None = None):
        self.resource, self.state, self.prefix, self.history, self.record_set = resource, state, prefix, history, record_set
        self.set_at = set_at  # index in prefix before which the record set's records come


NODES: dict[str, Node] = {}
CASES: list[dict] = []
CASE_BY_ID: dict[str, dict] = {}
RECORD_SETS: dict[str, dict] = {}
GROUPS: dict[str, list[str]] = {}
CURRENT_GROUP = ['']


def group(name: str) -> None:
    CURRENT_GROUP[0] = name
    GROUPS.setdefault(name, [])


def add_case(case: dict) -> dict:
    if case['id'] in CASE_BY_ID:
        raise SystemExit(f'duplicate case {case["id"]}')
    CASES.append(case)
    CASE_BY_ID[case['id']] = case
    GROUPS[CURRENT_GROUP[0]].append(case['id'])
    return case


def hx(b: bytes) -> dict:
    return {'hex': b.hex()}


def L(pid: bytes) -> str:
    return LABEL.get(pid, pid.hex())


def RL(rid: bytes) -> str:
    return RES_LABEL.get(rid, rid.hex())


def rule_of(text: str) -> dict:
    section, _, rest = text.partition(': ')
    return {'section': section.replace('W §', 'LFCP-WIRE-01 §').replace('W §', 'LFCP-WIRE-01 §'), 'text': rest}


def binding_facts(st: M.State, d: bytes) -> dict:
    b = st.devices[d]
    out = {
        'root': L(b.root), 'kind': b.kind, 'mask': sorted(b.mask), 'scope': sorted(RL(r) for r in b.scope),
        'registered': b.registered,
        'leaf': CERT_LABEL.get(b.leaf_id) if b.leaf_id else None,
        'issuers': [L(e) for e in b.issuers],
        'active': st.active(d),
        'suspended': st.suspended(d),
        'reads': st.holds(d, 1),
    }
    return {k: v for k, v in out.items() if v is not None}


def post_state(st: M.State, effects: dict | None = None) -> dict:
    out: dict[str, Any] = {'owner': L(st.owner), 'control_seq': st.seq, 'epoch': st.epoch}
    out['roles'] = {L(p): r for p, r in sorted(st.roles.items(), key=lambda kv: L(kv[0]))}
    out['devices'] = {L(d): binding_facts(st, d) for d in sorted(st.devices, key=L)}
    rv = {}
    for (r, d), (reason, approval) in sorted(st.revoked.items(), key=lambda kv: (L(kv[0][0]), L(kv[0][1]))):
        entry: dict[str, Any] = {'reason': reason}
        if approval is not None:
            entry['approval'] = hx(approval)
        rv[f'{L(r)}/{L(d)}'] = entry
    out['revoked'] = rv
    out['standing'] = sorted(L(p) for p in set(st.roles) if st.roles[p] == 'non-device' and st.standing(p))
    for k, v in (effects or {}).items():
        out[k] = L(v) if isinstance(v, bytes) else v
    return out


def record_bytes(resource: str, seq: int, prev: bytes | None, typ: int, issuer: str, body: Any, *,
                 kid: str | None = None, flip: bool = False, payload: dict | None = None) -> dict:
    obj = payload if payload is not None else {0: RES[resource], 1: seq, 2: prev, 3: typ, 4: P[issuer].pid, 5: body}
    s = sign(cbor(obj), P[kid or issuer], flip=flip)
    s['obj'] = obj
    return s


def context_refs(prefix: list[str]) -> list[dict]:
    return [{'case': cid, 'field': 'cose_sign1', 'in': 'inputs'} for cid in prefix]


def head_of_node(node) -> dict:
    """The head a case is decided on: its record ID and sequence, and the case that carries it when there is one."""
    st = node.state
    out = {}
    last = node.prefix[-1]
    if not (node.record_set and node.set_at == len(node.prefix)):
        if rid(last) != st.head:
            raise SystemExit(f'head of {last} is not the replayed head')
        out['head'] = {'case': last, 'field': 'record_id', 'in': 'inputs'}
    out['head_record_id'] = hx(st.head)
    out['head_control_seq'] = st.seq
    return out


def context_of(node) -> dict:
    """The ordered context records: `records`, then `record_set`, then `records_after_set`."""
    if not node.record_set:
        return {'records': context_refs(node.prefix)}
    out = {'records': context_refs(node.prefix[:node.set_at]), 'record_set': node.record_set}
    if node.prefix[node.set_at:]:
        out['records_after_set'] = context_refs(node.prefix[node.set_at:])
    return out


TYPE_NAME = {0: 'GENESIS', 1: 'CAPABILITY_GRANT', 2: 'CAPABILITY_REVOKE', 3: 'CAPABILITY_CLAIM', 4: 'KEY_EPOCH',
             6: 'OWNER_TRANSFER_COMMIT', 9: 'DEVICE_GRANT', 10: 'DEVICE_REVOKE', 11: 'reserved (IDENTITY_SUCCESSION)'}


def check_expectation(cid: str, expect, got_code: str | None, got_rule: str) -> None:
    if expect == 'accept':
        if got_code is not None:
            raise SystemExit(f'{cid}: expected accept, model rejects with {got_code} ({got_rule})')
        return
    code, token = expect
    if got_code != code:
        raise SystemExit(f'{cid}: expected {code} ({token}), model gives {got_code or "accept"} ({got_rule})')
    if token not in got_rule:
        raise SystemExit(f'{cid}: expected rule {token}, model decides by {got_rule}')


def control(cid: str, on: str | None, typ: int, issuer: str, body: Any, expect, description: str, *,
            resource: str | None = None, kid: str | None = None, flip: bool = False, readable: dict | None = None,
            rule: tuple[str, str] | None = None, register: bool | None = None, seq: int | None = None,
            prev: bytes | None = None, raw: dict | None = None, note: str | None = None) -> dict:
    """A Control Record case proposed on head `on` (a case id, `set:<name>` or None for a Genesis)."""
    node = NODES[on] if on else None
    res = resource or (node.resource if node else None)
    st = node.state if node else None
    rseq = seq if seq is not None else (st.seq + 1 if st else 0)
    rprev = prev if prev is not None else (st.head if st else None)
    r = raw or record_bytes(res, rseq, rprev, typ, issuer, body, kid=kid, flip=flip)
    try:
        nxt, effects = M.apply_record(st, r['cose'])
        got, why = None, ''
    except Reject as e:
        nxt, effects, got, why = None, None, e.code, e.rule
    check_expectation(cid, expect, got, why)
    inputs = {
        'resource': res, 'signer': kid or issuer, 'issuer': issuer, 'control_seq': rseq, 'control_type': typ,
        'control_type_name': TYPE_NAME.get(typ, 'unknown'),
    }
    if readable:
        inputs['body'] = readable
    inputs.update({'payload_cbor': hx(r['payload']), 'protected_header_cbor': hx(r['protected']),
                   'signature': hx(r['signature']), 'cose_sign1': hx(r['cose']), 'record_id': hx(r['id'])})
    case: dict[str, Any] = {'id': cid, 'type': 'validation', 'kind': 'control_record', 'description': description}
    if note:
        case['note'] = note
    if expect == 'accept':
        sec, text = rule
        case['rule'] = {'section': sec, 'text': text}
    else:
        case['rule'] = rule_of(why)
    case['inputs'] = inputs
    ctx: dict[str, Any] = {'resource_id': hx(RES[res])}
    if node:
        ctx.update(context_of(node))
        ctx.update(head_of_node(node))
        if raw is None and seq is None and prev is None and r['obj'][2] != st.head:
            raise SystemExit(f'{cid}: prev_control_id is not the head')
    case['context'] = ctx
    if got is None:
        case['expected'] = {'valid': True, 'post_state': post_state(nxt, effects)}
    else:
        case['expected'] = {'valid': False, 'error': {'code': got}}
    add_case(case)
    if got is None and register is not False:
        prefix = (node.prefix if node else []) + [cid]
        history = (node.history if node else []) + [nxt]
        NODES[cid] = Node(res, nxt, prefix, history, node.record_set if node else None, node.set_at if node else None)
    case['_record'] = r
    return case


def record_set(name: str, on: str, items: list[tuple[int, str, Any]], description: str) -> str:
    """Accepted records appended to head `on`, published once in fixtures.record_sets."""
    node = NODES[on]
    st, history = node.state, list(node.history)
    out = []
    for typ, issuer, body in items:
        r = record_bytes(node.resource, st.seq + 1, st.head, typ, issuer, body)
        try:
            st, _ = M.apply_record(st, r['cose'])
        except Reject as e:
            raise SystemExit(f'record set {name}: {e}')
        history.append(st)
        out.append(hx(r['cose']))
    RECORD_SETS[name] = {'description': description, 'resource': node.resource, 'after': on, 'records': out}
    key = f'set:{name}'
    NODES[key] = Node(node.resource, st, node.prefix, history, name, len(node.prefix))
    return key


# -----------------------------------------------------------------------------
# Bodies.
# -----------------------------------------------------------------------------


def endpoints() -> list:
    return [ENDPOINT_A]


def genesis_body(res: str, owner: str, chain: list[bytes] | None = None) -> dict:
    b = {0: RES_PROFILE[res], 1: P[owner].descriptor(), 2: commitment(res, 0), 3: endpoints(), 4: COORD_A}
    if chain is not None:
        b[5] = chain
    return b


def grant_body(subject: str, abilities, delegable, parent: bytes | None = None, limit: int | None = None) -> dict:
    b = {0: P[subject].descriptor(), 1: abilities, 2: delegable}
    if parent is not None:
        b[3] = parent
    if limit is not None:
        b[4] = limit
    return b


def dg(root: str, chain: list[bytes], pairing: str | None = None) -> dict:
    b = {0: P[root].pid, 1: chain}
    if pairing is not None:
        b[2] = P[pairing].pid
    return b


def dr(root: str, device: str, reason: int, approval: bytes | None = None) -> dict:
    b = {0: P[root].pid, 1: P[device].pid, 2: reason}
    if approval is not None:
        b[4] = approval
    return b


def rid(case_id: str) -> bytes:
    return CASE_BY_ID[case_id]['_record']['id']


def dg_readable(root: str, chain: list[str], pairing: str | None = None) -> dict:
    out = {'root': root, 'chain': chain}
    if pairing:
        out['pairing_device'] = pairing
    return out


def dr_readable(root, device, reason, approval_of: str | None = None) -> dict:
    out = {'root': root, 'device': device, 'reason': reason}
    if approval_of:
        out['approval'] = f'payload digest of {approval_of}'
    return out


def frontier(entries: dict) -> list:
    """Canonical frontier (W §28.2); a value is a contiguous sequence or (contiguous, [[start, end], ...])."""
    out = []
    for label, v in entries.items():
        contiguous, extras = (v, []) if isinstance(v, int) else v
        e = {0: P[label].pid, 1: contiguous}
        if extras:
            e[2] = [list(r) for r in extras]
        out.append(e)
    return sorted(out, key=lambda e: e[0])


def key_epoch_body(res: str, epoch: int, entries: dict[str, int], reason: int) -> dict:
    return {0: epoch, 1: commitment(res, epoch), 2: frontier(entries), 3: reason}


A_DEV = ('LFCP-WIRE-01 §17.4', 'A DEVICE_GRANT binds every device of the chain to its root and registers the leaf when its scope admits the Resource (rules 1 to 9).')

# -----------------------------------------------------------------------------
# The context chains (IDENTITY-PROFILE-01 §12.1).
# -----------------------------------------------------------------------------


def build_context() -> None:
    group('context chain of X')
    control('J0_genesis', None, 0, 'OWNER', genesis_body('X', 'OWNER'), 'accept',
            'Genesis of X, owner OWNER, profile org.lfcp.test.raw.v1', resource='X',
            readable={'data_profile': RAW_PROFILE, 'owner': 'OWNER', 'epoch0_dek_commitment': 'of X epoch 0'},
            rule=('LFCP-WIRE-01 §15', 'Genesis establishes the Resource, its Data Profile and its owner.'))
    control('J1_grant_bob', 'J0_genesis', 1, 'OWNER', grant_body('BOB', [1, 2, 3, 4, 5, 6, 7], [1, 2, 6, 11]), 'accept',
            'CAPABILITY_GRANT to BOB {1,2,3,4,5,6,7}, delegable {1,2,6,11}, by OWNER',
            readable={'subject': 'BOB', 'abilities': [1, 2, 3, 4, 5, 6, 7], 'delegable': [1, 2, 6, 11]},
            rule=('LFCP-WIRE-01 §17.2', 'The owner MAY grant any abilities without a parent grant.'))
    control('J2_grant_carol', 'J1_grant_bob', 1, 'OWNER', grant_body('CAROL', [1, 2, 5], []), 'accept',
            'CAPABILITY_GRANT to CAROL {1,2,5}, delegable [], by OWNER',
            readable={'subject': 'CAROL', 'abilities': [1, 2, 5], 'delegable': []},
            rule=('LFCP-WIRE-01 §17.2', 'The owner MAY grant any abilities without a parent grant.'))
    control('I1_device_grant_dev_a', 'J2_grant_carol', 9, 'OWNER', dg('OWNER', C('CERT_A')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_A]} by OWNER', readable=dg_readable('OWNER', ['CERT_A']),
            rule=('LFCP-WIRE-01 §17.4 rule 6', 'The issuer is R; R has standing as the owner.'))
    control('I2_device_grant_self_dev_b', 'I1_device_grant_dev_a', 9, 'DEV_B', dg('OWNER', C('CERT_B', 'CERT_A')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_B, CERT_A]} by DEV_B (kind-0 self-registration)',
            readable=dg_readable('OWNER', ['CERT_B', 'CERT_A']),
            rule=('LFCP-WIRE-01 §17.4 rule 6', 'D itself, when D is of kind 0 and devices[D] is absent or has no chain; (c2) to (c4) hold.'))
    control('I3_owner_action_by_dev_a', 'I2_device_grant_self_dev_b', 1, 'DEV_A', grant_body('DAVE', [1], []), 'accept',
            'CAPABILITY_GRANT to DAVE {1}, delegable [], no parent, by DEV_A',
            readable={'subject': 'DAVE', 'abilities': [1], 'delegable': []},
            rule=('LFCP-WIRE-01 §17.2, §80.1', '"The owner" is ownerAction(kid): DEV_A is active, its root owns X and 13 is in its mask; issuer_root = OWNER.'))
    control('I4_device_grant_dev_c_bob', 'I3_owner_action_by_dev_a', 9, 'BOB', dg('BOB', C('CERT_C')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_C]} by BOB', readable=dg_readable('BOB', ['CERT_C']),
            rule=('LFCP-WIRE-01 §17.4 rules 4 and 6', 'BOB has standing through J1 and issues for itself as R.'))
    control('I5_device_grant_dev_e_by_dev_c', 'I4_device_grant_dev_c_bob', 9, 'DEV_C', dg('BOB', C('CERT_E', 'CERT_C')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_E, CERT_C]} by DEV_C', readable=dg_readable('BOB', ['CERT_E', 'CERT_C']),
            rule=('LFCP-WIRE-01 §7.3 (c3), (c4), (c7); §17.4 rule 6', 'The leaf lists 12 and has two certificates; DEV_C issued inside the chain and is an active managing device.'))
    control('I6_grant_by_member_device', 'I5_device_grant_dev_e_by_dev_c', 1, 'DEV_C', grant_body('CAROL', [2], [], rid('J1_grant_bob')), 'accept',
            'CAPABILITY_GRANT by DEV_C to CAROL {2}, delegable [], parent J1',
            readable={'subject': 'CAROL', 'abilities': [2], 'delegable': [], 'parent': 'J1_grant_bob'},
            rule=('LFCP-WIRE-01 §17.2, §80.1', 'holds(DEV_C, 4); actsFor(DEV_C) = BOB = J1.subject; {2} is within the mask and J1.delegable; issuer_root = BOB.'))
    control('I7_revoke_covered_by_sibling', 'I6_grant_by_member_device', 2, 'DEV_E', {0: rid('I6_grant_by_member_device')}, 'accept',
            'CAPABILITY_REVOKE of I6 by DEV_E', readable={'grant': 'I6_grant_by_member_device'},
            rule=('LFCP-WIRE-01 §17.3, §80.1', 'holds(DEV_E, 5); actsFor(DEV_E) = BOB = I6.issuer_root covers I6.'))
    control('I8_bridge_grant', 'I7_revoke_covered_by_sibling', 9, 'DEV_C', dg('BOB', C('CERT_S')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_S]} by DEV_C', readable=dg_readable('BOB', ['CERT_S']),
            rule=('LFCP-WIRE-01 §17.4 rule 6', 'A kind-1 leaf in scope, issued by an active managing device of R.'))
    control('I9_device_revoke_dev_a', 'I8_bridge_grant', 10, 'OWNER', dr('OWNER', 'DEV_A', 1), 'accept',
            'DEVICE_REVOKE {OWNER, DEV_A, 1} by OWNER', readable=dr_readable('OWNER', 'DEV_A', 1),
            rule=('LFCP-WIRE-01 §17.5', 'R with standing revokes; the cascade suspends DEV_B; DEV_A and DEV_B lose data/read: exposing.'))
    control('I10_recertify_dev_b', 'I9_device_revoke_dev_a', 9, 'OWNER', dg('OWNER', C('CERT_B2')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_B2]} by OWNER (re-certification)', readable=dg_readable('OWNER', ['CERT_B2']),
            rule=('LFCP-WIRE-01 §7.3 step 4.3, §17.4 rule 5', 'Same kind, mask and scope; a new leaf certificate ID; issuers become [].'))
    control('I11_revoke_root_grant_bob', 'I10_recertify_dev_b', 2, 'OWNER', {0: rid('J1_grant_bob')}, 'accept',
            'CAPABILITY_REVOKE of J1 by OWNER', readable={'grant': 'J1_grant_bob'},
            rule=('LFCP-WIRE-01 §17.3, §17.5', 'The owner revokes any grant; BOB loses standing, so DEV_C, DEV_E and BRIDGE are inactive.'))
    control('I12_regrant_bob', 'I11_revoke_root_grant_bob', 1, 'OWNER', grant_body('BOB', [1, 2, 3, 4, 5, 6, 7], [1, 2, 6, 11]), 'accept',
            'CAPABILITY_GRANT to BOB as J1, by OWNER',
            readable={'subject': 'BOB', 'abilities': [1, 2, 3, 4, 5, 6, 7], 'delegable': [1, 2, 6, 11]},
            rule=('LFCP-WIRE-01 §7.2 N4, §17.5', 'Restoring the root\'s standing restores its devices without new device records.'))
    control('I13_owner_expels_dev_c', 'I12_regrant_bob', 10, 'OWNER', dr('BOB', 'DEV_C', 2), 'accept',
            'DEVICE_REVOKE {BOB, DEV_C, 2} by OWNER', readable=dr_readable('BOB', 'DEV_C', 2),
            rule=('LFCP-WIRE-01 §17.5 rule 4', 'The owner may expel any device of any root; DEV_E is suspended, BRIDGE (issued by BOB) stays active; exposing.'))

    group('branches')
    control('G1_genesis_by_dev_a', None, 0, 'DEV_A', genesis_body('Y', 'OWNER', C('CERT_A')), 'accept',
            'Genesis of Y, owner OWNER, field 5 [CERT_A], kid DEV_A', resource='Y',
            readable={'data_profile': RAW_PROFILE, 'owner': 'OWNER', 'device_chain': ['CERT_A']},
            rule=('LFCP-WIRE-01 §15', 'Genesis by a device of the owner: the leaf is of kind 0 with 13; DEV_A is registered at sequence 0.'))
    control('G2_grant_bob_y', 'G1_genesis_by_dev_a', 1, 'DEV_A', grant_body('BOB', [1, 2], []), 'accept',
            'CAPABILITY_GRANT to BOB {1,2}, delegable [], by DEV_A (ownerAction)',
            readable={'subject': 'BOB', 'abilities': [1, 2], 'delegable': []},
            rule=('LFCP-WIRE-01 §80.1', 'ownerAction(DEV_A): the owner-only grant without a parent.'))
    control('Yb1_bridge_out_of_scope', 'G2_grant_bob_y', 9, 'BOB', dg('BOB', C('CERT_S')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_S]} by BOB in Y (CERT_S lists only X)', readable=dg_readable('BOB', ['CERT_S']),
            rule=('LFCP-WIRE-01 §17.4 rule 9', 'An out-of-scope kind-1 leaf is bound in this Resource and holds nothing in it: registered = false.'))
    control('P0_genesis_i', None, 0, 'OWNER', genesis_body('I', 'OWNER'), 'accept',
            'Genesis of the Identity Resource I, owner OWNER, profile org.openlfcp.identity.v1', resource='I',
            readable={'data_profile': IDENTITY_PROFILE, 'owner': 'OWNER'},
            rule=('LFCP-WIRE-01 §15; IDENTITY-PROFILE-01 §5.1', 'The Identity Resource is an ordinary Resource owned by the root.'))
    control('P1_device_grant_dev_a_i', 'P0_genesis_i', 9, 'OWNER', dg('OWNER', C('CERT_A')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_A]} by OWNER in I', readable=dg_readable('OWNER', ['CERT_A']), rule=A_DEV)
    control('P2_pairing_device', 'P1_device_grant_dev_a_i', 9, 'DEV_A', dg('OWNER', C('CERT_J', 'CERT_A')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_J, CERT_A]} by DEV_A (pairing device)', readable=dg_readable('OWNER', ['CERT_J', 'CERT_A']),
            rule=('LFCP-WIRE-01 §7.3 (c6), §17.4 rule 6', 'A kind-2 leaf lists I; DEV_A is an active managing device of OWNER.'))
    control('P3_consume_for_dev_b', 'P2_pairing_device', 10, 'DEV_A', dr('OWNER', 'PAIR_J', 3, CERTS['CERT_B']['digest']), 'accept',
            'DEVICE_REVOKE {OWNER, PAIR_J, 3, 4: digest(CERT_B payload)} by DEV_A (pairing phase 1)',
            readable=dr_readable('OWNER', 'PAIR_J', 3, 'CERT_B'),
            rule=('LFCP-WIRE-01 §17.5', 'Reason 3 with field 4 consumes the pairing session; PAIR_J was a reader: exposing.'))
    control('P4_register_dev_b_approved', 'P3_consume_for_dev_b', 9, 'DEV_A', dg('OWNER', C('CERT_B', 'CERT_A'), 'PAIR_J'), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_B, CERT_A], 2: PAIR_J} by DEV_A (pairing phase 2)',
            readable=dg_readable('OWNER', ['CERT_B', 'CERT_A'], 'PAIR_J'),
            rule=('LFCP-WIRE-01 §17.4 rule 7', 'revoked[(OWNER, PAIR_J)] has reason 3 and its approval is the payload digest of the leaf.'))
    control('P3s_consume_for_bridge_o', 'P2_pairing_device', 10, 'DEV_A', dr('OWNER', 'PAIR_J', 3, CERTS['CERT_SO']['digest']), 'accept',
            'DEVICE_REVOKE {OWNER, PAIR_J, 3, 4: digest(CERT_SO payload)} by DEV_A (service variant)',
            readable=dr_readable('OWNER', 'PAIR_J', 3, 'CERT_SO'),
            rule=('LFCP-WIRE-01 §17.5', 'Reason 3 with field 4 consumes the pairing session.'))
    control('P4s_bind_bridge_o', 'P3s_consume_for_bridge_o', 9, 'DEV_A', dg('OWNER', C('CERT_SO', 'CERT_A'), 'PAIR_J'), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_SO, CERT_A], 2: PAIR_J} by DEV_A', readable=dg_readable('OWNER', ['CERT_SO', 'CERT_A'], 'PAIR_J'),
            rule=('LFCP-WIRE-01 §17.4 rules 7 and 9', 'The approval matches; I is not in CERT_SO\'s scope, so BRIDGE_O is bound in I and registered = false.'))
    control('P2k_pairing_device_k', 'P2_pairing_device', 9, 'DEV_A', dg('OWNER', C('CERT_JK', 'CERT_A')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_JK, CERT_A]} by DEV_A on P2: a second open pairing session (added branch, for the profile corpus)',
            readable=dg_readable('OWNER', ['CERT_JK', 'CERT_A']),
            rule=('LFCP-WIRE-01 §7.3 (c6), §17.4 rule 6', 'A kind-2 leaf lists I; DEV_A is an active managing device of OWNER.'))
    build_transfer('T1', 'I8_bridge_grant', 'OWNER', 'BOB', 'DEV_F', C('CERT_F'))
    control('T1_commit', 'I8_bridge_grant', 6, 'DEV_F', transfer_body('T1', C('CERT_F')), 'accept',
            'OWNER_TRANSFER_COMMIT {T1_offer, T1_accept, 2: [CERT_F]} by DEV_F on I8',
            readable={'offer': 'T1_offer', 'accept': 'T1_accept', 'device_chain': ['CERT_F']},
            rule=('LFCP-WIRE-01 §23.3', 'Transfer to a root through its device: the owner becomes BOB; DEV_F is bound and registered with [CERT_F].'))
    control('K1_key_epoch', 'I9_device_revoke_dev_a', 4, 'OWNER', key_epoch_body('X', 1, K1_FRONTIER, 2), 'accept',
            'KEY_EPOCH by OWNER on I9: epoch 1, frontier DEV_A <= 1, DEV_B <= 1, BRIDGE <= 1',
            readable={'epoch': 1, 'frontier': K1_FRONTIER, 'reason': 2},
            rule=('LFCP-WIRE-01 §19, §19.1', 'The owner rotates; the final frontier of epoch 0 is the accepted set: D_dev_a_seq1, D_dev_b_seq1, D_bridge_writes_x.'))
    control('V1_bind_dev_c_as_intermediate', 'J2_grant_carol', 9, 'BOB', dg('BOB', C('CERT_E', 'CERT_C')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_E, CERT_C]} by BOB on J2', readable=dg_readable('BOB', ['CERT_E', 'CERT_C']),
            rule=('LFCP-WIRE-01 §17.4 rule 9', 'DEV_E is registered and reads; DEV_C is bound only, as an intermediate.'))
    control('V2_revoke_dev_c', 'V1_bind_dev_c_as_intermediate', 10, 'BOB', dr('BOB', 'DEV_C', 1), 'accept',
            'DEVICE_REVOKE {BOB, DEV_C, 1} by BOB', readable=dr_readable('BOB', 'DEV_C', 1),
            rule=('LFCP-WIRE-01 §17.5', 'DEV_E is suspended by the cascade; DEV_E held data/read before and not after: exposing.'))
    control('Vu1_revoke_unbound', 'J2_grant_carol', 10, 'BOB', dr('BOB', 'DEV_X', 1), 'accept',
            'DEVICE_REVOKE {BOB, DEV_X, 1} by BOB on J2 (DEV_X unbound)', readable=dr_readable('BOB', 'DEV_X', 1),
            rule=('LFCP-WIRE-01 §17.5', 'An unbound tombstone without descendants removes no reader: not exposing.'))
    control('Rd1', 'I1_device_grant_dev_a', 9, 'OWNER', dg('OWNER', C('CERT_R')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_R]} by OWNER (read-only device)', readable=dg_readable('OWNER', ['CERT_R']), rule=A_DEV)
    control('W1', 'I1_device_grant_dev_a', 9, 'OWNER', dg('OWNER', C('CERT_W')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_W]} by OWNER (never-reading device)', readable=dg_readable('OWNER', ['CERT_W']), rule=A_DEV)
    control('W2', 'W1', 10, 'OWNER', dr('OWNER', 'DEV_W', 1), 'accept',
            'DEVICE_REVOKE {OWNER, DEV_W, 1} by OWNER', readable=dr_readable('OWNER', 'DEV_W', 1),
            rule=('LFCP-WIRE-01 §17.5', 'DEV_W never held data/read and has no descendants: not exposing.'))
    # Additions: an invitation in X, and a Resource owned by BOB.
    control('N1_invite_grant', 'J2_grant_carol', 1, 'OWNER', grant_body('INVITE', [1, 2, 11], [], limit=1), 'accept',
            'CAPABILITY_GRANT to INVITE {1,2,11}, claim_limit 1, by OWNER on J2 (added branch: an invitation in X)',
            readable={'subject': 'INVITE', 'abilities': [1, 2, 11], 'delegable': [], 'claim_limit': 1},
            rule=('LFCP-WIRE-01 §18', 'An invitation grant; INVITE is an Invitation Principal without standing.'))
    control('U0_genesis_by_bob', None, 0, 'BOB', genesis_body('U', 'BOB'), 'accept',
            'Genesis of U, owner BOB (added Resource: OWNER has no grant in it)', resource='U',
            readable={'data_profile': RAW_PROFILE, 'owner': 'BOB'},
            rule=('LFCP-WIRE-01 §15', 'Genesis establishes the Resource and its owner.'))


K1_FRONTIER = {'DEV_A': 1, 'DEV_B': 1, 'BRIDGE': 1}

TRANSFERS: dict[str, dict] = {}


def build_transfer(name: str, on: str, offer_by: str, new_owner: str, accept_by: str, chain: list[bytes] | None, *,
                   accept_names: str | None = None, emit: bool = True, offer_kid: str | None = None) -> dict:
    st = NODES[on].state
    offer_obj = {0: RES[NODES[on].resource], 1: st.head, 2: st.seq + 1, 3: P[new_owner].descriptor(),
                 4: h(f'LFCP-TV-IDENTITY-OFFER-NONCE-{name}')[:16]}
    offer = sign(cbor(offer_obj), P[offer_by], kid=P[offer_kid].pid if offer_kid else None)
    accept_obj = {0: RES[NODES[on].resource], 1: offer['id'], 2: P[accept_names or new_owner].pid}
    accept = sign(cbor(accept_obj), P[accept_by])
    TRANSFERS[name] = {'offer': offer, 'accept': accept, 'on': on}
    if emit:
        for part, obj, signer, readable in (
            ('offer', offer, offer_by, {'resource': NODES[on].resource, 'control_head': on,
                                        'expected_next_seq': st.seq + 1, 'new_owner': new_owner}),
            ('accept', accept, accept_by, {'resource': NODES[on].resource, 'offer': f'{name}_offer',
                                           'accepting_owner': accept_names or new_owner})):
            add_case({'id': f'{name}_{part}', 'type': 'bytes', 'kind': 'signed_object',
                      'description': f'Transfer {part} of {name}, signed by {signer}',
                      'inputs': {'signer': signer, 'object': f'owner-transfer-{part}-payload', **readable},
                      'expected': {'payload_cbor': hx(obj['payload']), 'protected_header_cbor': hx(obj['protected']),
                                   'signature': hx(obj['signature']), 'cose_sign1': hx(obj['cose']),
                                   'object_id': hx(obj['id'])}})
    return TRANSFERS[name]


def transfer_body(name: str, chain: list[bytes] | None = None) -> dict:
    t = TRANSFERS[name]
    b = {0: t['offer']['cose'], 1: t['accept']['cose']}
    if chain is not None:
        b[2] = chain
    return b


# -----------------------------------------------------------------------------
# ID-01 Device Certificates.
# -----------------------------------------------------------------------------


def cert_bytes_case(cid: str, label: str, description: str) -> None:
    c = CERTS[label]
    add_case({'id': cid, 'type': 'bytes', 'kind': 'device_certificate', 'description': description,
              'rule': {'section': 'LFCP-WIRE-01 §7.3', 'text': 'A Device Certificate is a standalone signed object; its ID is the §10.6 object ID of its exact COSE bytes, its payload digest the SHA-256 of the exact payload.'},
              'inputs': {'certificate': label, 'signer': c['issuer'], 'root': c['root'], 'device': c['device'],
                         'kind': c['kind'], 'mask_cbor': hx(cbor(c['mask'])),
                         'scope': ', '.join(s if isinstance(s, str) else s.hex() for s in c['scope']),
                         'scope_cbor': hx(cbor([RES[s] if isinstance(s, str) else s for s in c['scope']])),
                         'serial': hx(c['serial'])},
              'expected': {'payload_cbor': hx(c['payload']), 'protected_header_cbor': hx(c['protected']),
                           'sig_structure_cbor': hx(c['sig_structure']), 'signature': hx(c['signature']),
                           'cose_sign1': hx(c['cose']), 'certificate_id': hx(c['id']), 'payload_digest': hx(c['digest'])}})


def cert_case(cid: str, c: dict, expect, description: str, rule=None) -> None:
    signer = c['issuer']
    try:
        parsed = M.parse_cert(c['cose'])
        if parsed.signed.kid != P[signer].pid or not parsed.signed.verifies(P[signer].ed_pk):
            raise Reject(M.BAD_SIG, 'W §7.3 (c2), §10.5: the certificate signature verifies under its kid')
        got, why = None, ''
    except Reject as e:
        got, why = e.code, e.rule
    check_expectation(cid, expect, got, why)
    case = {'id': cid, 'type': 'validation', 'kind': 'device_certificate', 'description': description,
            'rule': rule_of(why) if got else {'section': rule[0], 'text': rule[1]},
            'inputs': {'signer': signer, 'cose_sign1': hx(c['cose']), 'certificate_id': hx(c['id'])},
            'context': {'signer_descriptor': {'case': f'principal_{signer.lower()}', 'field': 'descriptor_cbor'}},
            'expected': {'valid': True} if got is None else {'valid': False, 'error': {'code': got}}}
    add_case(case)


def build_certificates() -> None:
    group('ID-01 Device Certificate')
    cert_bytes_case('cert_a_by_root', 'CERT_A', 'CERT_A: DEV_A, kind 0, Full, issued by the root OWNER')
    cert_bytes_case('cert_b_by_device', 'CERT_B', 'CERT_B: DEV_B, kind 0, Edit {1,2,3}, issued by the managing device DEV_A')
    cert_bytes_case('cert_service_scoped', 'CERT_S', 'CERT_S: BRIDGE, kind 1, {1,2}, scope [X], issued by BOB')
    cert_bytes_case('cert_pairing_j', 'CERT_J', 'CERT_J: PAIR_J, kind 2, {1,2}, scope [I], issued by DEV_A')
    base_fields = ('OWNER', 'DEV_A2', 0, FULL, [], 'OWNER')
    serial = lambda label: h('LFCP-TV-SERIAL-' + label)[:16]  # noqa: E731
    A2 = P['DEV_A2']

    def neg(cid, expect, description, *, kind=0, mask=FULL, scope=(), payload=None, descriptor=None, flip=False, wrap=None, rule=None):
        c = cert(f'NEG_{cid}', 'OWNER', 'DEV_A2', kind, list(mask), list(scope), 'OWNER', register=False,
                 payload=payload, descriptor=descriptor, flip=flip, wrap=wrap)
        cert_case(cid, c, expect, description, rule)

    ok_rule = ('LFCP-WIRE-01 §7.3 rules 1 to 5', 'The structural rules hold; the signature verifies under the root.')
    bad = CERTS['CERT_A']
    flipped = cert('NEG_cert_bad_signature', 'OWNER', 'DEV_A', 0, FULL, [], 'OWNER', register=False)
    flipped = dict(flipped, issuer='OWNER')
    s = bad['signature'][:-1] + bytes([bad['signature'][-1] ^ 1])
    flipped['cose'] = cbor([bad['protected'], {}, bad['payload'], s])
    flipped['id'] = sha256(flipped['cose'])
    cert_case('cert_bad_signature', flipped, (M.BAD_SIG, '§7.3 (c2)'), 'CERT_A with the last signature bit flipped')
    neg('cert_payload_map', (M.MALFORMED, '§7.3 rule 1'), 'Payload as a map with keys 0 to 6',
        payload=cbor({0: 'LFCP-DEVICE-CERT-v1', 1: P['OWNER'].pid, 2: A2.descriptor(), 3: 0, 4: FULL, 5: [], 6: serial('x')}))
    neg('cert_wrong_label', (M.MALFORMED, '§7.3 rule 1'), 'Label LFCP-DEVICE-CERT-v2',
        payload=cbor(['LFCP-DEVICE-CERT-v2', P['OWNER'].pid, A2.descriptor(), 0, FULL, [], serial('y')]))
    neg('cert_six_elements', (M.MALFORMED, '§7.3 rule 1'), 'Six elements: the scope omitted',
        payload=cbor(['LFCP-DEVICE-CERT-v1', P['OWNER'].pid, A2.descriptor(), 0, FULL, serial('z')]))
    neg('cert_mask_repeat', (M.MALFORMED, '§7.3 rule 4'), 'Mask [1, 2, 2]', mask=[1, 2, 2])
    neg('cert_mask_empty', (M.MALFORMED, '§7.3 rule 4'), 'Mask []', mask=[])
    neg('cert_mask_33', (M.MALFORMED, '§7.3 rule 4'), 'Mask of 33 codes [1..33]', mask=list(range(1, 34)))
    neg('cert_mask_32', 'accept', 'Mask of 32 codes [1..32]', mask=list(range(1, 33)), rule=ok_rule)
    neg('cert_mask_unknown_u64', 'accept', 'Mask [1, 2, 18446744073709551615]: the unknown code is kept and confers nothing',
        mask=[1, 2, 2**64 - 1], rule=('LFCP-WIRE-01 §7.3 rule 4', 'Codes outside the §17.1 table are kept as received and confer nothing.'))
    neg('cert_manage_without_write', (M.MALFORMED, '§7.3 rule 4'), 'Mask {1, 12}', mask=[1, 12])
    neg('cert_manage_without_read', (M.MALFORMED, '§7.3 rule 4'), 'Mask {2, 12, 13}', mask=[2, 12, 13])
    neg('cert_service_with_manage', (M.MALFORMED, '§7.3 rule 5'), 'Kind 1, mask {1, 2, 12}, scope [X]', kind=1, mask=[1, 2, 12], scope=['X'])
    neg('cert_service_empty_scope', (M.MALFORMED, '§7.3 rule 5'), 'Kind 1, mask {1, 2}, scope []', kind=1, mask=[1, 2], scope=[])
    neg('cert_personal_with_scope', (M.MALFORMED, '§7.3 rule 5'), 'Kind 0, scope [X]', scope=['X'])
    neg('cert_scope_65', (M.MALFORMED, '§7.3'), 'Kind 1 with 65 Resource IDs', kind=1, mask=[1, 2], scope=SCOPE_FILL[:65])
    neg('cert_scope_64', 'accept', 'Kind 1 with 64 Resource IDs', kind=1, mask=[1, 2], scope=SCOPE_FILL[:64], rule=ok_rule)
    neg('cert_scope_repeat', (M.MALFORMED, '§7.3 rule 5'), 'Kind 1, scope [X, X]', kind=1, mask=[1, 2], scope=['X', 'X'])
    neg('cert_pairing_bad_mask', (M.MALFORMED, '§7.3 rule 5'), 'Kind 2, mask {1, 2, 3}, scope [I]', kind=2, mask=[1, 2, 3], scope=['I'])
    neg('cert_pairing_two_scopes', (M.MALFORMED, '§7.3 rule 5'), 'Kind 2, scope [I, X]', kind=2, mask=[1, 2], scope=['I', 'X'])
    neg('cert_pairing_no_scope', (M.MALFORMED, '§7.3 rule 5'), 'Kind 2, scope []', kind=2, mask=[1, 2], scope=[])
    neg('cert_kind_3', (M.MALFORMED, '§7.3 rule 3'), 'Kind 3', kind=3)
    neg('cert_device_is_root', (M.MALFORMED, '§7.3 rule 2'), 'Field 2 is the OWNER descriptor, field 1 is OWNER',
        descriptor=P['OWNER'].descriptor())
    d_bad = dict(A2.descriptor())
    d_bad[0] = bytes([d_bad[0][0] ^ 1]) + d_bad[0][1:]
    neg('cert_descriptor_bad_id', (M.MALFORMED, '§7'), 'Field 2 with a Principal ID that is not the recomputed ID', descriptor=d_bad)
    d_extra = dict(A2.descriptor())
    d_extra[3] = 0
    neg('cert_descriptor_extra_field', (M.MALFORMED, '§7'), 'Field 2 with an extra key 3', descriptor=d_extra)
    raw = (b'\x87' + cbor('LFCP-DEVICE-CERT-v1') + cbor(P['OWNER'].pid) + cbor(A2.descriptor()) + b'\x18\x00'
           + cbor(FULL) + cbor([]) + cbor(serial('n')))
    neg('cert_noncanonical_payload', (M.MALFORMED, '§5.2'), 'Kind 0 encoded as 0x1800 (not the shortest form)', payload=raw)
    neg('cert_tagged_cose', (M.MALFORMED, '§10'), 'COSE_Sign1 with tag 18', wrap=lambda b: b'\xd2' + b)


# -----------------------------------------------------------------------------
# ID-02 Chains: verifyChain against a named state.
# -----------------------------------------------------------------------------


def chain_case(cid: str, on: str, root: str, labels: list[str], expect, description: str, rule=None, chain=None) -> None:
    node = NODES[on]
    st = node.state
    chain = chain if chain is not None else C(*labels)
    try:
        certs = M.parse_chain(chain, P[root].pid)
        rd = st.descriptors.get(P[root].pid)
        if rd is None:
            raise Reject(M.MISSING, 'W §7.3 verification step 2: R_descriptor is available')
        M.chain_signatures(certs, rd)
        st.chain_state(certs, P[root].pid)
        got, why = None, ''
    except Reject as e:
        got, why = e.code, e.rule
    check_expectation(cid, expect, got, why)
    inputs = {'resource': node.resource, 'root': root, 'certificates': labels,
              'chain': [hx(c) for c in chain]}
    case = {'id': cid, 'type': 'validation', 'kind': 'certificate_chain', 'description': description,
            'rule': rule_of(why) if got else {'section': rule[0], 'text': rule[1]}, 'inputs': inputs,
            'context': {'resource_id': hx(RES[node.resource]), **context_of(node),
                        'head': {'case': node.prefix[-1], 'field': 'record_id', 'in': 'inputs'}}}
    if got is None:
        leaf = certs[0]
        case['expected'] = {'valid': True, 'post_state': {
            'leaf': L(leaf.device_id), 'leaf_certificate': CERT_LABEL[leaf.id], 'kind': leaf.kind, 'mask': leaf.mask,
            'issuers': [L(c.device_id) for c in certs[1:]], 'in_scope': st.in_scope(leaf),
            'new_bindings': [L(c.device_id) for c in certs if c.device_id not in st.devices]}}
    else:
        case['expected'] = {'valid': False, 'error': {'code': got}}
    add_case(case)


def build_chains() -> None:
    group('ID-02 Chains')
    ok = ('LFCP-WIRE-01 §7.3', 'verifyChain: structure, dependencies, signatures, then authority and state, all pass.')
    chain_case('chain_a', 'J2_grant_carol', 'OWNER', ['CERT_A'], 'accept', '[CERT_A] for OWNER in X at J2', ok)
    chain_case('chain_b_a', 'I1_device_grant_dev_a', 'OWNER', ['CERT_B', 'CERT_A'], 'accept', '[CERT_B, CERT_A] in X at I1', ok)
    chain_case('chain_e_c', 'I4_device_grant_dev_c_bob', 'BOB', ['CERT_E', 'CERT_C'], 'accept', '[CERT_E, CERT_C] for BOB in X at I4', ok)
    chain_case('chain_j_a', 'P1_device_grant_dev_a_i', 'OWNER', ['CERT_J', 'CERT_A'], 'accept', '[CERT_J, CERT_A] in I at P1', ok)
    chain_case('chain_empty', 'I1_device_grant_dev_a', 'OWNER', [], (M.MALFORMED, '(c1)'), 'The empty chain []')
    chain_case('chain_length_5', 'I1_device_grant_dev_a', 'OWNER', ['CERT_L_BY_M4', 'CERT_M4', 'CERT_M3', 'CERT_M2', 'CERT_A'],
               (M.MALFORMED, '(c1)'), 'Five certificates, non-managing leaf')
    chain_case('chain_managing_leaf_length_4', 'I1_device_grant_dev_a', 'OWNER', ['CERT_M4', 'CERT_M3', 'CERT_M2', 'CERT_A'],
               (M.MALFORMED, '(c7)'), 'A leaf listing 12 with four certificates')
    chain_case('chain_managing_leaf_length_3', 'I1_device_grant_dev_a', 'OWNER', ['CERT_M3', 'CERT_M2', 'CERT_A'], 'accept',
               'A leaf listing 12 with three certificates', ('LFCP-WIRE-01 §7.3 (c7)', 'A managing leaf has at most three certificates.'))
    chain_case('chain_non_managing_leaf_length_4', 'I1_device_grant_dev_a', 'OWNER', ['CERT_L_BY_M3', 'CERT_M3', 'CERT_M2', 'CERT_A'],
               'accept', 'Leaf {1,2,3} with four certificates', ('LFCP-WIRE-01 §7.3 (c1), (c7)', 'Four certificates are allowed for a leaf without 12.'))
    chain_case('chain_repeated_device', 'I1_device_grant_dev_a', 'OWNER', ['CERT_A_SELF', 'CERT_A'], (M.MALFORMED, '(c5)'),
               'DEV_A twice: [CERT_A_SELF (DEV_A by DEV_A), CERT_A]')
    chain_case('chain_mixed_roots', 'I4_device_grant_dev_c_bob', 'BOB', ['CERT_C', 'CERT_A'], (M.MALFORMED, '(c1)'),
               '[CERT_C (root BOB), CERT_A (root OWNER)] for BOB')
    chain_case('chain_bad_sig_and_repeat', 'I1_device_grant_dev_a', 'OWNER', ['CERT_A_SELF_BADSIG', 'CERT_A'], (M.MALFORMED, '(c5)'),
               '(c2) and (c5) both violated: structure is checked before signatures')
    chain_case('chain_not_root_terminated', 'I1_device_grant_dev_a', 'OWNER', ['CERT_B'], (M.BAD_SIG, '(c2)'),
               '[CERT_B] alone: its kid is DEV_A, not OWNER')
    chain_case('chain_kid_mismatch_inner', 'I1_device_grant_dev_a', 'OWNER', ['CERT_B', 'CERT_A2'], (M.BAD_SIG, '(c2)'),
               '[CERT_B, CERT_A2]: CERT_B.kid = DEV_A, not DEV_A2')
    chain_case('chain_root_unknown', 'U0_genesis_by_bob', 'OWNER', ['CERT_A'], (M.MISSING, 'step 2'),
               '[CERT_A] for OWNER in U, owned by BOB, where nothing describes OWNER')
    chain_case('chain_mask_exceeds_issuer', 'I4_device_grant_dev_c_bob', 'BOB', ['CERT_E_ROTATE', 'CERT_C'], (M.DENIED, '(c4)'),
               'Leaf {1,2,7} under CERT_C {1,2,4,5,12}')
    chain_case('chain_issuer_without_manage', 'I2_device_grant_self_dev_b', 'OWNER', ['CERT_X', 'CERT_B', 'CERT_A'], (M.DENIED, '(c3)'),
               '[CERT_X, CERT_B, CERT_A]: DEV_B lacks 12')
    chain_case('chain_issuer_service', 'I8_bridge_grant', 'BOB', ['CERT_L_BY_BRIDGE', 'CERT_S'], (M.DENIED, '(c3)'),
               'A leaf issued by BRIDGE (kind 1)')
    chain_case('chain_issuer_pairing', 'P2_pairing_device', 'OWNER', ['CERT_L_BY_J', 'CERT_J', 'CERT_A'], (M.DENIED, '(c3)'),
               'A leaf issued by PAIR_J (kind 2)')
    chain_case('chain_pairing_in_x', 'I1_device_grant_dev_a', 'OWNER', ['CERT_J', 'CERT_A'], (M.DENIED, '(c6)'),
               '[CERT_J, CERT_A] verified in X at I1: CERT_J lists only I')
    chain_case('chain_service_out_of_scope_is_not_failure', 'G2_grant_bob_y', 'BOB', ['CERT_S'], 'accept',
               '[CERT_S] verified in Y at G2', ('LFCP-WIRE-01 §7.3 (c6)', 'A kind-1 leaf that does not list the Resource is out of scope: in_scope = false, not a failure.'))
    chain_case('chain_root_is_device', 'I1_device_grant_dev_a', 'DEV_A', ['CERT_L_ROOT_DEV_A'], (M.DENIED, 'step 4.2'),
               'A chain for root DEV_A at I1')
    chain_case('chain_leaf_is_owner', 'J2_grant_carol', 'BOB', ['CERT_OWNER_AS_DEVICE'], (M.DENIED, 'step 4.3'),
               'A certificate on OWNER issued by BOB at J2')
    chain_case('chain_leaf_is_member', 'J2_grant_carol', 'OWNER', ['CERT_CAROL_AS_DEVICE'], (M.DENIED, 'step 4.3'),
               'A certificate on CAROL issued by OWNER at J2')
    chain_case('chain_leaf_is_invitation', 'N1_invite_grant', 'OWNER', ['CERT_INVITE_AS_DEVICE'], (M.DENIED, 'step 4.3'),
               'A certificate on INVITE after its invitation grant N1')
    chain_case('chain_intermediate_two_roots', 'I5_device_grant_dev_e_by_dev_c', 'OWNER', ['CERT_L_BY_C_FOR_OWNER', 'CERT_C_FOR_OWNER'],
               (M.DENIED, 'step 4.3'), 'At I5, a chain for root OWNER with DEV_C (bound to BOB) as intermediate')
    chain_case('chain_mask_changed', 'I2_device_grant_self_dev_b', 'OWNER', ["CERT_B''"], (M.DENIED, 'step 4.3'),
               "At I2, [CERT_B''] for DEV_B with mask {1}")
    chain_case('chain_kind_changed', 'I8_bridge_grant', 'BOB', ["CERT_S''"], (M.DENIED, 'step 4.3'),
               "At I8, [CERT_S''] for BRIDGE with kind 0")
    chain_case('chain_scope_changed', 'I8_bridge_grant', 'BOB', ["CERT_S'''"], (M.DENIED, 'step 4.3'),
               "At I8, [CERT_S'''] for BRIDGE with scope [X, Y]")
    chain_case('chain_old_intermediate_cert_reused', 'I10_recertify_dev_b', 'OWNER', ["CERT_B'", 'CERT_A'], (M.DENIED, 'step 4.4'),
               "At I10, [CERT_B', CERT_A]: CERT_A is DEV_A's only certificate and DEV_A is revoked")
    chain_case('chain_through_revoked_issuer', 'I9_device_revoke_dev_a', 'OWNER', ['CERT_B', 'CERT_A'], (M.DENIED, 'step 4.4'),
               'At I9, [CERT_B, CERT_A]')
    chain_case('chain_revoked_leaf', 'I9_device_revoke_dev_a', 'OWNER', ['CERT_A'], (M.DENIED, 'step 4.4'), 'At I9, [CERT_A]')


# -----------------------------------------------------------------------------
# ID-03 Control Records.
# -----------------------------------------------------------------------------


def build_records() -> None:
    group('ID-03 Control Records')
    ACC = ('LFCP-WIRE-01 §17.4', 'Accepted.')
    control('device_grant_root_without_standing', 'I11_revoke_root_grant_bob', 9, 'BOB', dg('BOB', C('CERT_F')),
            (M.DENIED, '§17.4 rule 4'), 'DEVICE_GRANT {BOB, [CERT_F]} by BOB on I11 (BOB known, no active grant)',
            readable=dg_readable('BOB', ['CERT_F']))
    control('device_grant_root_unknown', 'J2_grant_carol', 9, 'DAVE', dg('DAVE', C('CERT_D')), (M.MISSING, '§17.4 rule 2'),
            'DEVICE_GRANT {DAVE, [CERT_D]} by DAVE on J2 (no descriptor for DAVE yet)', readable=dg_readable('DAVE', ['CERT_D']))
    control('device_grant_root_invitation_only', 'N1_invite_grant', 9, 'INVITE', dg('INVITE', C('CERT_N')), (M.DENIED, '§17.4 rule 4'),
            'DEVICE_GRANT {INVITE, [CERT_N]} by INVITE after its invitation grant N1', readable=dg_readable('INVITE', ['CERT_N']))
    control('device_grant_standing_and_bad_sig', 'I11_revoke_root_grant_bob', 9, 'BOB', dg('BOB', C('CERT_F')), (M.BAD_SIG, '§10.5'),
            'device_grant_root_without_standing with the last record-signature bit flipped (class 4 before 5)',
            readable=dg_readable('BOB', ['CERT_F']), flip=True)
    # Exact-byte replay of I1 on the head I1.
    i1 = CASE_BY_ID['I1_device_grant_dev_a']
    node = NODES['I1_device_grant_dev_a']
    add_case({'id': 'device_grant_replay_exact_bytes', 'type': 'validation', 'kind': 'control_record',
              'description': 'The exact bytes of I1 sent again on the head I1',
              'rule': {'section': 'LFCP-WIRE-01 §47, §70; IDENTITY-PROFILE-01 §9.1',
                       'text': 'A coordinator answers a record it already committed with the same ACK; a validator reports the record as already in the chain. Not a transition.'},
              'inputs': {k: i1['inputs'][k] for k in ('resource', 'signer', 'issuer', 'control_seq', 'control_type', 'control_type_name', 'cose_sign1', 'record_id')},
              'context': {'resource_id': hx(RES['X']), **context_of(node),
                          'head': {'case': 'I1_device_grant_dev_a', 'field': 'record_id', 'in': 'inputs'}, 'head_control_seq': node.state.seq},
              'expected': {'valid': True, 'post_state': {'already_in_chain': True, 'ack_record': 'I1_device_grant_dev_a',
                                                         'control_seq': node.state.seq, 'state_unchanged': True}}})
    control('device_grant_repeat_same_leaf_fresh', 'I1_device_grant_dev_a', 9, 'OWNER', dg('OWNER', C('CERT_A')), (M.DENIED, '§17.4 rule 5'),
            'A fresh record on I1 with chain [CERT_A] and the correct prev/seq', readable=dg_readable('OWNER', ['CERT_A']))
    control('device_grant_revoked_pair', 'I9_device_revoke_dev_a', 9, 'OWNER', dg('OWNER', C("CERT_A'")), (M.DENIED, 'step 4.4'),
            "DEVICE_GRANT {OWNER, [CERT_A']} by OWNER on I9 (CERT_A': a fresh certificate for DEV_A)", readable=dg_readable('OWNER', ["CERT_A'"]))
    control('device_grant_issuer_unrelated', 'J2_grant_carol', 9, 'CAROL', dg('OWNER', C('CERT_A')), (M.DENIED, '§17.4 rule 6'),
            'DEVICE_GRANT {OWNER, [CERT_A]} by CAROL on J2', readable=dg_readable('OWNER', ['CERT_A']))
    control('device_grant_issuer_edit_device', 'I2_device_grant_self_dev_b', 9, 'DEV_B', dg('OWNER', C('CERT_A2')), (M.DENIED, '§17.4 rule 6'),
            'DEVICE_GRANT {OWNER, [CERT_A2]} by DEV_B on I2 (Edit: no 12, no 13)', readable=dg_readable('OWNER', ['CERT_A2']))
    control('device_grant_issuer_unknown', 'I1_device_grant_dev_a', 9, 'STRANGER', dg('OWNER', C('CERT_A2')), (M.MISSING, '§13.1'),
            'DEVICE_GRANT {OWNER, [CERT_A2]} by STRANGER, whom no record or chain describes, on I1', readable=dg_readable('OWNER', ['CERT_A2']))
    control('device_grant_service_self', 'I5_device_grant_dev_e_by_dev_c', 9, 'BRIDGE', dg('BOB', C('CERT_S')), (M.DENIED, '§17.4 rule 6'),
            'DEVICE_GRANT {BOB, [CERT_S]} by BRIDGE on I5 (a kind-1 leaf never registers itself)', readable=dg_readable('BOB', ['CERT_S']))
    control('device_grant_service_by_unregistered_issuer', 'G2_grant_bob_y', 9, 'DEV_C', dg('BOB', C('CERT_S2', 'CERT_C')), (M.DENIED, '§17.4 rule 6'),
            'In Y on G2: DEVICE_GRANT {BOB, [CERT_S2, CERT_C]} by DEV_C (DEV_C not registered in Y)', readable=dg_readable('BOB', ['CERT_S2', 'CERT_C']))
    control('device_grant_service_out_of_scope_bind_only', 'G2_grant_bob_y', 9, 'BOB', dg('BOB', C('CERT_S')), 'accept',
            'Yb1_bridge_out_of_scope as a vector: BRIDGE bound in Y, not registered, holds nothing', readable=dg_readable('BOB', ['CERT_S']),
            rule=('LFCP-WIRE-01 §17.4 rule 9', 'registered = true when in_scope, unchanged otherwise: an out-of-scope kind-1 leaf is bound and holds nothing.'),
            register=False, raw=CASE_BY_ID['Yb1_bridge_out_of_scope']['_record'])
    control('device_grant_pairing_self', 'P1_device_grant_dev_a_i', 9, 'PAIR_J', dg('OWNER', C('CERT_J', 'CERT_A')), (M.DENIED, '§17.4 rule 6'),
            "P2's record proposed by PAIR_J on P1", readable=dg_readable('OWNER', ['CERT_J', 'CERT_A']))
    control('device_grant_pairing_leaf_with_field_2', 'P1_device_grant_dev_a_i', 9, 'DEV_A', dg('OWNER', C('CERT_J', 'CERT_A'), 'PAIR_J'),
            (M.MALFORMED, '§17.4 rule 1'), 'Leaf CERT_J with field 2 present', readable=dg_readable('OWNER', ['CERT_J', 'CERT_A'], 'PAIR_J'))
    control('device_grant_body_extra_key', 'J2_grant_carol', 9, 'OWNER', {0: P['OWNER'].pid, 1: C('CERT_A'), 3: 0}, (M.MALFORMED, '§17.4 rule 1'),
            "I1's body with an extra key 3", readable={'root': 'OWNER', 'chain': ['CERT_A'], 'key_3': 0})
    control('device_grant_approval_without_consume', 'P2_pairing_device', 9, 'DEV_A', dg('OWNER', C('CERT_B', 'CERT_A'), 'PAIR_J'),
            (M.DENIED, '§17.4 rule 7'), 'A fresh P4-shaped record on P2 (no consuming revocation)', readable=dg_readable('OWNER', ['CERT_B', 'CERT_A'], 'PAIR_J'))
    control('device_grant_approval_mismatch', 'P3_consume_for_dev_b', 9, 'DEV_A', dg('OWNER', C("CERT_B'", 'CERT_A'), 'PAIR_J'),
            (M.DENIED, '§17.4 rule 7'), "On P3, DEVICE_GRANT {OWNER, [CERT_B', CERT_A], 2: PAIR_J}: the digest differs",
            readable=dg_readable('OWNER', ["CERT_B'", 'CERT_A'], 'PAIR_J'))
    control('P3c_cancel_pairing', 'P2_pairing_device', 10, 'DEV_A', dr('OWNER', 'PAIR_J', 0), 'accept',
            'DEVICE_REVOKE {OWNER, PAIR_J, 0} by DEV_A on P2 (session cancelled; context of device_grant_approval_after_cancel)',
            readable=dr_readable('OWNER', 'PAIR_J', 0),
            rule=('LFCP-WIRE-01 §17.5', 'Reason 0: a pairing session cancelled; PAIR_J was a reader: exposing.'))
    control('device_grant_approval_after_cancel', 'P3c_cancel_pairing', 9, 'DEV_A', dg('OWNER', C('CERT_B', 'CERT_A'), 'PAIR_J'),
            (M.DENIED, '§17.4 rule 7'), "P4's record on P2 + the cancellation: the reason is not 3",
            readable=dg_readable('OWNER', ['CERT_B', 'CERT_A'], 'PAIR_J'))
    control('device_grant_field2_personal', 'P3_consume_for_dev_b', 9, 'DEV_A', dg('OWNER', C('CERT_B', 'CERT_A'), 'DEV_A'),
            (M.DENIED, '§17.4 rule 7'), 'On P3, field 2 = DEV_A', readable=dg_readable('OWNER', ['CERT_B', 'CERT_A'], 'DEV_A'))
    control('device_grant_approved_without_field_2', 'P3_consume_for_dev_b', 9, 'DEV_A', dg('OWNER', C('CERT_B', 'CERT_A')), 'accept',
            'On P3, DEVICE_GRANT {OWNER, [CERT_B, CERT_A]} by DEV_A without field 2', readable=dg_readable('OWNER', ['CERT_B', 'CERT_A']),
            rule=('LFCP-WIRE-01 §17.4 rules 6 and 7', 'Field 2 is optional; the certificate exists only because the approval won (N9).'), register=False)
    control('device_grant_feasibility_full_depth_4', 'P1_device_grant_dev_a_i', 9, 'DEV_A',
            dg('OWNER', C('CERT_H_FULL_BY_M3', 'CERT_M3', 'CERT_M2', 'CERT_A')), (M.MALFORMED, '(c7)'),
            'A Full leaf issued by a manager whose chain has three certificates (the approver never proposes it)',
            readable=dg_readable('OWNER', ['CERT_H_FULL_BY_M3', 'CERT_M3', 'CERT_M2', 'CERT_A']))
    control('device_grant_feasibility_mask_exceeds_issuer', 'P1_device_grant_dev_a_i', 9, 'OWNER',
            dg('OWNER', C('CERT_H_EDIT_BY_G', 'CERT_G')), (M.DENIED, '(c4)'),
            'An Edit leaf {1,2,3} under a kind-0 issuer with mask {1,2,12}: structure and (c3) pass',
            readable=dg_readable('OWNER', ['CERT_H_EDIT_BY_G', 'CERT_G']))
    control('device_grant_feasibility_edit_issuer', 'P1_device_grant_dev_a_i', 9, 'OWNER',
            dg('OWNER', C('CERT_X_READ_BY_B', 'CERT_B', 'CERT_A')), (M.DENIED, '(c3)'),
            'A Read leaf issued by the Edit device DEV_B', readable=dg_readable('OWNER', ['CERT_X_READ_BY_B', 'CERT_B', 'CERT_A']))
    control('device_grant_self_recertify_suspended', 'I9_device_revoke_dev_a', 9, 'DEV_B', dg('OWNER', C('CERT_B2')), (M.DENIED, '§17.4 rule 6'),
            'On I9, DEVICE_GRANT {OWNER, [CERT_B2]} by DEV_B (the same record by OWNER is I10)', readable=dg_readable('OWNER', ['CERT_B2']))
    control('device_grant_self_recertify_active_managing', 'I1_device_grant_dev_a', 9, 'DEV_A', dg('OWNER', C("CERT_A'")), (M.DENIED, '§17.4 rule 6'),
            "On I1, DEVICE_GRANT {OWNER, [CERT_A']} by DEV_A itself: an active device with 12 and 13 does not re-certify itself",
            readable=dg_readable('OWNER', ["CERT_A'"]),
            note='Rule 6 admits D itself only for a first registration ("a device that was registered never re-certifies itself"); the clauses for an active managing device and an owner-acting device do not apply to D itself.')
    control('device_grant_self_recertify_active_managing.control', 'I1_device_grant_dev_a', 9, 'OWNER', dg('OWNER', C("CERT_A'")), 'accept',
            "Control: the same DEVICE_GRANT {OWNER, [CERT_A']} by OWNER is a re-certification", readable=dg_readable('OWNER', ["CERT_A'"]),
            rule=('LFCP-WIRE-01 §17.4 rules 5 and 6', 'The root re-certifies with a new leaf certificate ID.'), register=False)
    # Rule 8: live bindings. BOB has DEV_C, DEV_E and BRIDGE at I8.
    fill = record_set('bob_bindings_28', 'I8_bridge_grant', [(9, 'BOB', dg('BOB', C(f'CERT_{lab}'))) for lab in LIMIT[:28]],
                      'DEVICE_GRANT {BOB, [CERT_LIMIT_BOB_k]} by BOB, k = 01..28, on I8: 31 live Principals bound to BOB')
    control('device_grant_binding_limit.32nd', fill, 9, 'BOB', dg('BOB', C('CERT_LIMIT_BOB_29')), 'accept',
            'The 32nd live Principal bound to BOB in X', readable=dg_readable('BOB', ['CERT_LIMIT_BOB_29']),
            rule=('LFCP-WIRE-01 §17.4 rule 8', 'The record brings the live Principals bound to R to 32, not above.'))
    control('device_grant_binding_limit', 'device_grant_binding_limit.32nd', 9, 'BOB', dg('BOB', C('CERT_LIMIT_BOB_30')),
            (M.DENIED, '§17.4 rule 8'), 'A 33rd live Principal bound to BOB in X', readable=dg_readable('BOB', ['CERT_LIMIT_BOB_30']))
    control('device_grant_binding_limit.revoke_one', 'device_grant_binding_limit.32nd', 10, 'BOB', dr('BOB', 'LIMIT_BOB_01', 0), 'accept',
            'DEVICE_REVOKE {BOB, LIMIT_BOB_01, 0} by BOB: a revoked binding frees its place', readable=dr_readable('BOB', 'LIMIT_BOB_01', 0),
            rule=('LFCP-WIRE-01 §17.5', 'The revocation of a bound device is never limited.'))
    control('device_grant_binding_limit.after_revoke', 'device_grant_binding_limit.revoke_one', 9, 'BOB', dg('BOB', C('CERT_LIMIT_BOB_30')), 'accept',
            'After one binding is revoked, a new binding is accepted', readable=dg_readable('BOB', ['CERT_LIMIT_BOB_30']),
            rule=('LFCP-WIRE-01 §17.4 rule 8', 'A revoked binding no longer counts.'))
    # Rule 8: registrations per pair. I1 is the first DEVICE_GRANT of (OWNER, DEV_A).
    fill = record_set('dev_a_recertifications_6', 'I1_device_grant_dev_a',
                      [(9, 'OWNER', dg('OWNER', C(f'CERT_A#{k}'))) for k in range(2, 8)],
                      'DEVICE_GRANT {OWNER, [CERT_A#k]} by OWNER, k = 2..7, on I1: seven DEVICE_GRANTs of (OWNER, DEV_A)')
    control('device_grant_recertification_limit.eighth', fill, 9, 'OWNER', dg('OWNER', C('CERT_A#8')), 'accept',
            'The eighth DEVICE_GRANT for (OWNER, DEV_A)', readable=dg_readable('OWNER', ['CERT_A#8']),
            rule=('LFCP-WIRE-01 §17.4 rule 8', 'At most 8 registrations and re-certifications per pair.'))
    control('device_grant_recertification_limit', 'device_grant_recertification_limit.eighth', 9, 'OWNER', dg('OWNER', C('CERT_A#9')),
            (M.DENIED, '§17.4 rule 8'), 'A ninth DEVICE_GRANT for (OWNER, DEV_A)', readable=dg_readable('OWNER', ['CERT_A#9']))
    # §17.5 rule 5: unbound tombstones.
    fill = record_set('owner_tombstones_63', 'I1_device_grant_dev_a', [(10, 'OWNER', dr('OWNER', lab, 1)) for lab in TOMB_X[:63]],
                      'DEVICE_REVOKE {OWNER, TOMB_X_k, 1} by OWNER, k = 001..063, on I1 (unbound Principals)')
    control('device_revoke_tombstone_limit.64th', fill, 10, 'OWNER', dr('OWNER', TOMB_X[63], 1), 'accept',
            'The 64th revoked unbound pair of OWNER', readable=dr_readable('OWNER', TOMB_X[63], 1),
            rule=('LFCP-WIRE-01 §17.5 rule 5', 'At most 64 pairs (R, E) in revoked with devices[E] absent.'))
    control('device_revoke_tombstone_limit', 'device_revoke_tombstone_limit.64th', 10, 'OWNER', dr('OWNER', TOMB_X[64], 1),
            (M.DENIED, '§17.5 rule 5'), 'A 65th revoked unbound pair of OWNER', readable=dr_readable('OWNER', TOMB_X[64], 1))
    fill = record_set('dev_a_tombstones_64_in_i', 'P2_pairing_device', [(10, 'DEV_A', dr('OWNER', lab, 1)) for lab in TOMB_I],
                      'DEVICE_REVOKE {OWNER, TOMB_I_k, 1} by the managing device DEV_A, k = 001..064, on P2 in I')
    control('device_revoke_bound_after_tombstone_limit', fill, 10, 'OWNER', dr('OWNER', 'DEV_A', 2), 'accept',
            'After 64 unbound tombstones by DEV_A, the root revokes DEV_A with reason 2', readable=dr_readable('OWNER', 'DEV_A', 2),
            rule=('LFCP-WIRE-01 §17.5 rule 5', 'The revocation of a bound device, active, suspended or an intermediate, is never limited.'))
    control('device_revoke_bound_after_tombstone_limit.cancel_pairing', 'device_revoke_bound_after_tombstone_limit', 10, 'OWNER',
            dr('OWNER', 'PAIR_J', 0), 'accept', 'Then the root cancels the open pairing device PAIR_J (suspended by the cascade)',
            readable=dr_readable('OWNER', 'PAIR_J', 0),
            rule=('LFCP-WIRE-01 §17.5 rule 5', 'The revocation of a bound device is never limited.'))
    # Transfer offer by an unknown signer.
    build_transfer('T_unknown', 'I8_bridge_grant', 'STRANGER', 'BOB', 'BOB', None, emit=False)
    control('transfer_offer_unknown_signer', 'I8_bridge_grant', 6, 'BOB', transfer_body('T_unknown'), (M.DENIED, '§23.3 item 1'),
            'A commit whose offer is signed by STRANGER, whom no record describes (no field 2)',
            readable={'offer': 'signed by STRANGER, new owner BOB', 'accept': 'by BOB'})
    control('device_revoke_consume_twice', 'P3_consume_for_dev_b', 10, 'OWNER', dr('OWNER', 'PAIR_J', 3, CERTS["CERT_B'"]['digest']),
            (M.DENIED, '§17.5 rule 5'), "On P3, DEVICE_REVOKE {OWNER, PAIR_J, 3, 4: digest(CERT_B')} by OWNER",
            readable=dr_readable('OWNER', 'PAIR_J', 3, "CERT_B'"))
    control('device_revoke_reason3_without_field4', 'P2_pairing_device', 10, 'DEV_A', {0: P['OWNER'].pid, 1: P['PAIR_J'].pid, 2: 3},
            (M.MALFORMED, '§17.5 rule 1'), 'DEVICE_REVOKE {OWNER, PAIR_J, 3} without field 4', readable=dr_readable('OWNER', 'PAIR_J', 3))
    control('device_revoke_field4_with_reason_0', 'P2_pairing_device', 10, 'DEV_A', {0: P['OWNER'].pid, 1: P['PAIR_J'].pid, 2: 0, 4: CERTS['CERT_B']['digest']},
            (M.MALFORMED, '§17.5 rule 1'), 'DEVICE_REVOKE {OWNER, PAIR_J, 0, 4: digest}', readable=dr_readable('OWNER', 'PAIR_J', 0, 'CERT_B'))
    control('device_revoke_reason3_personal_target', 'P1_device_grant_dev_a_i', 10, 'OWNER', dr('OWNER', 'DEV_A', 3, CERTS['CERT_B']['digest']),
            (M.DENIED, '§17.5 rule 3'), 'DEVICE_REVOKE {OWNER, DEV_A, 3, 4: digest(CERT_B)} by OWNER on P1', readable=dr_readable('OWNER', 'DEV_A', 3, 'CERT_B'))
    control('claim_against_pairing_device', 'P2_pairing_device', 3, 'PAIR_J', {0: rid('P2_pairing_device'), 1: P['DAVE'].descriptor(), 2: [1, 2]},
            (M.DENIED, '§18.1 rule 1'), "CAPABILITY_CLAIM {P2's record ID, claimant DAVE, {1,2}} signed by PAIR_J on P2",
            readable={'grant': 'P2_pairing_device', 'claimant': 'DAVE', 'abilities': [1, 2]})
    control('grant_subject_bound', 'I2_device_grant_self_dev_b', 1, 'OWNER', grant_body('DEV_B', [1], []), (M.DENIED, '§80.1'),
            'CAPABILITY_GRANT to DEV_B by OWNER on I2', readable={'subject': 'DEV_B', 'abilities': [1], 'delegable': []})
    control('claim_by_bound_claimant.grant', 'I2_device_grant_self_dev_b', 1, 'OWNER', grant_body('INVITE', [1, 2, 11], [], limit=1), 'accept',
            'An invitation grant to INVITE on I2', readable={'subject': 'INVITE', 'abilities': [1, 2, 11], 'delegable': [], 'claim_limit': 1},
            rule=('LFCP-WIRE-01 §18', 'An invitation grant with claim_limit 1.'))
    control('claim_by_bound_claimant', 'claim_by_bound_claimant.grant', 3, 'INVITE',
            {0: rid('claim_by_bound_claimant.grant'), 1: P['DEV_B'].descriptor(), 2: [1, 2]}, (M.DENIED, '§80.1'),
            'CAPABILITY_CLAIM naming DEV_B (bound) as claimant', readable={'grant': 'claim_by_bound_claimant.grant', 'claimant': 'DEV_B', 'abilities': [1, 2]})
    legacy = ('LFCP-WIRE-01 §79', 'A chain without device records assigns only non-device roles and is never affected by the identity rules.')
    control('legacy_two_grants_either_order.plain_first', 'J2_grant_carol', 1, 'OWNER', grant_body('DAVE', [1], []), 'accept',
            'On J2: grant DAVE {1}', readable={'subject': 'DAVE', 'abilities': [1], 'delegable': []}, rule=legacy)
    control('legacy_two_grants_either_order', 'legacy_two_grants_either_order.plain_first', 1, 'OWNER', grant_body('DAVE', [1, 11], [], limit=1), 'accept',
            'Then grant DAVE {1,11}, claim_limit 1', readable={'subject': 'DAVE', 'abilities': [1, 11], 'delegable': [], 'claim_limit': 1}, rule=legacy)
    control('legacy_two_grants_either_order.invitation_first', 'J2_grant_carol', 1, 'OWNER', grant_body('DAVE', [1, 11], [], limit=1), 'accept',
            'Reverse order, on J2: grant DAVE {1,11}, claim_limit 1', readable={'subject': 'DAVE', 'abilities': [1, 11], 'delegable': [], 'claim_limit': 1}, rule=legacy)
    control('legacy_two_grants_either_order.reverse', 'legacy_two_grants_either_order.invitation_first', 1, 'OWNER', grant_body('DAVE', [1], []), 'accept',
            'Then grant DAVE {1}', readable={'subject': 'DAVE', 'abilities': [1], 'delegable': []}, rule=legacy)
    control('legacy_claim_with_delegated_11.grant', 'J2_grant_carol', 1, 'OWNER', grant_body('INVITE', [1, 2, 11], [11], limit=1), 'accept',
            'On J2: invitation grant {1,2,11}, delegable {11}, claim_limit 1', readable={'subject': 'INVITE', 'abilities': [1, 2, 11], 'delegable': [11], 'claim_limit': 1}, rule=legacy)
    control('legacy_claim_with_delegated_11', 'legacy_claim_with_delegated_11.grant', 3, 'INVITE',
            {0: rid('legacy_claim_with_delegated_11.grant'), 1: P['DAVE'].descriptor(), 2: [1, 11]}, 'accept',
            'A claim transferring {1,11} to DAVE', readable={'grant': 'legacy_claim_with_delegated_11.grant', 'claimant': 'DAVE', 'abilities': [1, 11]},
            rule=('LFCP-WIRE-01 §18.1 rule 4', 'invite/claim may be claimed when it is explicitly delegated.'))
    build_transfer('T_inv', 'N1_invite_grant', 'OWNER', 'INVITE', 'INVITE', None, emit=False)
    control('legacy_transfer_to_former_invitation_subject', 'N1_invite_grant', 6, 'INVITE', transfer_body('T_inv'), 'accept',
            'Offer to INVITE after its invitation grant; accept and commit by INVITE', readable={'offer': 'by OWNER, new owner INVITE', 'accept': 'by INVITE'},
            rule=('LFCP-WIRE-01 §23.3', 'A transfer to a former Invitation Principal is valid as before; INVITE stays non-device.'))
    j1 = rid('J1_grant_bob')
    control('grant_exceeds_device_mask', 'I5_device_grant_dev_e_by_dev_c', 1, 'DEV_C', grant_body('DAVE', [6], [], j1), (M.DENIED, 'delegation bound'),
            'By DEV_C to DAVE {6}, parent J1, on I5 (6 in J1.delegable, not in CERT_C.mask)', readable={'subject': 'DAVE', 'abilities': [6], 'delegable': [], 'parent': 'J1_grant_bob'})
    control('grant_delegable_exceeds_device_mask', 'I5_device_grant_dev_e_by_dev_c', 1, 'DEV_C', grant_body('DAVE', [1], [6], j1), (M.DENIED, 'delegation bound'),
            'By DEV_C to DAVE {1}, delegable {6}, parent J1, on I5', readable={'subject': 'DAVE', 'abilities': [1], 'delegable': [6], 'parent': 'J1_grant_bob'})
    control('grant_within_mask_and_parent', 'I5_device_grant_dev_e_by_dev_c', 1, 'DEV_C', grant_body('DAVE', [1, 2], [1], j1), 'accept',
            'By DEV_C to DAVE {1,2}, delegable {1}, parent J1, on I5', readable={'subject': 'DAVE', 'abilities': [1, 2], 'delegable': [1], 'parent': 'J1_grant_bob'},
            rule=('LFCP-WIRE-01 §17.2, §80.1', 'Within the mask and the parent\'s delegable list; issuer_root = BOB.'), register=False)
    control('invitation_grant_by_device_within_mask', 'I5_device_grant_dev_e_by_dev_c', 1, 'DEV_C', grant_body('INVITE2', [1, 2, 11], [], j1, limit=1), 'accept',
            'By DEV_C to a fresh Invitation Principal {1,2,11}, claim_limit 1, parent J1, on I5',
            readable={'subject': 'INVITE2', 'abilities': [1, 2, 11], 'delegable': [], 'parent': 'J1_grant_bob', 'claim_limit': 1},
            rule=('LFCP-WIRE-01 §17.2 delegation bound', '11 is in J1.delegable and passes through the mask bound as received.'), register=False)
    control('grant_exceeds_parent_delegable', 'I5_device_grant_dev_e_by_dev_c', 1, 'DEV_C', grant_body('DAVE', [4], [], j1), (M.DENIED, '§17.2'),
            'By DEV_C to DAVE {4}, parent J1, on I5 (4 in the mask, not in J1.delegable)', readable={'subject': 'DAVE', 'abilities': [4], 'delegable': [], 'parent': 'J1_grant_bob'})
    control('revoke_not_covered_unrelated', 'I6_grant_by_member_device', 2, 'CAROL', {0: rid('I6_grant_by_member_device')}, (M.DENIED, '§17.3 check 2'),
            'CAPABILITY_REVOKE of I6 by CAROL on I6 (5 in J2; CAROL issued neither I6 nor an ancestor)', readable={'grant': 'I6_grant_by_member_device'})
    control('owner_action_by_edit_device', 'I2_device_grant_self_dev_b', 1, 'DEV_B', grant_body('DAVE', [1], []), (M.DENIED, '§17.2'),
            'CAPABILITY_GRANT without parent by DEV_B on I2', readable={'subject': 'DAVE', 'abilities': [1], 'delegable': []})
    control('device_revoke_twice', 'I9_device_revoke_dev_a', 10, 'OWNER', dr('OWNER', 'DEV_A', 1), (M.DENIED, '§17.5 rule 5'),
            'A fresh DEVICE_REVOKE {OWNER, DEV_A, 1} on I9', readable=dr_readable('OWNER', 'DEV_A', 1))
    control('device_revoke_by_member_device', 'I5_device_grant_dev_e_by_dev_c', 10, 'DEV_C', dr('OWNER', 'DEV_B', 0), (M.DENIED, '§17.5 rule 4'),
            'DEVICE_REVOKE {OWNER, DEV_B, 0} by DEV_C on I5', readable=dr_readable('OWNER', 'DEV_B', 0))
    control('device_revoke_self', 'I2_device_grant_self_dev_b', 10, 'DEV_B', dr('OWNER', 'DEV_B', 0), 'accept',
            'DEVICE_REVOKE {OWNER, DEV_B, 0} by DEV_B on I2 (self-retirement)', readable=dr_readable('OWNER', 'DEV_B', 0),
            rule=('LFCP-WIRE-01 §17.5 rule 4', 'D itself when registered and not revoked, reason 0; DEV_B read before: exposing.'), register=False)
    control('device_revoke_self_reason_1', 'I2_device_grant_self_dev_b', 10, 'DEV_B', dr('OWNER', 'DEV_B', 1), (M.DENIED, '§17.5 rule 4'),
            'DEVICE_REVOKE {OWNER, DEV_B, 1} by DEV_B on I2', readable=dr_readable('OWNER', 'DEV_B', 1))
    control('device_revoke_unbound', 'I2_device_grant_self_dev_b', 10, 'OWNER', dr('OWNER', 'DEV_X', 2), 'accept',
            'DEVICE_REVOKE {OWNER, DEV_X, 2} by OWNER on I2 (DEV_X unbound)', readable=dr_readable('OWNER', 'DEV_X', 2),
            rule=('LFCP-WIRE-01 §17.5', 'revoked contains (OWNER, DEV_X); no binding; rootOf(DEV_X) = DEV_X; not exposing.'))
    control('device_revoke_by_invitation_only_root', 'N1_invite_grant', 10, 'INVITE', dr('INVITE', 'DEV_X', 2), (M.DENIED, '§17.5 rule 4'),
            'DEVICE_REVOKE {INVITE, DEV_X, 2} by INVITE after its invitation grant N1', readable=dr_readable('INVITE', 'DEV_X', 2))
    control('device_revoke_by_former_member', 'I11_revoke_root_grant_bob', 10, 'BOB', dr('BOB', 'DEV_X', 2), (M.DENIED, '§17.5 rule 4'),
            'On I11, DEVICE_REVOKE {BOB, DEV_X, 2} by BOB', readable=dr_readable('BOB', 'DEV_X', 2))
    control('device_revoke_foreign_root_of_intermediate', 'I5_device_grant_dev_e_by_dev_c', 10, 'CAROL', dr('CAROL', 'DEV_C', 2), (M.DENIED, '§17.5 rule 3'),
            'DEVICE_REVOKE {CAROL, DEV_C, 2} by CAROL on I5', readable=dr_readable('CAROL', 'DEV_C', 2))
    control('device_revoke_foreign_unbound_no_effect', 'J2_grant_carol', 10, 'CAROL', dr('CAROL', 'DEV_A', 2), 'accept',
            'DEVICE_REVOKE {CAROL, DEV_A, 2} by CAROL on J2', readable=dr_readable('CAROL', 'DEV_A', 2),
            rule=('LFCP-WIRE-01 §17.5', 'CAROL has standing; (CAROL, DEV_A) is another pair than (OWNER, DEV_A).'))
    control('device_revoke_foreign_unbound_no_effect.then_grant', 'device_revoke_foreign_unbound_no_effect', 9, 'OWNER', dg('OWNER', C('CERT_A')), 'accept',
            "Then I1's record re-created on top: DEV_A is active", readable=dg_readable('OWNER', ['CERT_A']),
            rule=('LFCP-WIRE-01 §17.5', 'A revocation recorded for another root has no effect on DEV_A.'))
    control('device_revoke_intermediate_with_reading_descendant', 'V1_bind_dev_c_as_intermediate', 10, 'BOB', dr('BOB', 'DEV_C', 1), 'accept',
            'V2_revoke_dev_c as a vector', readable=dr_readable('BOB', 'DEV_C', 1),
            rule=('LFCP-WIRE-01 §17.5', 'Exposure: DEV_E, registered and reading, is suspended by the cascade.'), register=False,
            raw=CASE_BY_ID['V2_revoke_dev_c']['_record'])
    control('device_revoke_unbound_without_descendants', 'J2_grant_carol', 10, 'BOB', dr('BOB', 'DEV_X', 1), 'accept',
            'Vu1_revoke_unbound as a vector', readable=dr_readable('BOB', 'DEV_X', 1),
            rule=('LFCP-WIRE-01 §17.5', 'Exposure: no registered reader is removed.'), register=False,
            raw=CASE_BY_ID['Vu1_revoke_unbound']['_record'])
    control('device_revoke_root_target', 'I4_device_grant_dev_c_bob', 10, 'BOB', dr('BOB', 'OWNER', 2), (M.DENIED, '§17.5 rule 3'),
            'DEVICE_REVOKE {BOB, OWNER, 2} by BOB on I4', readable=dr_readable('BOB', 'OWNER', 2))
    control('device_revoke_with_field_3', 'I1_device_grant_dev_a', 10, 'OWNER', {0: P['OWNER'].pid, 1: P['DEV_A'].pid, 2: 1, 3: []},
            (M.MALFORMED, '§17.5 rule 1'), 'DEVICE_REVOKE with the reserved key 3', readable={'root': 'OWNER', 'device': 'DEV_A', 'reason': 1, 'key_3': []})
    control('device_revoke_wrong_root', 'I1_device_grant_dev_a', 10, 'BOB', dr('BOB', 'DEV_A', 1), (M.DENIED, '§17.5 rule 3'),
            'DEVICE_REVOKE {BOB, DEV_A, 1} by BOB on I1', readable=dr_readable('BOB', 'DEV_A', 1))
    # Genesis with field 5 (Resource Z, each independent).
    gz = lambda chain, owner='OWNER': genesis_body('Z', owner, chain)  # noqa: E731
    control('genesis_device_without_owner_act', None, 0, 'DEV_B', gz(C('CERT_B', 'CERT_A')), (M.DENIED, '§15'),
            'Genesis of Z by DEV_B, field 5 [CERT_B, CERT_A] (13 not in the mask)', resource='Z', register=False,
            readable={'owner': 'OWNER', 'device_chain': ['CERT_B', 'CERT_A']})
    control('genesis_device_service', None, 0, 'BRIDGE_O', gz(C('CERT_SO', 'CERT_A')), (M.DENIED, '§15'),
            'Genesis of Z by BRIDGE_O, field 5 [CERT_SO, CERT_A] (kind 1)', resource='Z', register=False,
            readable={'owner': 'OWNER', 'device_chain': ['CERT_SO', 'CERT_A']})
    control('genesis_device_pairing', None, 0, 'PAIR_J', gz(C('CERT_J', 'CERT_A')), (M.DENIED, '§7.3 (c6)'),
            'Genesis of Z by PAIR_J, field 5 [CERT_J, CERT_A] (kind 2, scope [I])', resource='Z', register=False,
            readable={'owner': 'OWNER', 'device_chain': ['CERT_J', 'CERT_A']})
    control('genesis_device_foreign_root', None, 0, 'DEV_F', gz(C('CERT_F')), (M.MALFORMED, '(c1)'),
            'Genesis of Z, field 1 OWNER, field 5 [CERT_F] (a chain for BOB), by DEV_F', resource='Z', register=False,
            readable={'owner': 'OWNER', 'device_chain': ['CERT_F']})
    control('genesis_device_kid_owner', None, 0, 'OWNER', gz(C('CERT_A')), (M.BAD_SIG, '§15'),
            'Genesis of Z with field 5 [CERT_A] signed by OWNER (kid = OWNER)', resource='Z', register=False,
            readable={'owner': 'OWNER', 'device_chain': ['CERT_A']})
    control('genesis_after_revocation_elsewhere', None, 0, 'DEV_A', gz(C('CERT_A')), 'accept',
            'Genesis of the fresh Resource Z by DEV_A with [CERT_A], after I9 revoked DEV_A in X', resource='Z', register=False,
            readable={'owner': 'OWNER', 'device_chain': ['CERT_A']},
            rule=('LFCP-WIRE-01 §15, §98.1', 'S is empty at Genesis: nothing can be revoked there.'))
    # Transfers.
    control('transfer_commit_via_dev_f', 'I8_bridge_grant', 6, 'DEV_F', transfer_body('T1', C('CERT_F')), 'accept',
            'T1_commit on I8 as a vector', readable={'offer': 'T1_offer', 'accept': 'T1_accept', 'device_chain': ['CERT_F']},
            rule=('LFCP-WIRE-01 §23.3', 'Owner BOB; DEV_F bound and registered.'), register=False, raw=CASE_BY_ID['T1_commit']['_record'])
    control('transfer_commit_revoked_leaf.revoke', 'I8_bridge_grant', 10, 'BOB', dr('BOB', 'DEV_F', 1), 'accept',
            'DEVICE_REVOKE {BOB, DEV_F, 1} by BOB on I8 (DEV_F unbound in X)', readable=dr_readable('BOB', 'DEV_F', 1),
            rule=('LFCP-WIRE-01 §17.5', 'A pre-emptive revocation of an unbound Principal.'))
    build_transfer('T_rev', 'transfer_commit_revoked_leaf.revoke', 'OWNER', 'BOB', 'DEV_F', None, emit=False, accept_names='BOB')
    control('transfer_commit_revoked_leaf', 'transfer_commit_revoked_leaf.revoke', 6, 'DEV_F', transfer_body('T_rev', C('CERT_F')),
            (M.DENIED, 'step 4.4'), 'Offer, accept and commit re-created on the head after the revocation of (BOB, DEV_F)',
            readable={'offer': 'by OWNER, new owner BOB', 'accept': 'by DEV_F', 'device_chain': ['CERT_F']})
    build_transfer('T_noact', 'I8_bridge_grant', 'OWNER', 'BOB', 'DEV_E', None, emit=False, accept_names='BOB')
    control('transfer_commit_leaf_without_owner_act', 'I8_bridge_grant', 6, 'DEV_E', transfer_body('T_noact', C('CERT_E', 'CERT_C')),
            (M.DENIED, '§23.3'), 'Field 2 [CERT_E, CERT_C]; accept and commit by DEV_E on I8 (13 not in the mask)',
            readable={'offer': 'by OWNER, new owner BOB', 'accept': 'by DEV_E', 'device_chain': ['CERT_E', 'CERT_C']})
    build_transfer('T_other', 'I8_bridge_grant', 'OWNER', 'BOB', 'DEV_A', None, emit=False, accept_names='BOB')
    control('transfer_commit_leaf_other_root', 'I8_bridge_grant', 6, 'DEV_A', transfer_body('T_other', C('CERT_A')),
            (M.MALFORMED, '(c1)'), 'Field 2 [CERT_A] (root OWNER) for an offer naming BOB',
            readable={'offer': 'by OWNER, new owner BOB', 'accept': 'by DEV_A', 'device_chain': ['CERT_A']})
    build_transfer('T_bound', 'I2_device_grant_self_dev_b', 'OWNER', 'DEV_B', 'DEV_B', None, emit=False)
    control('transfer_commit_new_owner_bound', 'I2_device_grant_self_dev_b', 6, 'DEV_B', transfer_body('T_bound'), (M.DENIED, '§80.1'),
            'Offer naming DEV_B; accept and commit by DEV_B, no field 2, on I2', readable={'offer': 'by OWNER, new owner DEV_B', 'accept': 'by DEV_B'})
    control('transfer_commit_kid_mismatch', 'I8_bridge_grant', 6, 'BOB', transfer_body('T1', C('CERT_F')), (M.BAD_SIG, '§23.3: with field 2'),
            'Field 2 [CERT_F], commit signed by BOB', readable={'offer': 'T1_offer', 'accept': 'T1_accept', 'device_chain': ['CERT_F']})
    null_offer = sign(cbor(None), P['OWNER'])['cose']
    acc = TRANSFERS['T1']['accept']['cose']
    control('transfer_commit_malformed_offer_bad_placement', 'I8_bridge_grant', 6, 'BOB', {0: null_offer, 1: acc}, (M.MALFORMED, '§23.1'),
            'No field 2, offer = COSE_Sign1 of null, wrong prev and seq', seq=3, prev=rid('J1_grant_bob'),
            readable={'offer': 'COSE_Sign1 by OWNER whose payload is CBOR null', 'accept': 'T1_accept'})
    control('transfer_commit_malformed_offer_unknown_issuer', 'I8_bridge_grant', 6, 'STRANGER', {0: null_offer, 1: acc}, (M.MALFORMED, '§23.1'),
            'No field 2, offer = COSE_Sign1 of null, issuer STRANGER (unknown)',
            readable={'offer': 'COSE_Sign1 by OWNER whose payload is CBOR null', 'accept': 'T1_accept'})
    build_transfer('T_mis', 'I8_bridge_grant', 'OWNER', 'BOB', 'BOB', None, emit=False, accept_names='CAROL')
    control('transfer_accept_field2_mismatch_valid_signers', 'I8_bridge_grant', 6, 'BOB', transfer_body('T_mis'), (M.DENIED, '§23.3 item 3'),
            'Offer by OWNER naming BOB, accept by BOB with field 2 CAROL, commit by BOB', readable={'offer': 'by OWNER, new owner BOB', 'accept': 'by BOB, field 2 CAROL'})
    build_transfer('T_wrong', 'I8_bridge_grant', 'OWNER', 'BOB', 'CAROL', None, emit=False, accept_names='CAROL')
    control('transfer_accept_wrong_signer_before_acceptor_mismatch', 'I8_bridge_grant', 6, 'BOB', transfer_body('T_wrong'), (M.BAD_SIG, '§23.3 item 4'),
            'An acceptance signed by CAROL whose field 2 is CAROL (also differs from the offer), no field 2',
            readable={'offer': 'by OWNER, new owner BOB', 'accept': 'by CAROL, field 2 CAROL'})
    # Key epochs.
    control('key_epoch_by_dev_a', 'I8_bridge_grant', 4, 'DEV_A', key_epoch_body('X', 1, K1_FRONTIER, 0), 'accept',
            'KEY_EPOCH on I8 by DEV_A (13 in its mask, OWNER owns X)', readable={'epoch': 1, 'frontier': K1_FRONTIER, 'reason': 0},
            rule=('LFCP-WIRE-01 §19, §80.1', 'holds(DEV_A, 7) through owner/act.'), register=False)
    control('key_epoch_by_dev_f', 'T1_commit', 4, 'DEV_F', key_epoch_body('X', 1, K1_FRONTIER, 3), 'accept',
            'KEY_EPOCH on T1_commit by DEV_F (BOB owns X, 13 in its mask)', readable={'epoch': 1, 'frontier': K1_FRONTIER, 'reason': 3},
            rule=('LFCP-WIRE-01 §19, §80.1', 'holds(DEV_F, 7) through owner/act after the transfer.'), register=False)
    control('key_epoch_by_dev_c', 'I8_bridge_grant', 4, 'DEV_C', key_epoch_body('X', 1, K1_FRONTIER, 0), (M.DENIED, '§19'),
            'KEY_EPOCH on I8 by DEV_C (7 not in its mask)', readable={'epoch': 1, 'frontier': K1_FRONTIER, 'reason': 0})
    control('key_epoch_by_bridge', 'I8_bridge_grant', 4, 'BRIDGE', key_epoch_body('X', 1, K1_FRONTIER, 0), (M.DENIED, '§19'),
            'KEY_EPOCH on I8 by BRIDGE', readable={'epoch': 1, 'frontier': K1_FRONTIER, 'reason': 0})
    control('type_11_reserved', 'I1_device_grant_dev_a', 11, 'OWNER', {}, (M.PLACEMENT, '§14'),
            'A Control Record of the reserved core type 11', readable={})
    control('ability_12_in_grant_confers_nothing.grant', 'I3_owner_action_by_dev_a', 1, 'OWNER', grant_body('DAVE', [1, 12], []), 'accept',
            'CAPABILITY_GRANT to DAVE {1,12} by OWNER on I3: 12 confers nothing in a grant',
            readable={'subject': 'DAVE', 'abilities': [1, 12], 'delegable': []},
            rule=('LFCP-WIRE-01 §17.1', 'In a Capability Grant, 12 and 13 are kept as received and confer nothing.'))
    control('ability_12_in_grant_confers_nothing', 'ability_12_in_grant_confers_nothing.grant', 9, 'DAVE', dg('OWNER', C('CERT_A2')),
            (M.DENIED, '§17.4 rule 6'), 'Then DEVICE_GRANT {OWNER, [CERT_A2]} by DAVE', readable=dg_readable('OWNER', ['CERT_A2']))
    control('ability_12_in_grant_confers_nothing.control', 'ability_12_in_grant_confers_nothing.grant', 9, 'DEV_A', dg('OWNER', C('CERT_A2')), 'accept',
            'Control: the same DEVICE_GRANT by DEV_A is accepted', readable=dg_readable('OWNER', ['CERT_A2']),
            rule=('LFCP-WIRE-01 §17.4 rule 6', 'An active managing device of R.'), register=False)
    # Ability 11 on devices (W §80.1).
    control('KP_to_device_with_mask_11.invitation', 'I8_bridge_grant', 1, 'OWNER', grant_body('BOB', [1, 11], [], limit=1), 'accept',
            'An invitation grant to BOB {1,11}, claim_limit 1, on I8 (BOB also holds J1)',
            readable={'subject': 'BOB', 'abilities': [1, 11], 'delegable': [], 'claim_limit': 1},
            rule=('LFCP-WIRE-01 §18', 'BOB holds an ordinary grant and an invitation grant.'))
    control('KP_to_device_with_mask_11.register', 'KP_to_device_with_mask_11.invitation', 9, 'BOB', dg('BOB', C('CERT_K11')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_K11]} by BOB: an active device with mask {1,2,11}', readable=dg_readable('BOB', ['CERT_K11']), rule=A_DEV)
    control('KP_to_device_with_mask_11.register_without_read', 'KP_to_device_with_mask_11.register', 9, 'BOB', dg('BOB', C('CERT_K11W')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_K11W]} by BOB: an active device with mask {2,11}', readable=dg_readable('BOB', ['CERT_K11W']), rule=A_DEV)
    control('KP_to_owner_acting_device_with_mask_11.register', 'I1_device_grant_dev_a', 9, 'OWNER', dg('OWNER', C('CERT_K13')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_K13]} by OWNER: an active device with mask {1,2,11,13}', readable=dg_readable('OWNER', ['CERT_K13']), rule=A_DEV)
    control('device_grant_self_recertify_active_managing.owner_acting', 'KP_to_owner_acting_device_with_mask_11.register', 9, 'DEV_K13',
            dg('OWNER', C("CERT_K13'")), (M.DENIED, '§17.4 rule 6'),
            "DEVICE_GRANT {OWNER, [CERT_K13']} by DEV_K13 itself (active, 13 in its mask, OWNER owns X)", readable=dg_readable('OWNER', ["CERT_K13'"]))


# -----------------------------------------------------------------------------
# ID-04 Data Units, Key Packages, Snapshots, reads.
# -----------------------------------------------------------------------------

UNITS: dict[str, dict] = {}


def unit_bytes(res: str, actor: str, epoch: int, seq: int, prev: bytes | None, ref: bytes, text: str) -> dict:
    rid_ = RES[res]
    pt = text.encode('utf-8')
    aad = cbor(['LFCP-DATA-v1', rid_, epoch, P[actor].pid, seq, prev, ref])
    key = actor_key(rid_, epoch, dek(res, epoch), P[actor].pid)
    ct = ChaCha20Poly1305(key).encrypt(lfcp_nonce(seq), pt, aad)
    assert ChaCha20Poly1305(key).decrypt(lfcp_nonce(seq), ct, aad) == pt
    s = sign(cbor({0: rid_, 1: epoch, 2: P[actor].pid, 3: seq, 4: prev, 5: ref, 6: ct}), P[actor])
    s['plaintext'] = pt
    return s


def heads_of(node: Node) -> dict:
    return {st.head: st for st in node.history}


def obj_case(cid: str, kind: str, latest: str, s: dict, expect, description: str, inputs: dict, check, rule=None,
             head_case: str | None = None) -> dict:
    node = NODES[latest]
    try:
        check(node)
        got, why = None, ''
    except Reject as e:
        got, why = e.code, e.rule
    check_expectation(cid, expect, got, why)
    ctx = {'resource_id': hx(RES[node.resource]), **context_of(node),
           'latest': {'case': node.prefix[-1], 'field': 'record_id', 'in': 'inputs'}}
    if head_case:
        ctx['head'] = {'case': head_case, 'field': 'record_id', 'in': 'inputs'}
    case = {'id': cid, 'type': 'validation', 'kind': kind, 'description': description,
            'rule': rule_of(why) if got else {'section': rule[0], 'text': rule[1]},
            'inputs': {**inputs, 'payload_cbor': hx(s['payload']), 'protected_header_cbor': hx(s['protected']),
                       'signature': hx(s['signature']), 'cose_sign1': hx(s['cose']), 'object_id': hx(s['id'])},
            'context': ctx,
            'expected': {'valid': True} if got is None else {'valid': False, 'error': {'code': got}}}
    if got == M.STALE:
        case['expected']['disposition'] = 'quarantine'
    add_case(case)
    return case


def unit_case(cid: str, latest: str, actor: str, seq: int, prev: str | None, ref_case: str, expect, description: str,
              rule=None, epoch: int = 0, res: str | None = None, ref_bytes: bytes | None = None, text: str | None = None,
              equivocates_with: str | None = None) -> dict:
    res = res or NODES[latest].resource
    ref = ref_bytes if ref_bytes is not None else rid(ref_case)
    prev_id = UNITS[prev]['id'] if prev else None
    key = (res, actor, epoch, seq, prev_id, ref, text)
    s = next((u for u in UNITS.values() if u.get('key') == key), None)
    if s is None:
        s = unit_bytes(res, actor, epoch, seq, prev_id, ref, text or f'{actor} seq {seq} at {ref_case} in {res}')
        s['key'] = key
    UNITS[cid] = s

    def check(node):
        M.check_unit(None, node.state, s['cose'], heads_of(node))
        if equivocates_with:
            other = UNITS[equivocates_with]
            if other['key'][1:4] == key[1:4] and other['id'] != s['id']:
                raise Reject('ACTOR_EQUIVOCATION', 'W §26.2: two different Data Units with the same (resource, actor, seq)')

    case = obj_case(cid, 'data_unit', latest, s, expect, description,
                    {'resource': res, 'signer': actor, 'actor': actor, 'epoch': epoch, 'actor_seq': seq,
                     'previous': prev, 'control_ref': ref_case, 'plaintext_utf8': s['plaintext'].decode(),
                     'data_key': f'{res} epoch {epoch}'}, check, rule, head_case=ref_case if ref_bytes is None else None)
    if equivocates_with:
        case['context']['accepted_unit'] = {'case': equivocates_with, 'field': 'cose_sign1', 'in': 'inputs'}
    return case


def package_bytes(res: str, sender: str, recipient: str, epoch: int, head: bytes, label: str) -> dict:
    rid_ = RES[res]
    info = cbor(['LFCP-KEY-v1', rid_, epoch, P[recipient].pid])
    aad = cbor([rid_, epoch, head])
    ske = hpke_derive_key_pair_x25519(h('LFCP-TV-IDENTITY-KP-EPHEMERAL-' + label))
    sealed = hpke_seal_with_ephemeral(P[recipient].x_pk, ske, info, aad, dek(res, epoch))
    assert hpke_open(P[recipient].x_sk_raw, sealed['enc'], info, aad, sealed['ct']) == dek(res, epoch)
    s = sign(cbor({0: rid_, 1: epoch, 2: P[recipient].pid, 3: head, 4: P[sender].pid, 5: sealed['enc'], 6: sealed['ct']}), P[sender])
    s['ephemeral_seed'] = h('LFCP-TV-IDENTITY-KP-EPHEMERAL-' + label)
    return s


def package_case(cid: str, latest: str, sender: str, recipient: str, head_case: str, expect, description: str, rule=None,
                 epoch: int = 0) -> None:
    res = NODES[latest].resource
    s = package_bytes(res, sender, recipient, epoch, rid(head_case), cid)

    def check(node):
        M.check_package(s['cose'], heads_of(node))

    obj_case(cid, 'key_package', latest, s, expect, description,
             {'resource': res, 'signer': sender, 'sender': sender, 'recipient': recipient, 'epoch': epoch,
              'control_head': head_case, 'hpke_ikm_for_ephemeral': hx(s['ephemeral_seed']), 'dek': None} | {}, check, rule,
             head_case=head_case)
    CASE_BY_ID[cid]['inputs'].pop('dek')


def snapshot_case(cid: str, latest: str, publisher: str, head_case: str, expect, description: str, rule=None) -> None:
    res = NODES[latest].resource
    rid_ = RES[res]
    head = rid(head_case)
    fr = [{0: P[publisher].pid, 1: 0}] if False else []
    pt = f'snapshot by {publisher} at {head_case}'.encode()
    aad = cbor(['LFCP-SNAPSHOT-v1', rid_, 0, P[publisher].pid, 1, head, fr])
    key = snapshot_key(rid_, 0, dek(res, 0), P[publisher].pid)
    ct = ChaCha20Poly1305(key).encrypt(lfcp_nonce(1), pt, aad)
    s = sign(cbor({0: rid_, 1: 0, 2: P[publisher].pid, 3: 1, 4: head, 5: fr, 6: ct}), P[publisher])

    def check(node):
        M.check_snapshot(s['cose'], heads_of(node))

    obj_case(cid, 'snapshot', latest, s, expect, description,
             {'resource': res, 'signer': publisher, 'publisher': publisher, 'epoch': 0, 'snapshot_seq': 1,
              'control_head': head_case, 'frontier': [], 'plaintext_utf8': pt.decode()}, check, rule, head_case=head_case)


def read_case(cid: str, latest: str, session: str, request: str, expect, description: str, rule=None) -> None:
    node = NODES[latest]
    try:
        scope, idx = M.read_access(node.state, node.history, P[session].pid)
        if scope == 'prefix' and request not in ('RESOURCE_OPEN', 'CONTROL_HAVE', 'CONTROL_GET'):
            raise Reject(M.DENIED, 'W §41: a revoked reader may read only the Control prefix; every other read is refused')
        got, why = None, ''
    except Reject as e:
        got, why = e.code, e.rule
    check_expectation(cid, expect, got, why)
    case = {'id': cid, 'type': 'validation', 'kind': 'session_read', 'description': description,
            'rule': rule_of(why) if got else {'section': rule[0], 'text': rule[1]},
            'inputs': {'resource': node.resource, 'session': session, 'request': request, 'server_extensions': ['identity-01']},
            'context': {'resource_id': hx(RES[node.resource]), **context_of(node),
                        'latest': {'case': node.prefix[-1], 'field': 'record_id', 'in': 'inputs'}}}
    if got:
        case['expected'] = {'valid': False, 'error': {'code': got}}
    else:
        ps = {'read': scope}
        if scope == 'prefix':
            ps['control_head'] = node.prefix[idx]
            ps['records'] = node.prefix[:idx + 1]
            ps['refused_reads'] = ['later Control Records', 'DATA_HAVE', 'DATA_GET', 'KEY_PACKAGE_GET', 'SNAPSHOT_GET', 'presence']
        else:
            ps['control_head'] = node.prefix[-1]
        case['expected'] = {'valid': True, 'post_state': ps}
    add_case(case)


def build_flow_support() -> None:
    """Records, objects and reads that the flow fixtures (IDENTITY-FLOW-FIXTURES-01) step through."""
    group('flow support')
    control('flow.self_register_dev_b_on_j2', 'J2_grant_carol', 9, 'DEV_B', dg('OWNER', C('CERT_B', 'CERT_A')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_B, CERT_A]} by DEV_B on J2: DEV_B registered, DEV_A bound only as an intermediate',
            readable=dg_readable('OWNER', ['CERT_B', 'CERT_A']),
            rule=('LFCP-WIRE-01 §17.4 rules 6 and 9', 'Kind-0 self-registration; the issuer DEV_A is bound with registered = false.'))
    control('flow.reconcile_revoke_pairing_in_x', 'flow.self_register_dev_b_on_j2', 10, 'OWNER', dr('OWNER', 'PAIR_J', 0), 'accept',
            "Reconciliation step 1: I's revocation of (OWNER, PAIR_J), reason 3 propagated as 0", readable=dr_readable('OWNER', 'PAIR_J', 0),
            rule=('IDENTITY-PROFILE-01 §7.1 step 1; LFCP-WIRE-01 §17.5', 'Revocations first; an unbound tombstone, not exposing.'))
    control('flow.reconcile_register_dev_a', 'flow.reconcile_revoke_pairing_in_x', 9, 'OWNER', dg('OWNER', C('CERT_A')), 'accept',
            "Reconciliation step 2: DEV_A, active in I, bound but not registered in X, registered with I's chain [CERT_A]",
            readable=dg_readable('OWNER', ['CERT_A']),
            rule=('IDENTITY-PROFILE-01 §7.1 step 2', 'An intermediate-only binding is not a completed registration.'))
    control('flow.claim_for_root_dave', 'N1_invite_grant', 3, 'INVITE', {0: rid('N1_invite_grant'), 1: P['DAVE'].descriptor(), 2: [1, 2]}, 'accept',
            'A device of DAVE accepts the invitation N1: CAPABILITY_CLAIM naming the root DAVE, signed by INVITE',
            readable={'grant': 'N1_invite_grant', 'claimant': 'DAVE', 'abilities': [1, 2]},
            rule=('LFCP-WIRE-01 §18.1; IDENTITY-PROFILE-01 §7.2', 'The claimant is the root; the claim is signed by the Invitation Principal.'))
    control('flow.self_register_dev_d', 'flow.claim_for_root_dave', 9, 'DEV_D', dg('DAVE', C('CERT_D')), 'accept',
            'DEV_D registers itself: DEVICE_GRANT {DAVE, [CERT_D]} by DEV_D', readable=dg_readable('DAVE', ['CERT_D']),
            rule=('LFCP-WIRE-01 §17.4 rule 6; IDENTITY-PROFILE-01 §7.2 step 1', 'Kind-0 self-registration; DAVE has standing through the claim grant.'))
    package_case('flow.kp_dev_d_to_dave', 'flow.self_register_dev_d', 'DEV_D', 'DAVE', 'flow.self_register_dev_d', 'accept',
                 'DEV_D seals epoch 0 to its root DAVE (same root)', ('LFCP-WIRE-01 §25.2', 'sameRoot(DEV_D, DAVE); DAVE holds data/read from the claim.'))
    read_case('flow.open_as_dave', 'flow.self_register_dev_d', 'DAVE', 'RESOURCE_OPEN', 'accept', 'The root DAVE opens X',
              ('LFCP-WIRE-01 §41', 'holds(DAVE, 1) at the accepted head.'))
    control('flow.revoke_out_of_scope_bridge_in_y', 'Yb1_bridge_out_of_scope', 10, 'BOB', dr('BOB', 'BRIDGE', 0), 'accept',
            'DEVICE_REVOKE {BOB, BRIDGE, 0} by BOB in Y (BRIDGE bound out of scope)', readable=dr_readable('BOB', 'BRIDGE', 0),
            rule=('LFCP-WIRE-01 §17.5', 'An out-of-scope binding never read: not exposing.'))
    control('flow.revoke_suspended_dev_b', 'I9_device_revoke_dev_a', 10, 'OWNER', dr('OWNER', 'DEV_B', 1), 'accept',
            'DEVICE_REVOKE {OWNER, DEV_B, 1} by OWNER on I9 (DEV_B already suspended)', readable=dr_readable('OWNER', 'DEV_B', 1),
            rule=('LFCP-WIRE-01 §17.5', 'An already suspended device no longer reads: not exposing.'))
    control('flow.register_bridge_o_in_x', 'I1_device_grant_dev_a', 9, 'DEV_A', dg('OWNER', C('CERT_SO', 'CERT_A')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_SO, CERT_A]} by DEV_A in X (BRIDGE_O in scope)', readable=dg_readable('OWNER', ['CERT_SO', 'CERT_A']),
            rule=('LFCP-WIRE-01 §17.4 rule 6', 'A kind-1 leaf in scope, by an active managing device of R.'))
    KEYS = ('IDENTITY-PROFILE-01 §7.1 step 3; LFCP-WIRE-01 §25.2', 'The reconciler seals every epoch it holds to every active device of its root, by the same-root rule.')
    package_case('flow.kp_owner_to_dev_r', 'Rd1', 'OWNER', 'DEV_R', 'Rd1', 'accept', 'Key bootstrap: OWNER seals epoch 0 of X to the Read device DEV_R', KEYS)
    package_case('flow.kp_dev_a_to_dev_b_in_i', 'P4_register_dev_b_approved', 'DEV_A', 'DEV_B', 'P4_register_dev_b_approved', 'accept',
                 'Key bootstrap: DEV_A seals epoch 0 of I to DEV_B, registered in I at P4', KEYS)
    package_case('flow.kp_dev_a_to_bridge_o_in_x', 'flow.register_bridge_o_in_x', 'DEV_A', 'BRIDGE_O', 'flow.register_bridge_o_in_x', 'accept',
                 'Key bootstrap: DEV_A seals epoch 0 of X to BRIDGE_O, registered in X', KEYS)
    package_case('flow.kp_dev_a_to_pair_j_in_i', 'P2_pairing_device', 'DEV_A', 'PAIR_J', 'P2_pairing_device', 'accept',
                 'Pairing step 1: DEV_A seals epoch 0 of I to PAIR_J (same root; PAIR_J reads)', KEYS)
    package_case('flow.kp_dev_a_to_pair_j_after_consume', 'P3_consume_for_dev_b', 'DEV_A', 'PAIR_J', 'P3_consume_for_dev_b', (M.DENIED, '§25.2'),
                 'A consumed pairing device receives nothing: a package to PAIR_J at P3')


def rotator_facts(head: str, candidates: list[str]) -> dict:
    """IDENTITY-PROFILE-01 §8.1 on the state at `head`: holds 7 and (holds 6, or every reader is of the candidate's root)."""
    st = NODES[head].state
    readers = sorted(L(p) for p in set(st.roles) | set(st.devices) if st.holds(p, 1))
    out = {}
    for c in candidates:
        pid = P[c].pid
        own = all(st.root_of(P[r].pid if r in P else bytes.fromhex(r)) == st.root_of(pid) for r in readers)
        h6, h7 = st.holds(pid, 6), st.holds(pid, 7)
        out[c] = {'holds_6': h6, 'holds_7': h7, 'every_reader_of_own_root': own, 'rotator': h7 and (h6 or own)}
    return {'readers': readers, 'candidates': out}


def build_review_flows() -> None:
    """Records, objects and facts of the compound flows of IDENTITY-PROFILE-01 §12.3 (review of spec#3)."""
    group('flow support: compound scenarios')
    ACC_DG = ('LFCP-WIRE-01 §17.4', 'Accepted: rules 1 to 9 hold.')
    ACC_DR = ('LFCP-WIRE-01 §17.5', 'Accepted: rules 1 to 5 hold.')
    W2 = ('LFCP-WIRE-01 §26.3 rule 2, §80.1', 'holds(actor, 2) at the referenced Control Head.')
    KP = ('LFCP-WIRE-01 §25.2', 'sameRoot(sender, recipient) or holds(sender, 6); the recipient reads; a closed epoch stays valid.')
    # F14: a frontier with an extra range (W §19, §28.1), in Y.
    unit_case('flow.y_dev_a_seq1', 'Yb1_bridge_out_of_scope', 'DEV_A', 1, None, 'G2_grant_bob_y', 'accept', 'DEV_A writes sequence 1 in Y at G2', W2)
    unit_case('flow.y_dev_a_seq2', 'Yb1_bridge_out_of_scope', 'DEV_A', 2, 'flow.y_dev_a_seq1', 'G2_grant_bob_y', 'accept', 'DEV_A sequence 2 in Y', W2)
    unit_case('flow.y_dev_a_seq4', 'Yb1_bridge_out_of_scope', 'DEV_A', 4, 'flow.y_dev_a_seq2', 'G2_grant_bob_y', 'accept',
              'DEV_A sequence 4 in Y, previous = sequence 2: sequence 3 was reserved and never written; the hole does not block the actor chain', W2)
    fr = {'DEV_A': (2, [[4, 4]])}
    control('flow.y_key_epoch_noncanonical_range', 'Yb1_bridge_out_of_scope', 4, 'DEV_A', key_epoch_body('Y', 1, {'DEV_A': (2, [[3, 4]])}, 0),
            (M.MALFORMED, '§28.1'), 'KEY_EPOCH in Y whose frontier has the range [3, 4] adjacent to contiguous 2 (not canonical)',
            readable={'epoch': 1, 'frontier': {'DEV_A': {'contiguous': 2, 'extra_ranges': [[3, 4]]}}, 'reason': 0})
    control('flow.y_key_epoch_1', 'Yb1_bridge_out_of_scope', 4, 'DEV_A', key_epoch_body('Y', 1, fr, 0), 'accept',
            'KEY_EPOCH in Y by DEV_A: the final frontier of epoch 0 is DEV_A contiguous 2 with the extra range [4, 4], from its verified accepted set',
            readable={'epoch': 1, 'frontier': {'DEV_A': {'contiguous': 2, 'extra_ranges': [[4, 4]]}}, 'reason': 0},
            rule=('LFCP-WIRE-01 §19, §28.1', 'The frontier keeps the accepted range after the hole: {0: DEV_A, 1: 2, 2: [[4, 4]]}.'))
    unit_case('flow.y_dev_a_seq4_after_epoch', 'flow.y_key_epoch_1', 'DEV_A', 4, 'flow.y_dev_a_seq2', 'G2_grant_bob_y', 'accept',
              'Sequence 4 received after the KEY_EPOCH: inside the extra range', ('LFCP-WIRE-01 §19.1, §28.1', 'A closed-epoch unit inside an extra range of the frontier is within it.'))
    unit_case('flow.y_dev_a_seq3_after_epoch', 'flow.y_key_epoch_1', 'DEV_A', 3, 'flow.y_dev_a_seq2', 'G2_grant_bob_y', (M.STALE, '§19.1'),
              'A sequence 3 that arrives after the KEY_EPOCH: in the hole, outside the frontier')
    unit_case('flow.y_dev_a_seq5_after_epoch', 'flow.y_key_epoch_1', 'DEV_A', 5, 'flow.y_dev_a_seq4', 'G2_grant_bob_y', (M.STALE, '§19.1'),
              'Sequence 5 (previous = sequence 4) after the KEY_EPOCH: beyond the frontier')
    # F11: a revoker whose chain passes through the target re-certifies before revoking (X, from I8).
    control('flow.f11_dev_e_revokes_dev_c_unrecertified', 'I8_bridge_grant', 10, 'DEV_E', dr('BOB', 'DEV_C', 2), 'accept',
            'What the pre-check of §8.1 prevents: DEV_E, issued by DEV_C, revokes DEV_C and suspends itself by the cascade',
            readable=dr_readable('BOB', 'DEV_C', 2), rule=ACC_DR, register=False)
    control('flow.f11_recertify_dev_e', 'I8_bridge_grant', 9, 'BOB', dg('BOB', C('CERT_E2')), 'accept',
            'BOB re-certifies DEV_E with [CERT_E2], a chain that avoids DEV_C', readable=dg_readable('BOB', ['CERT_E2']),
            rule=('LFCP-WIRE-01 §17.4 rule 5', 'Same kind, mask and scope; a new leaf certificate ID; issuers become [].'))
    control('flow.f11_dev_e_revokes_dev_c', 'flow.f11_recertify_dev_e', 10, 'DEV_E', dr('BOB', 'DEV_C', 2), 'accept',
            'DEV_E, now issued by BOB, revokes DEV_C and stays active', readable=dr_readable('BOB', 'DEV_C', 2), rule=ACC_DR)
    control('flow.f11_dev_e_retires', 'flow.f11_dev_e_revokes_dev_c', 10, 'DEV_E', dr('BOB', 'DEV_E', 0), 'accept',
            'DEV_E retires itself (reason 0); rotation is left to another installation', readable=dr_readable('BOB', 'DEV_E', 0),
            rule=('LFCP-WIRE-01 §17.5 rule 4', 'D itself when registered and not revoked, reason 0.'))
    # F12: rotation of I with two open sessions, then one closed (I, from P2k).
    control('flow.f12_i_key_epoch_1', 'P2k_pairing_device_k', 4, 'DEV_A', key_epoch_body('I', 1, {'PAIR_J': 1}, 0), 'accept',
            'DEV_A rotates I while PAIR_J and PAIR_K are open: epoch 1, frontier PAIR_J <= 1 (D_pairing_j_in_i)',
            readable={'epoch': 1, 'frontier': {'PAIR_J': 1}, 'reason': 0}, rule=('LFCP-WIRE-01 §19', 'holds(DEV_A, 7) through owner/act in I.'))
    for who in ('OWNER', 'PAIR_J', 'PAIR_K'):
        package_case(f'flow.f12_kp_epoch1_to_{who.lower()}', 'flow.f12_i_key_epoch_1', 'DEV_A', who, 'flow.f12_i_key_epoch_1', 'accept',
                     f'The new DEK of I sealed to {who}', KP, epoch=1)
    control('flow.f12_cancel_j', 'flow.f12_i_key_epoch_1', 10, 'DEV_A', dr('OWNER', 'PAIR_J', 0), 'accept',
            'Then PAIR_J\'s session is cancelled; PAIR_K\'s continues', readable=dr_readable('OWNER', 'PAIR_J', 0), rule=ACC_DR)
    package_case('flow.f12_kp_epoch1_to_pair_j_after_cancel', 'flow.f12_cancel_j', 'DEV_A', 'PAIR_J', 'flow.f12_cancel_j', (M.DENIED, '§25.2'),
                 'A cancelled pairing device receives nothing', epoch=1)
    unit_case('flow.f12_pair_k_writes_request', 'flow.f12_cancel_j', 'PAIR_K', 1, None, 'flow.f12_cancel_j', 'accept',
              'PAIR_K writes its request in epoch 1 after J\'s cancellation', W2, epoch=1)
    # Rotator test of §8.1 on concrete states.
    control('flow.f12_register_r7', 'I8_bridge_grant', 9, 'BOB', dg('BOB', C('CERT_R7')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_R7]} by BOB: a device of BOB with 7 and without 6', readable=dg_readable('BOB', ['CERT_R7']), rule=ACC_DG)
    control('flow.f12_register_r6', 'flow.f12_register_r7', 9, 'BOB', dg('BOB', C('CERT_R6')), 'accept',
            'DEVICE_GRANT {BOB, [CERT_R6]} by BOB: a device of BOB with 6 and without 7', readable=dg_readable('BOB', ['CERT_R6']), rule=ACC_DG)
    control('flow.f12_register_r7o_in_i', 'P2k_pairing_device_k', 9, 'OWNER', dg('OWNER', C('CERT_R7O')), 'accept',
            'DEVICE_GRANT {OWNER, [CERT_R7O]} by OWNER in I: a device of OWNER with 7 and without 6', readable=dg_readable('OWNER', ['CERT_R7O']), rule=ACC_DG)
    tables = {'X at flow.f12_register_r6 (CAROL is a foreign reader)': rotator_facts('flow.f12_register_r6', ['DEV_R7', 'DEV_R6', 'BOB', 'OWNER', 'DEV_A']),
              'I at flow.f12_register_r7o_in_i (every reader is of OWNER)': rotator_facts('flow.f12_register_r7o_in_i', ['DEV_R7O', 'DEV_A'])}
    add_case({'id': 'flow.rotator_test', 'type': 'behavioral', 'kind': 'rotator_test',
              'description': 'The rotator test of IDENTITY-PROFILE-01 §8.1 for concrete candidates on concrete heads',
              'rule': {'section': 'IDENTITY-PROFILE-01 §8.1; LFCP-WIRE-01 §19, §25.2', 'text': 'A is the rotator only when holds(A, 7) and A can seal the new DEK to every reader of the new head: holds(A, 6), or every reader is of A\'s root.'},
              'inputs': {'heads': {'X': 'flow.f12_register_r6', 'I': 'flow.f12_register_r7o_in_i'}},
              'expected': {'tables': tables},
              'assertions': ['DEV_R7 (7 without 6) in X is not the rotator: CAROL is not of its root, so X is awaiting rotation.',
                             'DEV_R6 (6 without 7) is not the rotator.', 'BOB, holding 6 and 7 through J1, is the rotator of X.',
                             'DEV_R7O in I is the rotator with 7 alone: every reader of I is of OWNER.']})
    # F13: a second rotator commits the next epoch (X, after K1).
    control('flow.f13_second_rotator_epoch_2', 'K1_key_epoch', 4, 'BOB', key_epoch_body('X', 2, {}, 2), 'accept',
            'After the first rotator crashed before any package of epoch 1, BOB commits epoch 2 with a fresh DEK', readable={'epoch': 2, 'frontier': {}, 'reason': 2},
            rule=('IDENTITY-PROFILE-01 §9.2 (awaiting key holder); LFCP-WIRE-01 §19', 'Another rotator MAY commit the next KEY_EPOCH after a bounded wait; holds(BOB, 7).'))
    # F08: pairing in an Identity Resource already rotated to epoch 1 (I, from P1).
    unit_case('flow.pl_root_unit_1', 'P1_device_grant_dev_a_i', 'OWNER', 1, None, 'P1_device_grant_dev_a_i', 'accept',
              "The root's Data Unit with actor sequence 1 in I (it carries the initial change, profile case change.C0_initial)", W2)
    control('flow.pl_key_epoch_1', 'P1_device_grant_dev_a_i', 4, 'DEV_A', key_epoch_body('I', 1, {'OWNER': 1}, 0), 'accept',
            'I rotated from epoch 0 to epoch 1 before the session', readable={'epoch': 1, 'frontier': {'OWNER': 1}, 'reason': 0},
            rule=('LFCP-WIRE-01 §19', 'holds(DEV_A, 7) through owner/act in I.'))
    control('flow.pl_pairing_device_l', 'flow.pl_key_epoch_1', 9, 'DEV_A', dg('OWNER', C('CERT_JL', 'CERT_A')), 'accept',
            'DEV_A creates the pairing device PAIR_L', readable=dg_readable('OWNER', ['CERT_JL', 'CERT_A']), rule=ACC_DG)
    for e in (0, 1):
        package_case(f'flow.pl_kp_epoch{e}_to_pair_l', 'flow.pl_pairing_device_l', 'DEV_A', 'PAIR_L', 'flow.pl_pairing_device_l', 'accept',
                     f'DEV_A seals the DEK of epoch {e} of I to PAIR_L', KP, epoch=e)
    unit_case('flow.pl_pair_l_request', 'flow.pl_pairing_device_l', 'PAIR_L', 1, None, 'flow.pl_pairing_device_l', 'accept',
              'B writes its request as PAIR_L in epoch 1', W2, epoch=1, text='request of DEV_B, first installation')
    unit_case('flow.pl_pair_l_request_second_install', 'flow.pl_pairing_device_l', 'PAIR_L', 1, None, 'flow.pl_pairing_device_l',
              ('ACTOR_EQUIVOCATION', '§26.2'), 'A second installation given the same link also writes PAIR_L sequence 1: equivocation, both units excluded',
              epoch=1, text='request of DEV_X, second installation', equivocates_with='flow.pl_pair_l_request')
    unit_case('flow.pl_pair_l_reuse_seq2', 'flow.pl_pairing_device_l', 'PAIR_L', 2, 'flow.pl_pair_l_request', 'flow.pl_pairing_device_l', 'accept',
              'Sequential reuse: the second installation sees the first unit and writes PAIR_L sequence 2', W2, epoch=1)
    control('flow.pl_consume_l', 'flow.pl_pairing_device_l', 10, 'DEV_A', dr('OWNER', 'PAIR_L', 3, CERTS['CERT_B']['digest']), 'accept',
            'Phase 1: DEVICE_REVOKE {OWNER, PAIR_L, 3, 4: digest(CERT_B)}', readable=dr_readable('OWNER', 'PAIR_L', 3, 'CERT_B'), rule=ACC_DR)
    control('flow.pl_register_dev_b', 'flow.pl_consume_l', 9, 'DEV_A', dg('OWNER', C('CERT_B', 'CERT_A'), 'PAIR_L'), 'accept',
            'Phase 2: DEVICE_GRANT {OWNER, [CERT_B, CERT_A], 2: PAIR_L}', readable=dg_readable('OWNER', ['CERT_B', 'CERT_A'], 'PAIR_L'),
            rule=('LFCP-WIRE-01 §17.4 rule 7', 'The consumed approval of PAIR_L names this leaf.'))
    for e in (0, 1):
        package_case(f'flow.pl_kp_epoch{e}_to_dev_b', 'flow.pl_register_dev_b', 'DEV_A', 'DEV_B', 'flow.pl_register_dev_b', 'accept',
                     f'DEV_A seals the DEK of epoch {e} of I to DEV_B', KP, epoch=e)
    # F08: R at 31 live devices in I: the pairing device takes the 32nd place; the consume frees it.
    fill = record_set('owner_bindings_30_in_i', 'P1_device_grant_dev_a_i', [(9, 'OWNER', dg('OWNER', C(f'CERT_{lab}'))) for lab in LIMIT_OWNER],
                      'DEVICE_GRANT {OWNER, [CERT_LIMIT_OWNER_k]} by OWNER, k = 01..30, on P1 in I: 31 live Principals bound to OWNER')
    control('flow.p31_pairing_device', fill, 9, 'DEV_A', dg('OWNER', C('CERT_JM', 'CERT_A')), 'accept',
            'OWNER has 31 live devices in I: PAIR_M takes the 32nd place', readable=dg_readable('OWNER', ['CERT_JM', 'CERT_A']),
            rule=('LFCP-WIRE-01 §17.4 rule 8', 'The live Principals bound to R reach 32, not above.'))
    control('flow.p31_second_pairing_refused', 'flow.p31_pairing_device', 9, 'DEV_A', dg('OWNER', C('CERT_JM2', 'CERT_A')), (M.DENIED, '§17.4 rule 8'),
            'At 32 live devices no further pairing device: no link until a device is revoked', readable=dg_readable('OWNER', ['CERT_JM2', 'CERT_A']))
    control('flow.p31_consume', 'flow.p31_pairing_device', 10, 'DEV_A', dr('OWNER', 'PAIR_M', 3, CERTS['CERT_B']['digest']), 'accept',
            'The consume of PAIR_M frees its place', readable=dr_readable('OWNER', 'PAIR_M', 3, 'CERT_B'), rule=ACC_DR)
    control('flow.p31_register_dev_b', 'flow.p31_consume', 9, 'DEV_A', dg('OWNER', C('CERT_B', 'CERT_A'), 'PAIR_M'), 'accept',
            'DEV_B takes the 32nd place', readable=dg_readable('OWNER', ['CERT_B', 'CERT_A'], 'PAIR_M'),
            rule=('LFCP-WIRE-01 §17.4 rules 7 and 8', 'A revoked binding no longer counts.'))
    # F08: 40 sessions created and cancelled one after the other, then a session completes.
    items = []
    for lab in PAIR_S:
        items += [(9, 'DEV_A', dg('OWNER', C(f'CERT_{lab}', 'CERT_A'))), (10, 'DEV_A', dr('OWNER', lab, 0))]
    fill = record_set('forty_cancelled_sessions_in_i', 'P1_device_grant_dev_a_i', items,
                      'For k = 01..40, on P1 in I: DEVICE_GRANT {OWNER, [CERT_PAIR_S_k, CERT_A]} by DEV_A, then DEVICE_REVOKE {OWNER, PAIR_S_k, 0} by DEV_A')
    control('flow.p40_pairing_device', fill, 9, 'DEV_A', dg('OWNER', C('CERT_JM', 'CERT_A')), 'accept',
            'After 40 cancelled sessions a new session is created', readable=dg_readable('OWNER', ['CERT_JM', 'CERT_A']),
            rule=('LFCP-WIRE-01 §17.4 rule 8', 'Revoked pairing devices free their places.'))
    control('flow.p40_consume', 'flow.p40_pairing_device', 10, 'DEV_A', dr('OWNER', 'PAIR_M', 3, CERTS['CERT_B']['digest']), 'accept',
            'Phase 1 of the 41st session', readable=dr_readable('OWNER', 'PAIR_M', 3, 'CERT_B'), rule=ACC_DR)
    control('flow.p40_register_dev_b', 'flow.p40_consume', 9, 'DEV_A', dg('OWNER', C('CERT_B', 'CERT_A'), 'PAIR_M'), 'accept',
            'Phase 2 of the 41st session completes', readable=dg_readable('OWNER', ['CERT_B', 'CERT_A'], 'PAIR_M'), rule=ACC_DG)
    # F09: a service device bound in I with C0 = CERT_SO (digest d, P3s), its issuer revoked, re-certified as C1 = CERT_SO_R.
    control('flow.f09_revoke_issuer_in_i', 'P4s_bind_bridge_o', 10, 'OWNER', dr('OWNER', 'DEV_A', 1), 'accept',
            "C0's issuer DEV_A revoked in I", readable=dr_readable('OWNER', 'DEV_A', 1), rule=ACC_DR)
    control('flow.f09_recertify_c1_in_i', 'flow.f09_revoke_issuer_in_i', 9, 'OWNER', dg('OWNER', C('CERT_SO_R')), 'accept',
            'The root re-certifies BRIDGE_O as C1 = CERT_SO_R (same kind, mask and scope): bound in I, not registered',
            readable=dg_readable('OWNER', ['CERT_SO_R']), rule=ACC_DG)
    control('flow.f09_x_register_c1', 'I1_device_grant_dev_a', 9, 'OWNER', dg('OWNER', C('CERT_SO_R')), 'accept',
            'Candidate X where C0 was never accepted: reconciliation registers C1', readable=dg_readable('OWNER', ['CERT_SO_R']), rule=ACC_DG)
    control('flow.f09_x_recertify_c1', 'flow.register_bridge_o_in_x', 9, 'OWNER', dg('OWNER', C('CERT_SO_R')), 'accept',
            'Candidate X where C0 was registered first: re-certified there as C1', readable=dg_readable('OWNER', ['CERT_SO_R']),
            rule=('LFCP-WIRE-01 §17.4 rule 5', 'A new leaf certificate ID with the same kind, mask and scope.'))
    package_case('flow.f09_kp_to_bridge_o_after_recert', 'flow.f09_x_recertify_c1', 'DEV_A', 'BRIDGE_O', 'flow.f09_x_recertify_c1', 'accept',
                 'BRIDGE_O receives the DEK of X: with the certificate it is ready', KP)
    control('flow.f09_x_register_cstar', 'I1_device_grant_dev_a', 9, 'OWNER', dg('OWNER', C('CERT_SO_XY')), 'accept',
            'Another issuer registers C* = CERT_SO_XY (scope [X, Y], another digest) in a candidate where BRIDGE_O was unbound',
            readable=dg_readable('OWNER', ['CERT_SO_XY']), rule=ACC_DG)
    # F06: two managers revoke DEV_B on one head with different reasons.
    control('flow.f06_owner_revokes_dev_b', 'I2_device_grant_self_dev_b', 10, 'OWNER', dr('OWNER', 'DEV_B', 1), 'accept',
            'OWNER revokes DEV_B with reason 1 on I2; the coordinator commits it first', readable=dr_readable('OWNER', 'DEV_B', 1), rule=ACC_DR)
    control('flow.f06_dev_a_stale_proposal', 'I2_device_grant_self_dev_b', 10, 'DEV_A', dr('OWNER', 'DEV_B', 2), 'accept',
            'DEV_A proposed DEVICE_REVOKE {OWNER, DEV_B, 2} on the same head I2: valid there, refused by the coordinator with CONTROL_HEAD_MISMATCH',
            readable=dr_readable('OWNER', 'DEV_B', 2), rule=ACC_DR, register=False)
    control('flow.f06_dev_a_fresh_revoke', 'flow.f06_owner_revokes_dev_b', 10, 'DEV_A', dr('OWNER', 'DEV_B', 2), (M.DENIED, '§17.5 rule 5'),
            'After synchronising, the same intent proposed fresh on the new head', readable=dr_readable('OWNER', 'DEV_B', 2))
    # F08: a second manager and a wrong digest on the rotated Identity Resource.
    control('flow.pl_second_manager_consume', 'flow.pl_consume_l', 10, 'OWNER', dr('OWNER', 'PAIR_L', 3, CERTS["CERT_B'"]['digest']), (M.DENIED, '§17.5 rule 5'),
            "A second manager approving another request of PAIR_L's session after the consume", readable=dr_readable('OWNER', 'PAIR_L', 3, "CERT_B'"))
    control('flow.pl_register_wrong_digest', 'flow.pl_consume_l', 9, 'DEV_A', dg('OWNER', C("CERT_B'", 'CERT_A'), 'PAIR_L'), (M.DENIED, '§17.4 rule 7'),
            "A phase-2 record whose leaf is CERT_B' (another digest)", readable=dg_readable('OWNER', ["CERT_B'", 'CERT_A'], 'PAIR_L'))
    # §23.3 without field 2: the commit signed by someone other than the new owner.
    build_transfer('T_signer', 'I8_bridge_grant', 'OWNER', 'BOB', 'BOB', None, emit=False)
    control('transfer_commit_signed_by_other_than_new_owner', 'I8_bridge_grant', 6, 'CAROL', transfer_body('T_signer'), (M.DENIED, '§23.3 item 5'),
            'Offer by OWNER naming BOB, accept by BOB, no field 2, commit issued and signed by CAROL',
            readable={'offer': 'by OWNER, new owner BOB', 'accept': 'by BOB'})


def build_data_plane() -> None:
    group('ID-04 Data Units')
    W2 = ('LFCP-WIRE-01 §26.3 rule 2, §80.1', 'holds(actor, 2) at the referenced Control Head.')
    unit_case('D_dev_a_seq1', 'I1_device_grant_dev_a', 'DEV_A', 1, None, 'I1_device_grant_dev_a', 'accept',
              'DEV_A, actor sequence 1, control_ref I1', W2)
    unit_case('D_dev_b_seq1', 'I2_device_grant_self_dev_b', 'DEV_B', 1, None, 'I2_device_grant_self_dev_b', 'accept',
              'DEV_B, actor sequence 1, control_ref I2', W2)
    unit_case('D_dev_a_before_registration', 'J2_grant_carol', 'DEV_A', 1, None, 'J2_grant_carol', (M.MISSING, '§26.3'),
              'DEV_A with control_ref J2 (the chain through J2 does not describe DEV_A)')
    unit_case('D_dev_b_at_i1', 'I1_device_grant_dev_a', 'DEV_B', 1, None, 'I1_device_grant_dev_a', (M.MISSING, '§26.3'),
              'DEV_B with control_ref I1')
    unit_case('D_dev_a_after_revoke', 'I9_device_revoke_dev_a', 'DEV_A', 2, 'D_dev_a_seq1', 'I9_device_revoke_dev_a', (M.DENIED, '§26.3 rule 2'),
              'DEV_A, sequence 2, control_ref I9')
    unit_case('D_dev_a_old_head_after_revoke', 'I9_device_revoke_dev_a', 'DEV_A', 2, 'D_dev_a_seq1', 'I1_device_grant_dev_a', 'accept',
              'DEV_A, sequence 2, control_ref I1, epoch 0 open, latest I9',
              ('LFCP-WIRE-01 §26.3, §81', 'A unit by a revoked device that references a head before the revocation is evaluated at that head.'))
    unit_case('D_dev_a_beyond_epoch_cutoff', 'K1_key_epoch', 'DEV_A', 2, 'D_dev_a_seq1', 'I1_device_grant_dev_a', (M.STALE, '§19.1'),
              'The same unit as D_dev_a_old_head_after_revoke with latest K1 (frontier DEV_A <= 1)')
    unit_case('D_dev_b_suspended', 'I9_device_revoke_dev_a', 'DEV_B', 2, 'D_dev_b_seq1', 'I9_device_revoke_dev_a', (M.DENIED, '§26.3 rule 2'),
              'DEV_B, sequence 2, control_ref I9 (suspended by the cascade)')
    unit_case('D_dev_b_recertified', 'I10_recertify_dev_b', 'DEV_B', 2, 'D_dev_b_seq1', 'I10_recertify_dev_b', 'accept',
              'DEV_B, sequence 2, control_ref I10 (re-certified)', W2)
    unit_case('D_read_only_device_writes', 'Rd1', 'DEV_R', 1, None, 'Rd1', (M.DENIED, '§26.3 rule 2'), 'DEV_R, control_ref Rd1 (2 not in its mask)')
    unit_case('D_bridge_writes_x', 'I8_bridge_grant', 'BRIDGE', 1, None, 'I8_bridge_grant', 'accept', 'BRIDGE in X at I8', W2)
    unit_case('D_bridge_in_y', 'Yb1_bridge_out_of_scope', 'BRIDGE', 1, None, 'Yb1_bridge_out_of_scope', (M.DENIED, '§26.3 rule 2'),
              'BRIDGE in Y at Yb1 (bound, not registered)')
    unit_case('D_dev_c_without_standing', 'I11_revoke_root_grant_bob', 'DEV_C', 1, None, 'I11_revoke_root_grant_bob', (M.DENIED, '§26.3 rule 2'),
              'DEV_C, control_ref I11 (BOB without standing)')
    unit_case('D_dev_c_regranted', 'I12_regrant_bob', 'DEV_C', 1, None, 'I12_regrant_bob', 'accept', 'DEV_C, control_ref I12', W2)
    unit_case('D_pairing_j_in_i', 'P2_pairing_device', 'PAIR_J', 1, None, 'P2_pairing_device', 'accept',
              'PAIR_J in I at P2', ('LFCP-WIRE-01 §80.1', 'holds(PAIR_J, 2): 2 in its mask and its root owns I.'))
    unit_case('D_pairing_j_in_i.consumed', 'P3_consume_for_dev_b', 'PAIR_J', 2, 'D_pairing_j_in_i', 'P3_consume_for_dev_b', (M.DENIED, '§26.3 rule 2'),
              'PAIR_J in I at P3 (consumed)')
    unit_case('D_bridge_o_in_i', 'P4s_bind_bridge_o', 'BRIDGE_O', 1, None, 'P4s_bind_bridge_o', (M.DENIED, '§26.3 rule 2'),
              'BRIDGE_O in I at P4s (bound, not registered)')

    group('ID-04 Key Packages')
    KP = ('LFCP-WIRE-01 §25.2', 'holds(sender, 6) or sameRoot(sender, recipient); holds(recipient, 1) or the invitation exception.')
    package_case('KP_owner_to_dev_b', 'I8_bridge_grant', 'OWNER', 'DEV_B', 'I8_bridge_grant', 'accept',
                 'OWNER to DEV_B at I8 (the owner holds 6; DEV_B reads: 1 in its mask, its root owns X)', KP)
    package_case('KP_dev_a_to_dev_b', 'I8_bridge_grant', 'DEV_A', 'DEV_B', 'I8_bridge_grant', 'accept', 'DEV_A to DEV_B at I8', KP)
    package_case('KP_dev_b_to_owner', 'I8_bridge_grant', 'DEV_B', 'OWNER', 'I8_bridge_grant', 'accept', 'DEV_B to OWNER at I8 (same root)', KP)
    package_case('KP_dev_b_to_dev_a', 'I8_bridge_grant', 'DEV_B', 'DEV_A', 'I8_bridge_grant', 'accept', 'DEV_B to DEV_A at I8 (same root)', KP)
    package_case('KP_dev_a_to_carol', 'I8_bridge_grant', 'DEV_A', 'CAROL', 'I8_bridge_grant', 'accept', 'DEV_A to CAROL at I8 (holds(DEV_A, 6) through 13)', KP)
    package_case('KP_dev_b_to_carol', 'I8_bridge_grant', 'DEV_B', 'CAROL', 'I8_bridge_grant', (M.DENIED, '§25.2'), 'DEV_B to CAROL at I8 (no 6, not same root)')
    package_case('KP_dev_c_to_carol', 'I8_bridge_grant', 'DEV_C', 'CAROL', 'I8_bridge_grant', (M.DENIED, '§25.2'), 'DEV_C to CAROL at I8 (6 not in its mask)')
    package_case('KP_bob_to_carol', 'I8_bridge_grant', 'BOB', 'CAROL', 'I8_bridge_grant', 'accept', 'BOB to CAROL at I8 (key/distribute through J1)', KP)
    package_case('KP_dev_c_to_bridge', 'I8_bridge_grant', 'DEV_C', 'BRIDGE', 'I8_bridge_grant', 'accept', 'DEV_C to BRIDGE at I8 (same root)', KP)
    package_case('KP_bridge_to_dev_c', 'I8_bridge_grant', 'BRIDGE', 'DEV_C', 'I8_bridge_grant', 'accept', 'BRIDGE to DEV_C at I8 (same root)', KP)
    package_case('KP_dev_e_to_dev_c', 'I8_bridge_grant', 'DEV_E', 'DEV_C', 'I8_bridge_grant', 'accept', 'DEV_E to DEV_C at I8 (same root)', KP)
    package_case('KP_bridge_to_carol', 'I8_bridge_grant', 'BRIDGE', 'CAROL', 'I8_bridge_grant', (M.DENIED, '§25.2'), 'BRIDGE to CAROL at I8')
    package_case('KP_owner_to_dev_a_revoked', 'I9_device_revoke_dev_a', 'OWNER', 'DEV_A', 'I9_device_revoke_dev_a', (M.DENIED, '§25.2'),
                 'OWNER to DEV_A at I9 (revoked: does not read)')
    package_case('KP_owner_to_dev_b_suspended', 'I9_device_revoke_dev_a', 'OWNER', 'DEV_B', 'I9_device_revoke_dev_a', (M.DENIED, '§25.2'),
                 'OWNER to DEV_B at I9 (suspended: does not read)')
    package_case('KP_dev_b_suspended_to_owner', 'I9_device_revoke_dev_a', 'DEV_B', 'OWNER', 'I9_device_revoke_dev_a', (M.DENIED, '§25.2'),
                 'DEV_B to OWNER at I9 (a suspended sender qualifies for nothing)')
    package_case('KP_dev_c_to_dev_e_no_standing', 'I11_revoke_root_grant_bob', 'DEV_C', 'DEV_E', 'I11_revoke_root_grant_bob', (M.DENIED, '§25.2'),
                 'DEV_C to DEV_E at I11')
    package_case('KP_owner_to_dev_c_no_standing', 'I11_revoke_root_grant_bob', 'OWNER', 'DEV_C', 'I11_revoke_root_grant_bob', (M.DENIED, '§25.2'),
                 'OWNER to DEV_C at I11')
    package_case('KP_owner_to_bob_no_read', 'I11_revoke_root_grant_bob', 'OWNER', 'BOB', 'I11_revoke_root_grant_bob', (M.DENIED, '§25.2'),
                 'OWNER to BOB at I11')
    package_case('KP_at_old_head', 'I9_device_revoke_dev_a', 'DEV_A', 'DEV_B', 'I2_device_grant_self_dev_b', 'accept',
                 'DEV_A to DEV_B, epoch 0, head I2, received after I9 (authorized at its head)', KP)
    package_case('KP_epoch_unknown_at_head', 'I8_bridge_grant', 'OWNER', 'DEV_B', 'I8_bridge_grant', (M.MISSING, '§25.2'),
                 'OWNER to DEV_B, epoch 1, head I8', epoch=1)
    package_case('KP_to_device_with_mask_11', 'KP_to_device_with_mask_11.register_without_read', 'OWNER', 'DEV_K11',
                 'KP_to_device_with_mask_11.register', 'accept',
                 'OWNER to DEV_K11 (mask {1,2,11}; BOB holds J1 and an invitation grant): authorized through data/read only',
                 ('LFCP-WIRE-01 §80.1, §25.2', 'holds(DEV_K11, 11) is false; holds(DEV_K11, 1) is true; the invitation exception never applies to a device.'))
    package_case('KP_to_device_with_mask_11.without_read', 'KP_to_device_with_mask_11.register_without_read', 'OWNER', 'DEV_K11W',
                 'KP_to_device_with_mask_11.register_without_read', (M.DENIED, '§25.2'),
                 'OWNER to DEV_K11W (mask {2,11}): 11 confers no reading and no invitation exception')
    package_case('KP_to_owner_acting_device_with_mask_11', 'KP_to_owner_acting_device_with_mask_11.register', 'DEV_A', 'DEV_K13',
                 'KP_to_owner_acting_device_with_mask_11.register', 'accept',
                 'DEV_A to DEV_K13 (mask {1,2,11,13}) in X, owned by OWNER',
                 ('LFCP-WIRE-01 §80.1', 'holds(DEV_K13, 11) is false; direct(OWNER, 11) is true and consumed by nothing; the package is authorized through holds(DEV_K13, 1).'))
    add_holds_facts()
    build_matrix()

    group('ID-04 Snapshots')
    snapshot_case('SNAP_by_dev_a', 'I1_device_grant_dev_a', 'DEV_A', 'I1_device_grant_dev_a', 'accept', 'Snapshot by DEV_A at I1',
                  ('LFCP-WIRE-01 §29.2, §80.1', 'holds(DEV_A, 3) through owner/act.'))
    snapshot_case('SNAP_by_bridge', 'I8_bridge_grant', 'BRIDGE', 'I8_bridge_grant', (M.DENIED, '§29.2'), 'Snapshot by BRIDGE at I8 (3 not in its mask)')

    group('ID-04 Session')
    OPEN = ('LFCP-WIRE-01 §41, §80.1', 'holds(session, 1) at the accepted head.')
    read_case('OPEN_as_dev_b.I2', 'I2_device_grant_self_dev_b', 'DEV_B', 'RESOURCE_OPEN', 'accept', 'RESOURCE_OPEN as DEV_B, accepted head I2', OPEN)
    read_case('OPEN_as_dev_b.I9', 'I9_device_revoke_dev_a', 'DEV_B', 'RESOURCE_OPEN', (M.DENIED, '§41'),
              'RESOURCE_OPEN as DEV_B, accepted head I9 (suspended, no DEVICE_REVOKE names DEV_B)')
    read_case('OPEN_as_dev_b.I10', 'I10_recertify_dev_b', 'DEV_B', 'RESOURCE_OPEN', 'accept', 'RESOURCE_OPEN as DEV_B, accepted head I10', OPEN)
    PREFIX = ('LFCP-WIRE-01 §41', 'Control read for a revoked reader: the prefix through the first record that revoked it; every other read refused.')
    read_case('CONTROL_GET_by_revoked_reader', 'I10_recertify_dev_b', 'DEV_A', 'CONTROL_GET', 'accept',
              'Session DEV_A, latest I10, identity-01 server: records J0 to I9; CONTROL_HAVE answers head I9', PREFIX)
    read_case('CONTROL_GET_by_consumed_pairing', 'P4_register_dev_b_approved', 'PAIR_J', 'CONTROL_GET', 'accept',
              'Session PAIR_J, latest P4: records P0 to P3', PREFIX)
    read_case('CONTROL_GET_by_intermediate_only', 'V2_revoke_dev_c', 'DEV_C', 'CONTROL_GET', (M.DENIED, '§41'),
              'Session DEV_C at V2 (bound only as an intermediate)')
    read_case('CONTROL_GET_by_unbound_tombstoned', 'device_revoke_unbound', 'DEV_X', 'CONTROL_GET', (M.DENIED, '§41'),
              'Session DEV_X after device_revoke_unbound')
    read_case('CONTROL_GET_by_never_reader', 'W2', 'DEV_W', 'CONTROL_GET', (M.DENIED, '§41'), 'Session DEV_W at W2 (never held data/read)')
    read_case('CONTROL_GET_by_root_without_standing', 'I11_revoke_root_grant_bob', 'DEV_C', 'CONTROL_GET', (M.DENIED, '§41'),
              'Session DEV_C at I11 (no DEVICE_REVOKE)')
    read_case('DATA_GET_by_revoked_session', 'I10_recertify_dev_b', 'DEV_A', 'DATA_GET', (M.DENIED, '§41'),
              'Session DEV_A, latest I10: DATA_GET is refused (only the Control prefix is readable)')
    # Uploads are checked by object (W §41, §84).
    UP = ('LFCP-WIRE-01 §41, §84', 'Uploads are not reads: the object is checked as from its author, whichever session uploads it.')
    unit_case('DATA_PUT_by_revoked_session_foreign_unit', 'I10_recertify_dev_b', 'DEV_B', 2, 'D_dev_b_seq1', 'I10_recertify_dev_b', 'accept',
              'Session DEV_A (revoked at I9) uploads D_dev_b_recertified, a valid unit of DEV_B at I10', UP)
    package_case('KEY_PACKAGE_PUT_by_revoked_session_foreign_package', 'I10_recertify_dev_b', 'OWNER', 'DEV_B', 'I8_bridge_grant', 'accept',
                 'Session DEV_A uploads a package OWNER to DEV_B at I8 (the bytes of KP_owner_to_dev_b are re-derived for this case)', UP)
    unit_case('DATA_PUT_by_revoked_session_own_old_head_within_cutoff', 'I10_recertify_dev_b', 'DEV_A', 2, 'D_dev_a_seq1', 'I1_device_grant_dev_a',
              'accept', "Session DEV_A uploads its own unit at the old head I1 (epoch 0 still open at I10)", UP)
    unit_case('DATA_PUT_by_revoked_session_own_beyond_cutoff', 'K1_key_epoch', 'DEV_A', 2, 'D_dev_a_seq1', 'I1_device_grant_dev_a',
              (M.STALE, '§19.1'), 'Session DEV_A uploads its own unit at I1 after K1 closed epoch 0 at DEV_A <= 1')
    for cid in ('DATA_PUT_by_revoked_session_foreign_unit', 'KEY_PACKAGE_PUT_by_revoked_session_foreign_package',
                'DATA_PUT_by_revoked_session_own_old_head_within_cutoff', 'DATA_PUT_by_revoked_session_own_beyond_cutoff'):
        CASE_BY_ID[cid]['inputs']['session'] = 'DEV_A'
        CASE_BY_ID[cid]['kind'] = 'session_upload'
        CASE_BY_ID[cid]['inputs']['request'] = 'KEY_PACKAGE_PUT' if cid.startswith('KEY') else 'DATA_PUT'
    ready = base.wire_msg(1, base.msgid('READY-IDENTITY-01'), {0: 'lfcp-1', 1: base.SERVER_ID, 2: 1048576, 3: 1, 4: 30000, 5: ['identity-01']},
                          correlation=base.msgid('AUTH'))
    add_case({'id': 'READY_identity_01', 'type': 'bytes', 'kind': 'wire_message',
              'description': 'READY with field 5 ["identity-01"]',
              'rule': {'section': 'LFCP-WIRE-01 §37', 'text': 'Field 5 lists the server extensions; identity-01 announces the identity rules.'},
              'inputs': {'message_type': 'READY', 'message_id': hx(base.msgid('READY-IDENTITY-01')), 'correlation': hx(base.msgid('AUTH')),
                         'wire_profile': 'lfcp-1', 'server_id': hx(base.SERVER_ID), 'max_message_bytes': 1048576,
                         'durability': 1, 'heartbeat_ms': 30000, 'extension': 'identity-01'},
              'expected': {'message_cbor': hx(ready)}})


MATRIX_PRINCIPALS = ['OWNER', 'BOB', 'CAROL', 'INVITE', 'DAVE', 'DEV_A', 'DEV_A2', 'DEV_B', 'DEV_R', 'DEV_W', 'DEV_X',
                     'PAIR_J', 'BRIDGE_O', 'DEV_C', 'DEV_E', 'DEV_F', 'BRIDGE']


def build_matrix() -> None:
    table = {}
    for head in ('I8_bridge_grant', 'I9_device_revoke_dev_a', 'I11_revoke_root_grant_bob', 'I13_owner_expels_dev_c'):
        st = NODES[head].state
        rows = {}
        for s in MATRIX_PRINCIPALS:
            row = {}
            for r in MATRIX_PRINCIPALS:
                if P[s].pid not in st.descriptors:
                    row[r] = M.MISSING
                    continue
                try:
                    M.decide_package(st, P[s].pid, P[r].pid)
                    row[r] = 'accept'
                except Reject as e:
                    row[r] = e.code
            rows[s] = row
        table[head.split('_')[0]] = rows
    add_case({'id': 'KP_matrix', 'type': 'behavioral', 'kind': 'key_package_matrix',
              'description': 'Every (sender, recipient) pair of the fixture Principals at heads I8, I9, I11 and I13, epoch 0, in X',
              'rule': {'section': 'LFCP-WIRE-01 §25.2, §80.1',
                       'text': 'A package is accepted when holds(sender, 6) or sameRoot(sender, recipient), and holds(recipient, 1) or the invitation exception; a sender the chain does not describe is MISSING_DEPENDENCY.'},
              'inputs': {'resource': 'X', 'epoch': 0, 'heads': {k: v for k, v in zip(('I8', 'I9', 'I11', 'I13'),
                         ('I8_bridge_grant', 'I9_device_revoke_dev_a', 'I11_revoke_root_grant_bob', 'I13_owner_expels_dev_c'))},
                         'principals': MATRIX_PRINCIPALS},
              'expected': {'outcome_by_head_sender_recipient': table},
              'assertions': ['Each cell is the outcome of a validly signed Key Package from the row Principal to the column Principal whose control head is the named head; cells are decisions, not bytes.',
                             'The cases KP_* above give exact bytes for selected cells; every one of them agrees with this table.']})
    for c in CASES:
        if c['kind'] == 'key_package' and c['context'].get('head') and c['inputs']['epoch'] == 0 and c['inputs']['resource'] == 'X':
            head = c['context']['head']['case'].split('_')[0]
            if head in table and c['inputs']['sender'] in MATRIX_PRINCIPALS and c['inputs']['recipient'] in MATRIX_PRINCIPALS:
                cell = table[head][c['inputs']['sender']][c['inputs']['recipient']]
                got = 'accept' if c['expected']['valid'] else c['expected']['error']['code']
                if cell != got:
                    raise SystemExit(f'KP_matrix disagrees with {c["id"]}: {cell} vs {got}')


QUERY_HEADS = ('I2_device_grant_self_dev_b', 'I9_device_revoke_dev_a', 'I11_revoke_root_grant_bob', 'I13_owner_expels_dev_c')


def add_holds_facts() -> None:
    """Facts behind the ability-11 cases and the rootOf tables (IDENTITY-PROFILE-01 §12.2 root_of_corpus)."""
    st = NODES['KP_to_device_with_mask_11.register_without_read'].state
    CASE_BY_ID['KP_to_device_with_mask_11']['expected']['post_state'] = {
        'holds_DEV_K11_11': st.holds(P['DEV_K11'].pid, 11), 'holds_DEV_K11_1': st.holds(P['DEV_K11'].pid, 1),
        'direct_BOB_11': st.direct(P['BOB'].pid, 11), 'invitation_exception_DEV_K11': st.invitation_subject(P['DEV_K11'].pid)}
    st = NODES['KP_to_owner_acting_device_with_mask_11.register'].state
    CASE_BY_ID['KP_to_owner_acting_device_with_mask_11']['expected']['post_state'] = {
        'holds_DEV_K13_11': st.holds(P['DEV_K13'].pid, 11), 'holds_DEV_K13_1': st.holds(P['DEV_K13'].pid, 1),
        'direct_OWNER_11': st.direct(P['OWNER'].pid, 11), 'invitation_exception_DEV_K13': st.invitation_subject(P['DEV_K13'].pid)}
    for head in QUERY_HEADS:
        st = NODES[head].state
        CASE_BY_ID[head]['expected']['post_state']['queries'] = {
            label: {'rootOf': L(st.root_of(P[label].pid)), 'actsFor': L(st.acts_for(P[label].pid)),
                    'bound': st.bound(P[label].pid), 'active': st.active(P[label].pid)}
            for label in MATRIX_PRINCIPALS}


# -----------------------------------------------------------------------------
# Suite assembly.
# -----------------------------------------------------------------------------


def principal_cases() -> list[dict]:
    out = []
    for label in PRINCIPAL_ROLES:
        p = P[label]
        out.append({'id': f'principal_{label.lower()}', 'type': 'bytes', 'kind': 'principal', 'description': PRINCIPAL_ROLES[label],
                    'inputs': {'label': label, 'ed25519_seed': hx(p.ed_seed), 'x25519_private': hx(p.x_sk_raw)},
                    'expected': {'ed25519_public': hx(p.ed_pk), 'x25519_public': hx(p.x_pk), 'principal_id': hx(p.pid),
                                 'descriptor_cbor': hx(cbor(p.descriptor()))}})
    return out


def fixtures() -> dict:
    certs = {}
    for label, c in CERTS.items():
        certs[label] = {'root': c['root'], 'device': c['device'], 'kind': c['kind'], 'mask': c['mask'],
                        'scope': [s if isinstance(s, str) else s.hex() for s in c['scope']], 'issuer': c['issuer'],
                        'serial': hx(c['serial']), 'cose_sign1': hx(c['cose']), 'certificate_id': hx(c['id']),
                        'payload_digest': hx(c['digest'])}
    return {
        'resource': {'id': hx(RES['X']), 'dek0': hx(dek('X', 0)), 'dek1': hx(dek('X', 1))},
        'resources': {name: {'id': hx(r), 'label': f'LFCP-TV-IDENTITY-RESOURCE-{name}', 'data_profile': RES_PROFILE[name],
                             'dek0': hx(dek(name, 0)), 'dek0_commitment': hx(commitment(name, 0)),
                             **({'dek1': hx(dek(name, 1)), 'dek1_commitment': hx(commitment(name, 1))} if name == 'X' else {})}
                      for name, r in RES.items()},
        'derivations': {
            'principal': "ed25519 seed = SHA-256('LFCP-TV-' || label || '-ED25519'), x25519 private = SHA-256('LFCP-TV-' || label || '-X25519') (as LFCP-TEST-VECTORS-01)",
            'resource': "SHA-256('LFCP-TV-IDENTITY-RESOURCE-' || name)",
            'dek': "SHA-256('LFCP-TV-IDENTITY-DEK-' || resource name || '-EPOCH-' || epoch)",
            'serial': "first 16 bytes of SHA-256('LFCP-TV-SERIAL-' || certificate label)",
            'scope_fill': "SHA-256('LFCP-TV-IDENTITY-SCOPE-' || two-digit k), k = 01..65",
            'transfer_nonce': "first 16 bytes of SHA-256('LFCP-TV-IDENTITY-OFFER-NONCE-' || transfer name)",
            'hpke_ephemeral': "RFC 9180 DeriveKeyPair(SHA-256('LFCP-TV-IDENTITY-KP-EPHEMERAL-' || case id))",
            'limit_principals': 'LIMIT_BOB_01..30, LIMIT_OWNER_01..30, PAIR_S_01..40, TOMB_X_001..065 and TOMB_I_001..064 are Principals derived from these labels',
        },
        'endpoint': {'url': ENDPOINT_A[0], 'priority': ENDPOINT_A[1], 'flags': ENDPOINT_A[2], 'coordinator': COORD_A},
        'fill_principals': {label: {'principal_id': hx(P[label].pid), 'descriptor_cbor': hx(cbor(P[label].descriptor()))}
                            for label in LIMIT + TOMB_X + TOMB_I + LIMIT_OWNER + PAIR_S},
        'certificates': certs,
        'record_sets': RECORD_SETS,
    }


def strip(case: dict) -> dict:
    return {k: v for k, v in case.items() if not k.startswith('_')}


def suite() -> dict:
    return {
        'format': 'lfcp-vector-format/1',
        'suite': {
            'id': SUITE_ID, 'version': '01',
            'specification': {'id': 'LFCP-WIRE-01', 'revision': 'working-draft'},
            'description': 'Multi-device identity vectors (IDENTITY-PROFILE-01 §12.2 ID-01 to ID-04): Device Certificates, certificate chains, DEVICE_GRANT and DEVICE_REVOKE with the rules they change, Genesis field 5, transfer commit field 2, and the Data Units, Key Packages, Snapshots and reads they authorize.',
            'depends_on': ['LFCP-WIRE-01', 'IDENTITY-PROFILE-01', 'LFCP-TEST-VECTORS-01'],
            'conventions': {
                'cose_sign1_tag_policy': 'untagged-array',
                'cbor_profile': 'RFC8949 preferred deterministic serialization',
                'labels': 'Principals, certificates and Resources are named by fixture labels; fixtures.certificates and the principal_* cases give their bytes.',
                'context': 'A Control Record case is proposed on the head reached by replaying, in order, context.records, the records of context.record_set (fixtures.record_sets), when present, and context.records_after_set; context.head_record_id and context.head_control_seq give that head, and context.head names the case that carries it unless it is the last record of a record set. Data Plane objects and reads use context.latest as the receiver\'s latest Control state.',
                'variants': 'A vector of IDENTITY-PROFILE-01 §12.2 with several outcomes is split into cases <vector>.<variant>; the case without a suffix carries the outcome the specification names.',
                'post_state': 'For an accepted record, expected.post_state lists the derived state of LFCP-WIRE-01 §79 after it: roles, devices (with activity, suspension and data/read), revoked, the roots with standing, issuer_root for a grant and exposing for a DEVICE_REVOKE.',
                'rule': 'Every validation case names in `rule` the section and the rule that decide it; for a rejection, the first failing class of LFCP-WIRE-01 §62.',
            },
            'warning': 'All private keys, DEKs and derived keys in this suite are public test fixtures. They MUST NOT be used in production or as production defaults.',
            'conformance': {
                'validation': 'An implementation MUST reach every expected validity and, on rejection, report the expected error code; for an accepted record it MUST derive the listed post-state facts.',
                'bytes': 'The same inputs MUST produce exactly the expected bytes.',
                'diagnostics': 'Within one wire code, implementation diagnostics are not compared.',
            },
        },
        'fixtures': fixtures(),
        'cases': principal_cases() + [strip(c) for c in CASES],
    }


# -----------------------------------------------------------------------------
# Markdown.
# -----------------------------------------------------------------------------


def outcome(c: dict) -> str:
    if c['type'] == 'bytes':
        return 'exact bytes'
    if c['type'] == 'behavioral':
        return 'table'
    e = c['expected']
    if e['valid']:
        ps = e.get('post_state') or {}
        extra = []
        if 'exposing' in ps:
            extra.append('exposing' if ps['exposing'] else 'not exposing')
        if ps.get('read') == 'prefix':
            extra.append(f"prefix through {ps['control_head']}")
        return 'accept' + (f" ({', '.join(extra)})" if extra else '')
    return '`' + e['error']['code'] + '`'


def head_of(c: dict) -> str:
    ctx = c.get('context') or {}
    for k in ('head', 'latest'):
        if k in ctx:
            name = ctx[k]['case']
            return f'{name}' + (f" + set `{ctx['record_set']}`" if ctx.get('record_set') else '')
    return '—'


def markdown(doc: dict) -> str:
    lines = [f'# {SUITE_ID}', '',
             'Generated by `generate_lfcp_identity_test_vectors_01.py`; do not edit by hand. Machine-readable values are in',
             f'`{SUITE_ID}.json` (`lfcp-vector-format/1`). Rules: LFCP-WIRE-01 §7.2, §7.3, §15, §17.4, §17.5, §23.3, §25.2, §26.3,',
             '§41, §62, §79, §80.1; vector list: IDENTITY-PROFILE-01 §12.', '',
             '> All private keys and DEKs here are public test fixtures. Never use them in production.', '',
             '## Fixture Principals', '', '| Label | Role | Principal ID |', '|---|---|---|']
    for label, role in PRINCIPAL_ROLES.items():
        lines.append(f'| `{label}` | {role} | `{P[label].pid.hex()}` |')
    lines += ['', 'Fill Principals `LIMIT_BOB_01..30`, `TOMB_X_001..065`, `TOMB_I_001..064` use the same derivation.', '',
              '## Resources', '', '| Name | Profile | Resource ID |', '|---|---|---|']
    for name, r in RES.items():
        lines.append(f'| `{name}` | `{RES_PROFILE[name]}` | `{r.hex()}` |')
    lines += ['', '## Certificates', '', '| Label | Root | Device | Kind | Mask | Scope | Issuer | Certificate ID |', '|---|---|---|---|---|---|---|---|']
    for label, c in CERTS.items():
        if label.startswith('CERT_LIMIT'):
            continue
        scope = ', '.join(s if isinstance(s, str) else s.hex()[:8] for s in c['scope'])
        lines.append(f"| `{label}` | {c['root']} | {c['device']} | {c['kind']} | {c['mask']} | [{scope}] | {c['issuer']} | `{c['id'].hex()[:16]}…` |")
    lines += ['', '`CERT_LIMIT_BOB_k`: BOB, `LIMIT_BOB_k`, kind 0, [1], issued by BOB.', '',
              '## Record sets', '']
    for name, rs in RECORD_SETS.items():
        lines.append(f"- `{name}` ({len(rs['records'])} records after `{rs['after']}`): {rs['description']}")
    by_id = {c['id']: c for c in doc['cases']}
    for g, ids in GROUPS.items():
        lines += ['', f'## {g}', '', '| Case | Head / latest | Expected | Deciding rule | Description |', '|---|---|---|---|---|']
        for cid in ids:
            c = by_id[cid]
            rule = c.get('rule', {}).get('section', '')
            lines.append(f"| `{cid}` | {head_of(c)} | {outcome(c)} | {rule} | {c.get('description', '')} |")
    mat = by_id['KP_matrix']['expected']['outcome_by_head_sender_recipient']
    abbrev = {'accept': '✓', M.DENIED: 'A', M.MISSING: 'M'}
    lines += ['', '## KP_matrix', '', '✓ accept, A `AUTHORIZATION_FAILED`, M `MISSING_DEPENDENCY` (sender unknown at the head). Rows: sender; columns: recipient.']
    for head, rows in mat.items():
        lines += ['', f'### {head}', '', '| sender \\ recipient | ' + ' | '.join(MATRIX_PRINCIPALS) + ' |',
                  '|---|' + '---|' * len(MATRIX_PRINCIPALS)]
        for s in MATRIX_PRINCIPALS:
            lines.append(f'| {s} | ' + ' | '.join(abbrev[rows[s][r]] for r in MATRIX_PRINCIPALS) + ' |')
    counts = {}
    for c in doc['cases']:
        counts[c['type']] = counts.get(c['type'], 0) + 1
    lines += ['', '## Counts', '', ', '.join(f'{k}: {v}' for k, v in sorted(counts.items())) + f"; total {len(doc['cases'])}", '']
    return '\n'.join(lines)


def generate() -> dict:
    build_context()
    build_certificates()
    build_chains()
    build_records()
    build_data_plane()
    build_flow_support()
    build_review_flows()
    return suite()


def main() -> None:
    parser = argparse.ArgumentParser(description=f'Generate {SUITE_ID} JSON and Markdown.')
    parser.add_argument('--out-dir', type=Path, default=HERE)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    doc = generate()
    (args.out_dir / f'{SUITE_ID}.json').write_text(json.dumps(doc, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    (args.out_dir / f'{SUITE_ID}.md').write_text(markdown(doc), encoding='utf-8')
    print(args.out_dir / f'{SUITE_ID}.json')
    print(args.out_dir / f'{SUITE_ID}.md')


if __name__ == '__main__':
    main()
