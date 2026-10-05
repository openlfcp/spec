#!/usr/bin/env python3
"""Generate deterministic LFCP-TEST-VECTORS-01 fixtures.

This generator is intentionally self-contained except for `cryptography`.
It implements only the minimal deterministic CBOR, COSE_Sign1 and HPKE
operations needed by the published vectors.

DO NOT reuse any test private keys in production.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Output paths; main() points them at --out-dir (default: this script's directory).
OUT_MD = Path(__file__).resolve().parent / 'LFCP-TEST-VECTORS-01.md'
OUT_JSON = Path(__file__).resolve().parent / 'LFCP-TEST-VECTORS-01.json'

# -----------------------------------------------------------------------------
# Deterministic CBOR: RFC 8949 preferred deterministic serialization subset.
# -----------------------------------------------------------------------------

def _head(major: int, n: int) -> bytes:
    if n < 0:
        raise ValueError('negative length')
    if n < 24:
        return bytes([(major << 5) | n])
    if n <= 0xff:
        return bytes([(major << 5) | 24, n])
    if n <= 0xffff:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, 'big')
    if n <= 0xffffffff:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, 'big')
    if n <= 0xffffffffffffffff:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, 'big')
    raise ValueError('integer too large')


def cbor(obj: Any) -> bytes:
    if obj is None:
        return b'\xf6'
    if obj is False:
        return b'\xf4'
    if obj is True:
        return b'\xf5'
    if isinstance(obj, int):
        if obj >= 0:
            return _head(0, obj)
        return _head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _head(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode('utf-8')
        return _head(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        return _head(4, len(obj)) + b''.join(cbor(v) for v in obj)
    if isinstance(obj, dict):
        enc = [(cbor(k), cbor(v)) for k, v in obj.items()]
        # RFC 8949 preferred deterministic: sort by length of encoded key, then bytewise.
        enc.sort(key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(enc)) + b''.join(k + v for k, v in enc)
    raise TypeError(type(obj))


def hx(b: bytes) -> str:
    return b.hex()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def h(label: str) -> bytes:
    return sha256(label.encode('ascii'))


def u64(n: int) -> bytes:
    return n.to_bytes(8, 'big')


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

# -----------------------------------------------------------------------------
# HKDF and LFCP key derivation.
# -----------------------------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if salt is None:
        salt = b'\x00' * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, L: int) -> bytes:
    if L > 255 * 32:
        raise ValueError('too long')
    t = b''
    okm = b''
    counter = 1
    while len(okm) < L:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:L]


def actor_key(resource: bytes, epoch: int, dek: bytes, actor_pid: bytes) -> bytes:
    prk = hkdf_extract(resource + u64(epoch), dek)
    return hkdf_expand(prk, b'LFCP-DATA-KEY-v1' + actor_pid, 32)


def snapshot_key(resource: bytes, epoch: int, dek: bytes, publisher_pid: bytes) -> bytes:
    prk = hkdf_extract(resource + u64(epoch), dek)
    return hkdf_expand(prk, b'LFCP-SNAPSHOT-KEY-v1' + publisher_pid, 32)


def lfcp_nonce(seq: int) -> bytes:
    return b'\x00\x00\x00\x00' + u64(seq)

# -----------------------------------------------------------------------------
# Principals.
# -----------------------------------------------------------------------------

@dataclass
class Principal:
    label: str
    ed_seed: bytes
    x_sk_raw: bytes

    def __post_init__(self):
        self.ed_sk = Ed25519PrivateKey.from_private_bytes(self.ed_seed)
        self.ed_pk = self.ed_sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.x_sk = X25519PrivateKey.from_private_bytes(self.x_sk_raw)
        self.x_pk = self.x_sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pid = sha256(b'LFCP-PRINCIPAL-v1' + self.ed_pk + self.x_pk)

    def descriptor(self) -> dict[int, Any]:
        return {0: self.pid, 1: self.ed_pk, 2: self.x_pk}


def principal(label: str) -> Principal:
    return Principal(
        label,
        h('LFCP-TV-' + label + '-ED25519'),
        h('LFCP-TV-' + label + '-X25519'),
    )

OWNER = principal('OWNER')
BOB = principal('BOB')
CAROL = principal('CAROL')
INVITE = principal('INVITE')

RESOURCE = h('LFCP-TV-RESOURCE-01')
DEK0 = h('LFCP-TV-DEK-EPOCH-0')
DEK1 = h('LFCP-TV-DEK-EPOCH-1')
SERVER_ID = h('LFCP-TV-SERVER-A-ID')

ENDPOINT_A = {0: 'wss://sync-a.example.test/v1/ws', 1: 0, 2: 0x3f}
ENDPOINT_B = {0: 'wss://sync-b.example.test/v1/ws', 1: 10, 2: 0x17}
COORD_A = 'wss://sync-a.example.test/v1/ws'
COORD_B = 'wss://sync-b.example.test/v1/ws'
DATA_PROFILE = 'org.lfcp.test.raw.v1'

# -----------------------------------------------------------------------------
# COSE_Sign1.
# LFCP-WIRE-01 §10 requires the untagged four-element COSE_Sign1 array.
# -----------------------------------------------------------------------------

COSE_ALG_EDDSA = -8
COSE_HDR_ALG = 1
COSE_HDR_KID = 4


def cose_sign1(payload_obj: Any, signer: Principal) -> tuple[bytes, bytes, bytes, bytes]:
    payload = cbor(payload_obj)
    protected = cbor({COSE_HDR_ALG: COSE_ALG_EDDSA, COSE_HDR_KID: signer.pid})
    sig_structure = cbor(['Signature1', protected, b'', payload])
    signature = signer.ed_sk.sign(sig_structure)
    cose = cbor([protected, {}, payload, signature])
    # Self-check.
    Ed25519PublicKey.from_public_bytes(signer.ed_pk).verify(signature, sig_structure)
    return cose, payload, protected, sig_structure

# -----------------------------------------------------------------------------
# HPKE RFC 9180 Base mode, suite X25519/HKDF-SHA256/ChaCha20Poly1305.
# -----------------------------------------------------------------------------

KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0003
Nh = 32
Nk = 32
Nn = 12


def i2osp(n: int, w: int) -> bytes:
    return n.to_bytes(w, 'big')


def hpke_labeled_extract(salt: bytes, suite_id: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b'HPKE-v1' + suite_id + label + ikm)


def hpke_labeled_expand(prk: bytes, suite_id: bytes, label: bytes, info: bytes, L: int) -> bytes:
    labeled_info = i2osp(L, 2) + b'HPKE-v1' + suite_id + label + info
    return hkdf_expand(prk, labeled_info, L)


def dhkem_extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    suite_id = b'KEM' + i2osp(KEM_ID, 2)
    eae_prk = hpke_labeled_extract(b'', suite_id, b'eae_prk', dh)
    return hpke_labeled_expand(eae_prk, suite_id, b'shared_secret', kem_context, Nh)


def hpke_key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    suite_id = b'HPKE' + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)
    psk_id_hash = hpke_labeled_extract(b'', suite_id, b'psk_id_hash', b'')
    info_hash = hpke_labeled_extract(b'', suite_id, b'info_hash', info)
    ctx = b'\x00' + psk_id_hash + info_hash  # mode_base = 0
    secret = hpke_labeled_extract(shared_secret, suite_id, b'secret', b'')
    key = hpke_labeled_expand(secret, suite_id, b'key', ctx, Nk)
    base_nonce = hpke_labeled_expand(secret, suite_id, b'base_nonce', ctx, Nn)
    exporter_secret = hpke_labeled_expand(secret, suite_id, b'exp', ctx, Nh)
    return key, base_nonce, exporter_secret, ctx


def hpke_seal_with_ephemeral(pkR_raw: bytes, skE_raw: bytes, info: bytes, aad: bytes, pt: bytes):
    skE = X25519PrivateKey.from_private_bytes(skE_raw)
    pkE_raw = skE.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pkR = X25519PublicKey.from_public_bytes(pkR_raw)
    dh = skE.exchange(pkR)
    kem_context = pkE_raw + pkR_raw
    shared_secret = dhkem_extract_and_expand(dh, kem_context)
    key, base_nonce, exporter_secret, ks_ctx = hpke_key_schedule(shared_secret, info)
    ct = ChaCha20Poly1305(key).encrypt(base_nonce, pt, aad)
    return {
        'enc': pkE_raw,
        'ct': ct,
        'shared_secret': shared_secret,
        'key': key,
        'base_nonce': base_nonce,
        'exporter_secret': exporter_secret,
        'key_schedule_context': ks_ctx,
    }


def hpke_open(skR_raw: bytes, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    skR = X25519PrivateKey.from_private_bytes(skR_raw)
    pkR_raw = skR.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pkE = X25519PublicKey.from_public_bytes(enc)
    dh = skR.exchange(pkE)
    shared_secret = dhkem_extract_and_expand(dh, enc + pkR_raw)
    key, base_nonce, _, _ = hpke_key_schedule(shared_secret, info)
    return ChaCha20Poly1305(key).decrypt(base_nonce, ct, aad)


def validate_hpke_against_rfc9180_a2_1():
    # RFC 9180 Appendix A.2.1 Base mode fixture.
    skE = bytes.fromhex('f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600')
    pkE_expected = bytes.fromhex('1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a')
    skR = bytes.fromhex('8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb')
    pkR = bytes.fromhex('4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a')
    info = bytes.fromhex('4f6465206f6e2061204772656369616e2055726e')
    aad = bytes.fromhex('436f756e742d30')
    pt = bytes.fromhex('4265617574792069732074727574682c20747275746820626561757479')
    out = hpke_seal_with_ephemeral(pkR, skE, info, aad, pt)
    assert out['enc'] == pkE_expected
    assert out['shared_secret'].hex() == '0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7'
    assert out['key'].hex() == 'ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91'
    assert out['base_nonce'].hex() == '5c4d98150661b848853b547f'
    assert out['ct'].hex() == ('1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db'
                                 '21993c62ce81883d2dd1b51a28')
    assert hpke_open(skR, out['enc'], info, aad, out['ct']) == pt

# -----------------------------------------------------------------------------
# Fixture constructors.
# -----------------------------------------------------------------------------

def dek_commitment(epoch: int, dek: bytes) -> bytes:
    return sha256(b'LFCP-DEK-v1' + RESOURCE + u64(epoch) + dek)


def control_record(seq: int, prev: bytes | None, typ: int, issuer: Principal, body: Any):
    payload = {0: RESOURCE, 1: seq, 2: prev, 3: typ, 4: issuer.pid, 5: body}
    cose, payload_bytes, protected, sig_struct = cose_sign1(payload, issuer)
    return {
        'payload_obj': payload,
        'payload': payload_bytes,
        'protected': protected,
        'sig_structure': sig_struct,
        'cose': cose,
        'id': sha256(cose),
        'signer': issuer.label,
    }


def data_unit(actor: Principal, epoch: int, seq: int, prev: bytes | None, control_ref: bytes, plaintext: bytes, dek: bytes):
    aad_obj = ['LFCP-DATA-v1', RESOURCE, epoch, actor.pid, seq, prev, control_ref]
    aad = cbor(aad_obj)
    key = actor_key(RESOURCE, epoch, dek, actor.pid)
    nonce = lfcp_nonce(seq)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    payload_obj = {0: RESOURCE, 1: epoch, 2: actor.pid, 3: seq, 4: prev, 5: control_ref, 6: ciphertext}
    cose, payload, protected, sig_struct = cose_sign1(payload_obj, actor)
    # Self-check.
    recovered = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    assert recovered == plaintext
    return {
        'aad_obj': aad_obj,
        'aad': aad,
        'actor_key': key,
        'nonce': nonce,
        'plaintext': plaintext,
        'ciphertext': ciphertext,
        'payload_obj': payload_obj,
        'payload': payload,
        'protected': protected,
        'sig_structure': sig_struct,
        'cose': cose,
        'id': sha256(cose),
    }


def wire_msg(msg_type: int, msg_id: bytes, body: Any, correlation: bytes | None = None, flags: int | None = None) -> bytes:
    obj = {0: msg_type, 1: msg_id, 4: body}
    if correlation is not None:
        obj[2] = correlation
    if flags is not None:
        obj[3] = flags
    return cbor(obj)


def msgid(label: str) -> bytes:
    return h('LFCP-TV-MSG-' + label)[:16]


def actor_have(pid: bytes, contiguous: int, extras: list[list[int]] | None = None) -> dict[int, Any]:
    """Canonical actor-have, LFCP-WIRE-01 §28.1."""
    extras = extras or []
    prev_end = contiguous
    for start, end in extras:
        # rules 4-8: start <= end, above contiguous, sorted, non-overlapping, non-adjacent
        assert start <= end and start > prev_end + 1, 'non-canonical sequence range'
        prev_end = end
    entry = {0: pid, 1: contiguous}
    if extras:  # rules 2-3: key 2 present only when there are extra ranges
        entry[2] = [list(r) for r in extras]
    return entry


def canonical_frontier(entries: list[dict[int, Any]]) -> list[dict[int, Any]]:
    """Canonical frontier, LFCP-WIRE-01 §28.2: sorted by raw principal-id bytes."""
    pids = [e[0] for e in entries]
    assert len(set(pids)) == len(pids), 'duplicate Principal in frontier (§28.1 rule 9)'
    return sorted(entries, key=lambda e: e[0])


def snapshot(publisher: Principal, epoch: int, seq: int, control_head: bytes, frontier: list[dict[int, Any]],
             plaintext: bytes, dek: bytes) -> dict[str, Any]:
    """Encrypted, signed Snapshot, LFCP-WIRE-01 §29."""
    aad_obj = ['LFCP-SNAPSHOT-v1', RESOURCE, epoch, publisher.pid, seq, control_head, frontier]  # §29.1.3
    aad = cbor(aad_obj)
    key = snapshot_key(RESOURCE, epoch, dek, publisher.pid)  # §29.1.1
    nonce = lfcp_nonce(seq)  # §29.1.2: 0x00000000 || uint64_be(snapshot_sequence)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)  # §29.1.4
    payload_obj = {0: RESOURCE, 1: epoch, 2: publisher.pid, 3: seq, 4: control_head, 5: frontier, 6: ciphertext}
    # §29.1.3: the AAD elements after the label equal payload fields 0..5.
    assert aad_obj[1:] == [payload_obj[i] for i in range(6)]
    cose, payload, protected, sig_struct = cose_sign1(payload_obj, publisher)  # §29, §10
    assert ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad) == plaintext
    return {
        'frontier': frontier,
        'frontier_cbor': cbor(frontier),
        'aad': aad,
        'key': key,
        'nonce': nonce,
        'plaintext': plaintext,
        'ciphertext': ciphertext,
        'payload': payload,
        'protected': protected,
        'sig_structure': sig_struct,
        'cose': cose,
        'id': sha256(cose),  # §29: snapshot_id = SHA-256(exact COSE_Sign1 bytes)
    }

# -----------------------------------------------------------------------------
# Generate chain.
# -----------------------------------------------------------------------------

def generate():
    validate_hpke_against_rfc9180_a2_1()

    # Control C0 Genesis.
    genesis_body = {
        0: DATA_PROFILE,
        1: OWNER.descriptor(),
        2: dek_commitment(0, DEK0),
        3: [ENDPOINT_A],
        4: COORD_A,
    }
    C0 = control_record(0, None, 0, OWNER, genesis_body)

    # C1 grant Bob read/write/snapshot.
    grant_bob_body = {0: BOB.descriptor(), 1: [1, 2, 3], 2: []}
    C1 = control_record(1, C0['id'], 1, OWNER, grant_bob_body)

    # C2 one-time invitation grant.
    invite_grant_body = {0: INVITE.descriptor(), 1: [1, 2, 11], 2: [], 4: 1}
    C2 = control_record(2, C1['id'], 1, OWNER, invite_grant_body)

    # C3 invitation claim to Carol.
    claim_body = {0: C2['id'], 1: CAROL.descriptor(), 2: [1, 2]}
    C3 = control_record(3, C2['id'], 3, INVITE, claim_body)

    # Ownership transfer to Bob, committed as C4.
    transfer_nonce = h('LFCP-TV-OWNER-TRANSFER-NONCE')[:16]
    offer_payload_obj = {0: RESOURCE, 1: C3['id'], 2: 4, 3: BOB.descriptor(), 4: transfer_nonce}
    offer_cose, offer_payload, offer_protected, offer_sig_struct = cose_sign1(offer_payload_obj, OWNER)
    offer_id = sha256(offer_cose)
    accept_payload_obj = {0: RESOURCE, 1: offer_id, 2: BOB.pid}
    accept_cose, accept_payload, accept_protected, accept_sig_struct = cose_sign1(accept_payload_obj, BOB)
    accept_id = sha256(accept_cose)
    transfer_commit_body = {0: offer_cose, 1: accept_cose}
    C4 = control_record(4, C3['id'], 6, BOB, transfer_commit_body)

    # C5 route migration; Bob is now owner.
    route_body = {0: 1, 1: [ENDPOINT_B, ENDPOINT_A], 2: COORD_B}
    C5 = control_record(5, C4['id'], 5, BOB, route_body)

    # Data under epoch 0 before close.
    D1 = data_unit(BOB, 0, 1, None, C3['id'], b'LFCP test data unit #1', DEK0)
    # Negative AEAD AAD check.
    try:
        wrong_aad = cbor(['LFCP-DATA-v1', RESOURCE, 0, BOB.pid, 2, None, C3['id']])
        ChaCha20Poly1305(D1['actor_key']).decrypt(D1['nonce'], D1['ciphertext'], wrong_aad)
        raise AssertionError('AAD mismatch unexpectedly decrypted')
    except Exception:
        pass
    D2 = data_unit(BOB, 0, 2, D1['id'], C3['id'], b'LFCP test data unit #2', DEK0)

    # C6 key rotation; only Bob seq<=2 is accepted in old epoch.
    actor_have_bob2 = {0: BOB.pid, 1: 2}
    key_epoch_body = {0: 1, 1: dek_commitment(1, DEK1), 2: [actor_have_bob2], 3: 3}
    C6 = control_record(6, C5['id'], 4, BOB, key_epoch_body)

    # Cryptographically valid but stale unit after strict cutoff.
    D3_STALE = data_unit(BOB, 0, 3, D2['id'], C3['id'], b'LFCP stale offline unit #3', DEK0)

    # Key package for Bob, epoch 0 at C1.
    kp0_info = cbor(['LFCP-KEY-v1', RESOURCE, 0, BOB.pid])
    kp0_aad = cbor([RESOURCE, 0, C1['id']])
    kp0_skE = h('LFCP-TV-HPKE-BOB-E0-EPHEMERAL')
    hp0 = hpke_seal_with_ephemeral(BOB.x_pk, kp0_skE, kp0_info, kp0_aad, DEK0)
    assert hpke_open(BOB.x_sk_raw, hp0['enc'], kp0_info, kp0_aad, hp0['ct']) == DEK0
    # Negative HPKE recipient check.
    try:
        hpke_open(CAROL.x_sk_raw, hp0['enc'], kp0_info, kp0_aad, hp0['ct'])
        raise AssertionError('wrong HPKE recipient unexpectedly decrypted')
    except Exception:
        pass
    kp0_payload_obj = {0: RESOURCE, 1: 0, 2: BOB.pid, 3: C1['id'], 4: OWNER.pid, 5: hp0['enc'], 6: hp0['ct']}
    KP0_cose, KP0_payload, KP0_prot, KP0_sig = cose_sign1(kp0_payload_obj, OWNER)
    KP0 = {'cose': KP0_cose, 'payload': KP0_payload, 'protected': KP0_prot, 'sig_structure': KP0_sig, 'id': sha256(KP0_cose), **hp0,
           'info': kp0_info, 'aad': kp0_aad, 'ephemeral_sk': kp0_skE}

    # Key package for Invitation Principal at C2.
    kpi_info = cbor(['LFCP-KEY-v1', RESOURCE, 0, INVITE.pid])
    kpi_aad = cbor([RESOURCE, 0, C2['id']])
    kpi_skE = h('LFCP-TV-HPKE-INVITE-E0-EPHEMERAL')
    hpi = hpke_seal_with_ephemeral(INVITE.x_pk, kpi_skE, kpi_info, kpi_aad, DEK0)
    assert hpke_open(INVITE.x_sk_raw, hpi['enc'], kpi_info, kpi_aad, hpi['ct']) == DEK0
    kpi_payload_obj = {0: RESOURCE, 1: 0, 2: INVITE.pid, 3: C2['id'], 4: OWNER.pid, 5: hpi['enc'], 6: hpi['ct']}
    KPI_cose, KPI_payload, KPI_prot, KPI_sig = cose_sign1(kpi_payload_obj, OWNER)
    KPI = {'cose': KPI_cose, 'payload': KPI_payload, 'protected': KPI_prot, 'sig_structure': KPI_sig, 'id': sha256(KPI_cose), **hpi,
           'info': kpi_info, 'aad': kpi_aad, 'ephemeral_sk': kpi_skE}

    # Key package for Carol, epoch 1 at C6, sent by owner Bob.
    kpc_info = cbor(['LFCP-KEY-v1', RESOURCE, 1, CAROL.pid])
    kpc_aad = cbor([RESOURCE, 1, C6['id']])
    kpc_skE = h('LFCP-TV-HPKE-CAROL-E1-EPHEMERAL')
    hpc = hpke_seal_with_ephemeral(CAROL.x_pk, kpc_skE, kpc_info, kpc_aad, DEK1)
    assert hpke_open(CAROL.x_sk_raw, hpc['enc'], kpc_info, kpc_aad, hpc['ct']) == DEK1
    kpc_payload_obj = {0: RESOURCE, 1: 1, 2: CAROL.pid, 3: C6['id'], 4: BOB.pid, 5: hpc['enc'], 6: hpc['ct']}
    KPC_cose, KPC_payload, KPC_prot, KPC_sig = cose_sign1(kpc_payload_obj, BOB)
    KPC = {'cose': KPC_cose, 'payload': KPC_payload, 'protected': KPC_prot, 'sig_structure': KPC_sig, 'id': sha256(KPC_cose), **hpc,
           'info': kpc_info, 'aad': kpc_aad, 'ephemeral_sk': kpc_skE}

    # Carol's first epoch-1 unit.
    D_C1 = data_unit(CAROL, 1, 1, None, C6['id'], b'LFCP epoch-1 unit from Carol', DEK1)

    # SNAPSHOT-01: BOB (owner since C4, so snapshot/publish per §29.2) publishes
    # epoch 1 at Control Head C6. The frontier matches the accepted Data Units:
    # BOB 1..2 (C6 cut epoch 0 at seq 2, so D3 is excluded) and CAROL 1 (D4).
    # Entries are given out of order on purpose; §28.2 sorts them.
    S1 = snapshot(BOB, 1, 1, C6['id'],
                  canonical_frontier([actor_have(CAROL.pid, 1), actor_have(BOB.pid, 2)]),
                  b'LFCP test snapshot #1', DEK1)
    # SNAPSHOT-02: same publisher and epoch, next snapshot sequence, with the
    # BOB entry of DATA_HAVE_with_hole (1..100 plus 105..107) to exercise an
    # extra range in a canonical frontier (§28.1 rule 3). It is not derived
    # from D1-D4.
    S2 = snapshot(BOB, 1, 2, C6['id'],
                  canonical_frontier([actor_have(CAROL.pid, 1), actor_have(BOB.pid, 100, [[105, 107]])]),
                  b'LFCP test snapshot #2', DEK1)

    # Invite secret and URI.
    invite_secret_obj = {0: 1, 1: INVITE.ed_seed, 2: INVITE.x_sk_raw}
    invite_secret_cbor = cbor(invite_secret_obj)
    invite_uri = (
        'lfcp://join/' + b64u(RESOURCE)
        + '?endpoint=' + quote(COORD_A, safe='')
        + '&grant=' + b64u(C2['id'])
        + '#secret=' + b64u(invite_secret_cbor)
    )

    # Session handshake vectors with Bob as session Principal.
    client_nonce = h('LFCP-TV-CLIENT-NONCE')[:16]
    server_nonce = h('LFCP-TV-SERVER-NONCE')[:16]
    session_id = h('LFCP-TV-SESSION-ID')[:16]
    hello_body = {0: ['LFCP-WIRE-01'], 1: BOB.descriptor(), 2: client_nonce, 3: [DATA_PROFILE]}
    hello_mid = msgid('HELLO')
    HELLO = wire_msg(0, hello_mid, hello_body)

    challenge_body = {0: 'LFCP-WIRE-01', 1: server_nonce, 2: session_id, 3: SERVER_ID}
    challenge_mid = msgid('CHALLENGE')
    CHALLENGE = wire_msg(1, challenge_mid, challenge_body, correlation=hello_mid)

    auth_transcript_obj = ['LFCP-AUTH-v1', session_id, client_nonce, server_nonce, SERVER_ID, BOB.pid]
    auth_proof, auth_payload, auth_prot, auth_sig = cose_sign1(auth_transcript_obj, BOB)
    auth_body = {0: auth_proof}
    auth_mid = msgid('AUTH')
    AUTH = wire_msg(2, auth_mid, auth_body, correlation=challenge_mid)

    ready_body = {0: 'LFCP-WIRE-01', 1: SERVER_ID, 2: 8 * 1024 * 1024, 3: 2, 4: 30000, 5: []}
    ready_mid = msgid('READY')
    READY = wire_msg(3, ready_mid, ready_body, correlation=auth_mid)

    # Resource open at latest head, with Bob data 1..2.
    resource_open_body = {0: RESOURCE, 1: [{0: 6, 1: C6['id']}], 2: [{0: BOB.pid, 1: 2}], 4: 3}
    ro_mid = msgid('RESOURCE-OPEN')
    RESOURCE_OPEN = wire_msg(12, ro_mid, resource_open_body)

    # Data put D1+D2.
    data_put_body = {0: RESOURCE, 1: [D1['cose'], D2['cose']]}
    dp_mid = msgid('DATA-PUT')
    DATA_PUT = wire_msg(33, dp_mid, data_put_body)

    # DATA_HAVE canonical example with a hole.
    have_hole = {0: BOB.pid, 1: 100, 2: [[105, 107]]}
    data_have_body = {0: RESOURCE, 1: [have_hole]}
    dh_mid = msgid('DATA-HAVE')
    DATA_HAVE = wire_msg(30, dh_mid, data_have_body)

    # Further message vectors (LFCP-WIRE-01 §33 registry), built only from the
    # fixtures above. Responses correlate to their request (§32).
    def mid(label):
        return msgid(label)
    control_head_c6 = {0: 6, 1: C6['id']}
    ping_payload = h('LFCP-TV-PING-PAYLOAD')[:8]
    MESSAGES = [
        ('RESOURCE_HOST', 'message type 10; exact Genesis C0 COSE bytes (§39)',
         wire_msg(10, mid('RESOURCE-HOST'), {0: C0['cose']})),
        ('RESOURCE_HOSTED', 'message type 11; durability level 2 as advertised in READY (§40)',
         wire_msg(11, mid('RESOURCE-HOSTED'), {0: RESOURCE, 1: 2}, correlation=mid('RESOURCE-HOST'))),
        ('RESOURCE_OPENED', 'message type 13; head C6, BOB 1..2 and CAROL 1, SNAPSHOT-01 summary, route version 1 and coordinator from C5 (§42)',
         wire_msg(13, mid('RESOURCE-OPENED'), {
             0: RESOURCE, 1: [control_head_c6], 2: [actor_have(BOB.pid, 2), actor_have(CAROL.pid, 1)],
             3: {0: S1['id'], 1: 1, 2: S1['frontier']}, 4: 1, 5: COORD_B}, correlation=ro_mid)),
        ('RESOURCE_CLOSE', 'message type 14 (§43)',
         wire_msg(14, mid('RESOURCE-CLOSE'), {0: RESOURCE})),
        ('CONTROL_HAVE', 'message type 20; head C6 (§44)',
         wire_msg(20, mid('CONTROL-HAVE'), {0: RESOURCE, 1: [control_head_c6]})),
        ('CONTROL_GET', 'message type 21; Control Sequences 0..6 (§45)',
         wire_msg(21, mid('CONTROL-GET'), {0: RESOURCE, 1: 0, 2: 6})),
        ('CONTROL_BATCH', 'message type 22; exact C0..C6 COSE bytes, answering CONTROL_GET (§46)',
         wire_msg(22, mid('CONTROL-BATCH'), {0: RESOURCE, 1: [C['cose'] for C in (C0, C1, C2, C3, C4, C5, C6)]},
                  correlation=mid('CONTROL-GET'))),
        ('CONTROL_PUT', 'message type 23; C6 with expected current head C5 (§47)',
         wire_msg(23, mid('CONTROL-PUT'), {0: RESOURCE, 1: C5['id'], 2: C6['cose']})),
        ('DATA_GET', 'message type 31; BOB sequences 1..2 (§49)',
         wire_msg(31, mid('DATA-GET'), {0: RESOURCE, 1: [{0: BOB.pid, 1: 1, 2: 2}]})),
        ('DATA_BATCH', 'message type 32; exact D1 and D2 COSE bytes, answering DATA_GET (§50)',
         wire_msg(32, mid('DATA-BATCH'), {0: RESOURCE, 1: [D1['cose'], D2['cose']]}, correlation=mid('DATA-GET'))),
        ('KEY_PACKAGE_GET', 'message type 40; CAROL, Data Epoch 1 (§52)',
         wire_msg(40, mid('KEY-PACKAGE-GET'), {0: RESOURCE, 1: CAROL.pid, 2: [1]})),
        ('KEY_PACKAGE_BATCH', 'message type 41; exact KPC_carol_epoch1 COSE bytes, answering KEY_PACKAGE_GET (§53)',
         wire_msg(41, mid('KEY-PACKAGE-BATCH'), {0: RESOURCE, 1: [KPC_cose]}, correlation=mid('KEY-PACKAGE-GET'))),
        ('KEY_PACKAGE_PUT', 'message type 42; exact KPC_carol_epoch1 COSE bytes (§54)',
         wire_msg(42, mid('KEY-PACKAGE-PUT'), {0: RESOURCE, 1: [KPC_cose]})),
        ('SNAPSHOT_GET', 'message type 50; SNAPSHOT-01 ID (§55)',
         wire_msg(50, mid('SNAPSHOT-GET'), {0: RESOURCE, 1: S1['id']})),
        ('SNAPSHOT', 'message type 51; exact SNAPSHOT-01 COSE bytes, answering SNAPSHOT_GET (§56)',
         wire_msg(51, mid('SNAPSHOT'), {0: RESOURCE, 1: S1['cose']}, correlation=mid('SNAPSHOT-GET'))),
        ('SNAPSHOT_PUT', 'message type 52; exact SNAPSHOT-01 COSE bytes (§57)',
         wire_msg(52, mid('SNAPSHOT-PUT'), {0: RESOURCE, 1: S1['cose']})),
        ('NACK_STALE_DATA_EPOCH', 'message type 91; error code 14 STALE_DATA_EPOCH (§60, §62)',
         wire_msg(91, mid('NACK'), {0: 14})),
        ('ERROR_AUTH_FAILED', 'message type 4; error code 3 AUTH_FAILED (§61, §62)',
         wire_msg(4, mid('ERROR'), {0: 3})),
        ('PING', 'message type 5; 8-byte payload (§38)',
         wire_msg(5, mid('PING'), {0: ping_payload})),
        ('PONG', 'message type 6; echoes the PING payload (§38)',
         wire_msg(6, mid('PONG'), {0: ping_payload}, correlation=mid('PING'))),
    ]

    # Negative: actor equivocation, same tuple Bob seq 2 but different plaintext and valid signature.
    D2_EQ = data_unit(BOB, 0, 2, D1['id'], C3['id'], b'LFCP DIFFERENT unit #2', DEK0)
    assert D2_EQ['id'] != D2['id']

    # Negative: tamper a ciphertext byte (signature also becomes invalid if payload changed without resigning).
    tampered_d1_cose = bytearray(D1['cose'])
    tampered_d1_cose[-70] ^= 0x01  # deterministic interior byte; validation should reject exact object.
    tampered_d1_cose = bytes(tampered_d1_cose)

    # Assertions on ownership transfer relationships.
    assert offer_payload_obj[1] == C3['id'] and offer_payload_obj[2] == 4
    assert accept_payload_obj[1] == offer_id and accept_payload_obj[2] == BOB.pid
    assert C4['payload_obj'][4] == BOB.pid

    # -------------------------------------------------------------------------
    # LFCP-009 negative vectors. Each one changes exactly one property of a
    # published positive case; derived bytes (ciphertext, signature) are
    # recomputed so that only the named rule is violated.
    # -------------------------------------------------------------------------
    NEG: list[dict[str, Any]] = []

    def ref(case_id: str, field: str, where: str = 'expected') -> dict[str, str]:
        r = {'case': case_id, 'field': field}
        if where != 'expected':
            r['in'] = where
        return r

    def neg(case_id, kind, title, base_case, field, old, new, section, text, why, inputs, expected,
            context=None, cddl=None):
        NEG.append({
            'id': case_id, 'kind': kind, 'description': title,
            'inputs': inputs, 'context': context, 'expected': expected,
            'derivation': {
                'base_case': base_case,
                'mutation': {'field': field, 'from': old, 'to': new},
                'rule': {'section': section, 'text': text},
                'why': why,
            },
            'cddl': cddl,
        })

    def hexv(b: bytes) -> dict[str, str]:
        return {'hex': hx(b)}

    def signed_data_unit(payload_obj: dict[int, Any], signer: Principal) -> bytes:
        return cose_sign1(payload_obj, signer)[0]

    def sealed(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)

    D1_plain = b'LFCP test data unit #1'

    # 1. Non-canonical CBOR in a reconstructed structure: D1 sealed under an AAD
    #    whose actor sequence is encoded as 0x18 0x01 instead of 0x01.
    aad_items = [cbor(x) for x in D1['aad_obj']]
    assert aad_items[4] == b'\x01'
    noncanon_aad = b'\x87' + b''.join(aad_items[:4] + [b'\x18\x01'] + aad_items[5:])
    assert noncanon_aad != D1['aad'] and len(noncanon_aad) == len(D1['aad']) + 1
    ct_nc = sealed(D1['actor_key'], D1['nonce'], D1_plain, noncanon_aad)
    du_nc = signed_data_unit({**D1['payload_obj'], 6: ct_nc}, BOB)
    neg('noncanonical_aad_D1', 'data_unit', 'D1 sealed under a non-deterministically encoded AAD',
        'D1_bob_epoch0_seq1', 'AAD encoding of the actor sequence (seq 1)', hexv(b'\x01'), hexv(b'\x18\x01'),
        'LFCP-WIRE-01 §5.2; §26.3',
        'When an LFCP algorithm requires reconstructing a deterministic structure, such as AEAD AAD, HPKE `info`, '
        'or HPKE AAD, the reconstructed structure MUST follow these deterministic CBOR rules exactly. '
        '(§26.3: a Data Unit is eligible for merge only if "the unit decrypts successfully".)',
        'The receiver reconstructs the canonical AAD, so decryption fails; accepting it would require guessing alternative encodings of signed or authenticated structures.',
        {'cose_sign1': hexv(du_nc), 'noncanonical_aad_cbor': hexv(noncanon_aad)},
        {'valid': False, 'disposition': 'reject'},
        cddl=('data-unit', 'pass'))

    # 2. Tagged COSE_Sign1 (tag 18).
    neg('tagged_cose_D1', 'data_unit', 'D1 wrapped in COSE_Sign1 tag 18',
        'D1_bob_epoch0_seq1', 'outer CBOR tag', 'none', 'tag 18',
        'LFCP-WIRE-01 §10',
        'A strict LFCP-WIRE-01 implementation MUST reject a tagged persistent LFCP object as non-canonical.',
        'The object ID is SHA-256 of the exact bytes; a tagged copy would be a second, different object for the same content.',
        {'cose_sign1': hexv(b'\xd2' + D1['cose'])},
        {'valid': False, 'disposition': 'reject'},
        cddl=('data-unit', 'fail'))

    # 3. Invalid Ed25519 signature: last signature byte flipped.
    bad_sig = bytearray(D1['cose']); bad_sig[-1] ^= 0x01; bad_sig = bytes(bad_sig)
    neg('invalid_signature_D1', 'data_unit', 'D1 with one signature bit flipped',
        'D1_bob_epoch0_seq1', 'signature byte 63', hexv(D1['cose'][-1:]), hexv(bad_sig[-1:]),
        'LFCP-WIRE-01 §26.3, §10.5',
        'A Data Unit is eligible for merge only if: 1. its signature is valid for the actor Principal;',
        'An unverified signature lets anyone inject Data Units in the actor\'s name.',
        {'cose_sign1': hexv(bad_sig)},
        {'valid': False, 'disposition': 'reject'},
        cddl=('data-unit', 'pass'))

    # 4. Wrong kid: D1's payload (actor BOB) signed by CAROL with kid CAROL.
    du_kid = signed_data_unit(D1['payload_obj'], CAROL)
    neg('wrong_kid_D1', 'data_unit', 'D1 payload signed by CAROL (kid CAROL) instead of the actor BOB',
        'D1_bob_epoch0_seq1', 'protected header kid (and signing key)', hexv(BOB.pid), hexv(CAROL.pid),
        'LFCP-WIRE-01 §10.1, §26',
        'The value of `kid` MUST be the 32-byte Principal ID of the signing Principal. '
        '(§26: "The payload is signed by the actor using COSE_Sign1.")',
        'The signature is valid but by the wrong Principal; accepting it lets one member forge another member\'s edits.',
        {'cose_sign1': hexv(du_kid)},
        {'valid': False, 'disposition': 'reject'},
        context={'actor': ref('principal_bob', 'principal_id'), 'kid': ref('principal_carol', 'principal_id')},
        cddl=('data-unit', 'pass'))

    # 5. AEAD authentication failure: D1 sealed under the AAD of sequence 2.
    wrong_aad = cbor(['LFCP-DATA-v1', RESOURCE, 0, BOB.pid, 2, None, C3['id']])
    ct_aead = sealed(D1['actor_key'], D1['nonce'], D1_plain, wrong_aad)
    du_aead = signed_data_unit({**D1['payload_obj'], 6: ct_aead}, BOB)
    try:
        ChaCha20Poly1305(D1['actor_key']).decrypt(D1['nonce'], ct_aead, D1['aad'])
        raise AssertionError('AEAD failure vector unexpectedly decrypts')
    except AssertionError:
        raise
    except Exception:
        pass
    neg('aead_failure_D1', 'data_unit', 'D1 ciphertext sealed under the AAD of sequence 2',
        'D1_bob_epoch0_seq1', 'AAD actor sequence used for sealing', 1, 2,
        'LFCP-WIRE-01 §26.1, §26.3',
        'A Data Unit is eligible for merge only if: [...] 6. the unit decrypts successfully;',
        'The AAD binds the ciphertext to its resource, epoch, actor and position; accepting it would let ciphertext be replayed elsewhere.',
        {'cose_sign1': hexv(du_aead)},
        {'valid': False, 'disposition': 'reject'},
        cddl=('data-unit', 'pass'))

    # 6. Stale Control Head: CONTROL_PUT expecting C4 while the head is C5.
    stale_put = wire_msg(23, msgid('CONTROL-PUT'), {0: RESOURCE, 1: C4['id'], 2: C6['cose']})
    neg('stale_control_head_put', 'control_put', 'CONTROL_PUT of C6 with expected head C4 while the coordinator head is C5',
        'CONTROL_PUT', 'expected current Control Head (body field 1)', hexv(C5['id']), hexv(C4['id']),
        'LFCP-WIRE-01 §47',
        'If not equal, it MUST return `NACK(CONTROL_HEAD_MISMATCH)` with the current head.',
        'Compare-and-swap is what keeps the Control Chain linear; committing against a stale head would fork it.',
        {'message_cbor': hexv(stale_put)},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'CONTROL_HEAD_MISMATCH'}},
        context={'current_control_head': ref('C5_route_update', 'record_id')},
        cddl=('typed-lfcp-message', 'pass'))

    # 7. Control fork: a second validly signed record at seq 6 after C5,
    #    differing from C6 only in the cutoff frontier (BOB 3 instead of 2).
    fork_body = {0: 1, 1: dek_commitment(1, DEK1), 2: [{0: BOB.pid, 1: 3}], 3: 3}
    C6_FORK = control_record(6, C5['id'], 4, BOB, fork_body)
    assert C6_FORK['id'] != C6['id']
    neg('control_fork_C6', 'control_record', 'A second Control Record at sequence 6 on top of C5',
        'C6_key_epoch_1', 'body field 2: BOB cutoff sequence', 2, 3,
        'LFCP-WIRE-01 §13.2',
        'Two different validly signed records referencing the same previous Control Record create a Control Fork. '
        'A client MUST NOT silently choose a branch. The Resource enters `CONTROL_CONFLICT` [...]',
        'Choosing a branch silently would let replicas diverge on authorization and keys.',
        {'cose_sign1': hexv(C6_FORK['cose']), 'record_id': hexv(C6_FORK['id'])},
        {'valid': False, 'disposition': 'conflict', 'error': {'code': 'CONTROL_CONFLICT'}},
        context={'previous_record': ref('C5_route_update', 'record_id'), 'competing_record': ref('C6_key_epoch_1', 'record_id')},
        cddl=('control-record', 'pass'))

    # 8. Bad actor sequence.
    D_SEQ0 = data_unit(BOB, 0, 0, None, C3['id'], D1_plain, DEK0)
    neg('actor_seq_zero_D1', 'data_unit', 'D1 re-issued with actor sequence 0',
        'D1_bob_epoch0_seq1', 'actor sequence (payload field 3)', 1, 0,
        'LFCP-WIRE-01 §8',
        'Sequence numbers begin at `1`.',
        'Sequence 0 is outside the per-actor sequence space, so Have Vectors and hash chains cannot describe it.',
        {'cose_sign1': hexv(D_SEQ0['cose'])},
        {'valid': False},
        cddl=('data-unit', 'pass'))
    D_PREV = data_unit(BOB, 0, 1, D2['id'], C3['id'], D1_plain, DEK0)
    neg('actor_seq1_prev_not_null_D1', 'data_unit', 'D1 with a previous-unit reference although it is sequence 1',
        'D1_bob_epoch0_seq1', 'previous Data Unit (payload field 4)', None, hexv(D2['id']),
        'LFCP-WIRE-01 §26.2',
        'For sequence `1`, it MUST be `null`. [...] A gap or mismatch MUST be reported to the sync engine.',
        'The actor hash chain must start at sequence 1; a non-null link there breaks gap and equivocation detection.',
        {'cose_sign1': hexv(D_PREV['cose'])},
        {'valid': False, 'disposition': 'report'},
        cddl=('data-unit', 'pass'))

    # 10. HPKE recipient binding: KP0 relabelled for CAROL, sealed to BOB.
    kp_wrong_obj = {**kp0_payload_obj, 2: CAROL.pid}
    KP_WRONG = cose_sign1(kp_wrong_obj, OWNER)[0]
    carol_info = cbor(['LFCP-KEY-v1', RESOURCE, 0, CAROL.pid])
    try:
        hpke_open(CAROL.x_sk_raw, hp0['enc'], carol_info, kp0_aad, hp0['ct'])
        raise AssertionError('HPKE recipient vector unexpectedly opens')
    except AssertionError:
        raise
    except Exception:
        pass
    neg('hpke_recipient_mismatch_KP0', 'key_package', 'KP0 payload names CAROL as recipient but is sealed to BOB',
        'KP0_bob_epoch0', 'recipient (payload field 2)', hexv(BOB.pid), hexv(CAROL.pid),
        'LFCP-WIRE-01 §25.1, §25.2',
        'The HPKE `info` value is deterministic CBOR encoding of ["LFCP-KEY-v1", resource-id, data epoch, recipient]. '
        '[...] Clients accept any cryptographically valid package that yields the correct DEK commitment.',
        'HPKE info binds the recipient; a package that does not open for its named recipient delivers no key.',
        {'cose_sign1': hexv(KP_WRONG)},
        {'valid': False, 'disposition': 'reject'},
        context={'recipient_x25519_private': ref('principal_carol', 'x25519_private', 'inputs')},
        cddl=('key-package', 'pass'))

    # 11. Malformed Have ranges inside a Snapshot frontier (re-sealed and
    #     re-signed, so only canonicality is wrong).
    def raw_snapshot(frontier, seq, plaintext):
        aad = cbor(['LFCP-SNAPSHOT-v1', RESOURCE, 1, BOB.pid, seq, C6['id'], frontier])
        key = snapshot_key(RESOURCE, 1, DEK1, BOB.pid)
        ct = sealed(key, lfcp_nonce(seq), plaintext, aad)
        payload = {0: RESOURCE, 1: 1, 2: BOB.pid, 3: seq, 4: C6['id'], 5: frontier, 6: ct}
        return cose_sign1(payload, BOB)[0]

    def bob(contiguous, extras=None):
        e = {0: BOB.pid, 1: contiguous}
        if extras is not None:
            e[2] = extras
        return e
    carol = {0: CAROL.pid, 1: 1}
    have_cases = [
        ('have_empty_extra_list', 'SNAPSHOT-01', 'CAROL entry key 2', 'absent', '[] (present and empty)',
         [bob(2), {**carol, 2: []}], 'rule 2',
         '2. key `2` MUST be omitted when there are no extra ranges;'),
        ('have_range_reversed', 'SNAPSHOT-02', 'BOB extra range', [[105, 107]], [[107, 105]],
         [bob(100, [[107, 105]]), carol], 'rule 4', '4. each sequence range MUST have `start <= end`;'),
        ('have_range_not_above_contiguous', 'SNAPSHOT-02', 'BOB extra range', [[105, 107]], [[95, 107]],
         [bob(100, [[95, 107]]), carol], 'rule 5', '5. ranges MUST be strictly above `contiguous`;'),
        ('have_ranges_unsorted', 'SNAPSHOT-02', 'BOB extra ranges', [[105, 107]], [[110, 112], [105, 107]],
         [bob(100, [[110, 112], [105, 107]]), carol], 'rule 6',
         '6. ranges MUST be sorted by ascending `start`, then ascending `end`;'),
        ('have_ranges_overlapping', 'SNAPSHOT-02', 'BOB extra ranges', [[105, 107]], [[105, 107], [106, 110]],
         [bob(100, [[105, 107], [106, 110]]), carol], 'rule 7', '7. ranges MUST be non-overlapping;'),
        ('have_ranges_adjacent', 'SNAPSHOT-02', 'BOB extra ranges', [[105, 107]], [[105, 107], [108, 110]],
         [bob(100, [[105, 107], [108, 110]]), carol], 'rule 8', '8. ranges MUST be non-adjacent;'),
        ('frontier_duplicate_principal', 'SNAPSHOT-01', 'BOB entries in the frontier', 1, 2,
         [bob(2), bob(2), carol], 'rule 9',
         '9. no two `actor-have` entries for the same Principal MAY occur in one canonical frontier.'),
    ]
    base_seq = {'SNAPSHOT-01': (1, S1), 'SNAPSHOT-02': (2, S2)}
    for cid, base, field, old, new, frontier, rule_no, text in have_cases:
        seq, base_snap = base_seq[base]
        cose = raw_snapshot(frontier, seq, base_snap['plaintext'])
        neg(cid, 'snapshot', f'{base} with a frontier that violates §28.1 {rule_no}', base, field, old, new,
            f'LFCP-WIRE-01 §28.1 {rule_no}; §28.2',
            f'{text} (§28.2: "A Snapshot verifier MUST reject a Snapshot whose frontier is not canonical.")',
            'Snapshot AAD and signature cover the frontier bytes, so replicas must agree on exactly one encoding of a frontier.',
            {'cose_sign1': hexv(cose)},
            {'valid': False, 'disposition': 'reject'},
            cddl=('snapshot', 'pass'))
    cose = raw_snapshot([carol, bob(2)], 1, S1['plaintext'])
    neg('frontier_unsorted', 'snapshot', 'SNAPSHOT-01 with CAROL listed before BOB', 'SNAPSHOT-01',
        'frontier entry order', 'BOB, CAROL', 'CAROL, BOB',
        'LFCP-WIRE-01 §28.2',
        'Entries MUST be sorted by ascending raw 32-byte `principal-id`, compared lexicographically as unsigned bytes. '
        '[...] A Snapshot verifier MUST reject a Snapshot whose frontier is not canonical.',
        'Snapshot AAD and signature cover the frontier bytes, so replicas must agree on exactly one entry order.',
        {'cose_sign1': hexv(cose)},
        {'valid': False, 'disposition': 'reject'},
        cddl=('snapshot', 'pass'))

    # 12. Stale-epoch cutoff for an actor absent from the cutoff frontier:
    #     D4 moved to the closed epoch 0 (keys re-derived from DEK0).
    D_ABSENT = data_unit(CAROL, 0, 1, None, C6['id'], b'LFCP epoch-1 unit from Carol', DEK0)
    neg('stale_epoch_absent_actor', 'data_unit', 'CAROL Data Unit in closed epoch 0, where C6 records no CAROL entry',
        'D4_carol_epoch1_seq1', 'Data Epoch (payload field 1)', 1, 0,
        'LFCP-WIRE-01 §19.1; §88 step 7; §75',
        'If an actor is absent from the recorded frontier, no newly discovered Data Units from that actor in the closed '
        'epoch are automatically acceptable. Any later-arriving previous-epoch unit beyond that frontier MUST NOT be merged '
        'automatically. It SHOULD be surfaced to the application as stale offline work [...]',
        'The cutoff frontier makes revocation deterministic; merging late closed-epoch work would let removed members keep writing.',
        {'cose_sign1': hexv(D_ABSENT['cose'])},
        {'valid': False, 'disposition': 'quarantine', 'error': {'code': 'STALE_DATA_EPOCH'}},
        context={'cutoff_record': ref('C6_key_epoch_1', 'record_id'), 'closed_epoch': 0},
        cddl=('data-unit', 'pass'))

    fixtures = {
        'meta': {
            'wire_spec': 'LFCP-WIRE-01',
            'vector_spec': 'LFCP-TEST-VECTORS-01',
            'cose_sign1_tag_policy': 'untagged-array',
            'cbor_profile': 'RFC8949 preferred deterministic serialization',
            'warning': 'All private keys, DEKs and derived keys in this suite are public test fixtures. They MUST NOT be used in production or as production defaults.'
        },
        'principals': {},
        'resource': {
            'id': hx(RESOURCE), 'dek0': hx(DEK0), 'dek1': hx(DEK1),
            'dek0_commitment': hx(dek_commitment(0, DEK0)),
            'dek1_commitment': hx(dek_commitment(1, DEK1)),
        },
        'control': {},
        'transfers': {},
        'key_packages': {},
        'data_units': {},
        'snapshots': {},
        'invite': {},
        'wire': {},
        'negative': {},
    }

    for p in [OWNER, BOB, CAROL, INVITE]:
        fixtures['principals'][p.label.lower()] = {
            'ed25519_seed': hx(p.ed_seed),
            'ed25519_public': hx(p.ed_pk),
            'x25519_private': hx(p.x_sk_raw),
            'x25519_public': hx(p.x_pk),
            'principal_id': hx(p.pid),
            'descriptor_cbor': hx(cbor(p.descriptor())),
        }

    def add_ctrl(name, C):
        fixtures['control'][name] = {
            'payload_cbor': hx(C['payload']),
            'protected_header_cbor': hx(C['protected']),
            'sig_structure_cbor': hx(C['sig_structure']),
            'cose_sign1': hx(C['cose']),
            'record_id': hx(C['id']),
            'signer': C['signer'],
        }

    add_ctrl('C0_genesis', C0)
    add_ctrl('C1_grant_bob', C1)
    add_ctrl('C2_invite_grant', C2)
    add_ctrl('C3_invite_claim_carol', C3)
    add_ctrl('C4_owner_transfer_commit', C4)
    add_ctrl('C5_route_update', C5)
    add_ctrl('C6_key_epoch_1', C6)

    fixtures['transfers'] = {
        'offer_payload_cbor': hx(offer_payload),
        'offer_cose_sign1': hx(offer_cose),
        'offer_id': hx(offer_id),
        'accept_payload_cbor': hx(accept_payload),
        'accept_cose_sign1': hx(accept_cose),
        'accept_id': hx(accept_id),
        'nonce': hx(transfer_nonce),
    }

    def add_kp(name, K):
        fixtures['key_packages'][name] = {
            'hpke_ephemeral_private': hx(K['ephemeral_sk']),
            'hpke_info_cbor': hx(K['info']),
            'hpke_aad_cbor': hx(K['aad']),
            'hpke_enc': hx(K['enc']),
            'hpke_shared_secret': hx(K['shared_secret']),
            'hpke_key': hx(K['key']),
            'hpke_base_nonce': hx(K['base_nonce']),
            'hpke_ciphertext': hx(K['ct']),
            'payload_cbor': hx(K['payload']),
            'cose_sign1': hx(K['cose']),
            'package_id': hx(K['id']),
        }

    add_kp('KP0_bob_epoch0', KP0)
    add_kp('KPI_invite_epoch0', KPI)
    add_kp('KPC_carol_epoch1', KPC)

    def add_du(name, D):
        fixtures['data_units'][name] = {
            'plaintext_utf8': D['plaintext'].decode('utf-8'),
            'plaintext_hex': hx(D['plaintext']),
            'actor_key': hx(D['actor_key']),
            'nonce': hx(D['nonce']),
            'aad_cbor': hx(D['aad']),
            'ciphertext': hx(D['ciphertext']),
            'payload_cbor': hx(D['payload']),
            'cose_sign1': hx(D['cose']),
            'unit_id': hx(D['id']),
        }

    add_du('D1_bob_epoch0_seq1', D1)
    add_du('D2_bob_epoch0_seq2', D2)
    add_du('D3_bob_epoch0_seq3_stale', D3_STALE)
    add_du('D4_carol_epoch1_seq1', D_C1)

    def add_snap(name, S, publisher, epoch, seq, note):
        fixtures['snapshots'][name] = {
            'note': note,
            'publisher': publisher.label,
            'data_epoch': epoch,
            'snapshot_sequence': seq,
            'control_head': hx(C6['id']),
            'plaintext_utf8': S['plaintext'].decode('utf-8'),
            'plaintext_hex': hx(S['plaintext']),
            'frontier_cbor': hx(S['frontier_cbor']),
            'aad_cbor': hx(S['aad']),
            'snapshot_key': hx(S['key']),
            'nonce': hx(S['nonce']),
            'ciphertext': hx(S['ciphertext']),
            'payload_cbor': hx(S['payload']),
            'protected_header_cbor': hx(S['protected']),
            'sig_structure_cbor': hx(S['sig_structure']),
            'cose_sign1': hx(S['cose']),
            'snapshot_id': hx(S['id']),
        }

    add_snap('SNAPSHOT-01', S1, BOB, 1, 1,
             'Frontier from the accepted Data Units: BOB 1..2 (D1, D2; D3 is past the C6 cutoff) and CAROL 1 (D4).')
    add_snap('SNAPSHOT-02', S2, BOB, 1, 2,
             'Frontier with an extra range: the BOB entry of DATA_HAVE_with_hole (1..100, 105..107) and CAROL 1. '
             'Not derived from D1-D4.')

    fixtures['invite'] = {
        'secret_cbor': hx(invite_secret_cbor),
        'secret_b64url': b64u(invite_secret_cbor),
        'resource_b64url': b64u(RESOURCE),
        'grant_id_b64url': b64u(C2['id']),
        'uri': invite_uri,
    }

    fixtures['wire'] = {
        'client_nonce': hx(client_nonce),
        'server_nonce': hx(server_nonce),
        'session_id': hx(session_id),
        'server_id': hx(SERVER_ID),
        'auth_transcript_cbor': hx(auth_payload),
        'auth_proof_cose_sign1': hx(auth_proof),
        'HELLO': hx(HELLO),
        'CHALLENGE': hx(CHALLENGE),
        'AUTH': hx(AUTH),
        'READY': hx(READY),
        'RESOURCE_OPEN': hx(RESOURCE_OPEN),
        'DATA_HAVE_with_hole': hx(DATA_HAVE),
        'DATA_PUT_D1_D2': hx(DATA_PUT),
    }
    fixtures['messages'] = {name: {'description': desc, 'message_cbor': hx(m)} for name, desc, m in MESSAGES}

    fixtures['negative'] = {
        'actor_equivocation_original_D2_id': hx(D2['id']),
        'actor_equivocation_conflicting_D2_id': hx(D2_EQ['id']),
        'actor_equivocation_conflicting_D2_cose': hx(D2_EQ['cose']),
        'tampered_D1_cose': hx(tampered_d1_cose),
        'stale_epoch_unit_id': hx(D3_STALE['id']),
        'stale_epoch_expected': 'STALE_DATA_EPOCH / quarantine because Bob cutoff at epoch 0 is seq=2',
    }

    fixtures['negatives'] = NEG
    OUT_JSON.write_text(json.dumps(to_vector_format(fixtures), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return fixtures


# -----------------------------------------------------------------------------
# Machine-readable output in lfcp-vector-format/1 (spec: schemas/).
# -----------------------------------------------------------------------------

def to_vector_format(fixtures: dict) -> dict:
    """Arrange the generated fixture values as an lfcp-vector-format/1 suite.

    Values are copied unchanged; only their placement differs from the internal
    `fixtures` dict that the Markdown generator consumes.
    """
    def hexv(v: str) -> dict:
        return {'hex': v}

    def b64v(v: str) -> dict:
        return {'b64url': v}

    def bytes_case(case_id: str, kind: str, inputs: dict | None, expected: dict) -> dict:
        case = {'id': case_id, 'type': 'bytes', 'kind': kind}
        if inputs:
            case['inputs'] = inputs
        case['expected'] = expected
        return case

    meta = fixtures['meta']
    cases = []

    principal_inputs = ('ed25519_seed', 'x25519_private')
    for label, p in fixtures['principals'].items():
        cases.append(bytes_case(
            f'principal_{label}', 'principal',
            {k: hexv(p[k]) for k in principal_inputs},
            {k: hexv(v) for k, v in p.items() if k not in principal_inputs},
        ))

    r = fixtures['resource']
    # Epochs are explicit inputs so the §11 commitment can be recomputed.
    cases.append(bytes_case('dek_commitments', 'dek_commitment', {'dek0_epoch': 0, 'dek1_epoch': 1}, {
        'dek0_commitment': hexv(r['dek0_commitment']),
        'dek1_commitment': hexv(r['dek1_commitment']),
    }))

    for name, c in fixtures['control'].items():
        cases.append(bytes_case(
            name, 'control_record',
            {'signer': c['signer']},
            {k: hexv(v) for k, v in c.items() if k != 'signer'},
        ))

    t = fixtures['transfers']
    cases.append(bytes_case(
        'owner_transfer', 'owner_transfer',
        {'nonce': hexv(t['nonce'])},
        {k: hexv(v) for k, v in t.items() if k != 'nonce'},
    ))

    for name, k in fixtures['key_packages'].items():
        cases.append(bytes_case(
            name, 'key_package',
            {'hpke_ephemeral_private': hexv(k['hpke_ephemeral_private'])},
            {f: hexv(v) for f, v in k.items() if f != 'hpke_ephemeral_private'},
        ))

    for name, d in fixtures['data_units'].items():
        cases.append(bytes_case(
            name, 'data_unit',
            {'plaintext_utf8': d['plaintext_utf8'], 'plaintext_hex': hexv(d['plaintext_hex'])},
            {f: hexv(v) for f, v in d.items() if f not in ('plaintext_utf8', 'plaintext_hex')},
        ))

    snapshot_inputs = ('publisher', 'data_epoch', 'snapshot_sequence', 'control_head', 'plaintext_utf8', 'plaintext_hex')
    for name, x in fixtures['snapshots'].items():
        case = bytes_case(
            name, 'snapshot',
            {
                'signer': x['publisher'],
                'data_epoch': x['data_epoch'],
                'snapshot_sequence': x['snapshot_sequence'],
                'control_head': hexv(x['control_head']),
                'plaintext_utf8': x['plaintext_utf8'],
                'plaintext_hex': hexv(x['plaintext_hex']),
            },
            {k: hexv(v) for k, v in x.items() if k not in snapshot_inputs and k != 'note'},
        )
        case = {'id': case['id'], 'type': case['type'], 'kind': case['kind'], 'note': x['note'],
                'inputs': case['inputs'], 'expected': case['expected']}
        cases.append(case)

    inv = fixtures['invite']
    cases.append(bytes_case('invite_uri', 'invite_uri', None, {
        'secret_cbor': hexv(inv['secret_cbor']),
        'secret_b64url': b64v(inv['secret_b64url']),
        'resource_b64url': b64v(inv['resource_b64url']),
        'grant_id_b64url': b64v(inv['grant_id_b64url']),
        'uri': inv['uri'],
    }))

    w = fixtures['wire']
    session_fields = ('client_nonce', 'server_nonce', 'session_id', 'server_id')
    for name in ('HELLO', 'CHALLENGE', 'AUTH', 'READY', 'RESOURCE_OPEN', 'DATA_HAVE_with_hole', 'DATA_PUT_D1_D2'):
        expected = {}
        if name == 'AUTH':
            expected['auth_transcript_cbor'] = hexv(w['auth_transcript_cbor'])
            expected['auth_proof_cose_sign1'] = hexv(w['auth_proof_cose_sign1'])
        expected['message_cbor'] = hexv(w[name])
        cases.append(bytes_case(name, 'wire_message', None, expected))
    for name, m in fixtures['messages'].items():
        cases.append(bytes_case(name, 'wire_message', None, {'message_cbor': hexv(m['message_cbor'])}))

    n = fixtures['negative']
    cases.append({
        'id': 'actor_equivocation', 'type': 'validation', 'kind': 'data_unit',
        'inputs': {
            'original_D2_id': hexv(n['actor_equivocation_original_D2_id']),
            'conflicting_D2_id': hexv(n['actor_equivocation_conflicting_D2_id']),
            'conflicting_D2_cose': hexv(n['actor_equivocation_conflicting_D2_cose']),
        },
        # LFCP-WIRE-01 section 62, error code 16.
        'expected': {'valid': False, 'error': {'code': 'ACTOR_EQUIVOCATION'}},
    })
    cases.append({
        'id': 'tampered_D1', 'type': 'validation', 'kind': 'data_unit',
        'inputs': {'cose_sign1': hexv(n['tampered_D1_cose'])},
        # No error code is specified for this rejection yet.
        'expected': {'valid': False},
    })
    cases.append({
        'id': 'stale_epoch', 'type': 'validation', 'kind': 'data_unit',
        'inputs': {'unit_id': hexv(n['stale_epoch_unit_id'])},
        # LFCP-WIRE-01 section 62, error code 14.
        'expected': {'valid': False, 'error': {'code': 'STALE_DATA_EPOCH', 'detail': n['stale_epoch_expected']}},
    })
    for x in fixtures['negatives']:
        case = {'id': x['id'], 'type': 'validation', 'kind': x['kind'], 'description': x['description'],
                'inputs': x['inputs']}
        if x['context']:
            case['context'] = x['context']
        case['derivation'] = x['derivation']
        case['expected'] = x['expected']
        cases.append(case)

    return {
        'format': 'lfcp-vector-format/1',
        'suite': {
            'id': meta['vector_spec'],
            'version': '01',
            'specification': {'id': meta['wire_spec'], 'revision': 'working-draft'},
            'description': 'Byte-exact LFCP Wire interoperability vectors: Principals, Control Records, '
                           'ownership transfer, Key Packages, Data Units, invitation URI, session '
                           'messages and negative validation cases.',
            'conventions': {
                'cose_sign1_tag_policy': meta['cose_sign1_tag_policy'],
                'cbor_profile': meta['cbor_profile'],
            },
            'warning': meta['warning'],
        },
        'fixtures': {
            'resource': {k: hexv(r[k]) for k in ('id', 'dek0', 'dek1')},
            'session': {k: hexv(w[k]) for k in session_fields},
        },
        'cases': cases,
    }

# -----------------------------------------------------------------------------
# Markdown formatting.
# -----------------------------------------------------------------------------

def wrap_hex(s: str, width: int = 96) -> str:
    return '\n'.join(s[i:i+width] for i in range(0, len(s), width))


def code_hex(s: str) -> str:
    return '```text\n' + wrap_hex(s) + '\n```'


def md_row(k: str, v: str) -> str:
    return f'| `{k}` | `{v}` |'


def generate_markdown(f: dict):
    P = f['principals']; R = f['resource']; C = f['control']; K = f['key_packages']; D = f['data_units']; W = f['wire']; I = f['invite']; N = f['negative']
    lines: list[str] = []
    a = lines.append
    a('# LFCP-TEST-VECTORS-01: Interoperability Test Vectors')
    a('')
    a('**Status:** Working Draft 0.1  ')
    a('**Companion specification:** `LFCP-WIRE-01`  ')
    a('**Vector set:** `LFCP-TEST-VECTORS-01`')
    a('')
    a('This document defines deterministic byte-level fixtures for independent LFCP implementations. A conforming implementation should be able to reproduce or consume these values exactly, subject to the clarifications in Section 2.')
    a('')
    a('> **Security warning:** every private key, DEK and derived key in this document is public test material. They MUST NOT be reused in production and MUST NOT be used as production defaults.')
    a('')
    a('## 1. What these vectors test')
    a('')
    a('The suite covers deterministic CBOR, Principal IDs, LFCP DEK commitments, COSE_Sign1, Control Chain records, capability invitation and claim, ownership transfer, route migration, HPKE Key Packages, Data Unit encryption, actor hash chaining, strict epoch cutoff, invitation URIs, session handshake messages, Resource, Control, Data, Key Package and Snapshot transport messages, PING/PONG, NACK and ERROR, Have Vectors, encrypted signed Snapshots with canonical frontiers, and negative validation cases.')
    a('')
    a('The test profile uses `org.lfcp.test.raw.v1`; its decrypted Data Unit plaintext is opaque bytes and has no application-level merge semantics. This isolates Wire Protocol interoperability from Automerge/Yjs behavior.')
    a('')
    a('## 2. Clarifications incorporated into LFCP-WIRE-01')
    a('')
    a('Producing the first byte-exact vectors exposed ambiguities around COSE tagging and Snapshot AAD. Those clarifications are now incorporated directly into the consolidated `LFCP-WIRE-01` Working Draft.')
    a('')
    a('The canonical rules used by this suite are therefore normative WIRE-01 rules:')
    a('')
    a('1. persistent LFCP `COSE_Sign1` objects use the untagged four-element array form;')
    a('2. the unprotected COSE header is empty;')
    a('3. deterministic CBOR follows the explicit WIRE-01 canonical rules;')
    a('4. Snapshot frontiers are canonicalized and Snapshot AAD is the exact seven-element array defined by WIRE-01.')
    a('')
    a('The byte-exact Snapshot vectors `SNAPSHOT-01` and `SNAPSHOT-02` (Section 18) follow these consolidated rules.')
    a('')
    a('## 3. Conformance rules')
    a('')
    a('- Hex strings are lowercase and contain no `0x` prefix.')
    a('- Multi-line hex blocks are line-wrapped only for readability; implementations concatenate lines before decoding.')
    a('- Object IDs are SHA-256 of the exact, untagged COSE_Sign1 bytes shown here.')
    a('- COSE protected headers are `{1: -8, 4: principal_id}`, where `1` is `alg`, `-8` is EdDSA, and `4` is `kid`.')
    a('- COSE unprotected headers are the empty map `{}`; external AAD is empty.')
    a('- HPKE is Base mode with `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, and `ChaCha20Poly1305`.')
    a('- Production HPKE uses fresh randomness. The vectors expose a fixed ephemeral private key solely so sender-side output is reproducible.')
    a('')
    a('## 4. Deterministic fixture inputs')
    a('')
    a('Test values are generated as `SHA-256(ASCII(label))`, using labels shown by the generator. The machine-readable JSON and generator script shipped beside this document are the authoritative source for all fixture inputs.')
    a('')
    a('### 4.1 Resource and DEKs')
    a('')
    a('| Field | Hex |')
    a('|---|---|')
    for k in ['id','dek0','dek0_commitment','dek1','dek1_commitment']:
        a(md_row(k, R[k]))
    a('')

    for pname in ['owner','bob','carol','invite']:
        p = P[pname]
        a(f'### 4.{2 + ["owner","bob","carol","invite"].index(pname)} Principal: {pname.upper()}')
        a('')
        a('| Field | Hex |')
        a('|---|---|')
        for k in ['ed25519_seed','ed25519_public','x25519_private','x25519_public','principal_id']:
            a(md_row(k, p[k]))
        a('')
        a('Principal Descriptor CBOR:')
        a('')
        a(code_hex(p['descriptor_cbor']))
        a('')

    a('## 5. Primitive vector: Principal ID')
    a('')
    a('For each Principal:')
    a('')
    a('```text\nprincipal_id = SHA-256(\n  ASCII("LFCP-PRINCIPAL-v1") ||\n  ed25519_public_key ||\n  x25519_public_key\n)\n```')
    a('')
    a('An implementation MUST reproduce the IDs in Section 4 exactly and MUST reject a Principal Descriptor whose transmitted ID differs from the recomputed ID.')
    a('')

    a('## 6. Primitive vector: DEK commitment')
    a('')
    a('For epoch `E`:')
    a('')
    a('```text\ndek_commitment = SHA-256(\n  ASCII("LFCP-DEK-v1") || resource_id || uint64_be(E) || DEK\n)\n```')
    a('')
    a(f'Epoch 0 expected: `{R["dek0_commitment"]}`  ')
    a(f'Epoch 1 expected: `{R["dek1_commitment"]}`')
    a('')

    a('## 7. COSE_Sign1 baseline')
    a('')
    a('Every signed object in this suite uses the same protected-header form. For the OWNER Principal, protected header CBOR is:')
    a('')
    # Protected header can be read from C0.
    a(code_hex(C['C0_genesis']['protected_header_cbor']))
    a('')
    a('The signature input is the deterministic CBOR encoding of:')
    a('')
    a('```text\n["Signature1", protected_bstr, h\'\', payload_bstr]\n```')
    a('')

    a('## 8. Control Chain vectors')
    a('')
    ctrl_desc = [
        ('C0_genesis', 'GENESIS, owner=OWNER, profile=org.lfcp.test.raw.v1, epoch=0, route A'),
        ('C1_grant_bob', 'CAPABILITY_GRANT, BOB gets data/read + data/write + snapshot/publish'),
        ('C2_invite_grant', 'CAPABILITY_GRANT, one-time Invitation Principal gets data/read + data/write + invite/claim'),
        ('C3_invite_claim_carol', 'CAPABILITY_CLAIM, Invitation Principal transfers read/write to CAROL'),
        ('C4_owner_transfer_commit', 'OWNER_TRANSFER_COMMIT, ownership moves OWNER -> BOB'),
        ('C5_route_update', 'ROUTE_UPDATE, route version 1, coordinator moves to Server B'),
        ('C6_key_epoch_1', 'KEY_EPOCH, epoch 1, old epoch cutoff BOB<=2'),
    ]
    for idx, (name, desc) in enumerate(ctrl_desc):
        x = C[name]
        a(f'### 8.{idx+1} {name}: {desc}')
        a('')
        a(f'Record ID: `{x["record_id"]}`  ')
        a(f'Signer fixture: `{x["signer"]}`')
        a('')
        a('Payload CBOR:')
        a('')
        a(code_hex(x['payload_cbor']))
        a('')
        a('Sig_structure CBOR:')
        a('')
        a(code_hex(x['sig_structure_cbor']))
        a('')
        a('Exact COSE_Sign1:')
        a('')
        a(code_hex(x['cose_sign1']))
        a('')

    a('## 9. Ownership transfer standalone objects')
    a('')
    T = f['transfers']
    a(f'Transfer nonce: `{T["nonce"]}`')
    a('')
    a(f'Offer ID: `{T["offer_id"]}`')
    a('')
    a('Offer payload CBOR:')
    a('')
    a(code_hex(T['offer_payload_cbor']))
    a('')
    a('Offer COSE_Sign1:')
    a('')
    a(code_hex(T['offer_cose_sign1']))
    a('')
    a(f'Acceptance ID: `{T["accept_id"]}`')
    a('')
    a('Acceptance payload CBOR:')
    a('')
    a(code_hex(T['accept_payload_cbor']))
    a('')
    a('Acceptance COSE_Sign1:')
    a('')
    a(code_hex(T['accept_cose_sign1']))
    a('')
    a('The `C4_owner_transfer_commit` record in Section 8 embeds the exact offer and acceptance COSE byte strings. A verifier must confirm the offer references `C3`, names BOB as proposed owner, expects control sequence 4, the acceptance references the exact offer ID, and all three signatures match their required Principals.')
    a('')

    a('## 10. HPKE self-test against RFC 9180')
    a('')
    a('The generator first verifies its HPKE implementation against RFC 9180 Appendix A.2.1, Base mode for X25519/HKDF-SHA256/ChaCha20Poly1305. Generation aborts if `enc`, shared secret, key, base nonce, or first ciphertext differ from the RFC fixture. This prevents LFCP-specific vectors from being built on an unverified HPKE implementation.')
    a('')

    a('## 11. Key Package vectors')
    a('')
    kp_desc = [
        ('KP0_bob_epoch0','OWNER -> BOB, epoch 0, authorized at C1'),
        ('KPI_invite_epoch0','OWNER -> Invitation Principal, epoch 0, authorized at C2'),
        ('KPC_carol_epoch1','BOB -> CAROL, epoch 1, authorized at C6'),
    ]
    for idx,(name,desc) in enumerate(kp_desc):
        x=K[name]
        a(f'### 11.{idx+1} {name}: {desc}')
        a('')
        for label,key in [
            ('HPKE ephemeral private key', 'hpke_ephemeral_private'),
            ('HPKE `info` CBOR','hpke_info_cbor'),
            ('HPKE AAD CBOR','hpke_aad_cbor'),
            ('HPKE `enc`','hpke_enc'),
            ('HPKE shared secret','hpke_shared_secret'),
            ('HPKE key','hpke_key'),
            ('HPKE base nonce','hpke_base_nonce'),
            ('HPKE ciphertext','hpke_ciphertext'),
            ('Key Package ID','package_id')]:
            a(f'**{label}:**')
            a('')
            a(code_hex(x[key]))
            a('')
        a('Key Package payload CBOR:')
        a('')
        a(code_hex(x['payload_cbor']))
        a('')
        a('Exact signed Key Package COSE_Sign1:')
        a('')
        a(code_hex(x['cose_sign1']))
        a('')

    a('## 12. Data Unit vectors')
    a('')
    du_desc = [
        ('D1_bob_epoch0_seq1','BOB epoch 0, seq 1, previous=null, valid'),
        ('D2_bob_epoch0_seq2','BOB epoch 0, seq 2, previous=D1, valid'),
        ('D3_bob_epoch0_seq3_stale','BOB epoch 0, seq 3, cryptographically valid but stale after C6 cutoff'),
        ('D4_carol_epoch1_seq1','CAROL epoch 1, seq 1, valid under DEK1'),
    ]
    for idx,(name,desc) in enumerate(du_desc):
        x=D[name]
        a(f'### 12.{idx+1} {name}: {desc}')
        a('')
        a(f'Plaintext UTF-8: `{x["plaintext_utf8"]}`')
        a('')
        for label,key in [
            ('Actor key','actor_key'),('Nonce','nonce'),('AAD CBOR','aad_cbor'),('Ciphertext + tag','ciphertext'),('Payload CBOR','payload_cbor'),('Data Unit ID','unit_id')]:
            a(f'**{label}:**')
            a('')
            a(code_hex(x[key]))
            a('')
        a('Exact Data Unit COSE_Sign1:')
        a('')
        a(code_hex(x['cose_sign1']))
        a('')

    a('### 12.5 Strict epoch-cutoff expectation')
    a('')
    a('`C6_key_epoch_1` records the final epoch-0 frontier as BOB contiguous sequence `2`. Therefore `D3_bob_epoch0_seq3_stale` is intentionally valid at the cryptographic layer but MUST NOT be merged automatically after C6 is known. Expected result: `STALE_DATA_EPOCH` or equivalent local quarantine state.')
    a('')

    a('## 13. Have Vector normalization vector')
    a('')
    a('The wire vector `DATA_HAVE_with_hole` represents:')
    a('')
    a('```text\nBOB has 1..100 contiguously and 105..107 additionally.\nMissing: 101..104.\n```')
    a('')
    a('Exact LFCP message bytes are in Section 16.')
    a('')

    a('## 14. Invitation vector')
    a('')
    a('Invitation secret CBOR:')
    a('')
    a(code_hex(I['secret_cbor']))
    a('')
    a(f'Invitation secret Base64url: `{I["secret_b64url"]}`')
    a('')
    a(f'Resource Base64url: `{I["resource_b64url"]}`  ')
    a(f'Grant ID Base64url: `{I["grant_id_b64url"]}`')
    a('')
    a('Canonical bearer invitation URI:')
    a('')
    a('```text')
    a(I['uri'])
    a('```')
    a('')
    a('A client decoding this URI MUST derive the Invitation Principal public keys from the secret, recompute its Principal ID, and verify that it equals the subject of `C2_invite_grant`.')
    a('')

    a('## 15. Session authentication vector')
    a('')
    for k in ['client_nonce','server_nonce','session_id','server_id']:
        a(f'**{k}:** `{W[k]}`')
    a('')
    a('AUTH transcript payload CBOR:')
    a('')
    a(code_hex(W['auth_transcript_cbor']))
    a('')
    a('AUTH proof COSE_Sign1:')
    a('')
    a(code_hex(W['auth_proof_cose_sign1']))
    a('')
    a('The proof is signed by BOB, whose Principal is the session Principal in HELLO.')
    a('')

    a('## 16. Exact WebSocket message vectors')
    a('')
    wire_desc = [
        ('HELLO','message type 0'),('CHALLENGE','message type 1; correlation=HELLO msg id'),('AUTH','message type 2; correlation=CHALLENGE msg id'),('READY','message type 3; correlation=AUTH msg id'),('RESOURCE_OPEN','message type 12; latest head=C6; live Data+Control flags'),('DATA_HAVE_with_hole','message type 30'),('DATA_PUT_D1_D2','message type 33; exact D1 and D2 COSE byte strings')]
    for idx,(name,desc) in enumerate(wire_desc):
        a(f'### 16.{idx+1} {name}: {desc}')
        a('')
        a(code_hex(W[name]))
        a('')
    for idx,(name,m) in enumerate(f['messages'].items(), start=len(wire_desc)+1):
        a(f'### 16.{idx} {name}: {m["description"]}')
        a('')
        a(code_hex(m['message_cbor']))
        a('')

    a('## 17. Negative test vectors')
    a('')
    a('### 17.1 Principal descriptor ID mismatch')
    a('')
    a('Take the BOB Principal Descriptor from Section 4 and flip any bit of field `0` without changing fields `1` or `2`. Expected result: descriptor rejection before it is used for authorization or signature verification.')
    a('')
    a('### 17.2 COSE payload tamper')
    a('')
    a('The following bytes are a one-byte mutation of D1. Expected result: reject the object; it must not be assigned a valid Data Unit identity or merged.')
    a('')
    a(code_hex(N['tampered_D1_cose']))
    a('')
    a('### 17.3 Actor equivocation')
    a('')
    a(f'Original D2 ID: `{N["actor_equivocation_original_D2_id"]}`  ')
    a(f'Conflicting D2 ID: `{N["actor_equivocation_conflicting_D2_id"]}`')
    a('')
    a('Both objects carry `(resource, actor=BOB, seq=2)` and both are independently well-signed, but the bytes differ. Expected result: `ACTOR_EQUIVOCATION`; a client/server MUST NOT silently choose either object.')
    a('')
    a('Conflicting D2 exact COSE bytes:')
    a('')
    a(code_hex(N['actor_equivocation_conflicting_D2_cose']))
    a('')
    a('### 17.4 AEAD AAD mismatch')
    a('')
    a('Decrypt D1 with the same actor key and nonce but change any AAD field, for example `seq=2`. Expected result: ChaCha20-Poly1305 authentication failure.')
    a('')
    a('### 17.5 Wrong HPKE recipient')
    a('')
    a('Attempt to decrypt `KP0_bob_epoch0` using CAROL\'s X25519 private key. Expected result: HPKE/AEAD open failure; no DEK is returned.')
    a('')
    a('### 17.6 Stale epoch')
    a('')
    a(f'Stale Data Unit ID: `{N["stale_epoch_unit_id"]}`  ')
    a(f'Expected: `{N["stale_epoch_expected"]}`')
    a('')
    a('### 17.7 Control compare-and-swap mismatch')
    a('')
    a('Submit a syntactically valid C6 candidate with `CONTROL_PUT.expected_head = C4` while the coordinator current head is C5. Expected response: `NACK(CONTROL_HEAD_MISMATCH)` and current head C5 in machine-readable details. The candidate MUST NOT be committed.')
    a('')
    a('### 17.8 Invitation double claim')
    a('')
    a('After C3 consumes the C2 invitation grant with `claim_limit=1`, a second `CAPABILITY_CLAIM` referencing C2 MUST be rejected by the current Control Coordinator. It must not create a second valid Control Chain record.')
    a('')
    a('### 17.9 Non-deterministic CBOR signed object')
    a('')
    a('Re-encode any signed payload using a non-preferred integer width or non-deterministic map ordering and sign those different bytes. Even with a mathematically valid Ed25519 signature, a WIRE-01 validator claiming deterministic-CBOR conformance SHOULD reject the object as non-canonical. This requirement should be stated explicitly in the next WIRE draft.')
    a('')
    a('### 17.10 Machine-readable negative vectors')
    a('')
    a('Each vector below changes exactly one property of a published positive case and recomputes only what that change forces (ciphertext, signature). The JSON carries the same data as `validation` cases with `derivation` (base case, mutation, rule, rationale) and, where the outcome depends on state, `context`. An `error.code` is given only where `LFCP-WIRE-01` names the code for that rejection.')
    a('')
    for idx, x in enumerate(f['negatives']):
        d = x['derivation']; e = x['expected']
        a(f'#### 17.10.{idx+1} {x["id"]}: {x["description"]}')
        a('')
        a(f'- Base case: `{d["base_case"]}`')
        show = lambda v: v['hex'] if isinstance(v, dict) and 'hex' in v else json.dumps(v)
        a(f'- Mutation: {d["mutation"]["field"]}: `{show(d["mutation"]["from"])}` → `{show(d["mutation"]["to"])}`')
        a(f'- Rule ({d["rule"]["section"]}): {d["rule"]["text"]}')
        outcome = 'invalid'
        if 'disposition' in e:
            outcome += f', {e["disposition"]}'
        outcome += f', error code `{e["error"]["code"]}`' if 'error' in e else ', no error code specified'
        a(f'- Expected: {outcome}')
        a(f'- Why: {d["why"]}')
        a('')
        for k, v in x['inputs'].items():
            a(f'{k}:')
            a('')
            a(code_hex(v['hex']))
            a('')

    a('## 18. Snapshot vectors')
    a('')
    a('`SNAPSHOT-01` and `SNAPSHOT-02` are byte-exact Snapshots under the consolidated `LFCP-WIRE-01` rules. Both are published by BOB, who owns the Resource after C4 and therefore holds `snapshot/publish` (§29.2), in Data Epoch 1 at Control Head C6, using DEK1. The plaintext is opaque test bytes: Snapshot plaintext framing belongs to the application profile, not to the Wire suite.')
    a('')
    a('Derivation, with the defining sections of `LFCP-WIRE-01`:')
    a('')
    a('1. **Actor Have** (§28.1): keys `0` and `1` always; key `2` only when there are extra ranges, which are sorted, non-overlapping, non-adjacent and above `contiguous`.')
    a('2. **Canonical frontier** (§28.2): the actor-have entries sorted by raw 32-byte Principal ID, one entry per Principal. BOB (`3ddf…`) sorts before CAROL (`a6e4…`).')
    a('3. **Snapshot AAD** (§29.1.3): deterministic CBOR of `["LFCP-SNAPSHOT-v1", resource_id, data_epoch, publisher_id, snapshot_sequence, control_head, frontier]`, i.e. payload fields `0`..`5` after the label.')
    a('4. **Snapshot key** (§29.1.1): `HKDF-Expand(HKDF-Extract(resource_id || uint64_be(data_epoch), DEK), ASCII("LFCP-SNAPSHOT-KEY-v1") || publisher_id, 32)`.')
    a('5. **Nonce** (§29.1.2): `0x00000000 || uint64_be(snapshot_sequence)`.')
    a('6. **Encryption** (§29.1.4): ChaCha20-Poly1305 Seal of the plaintext with that key, nonce and AAD; the result includes the 16-byte tag.')
    a('7. **Payload** (§29): `{0: resource_id, 1: data_epoch, 2: publisher_id, 3: snapshot_sequence, 4: control_head, 5: frontier, 6: ciphertext}`.')
    a('8. **COSE_Sign1** (§10, §29): untagged four-element array, protected header `{1: -8, 4: publisher_id}`, empty unprotected header.')
    a('9. **Signature** (§10.5): Ed25519 by BOB over the deterministic CBOR `Sig_structure`.')
    a('10. **Snapshot ID** (§29): `SHA-256(exact COSE_Sign1 bytes)`.')
    a('')
    S = f['snapshots']
    for idx, (name, x) in enumerate(S.items()):
        a(f'### 18.{idx+1} {name}')
        a('')
        a(x['note'])
        a('')
        a(f'Publisher `{x["publisher"]}`, Data Epoch `{x["data_epoch"]}`, Snapshot Sequence `{x["snapshot_sequence"]}`, plaintext UTF-8 `{x["plaintext_utf8"]}`.')
        a('')
        for label, key in [
            ('Control Head (C6)', 'control_head'), ('Canonical frontier CBOR', 'frontier_cbor'), ('Snapshot AAD CBOR', 'aad_cbor'),
            ('Snapshot key', 'snapshot_key'), ('Nonce', 'nonce'), ('Ciphertext + tag', 'ciphertext'), ('Payload CBOR', 'payload_cbor'),
            ('Protected header CBOR', 'protected_header_cbor'), ('Sig_structure CBOR', 'sig_structure_cbor'), ('Snapshot ID', 'snapshot_id')]:
            a(f'**{label}:**')
            a('')
            a(code_hex(x[key]))
            a('')
        a('Exact Snapshot COSE_Sign1:')
        a('')
        a(code_hex(x['cose_sign1']))
        a('')

    a('## 19. Minimum implementation test matrix')
    a('')
    a('| Area | Must pass |')
    a('|---|---|')
    matrix = [
        ('CBOR','Principal Descriptor, every Control payload, wire envelopes'),
        ('Principal','all four Principal IDs'),
        ('COSE','C0..C6, ownership offer/accept, Key Packages, D1/D2/D4, AUTH proof'),
        ('Control','linear chain C0→C6, owner transition at C4, route transition at C5'),
        ('HPKE','RFC 9180 A.2.1 self-test + all three LFCP Key Packages'),
        ('Data crypto','D1/D2/D4 decrypt; D3 decrypts cryptographically but is rejected semantically'),
        ('Anti-entropy','Have Vector hole 101..104 inferred correctly'),
        ('Snapshot','SNAPSHOT-01/02 canonical frontier, exact AAD, key, nonce, decrypt, signature, Snapshot ID'),
        ('Invitation','URI decode, Principal reconstruction, C2 subject match, C3 claim'),
        ('Wire','HELLO→CHALLENGE→AUTH→READY exact decoding and signature verification; every Section 16 message decodes to its §33 body'),
        ('Negative','tamper, wrong recipient, equivocation, stale epoch, CAS mismatch, double claim'),
    ]
    for x,y in matrix:
        a(f'| {x} | {y} |')
    a('')

    a('## 20. Machine-readable artifacts')
    a('')
    a('The publication SHOULD ship three files together:')
    a('')
    a('```text\nLFCP-TEST-VECTORS-01.md\nLFCP-TEST-VECTORS-01.json\ngenerate_lfcp_test_vectors_01.py\n```')
    a('')
    a('The JSON contains the same exact fixture values without prose, laid out as an `lfcp-vector-format/1` suite (`schemas/lfcp-vector-format-1.schema.json` in the spec repository). The Python generator recomputes all values and aborts if its HPKE implementation fails the official RFC 9180 A.2.1 check.')
    a('')

    a('## 21. Conformance philosophy')
    a('')
    a('A protocol becomes interoperable when two teams can write implementations without sharing source code and still produce the same bytes, reject the same invalid objects, and converge on the same durable state. These vectors are intended to make that claim mechanically testable rather than aspirational.')
    a('')
    a('Before LFCP-WIRE-01 reaches Release Candidate, at least one implementation in two independent language stacks SHOULD pass this suite end-to-end.')
    a('')

    OUT_MD.write_text('\n'.join(lines) + '\n', encoding='utf-8')

def main() -> None:
    global OUT_MD, OUT_JSON
    parser = argparse.ArgumentParser(description='Generate LFCP-TEST-VECTORS-01 JSON and Markdown.')
    parser.add_argument('--out-dir', type=Path, default=Path(__file__).resolve().parent,
                        help='directory to write the vector files into (default: this script\'s directory)')
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    OUT_MD = args.out_dir / 'LFCP-TEST-VECTORS-01.md'
    OUT_JSON = args.out_dir / 'LFCP-TEST-VECTORS-01.json'
    fixtures = generate()
    generate_markdown(fixtures)
    print(OUT_MD)
    print(OUT_JSON)


if __name__ == '__main__':
    main()
