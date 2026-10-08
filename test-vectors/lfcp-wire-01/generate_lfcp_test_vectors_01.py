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


def cbor_decode(b: bytes, i: int = 0):
    """Decode one item of the deterministic subset above; returns (value, next index)."""
    major, info = b[i] >> 5, b[i] & 0x1f
    i += 1
    if info < 24:
        n = info
    else:
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        n, i = int.from_bytes(b[i:i + size], 'big'), i + size
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major == 2:
        return b[i:i + n], i + n
    if major == 3:
        return b[i:i + n].decode('utf-8'), i + n
    if major == 4:
        items = []
        for _ in range(n):
            item, i = cbor_decode(b, i)
            items.append(item)
        return items, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = cbor_decode(b, i)
            out[k], i = cbor_decode(b, i)
        return out, i
    if major == 6:
        return cbor_decode(b, i)  # tag: the tagged item
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], i
    raise ValueError('unsupported CBOR item')


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
# Minimal Ed25519 group arithmetic (RFC 8032 §5.1), used only to build and
# self-check the strict-verification negatives of LFCP-WIRE-01 §10.5.1.
# -----------------------------------------------------------------------------

ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)
ED_IDENTITY = (0, 1)


def ed_add(P, Q):
    (x1, y1), (x2, y2) = P, Q
    t = ED_D * x1 * x2 * y1 * y2 % ED_P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, ED_P - 2, ED_P) % ED_P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, ED_P - 2, ED_P) % ED_P
    return (x3, y3)


def ed_mul(k: int, P):
    Q = ED_IDENTITY
    while k:
        if k & 1:
            Q = ed_add(Q, P)
        P = ed_add(P, P)
        k >>= 1
    return Q


def ed_decode(b: bytes):
    """RFC 8032 §5.1.3 point decoding; only canonical encodings are accepted."""
    y = int.from_bytes(b, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    assert y < ED_P, 'non-canonical y'
    u, v = (y * y - 1) % ED_P, (ED_D * y * y + 1) % ED_P
    x = u * pow(v, 3, ED_P) * pow(u * pow(v, 7, ED_P), (ED_P - 5) // 8, ED_P) % ED_P
    if v * x * x % ED_P != u:
        x = x * ED_SQRT_M1 % ED_P
    assert v * x * x % ED_P == u, 'not a curve point'
    assert not (x == 0 and sign), 'x = 0 with the sign bit set'
    if x & 1 != sign:
        x = ED_P - x
    return (x, y)


ED_B = ed_decode(bytes.fromhex('5866666666666666666666666666666666666666666666666666666666666666'))


def ed_small_order(P) -> bool:
    return ed_mul(8, P) == ED_IDENTITY


def ed_secret_scalar(seed: bytes) -> int:
    a = int.from_bytes(hashlib.sha512(seed).digest()[:32], 'little')
    a &= (1 << 254) - 8
    return a | (1 << 254)


def ed_encode(P) -> bytes:
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def ed_try_decode(b: bytes):
    try:
        return ed_decode(b)
    except AssertionError:
        return None


def ed_verify_strict(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """LFCP-WIRE-01 §10.5.1, rules 1-4, in the stated order."""
    if len(pk) != 32 or len(sig) != 64:
        return False
    A, R = ed_try_decode(pk), ed_try_decode(sig[:32])  # rule 2
    if A is None or R is None:
        return False
    S = int.from_bytes(sig[32:], 'little')
    if S >= ED_L:  # rule 1
        return False
    if ed_small_order(A) or ed_small_order(R):  # rule 3
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), 'little') % ED_L
    return ed_mul(S, ED_B) == ed_add(R, ed_mul(k, A))  # rule 4, cofactorless


def ed_verify_cofactored(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """The cofactored equation with canonical decoding: what §10.5.1 is stricter than."""
    A, R = ed_try_decode(pk), ed_try_decode(sig[:32])
    S = int.from_bytes(sig[32:], 'little')
    if A is None or R is None or S >= ED_L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), 'little') % ED_L
    return ed_mul(8, ed_mul(S, ED_B)) == ed_mul(8, ed_add(R, ed_mul(k, A)))

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


def hpke_derive_key_pair_x25519(ikm: bytes) -> bytes:
    """RFC 9180 §7.1.3 DeriveKeyPair for DHKEM(X25519, HKDF-SHA256): the private key."""
    suite_id = b'KEM' + i2osp(KEM_ID, 2)
    dkp_prk = hpke_labeled_extract(b'', suite_id, b'dkp_prk', ikm)
    return hpke_labeled_expand(dkp_prk, suite_id, b'sk', b'', 32)


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
    ikmE = bytes.fromhex('909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b')
    skE = bytes.fromhex('f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600')
    assert hpke_derive_key_pair_x25519(ikmE) == skE  # §7.1.3 DeriveKeyPair
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

    # C7-C10: a continuation of the chain for the delegation and revocation
    # decisions (SPEC-PATCH-03 / G-CAP4, DV4). BOB (owner) lets CAROL
    # delegate; CAROL delegates to OWNER (the former owner, who holds no
    # implicit authority any more); OWNER delegates further to INVITE;
    # CAROL then revokes that grandchild, which her revoke authority covers.
    grant_carol_body = {0: CAROL.descriptor(), 1: [1, 2, 4, 5], 2: [1, 4]}
    C7 = control_record(7, C6['id'], 1, BOB, grant_carol_body)
    grant_owner_body = {0: OWNER.descriptor(), 1: [1, 4], 2: [1], 3: C7['id']}
    C8 = control_record(8, C7['id'], 1, CAROL, grant_owner_body)
    grant_invite_body = {0: INVITE.descriptor(), 1: [1], 2: [], 3: C8['id']}
    C9 = control_record(9, C8['id'], 1, OWNER, grant_invite_body)
    revoke_c9_body = {0: C9['id']}
    C10 = control_record(10, C9['id'], 2, CAROL, revoke_c9_body)

    # Cryptographically valid but stale unit after strict cutoff.
    D3_STALE = data_unit(BOB, 0, 3, D2['id'], C3['id'], b'LFCP stale offline unit #3', DEK0)

    # Key package for Bob, epoch 0 at C1.
    kp0_info = cbor(['LFCP-KEY-v1', RESOURCE, 0, BOB.pid])
    kp0_aad = cbor([RESOURCE, 0, C1['id']])
    # SPEC-PATCH-03 / G-KP2: the published input is ikmE; skE = DeriveKeyPair(ikmE).
    kp0_ikmE = h('LFCP-TV-HPKE-BOB-E0-IKM')
    kp0_skE = hpke_derive_key_pair_x25519(kp0_ikmE)
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
           'info': kp0_info, 'aad': kp0_aad, 'ephemeral_ikm': kp0_ikmE, 'ephemeral_sk': kp0_skE}

    # Key package for Invitation Principal at C2.
    kpi_info = cbor(['LFCP-KEY-v1', RESOURCE, 0, INVITE.pid])
    kpi_aad = cbor([RESOURCE, 0, C2['id']])
    # SPEC-PATCH-03 / G-KP2: the published input is ikmE; skE = DeriveKeyPair(ikmE).
    kpi_ikmE = h('LFCP-TV-HPKE-INVITE-E0-IKM')
    kpi_skE = hpke_derive_key_pair_x25519(kpi_ikmE)
    hpi = hpke_seal_with_ephemeral(INVITE.x_pk, kpi_skE, kpi_info, kpi_aad, DEK0)
    assert hpke_open(INVITE.x_sk_raw, hpi['enc'], kpi_info, kpi_aad, hpi['ct']) == DEK0
    kpi_payload_obj = {0: RESOURCE, 1: 0, 2: INVITE.pid, 3: C2['id'], 4: OWNER.pid, 5: hpi['enc'], 6: hpi['ct']}
    KPI_cose, KPI_payload, KPI_prot, KPI_sig = cose_sign1(kpi_payload_obj, OWNER)
    KPI = {'cose': KPI_cose, 'payload': KPI_payload, 'protected': KPI_prot, 'sig_structure': KPI_sig, 'id': sha256(KPI_cose), **hpi,
           'info': kpi_info, 'aad': kpi_aad, 'ephemeral_ikm': kpi_ikmE, 'ephemeral_sk': kpi_skE}

    # Key package for Carol, epoch 1 at C6, sent by owner Bob.
    kpc_info = cbor(['LFCP-KEY-v1', RESOURCE, 1, CAROL.pid])
    kpc_aad = cbor([RESOURCE, 1, C6['id']])
    # SPEC-PATCH-03 / G-KP2: the published input is ikmE; skE = DeriveKeyPair(ikmE).
    kpc_ikmE = h('LFCP-TV-HPKE-CAROL-E1-IKM')
    kpc_skE = hpke_derive_key_pair_x25519(kpc_ikmE)
    hpc = hpke_seal_with_ephemeral(CAROL.x_pk, kpc_skE, kpc_info, kpc_aad, DEK1)
    assert hpke_open(CAROL.x_sk_raw, hpc['enc'], kpc_info, kpc_aad, hpc['ct']) == DEK1
    kpc_payload_obj = {0: RESOURCE, 1: 1, 2: CAROL.pid, 3: C6['id'], 4: BOB.pid, 5: hpc['enc'], 6: hpc['ct']}
    KPC_cose, KPC_payload, KPC_prot, KPC_sig = cose_sign1(kpc_payload_obj, BOB)
    KPC = {'cose': KPC_cose, 'payload': KPC_payload, 'protected': KPC_prot, 'sig_structure': KPC_sig, 'id': sha256(KPC_cose), **hpc,
           'info': kpc_info, 'aad': kpc_aad, 'ephemeral_ikm': kpc_ikmE, 'ephemeral_sk': kpc_skE}

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
        ('ACK_DATA_PUT_D1_D2', 'message type 90; acknowledges DATA_PUT_D1_D2: field 0 = 33 (DATA_PUT), the accepted D1 and D2 IDs, durable (§59)',
         wire_msg(90, mid('ACK'), {0: 33, 1: [D1['id'], D2['id']], 2: True}, correlation=dp_mid)),
        ('NACK_CONTROL_HEAD_MISMATCH', 'message type 91; error code 10 CONTROL_HEAD_MISMATCH with the current head C5 as details, answering the CONTROL_PUT of stale_control_head_put (§47, §60)',
         wire_msg(91, mid('NACK-CONTROL-HEAD-MISMATCH'), {0: 10, 2: C5['id']}, correlation=mid('CONTROL-PUT'))),
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
            context=None, cddl=None, note=None):
        NEG.append({
            'id': case_id, 'kind': kind, 'description': title, 'note': note,
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
    CLIENT_NOTE = ('Client-local rejection (SPEC-PATCH-01 / N3): only a client holding the DEK can detect it; '
                   'there is no wire error code.')

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
        '(§26.3: a Data Unit is eligible for merge only if "the unit decrypts successfully"; '
        '"A client MUST NOT merge a Data Unit that fails AEAD authentication and SHOULD surface it to the application.")',
        'The receiver reconstructs the canonical AAD, so decryption fails; accepting it would require guessing alternative encodings of signed or authenticated structures.',
        {'cose_sign1': hexv(du_nc), 'noncanonical_aad_cbor': hexv(noncanon_aad)},
        {'valid': False, 'disposition': 'reject'},
        cddl=('data-unit', 'pass'),
        note=CLIENT_NOTE)

    # 2. Tagged COSE_Sign1 (tag 18).
    neg('tagged_cose_D1', 'data_unit', 'D1 wrapped in COSE_Sign1 tag 18',
        'D1_bob_epoch0_seq1', 'outer CBOR tag', 'none', 'tag 18',
        'LFCP-WIRE-01 §10',
        'A strict LFCP-WIRE-01 implementation MUST reject a tagged persistent LFCP object as non-canonical, with `MALFORMED_MESSAGE`.',
        'The object ID is SHA-256 of the exact bytes; a tagged copy would be a second, different object for the same content.',
        {'cose_sign1': hexv(b'\xd2' + D1['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
        cddl=('data-unit', 'fail'))

    # 3. Invalid Ed25519 signature: last signature byte flipped.
    bad_sig = bytearray(D1['cose']); bad_sig[-1] ^= 0x01; bad_sig = bytes(bad_sig)
    neg('invalid_signature_D1', 'data_unit', 'D1 with one signature bit flipped',
        'D1_bob_epoch0_seq1', 'signature byte 63', hexv(D1['cose'][-1:]), hexv(bad_sig[-1:]),
        'LFCP-WIRE-01 §10.5, §26.3',
        'A receiver MUST reject a signed object whose signature does not verify under the public key of the Principal '
        'named by `kid` [...]. It reports `INVALID_SIGNATURE`.',
        'An unverified signature lets anyone inject Data Units in the actor\'s name.',
        {'cose_sign1': hexv(bad_sig)},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'INVALID_SIGNATURE'}},
        cddl=('data-unit', 'pass'))

    # 4. Wrong kid: D1's payload (actor BOB) signed by CAROL with kid CAROL.
    du_kid = signed_data_unit(D1['payload_obj'], CAROL)
    neg('wrong_kid_D1', 'data_unit', 'D1 payload signed by CAROL (kid CAROL) instead of the actor BOB',
        'D1_bob_epoch0_seq1', 'protected header kid (and signing key)', hexv(BOB.pid), hexv(CAROL.pid),
        'LFCP-WIRE-01 §10.1, §10.5, §26',
        'A receiver MUST reject a signed object [...] whose `kid` does not identify the Principal the object requires '
        'as signer (for example, the actor of a Data Unit). It reports `INVALID_SIGNATURE`.',
        'The signature is valid but by the wrong Principal; accepting it lets one member forge another member\'s edits.',
        {'cose_sign1': hexv(du_kid)},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'INVALID_SIGNATURE'}},
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
        'A Data Unit is eligible for merge only if: [...] 6. the unit decrypts successfully [...] '
        'A client MUST NOT merge a Data Unit that fails AEAD authentication and SHOULD surface it to the application.',
        'The AAD binds the ciphertext to its resource, epoch, actor and position; accepting it would let ciphertext be replayed elsewhere.',
        {'cose_sign1': hexv(du_aead)},
        {'valid': False, 'disposition': 'reject'},
        cddl=('data-unit', 'pass'),
        note=CLIENT_NOTE)

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

    # 6b. Message-level decisions (SPEC-PATCH-03 / G-MSG1, G-MSG5, G-HV1).
    neg('unknown_message_type', 'wire_message', 'PING sent with the unassigned message type 7',
        'PING', 'message type (envelope field 0)', 5, 7,
        'LFCP-WIRE-01 §33',
        'A message whose type is not assigned in this registry, or is an extension type that was not negotiated for the '
        'session, is rejected with `PROTOCOL_UNSUPPORTED`.',
        'A receiver cannot know the body of an unassigned type, so it cannot process the message.',
        {'message_cbor': hexv(wire_msg(7, msgid('PING'), {0: ping_payload}))},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'PROTOCOL_UNSUPPORTED'}},
        cddl=('typed-lfcp-message', 'fail'))
    neg('control_put_null_expected_head', 'control_put', 'CONTROL_PUT of C6 with a null expected head',
        'CONTROL_PUT', 'expected current Control Head (body field 1)', hexv(C5['id']), None,
        'LFCP-WIRE-01 §47',
        'A `CONTROL_PUT` always names an expected head; a null expected head is invalid, because Genesis uses `RESOURCE_HOST`.',
        'Compare-and-swap needs a head to compare against; null would bypass it.',
        {'message_cbor': hexv(wire_msg(23, msgid('CONTROL-PUT'), {0: RESOURCE, 1: None, 2: C6['cose']}))},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
        cddl=('typed-lfcp-message', 'fail'))
    neg('data_have_reversed_range', 'wire_message', 'DATA_HAVE_with_hole with the extra range written 107..105',
        'DATA_HAVE_with_hole', 'BOB extra range', [[105, 107]], [[107, 105]],
        'LFCP-WIRE-01 §48',
        'A range with `start > end`, or one that includes sequence `0`, is rejected with `MALFORMED_MESSAGE`.',
        'Unnormalized live Haves are merged, but a reversed range describes no set of sequences at all.',
        {'message_cbor': hexv(wire_msg(30, dh_mid, {0: RESOURCE, 1: [{0: BOB.pid, 1: 100, 2: [[107, 105]]}]}))},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
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
        'A client MUST NOT silently choose a branch. Neither record is accepted as the Control Head; a receiver that '
        'refuses a competing record reports `CONTROL_CONFLICT`.',
        'Choosing a branch silently would let replicas diverge on authorization and keys.',
        {'cose_sign1': hexv(C6_FORK['cose']), 'record_id': hexv(C6_FORK['id'])},
        {'valid': False, 'disposition': 'conflict', 'error': {'code': 'CONTROL_CONFLICT'}},
        context={'previous_record': ref('C5_route_update', 'record_id'), 'competing_record': ref('C6_key_epoch_1', 'record_id')},
        cddl=('control-record', 'pass'))

    # 7b. Non-canonical Key Epoch final frontier (SPEC-PATCH-03 / G-CP1): C6
    #     with its field-2 frontier unsorted or with a duplicate Principal,
    #     re-signed by BOB on top of C5.
    for cid, frontier, field_from, field_to, why in [
        ('key_epoch_frontier_unsorted', [{0: CAROL.pid, 1: 1}, actor_have_bob2], 'BOB', 'CAROL, BOB',
         'Replicas compute the cutoff from the same frontier bytes; an unsorted frontier would be a second encoding of one cutoff.'),
        ('key_epoch_frontier_duplicate', [actor_have_bob2, actor_have_bob2], 'BOB', 'BOB, BOB',
         'Two entries for one Principal would make the cutoff ambiguous.'),
    ]:
        bad = control_record(6, C5['id'], 4, BOB, {**key_epoch_body, 2: frontier})
        neg(cid, 'control_record', f'C6 with a final frontier of entries {field_to}',
            'C6_key_epoch_1', 'body field 2: final frontier entries', field_from, field_to,
            'LFCP-WIRE-01 §19; §28.2',
            'Field `2` is a canonical frontier (Sections 28.1 and 28.2): canonical `actor-have` entries sorted by raw '
            'Principal ID, with at most one entry per Principal. A Key Epoch Record whose final frontier is not canonical '
            'MUST be rejected with `MALFORMED_MESSAGE`.',
            why,
            {'cose_sign1': hexv(bad['cose'])},
            {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
            context={'previous_record': ref('C5_route_update', 'record_id')},
            cddl=('control-record', 'pass'))

    # 7c. Capability decisions (SPEC-PATCH-03 / G-CP6, G-CAP4, DV3, DV4),
    #     each on top of the record its context names.
    dup_c1 = control_record(1, C0['id'], 1, OWNER, {**grant_bob_body, 1: [1, 2, 2]})
    neg('grant_duplicate_ability_C1', 'control_record', 'C1 with the ability code 2 listed twice',
        'C1_grant_bob', 'body field 1: abilities', [1, 2, 3], [1, 2, 2],
        'LFCP-WIRE-01 §17.1',
        'An ability list (the abilities and the delegable abilities of a grant, and the abilities of a claim) MUST NOT repeat '
        'a code; a record whose list repeats a code is rejected with `MALFORMED_MESSAGE`.',
        'A repeated code makes one grant expressible in several byte forms with different record IDs.',
        {'cose_sign1': hexv(dup_c1['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
        context={'previous_record': ref('C0_genesis', 'record_id')},
        cddl=('control-record', 'pass'))
    escalated = control_record(9, C8['id'], 1, OWNER, {**grant_invite_body, 1: [2]})
    neg('grant_escalation_C9', 'control_record', 'C9 granting data/write, which the parent grant C8 cannot delegate',
        'C9_grant_invite_grandchild', 'body field 1: abilities', [1], [2],
        'LFCP-WIRE-01 §17.2',
        'If `parent grant id` is present: [...] every granted ability MUST be included in the parent\'s delegable abilities;',
        'Delegation can only narrow authority; a child granting more than its parent may delegate would escalate it.',
        {'cose_sign1': hexv(escalated['cose'])},
        # SPEC-PATCH-04 / general code rule: an authority failure is AUTHORIZATION_FAILED.
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'AUTHORIZATION_FAILED'}},
        context={'previous_record': ref('C8_grant_owner_delegated', 'record_id')},
        cddl=('control-record', 'pass'))
    revoke_received = control_record(10, C9['id'], 2, CAROL, {0: C7['id']})
    neg('revoke_received_grant', 'control_record', 'CAROL revokes C7, the grant she received, instead of C9',
        'C10_revoke_grandchild', 'body field 0: revoked grant', hexv(C9['id']), hexv(C7['id']),
        'LFCP-WIRE-01 §17.3',
        'The owner may revoke any grant. Otherwise, revoke authority **covers** a grant when the revoker issued it, or when '
        'it was delegated, directly or through further delegations, from a grant the revoker issued. A grant the revoker '
        'received is not covered unless the revoker also issued one of its ancestors.',
        'Holding capability/revoke lets a member undo what it delegated, not the grants others gave it.',
        {'cose_sign1': hexv(revoke_received['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'AUTHORIZATION_FAILED'}},
        context={'previous_record': ref('C9_grant_invite_grandchild', 'record_id')},
        cddl=('control-record', 'pass'))
    revoke_again = control_record(11, C10['id'], 2, CAROL, revoke_c9_body)
    neg('revoke_already_revoked', 'control_record', 'CAROL revokes C9 a second time, after C10',
        'C10_revoke_grandchild', 'position: Control Sequence and previous record', 'seq 10 after C9', 'seq 11 after C10',
        'LFCP-WIRE-01 §17.3',
        'Revoking a grant that is already revoked is rejected with `AUTHORIZATION_FAILED`.',
        'A second revocation has no effect to apply; rejecting it keeps every committed record meaningful.',
        {'cose_sign1': hexv(revoke_again['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'AUTHORIZATION_FAILED'}},
        context={'previous_record': ref('C10_revoke_grandchild', 'record_id')},
        cddl=('control-record', 'pass'))

    # 7c'. Codes for authority failures (SPEC-PATCH-04 / general code rule):
    #      a revocation of a grant that does not exist, and a Route Update that
    #      does not advance the route version (Genesis implies version 0).
    revoke_unknown = control_record(10, C9['id'], 2, CAROL, {0: h('LFCP-TV-NO-SUCH-GRANT')})
    neg('revoke_unknown_grant', 'control_record', 'CAROL revokes a grant ID that names no grant of the chain, instead of C9',
        'C10_revoke_grandchild', 'body field 0: revoked grant', hexv(C9['id']), hexv(h('LFCP-TV-NO-SUCH-GRANT')),
        'LFCP-WIRE-01 §17.3',
        'A revocation is checked in this order, and each failure is rejected with `AUTHORIZATION_FAILED`: 1. the target '
        'grant ID MUST name a grant of this Control Chain; revoking a grant that does not exist fails;',
        'A revocation of nothing has no authority to check against; accepting it would put a meaningless record in the chain.',
        {'cose_sign1': hexv(revoke_unknown['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'AUTHORIZATION_FAILED'}},
        context={'previous_record': ref('C9_grant_invite_grandchild', 'record_id')},
        cddl=('control-record', 'pass'))
    route_v0 = control_record(5, C4['id'], 5, BOB, {**route_body, 0: 0})
    neg('route_version_not_increasing_C5', 'control_record', 'C5 with route version 0, the version Genesis already implies',
        'C5_route_update', 'body field 0: route version', 1, 0,
        'LFCP-WIRE-01 §20',
        'Each Route Update MUST carry a route version strictly greater than the current one: `0` after Genesis (Section 15), '
        'otherwise the version of the last committed Route Update. A Route Update whose issuer lacks `route/update`, or whose '
        'route version is not greater, is rejected with `AUTHORIZATION_FAILED`.',
        'A route version that does not advance could replace the current route with an older one.',
        {'cose_sign1': hexv(route_v0['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'AUTHORIZATION_FAILED'}},
        context={'previous_record': ref('C4_owner_transfer_commit', 'record_id')},
        cddl=('control-record', 'pass'))

    # 7d. Genesis and chain-structure codes (SPEC-PATCH-03 / S2, G-CP5,
    #     G-CP4, W1).
    genesis_by_bob = cose_sign1({**C0['payload_obj'], 4: BOB.pid}, BOB)[0]
    neg('genesis_signer_not_owner', 'control_record', 'C0 issued and signed by BOB while its body names OWNER as owner',
        'C0_genesis', 'issuer (payload field 4) and signer', 'OWNER', 'BOB',
        'LFCP-WIRE-01 §15',
        'The Genesis Record MUST be signed by the owner Principal contained in the body. A Genesis Record whose issuer or '
        '`kid` is not that owner is rejected with `INVALID_SIGNATURE`.',
        'Genesis establishes the owner; a Genesis signed by anyone else would let them claim a Resource in another name.',
        {'cose_sign1': hexv(genesis_by_bob)},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'INVALID_SIGNATURE'}},
        cddl=('control-record', 'pass'))
    second_genesis = control_record(0, None, 0, OWNER, {**genesis_body, 0: 'org.lfcp.test.raw.v2'})
    neg('genesis_competing_root', 'control_record', 'A second, different Genesis for the same Resource ID',
        'C0_genesis', 'body field 0: data profile', DATA_PROFILE, 'org.lfcp.test.raw.v2',
        'LFCP-WIRE-01 §13.2',
        'Two different validly signed Genesis Records for one Resource ID are a fork at the root, handled the same way: '
        'neither is accepted, and the Resource is in `CONTROL_CONFLICT`.',
        'Genesis has no previous record, so without this rule two roots would not count as a fork.',
        {'cose_sign1': hexv(second_genesis['cose']), 'record_id': hexv(second_genesis['id'])},
        {'valid': False, 'disposition': 'conflict', 'error': {'code': 'CONTROL_CONFLICT'}},
        context={'competing_record': ref('C0_genesis', 'record_id')},
        cddl=('control-record', 'pass'))
    http_endpoint = {**ENDPOINT_A, 0: 'http://sync-a.example.test/v1/ws'}
    genesis_http = control_record(0, None, 0, OWNER, {**genesis_body, 3: [http_endpoint]})
    neg('genesis_http_endpoint', 'control_record', 'C0 with an http:// sync endpoint',
        'C0_genesis', 'body field 3: endpoint URL scheme', 'wss', 'http',
        'LFCP-WIRE-01 §16',
        'A receiver MUST reject a record carrying such a URL with any scheme other than `ws` or `wss` with `MALFORMED_MESSAGE`.',
        'Endpoints carry LFCP over WebSocket; any other scheme cannot be reached as an LFCP endpoint.',
        {'cose_sign1': hexv(genesis_http['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
        cddl=('control-record', 'pass'))
    unknown_type = control_record(1, C0['id'], 9, OWNER, grant_bob_body)
    neg('unknown_core_type_C1', 'control_record', 'C1 with the reserved core Control Record type 9',
        'C1_grant_bob', 'payload field 3: Control Record type', 1, 9,
        'LFCP-WIRE-01 §14',
        'Unknown core Control Record types MUST cause validation failure, with `INVALID_CONTROL_CHAIN`.',
        'A core type the receiver does not know may carry authority it cannot evaluate; accepting it would let replicas disagree on the chain.',
        {'cose_sign1': hexv(unknown_type['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'INVALID_CONTROL_CHAIN'}},
        context={'previous_record': ref('C0_genesis', 'record_id')},
        cddl=('control-record', 'fail'))

    extension_record = control_record(1, C0['id'], 32, BOB, {0: b'LFCP-TV-EXTENSION'})
    neg('extension_type_non_owner_C1', 'control_record', 'C1 replaced by an extension-type (32) record issued by BOB',
        'C1_grant_bob', 'payload field 3 and issuer', 'type 1 issued by OWNER', 'type 32 issued and signed by BOB',
        'LFCP-WIRE-01 §14',
        'A Control Record of an extension type (`32` or above) requires owner authority: its issuer MUST be the '
        'Resource owner at the record\'s position in the chain, whether or not the receiver supports the extension.',
        'Extension records share the chain with core records; letting a non-owner append them would let any member '
        'fork or extend the chain with records other replicas cannot evaluate.',
        {'cose_sign1': hexv(extension_record['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'AUTHORIZATION_FAILED'}},
        # SPEC-PATCH-04: at C0 no Control Record describes BOB, so the context
        # carries his descriptor; without it a receiver stops at
        # MISSING_DEPENDENCY (§10.5) before the owner rule.
        context={'previous_record': ref('C0_genesis', 'record_id'),
                 'issuer_descriptor': ref('principal_bob', 'descriptor_cbor')},
        cddl=('control-record', 'pass'),
        note='Structurally valid: the typed CDDL admits extension types 32 and above (SPEC-PATCH-03 / W2). '
             'The owner-authority failure is AUTHORIZATION_FAILED (SPEC-PATCH-04 / general code rule).')

    # 8. Bad actor sequence.
    D_SEQ0 = data_unit(BOB, 0, 0, None, C3['id'], D1_plain, DEK0)
    neg('actor_seq_zero_D1', 'data_unit', 'D1 re-issued with actor sequence 0',
        'D1_bob_epoch0_seq1', 'actor sequence (payload field 3)', 1, 0,
        'LFCP-WIRE-01 §8',
        'Sequence numbers begin at `1`. A receiver MUST reject a Data Unit with actor sequence `0` with `MALFORMED_MESSAGE`.',
        'Sequence 0 is outside the per-actor sequence space, so Have Vectors and hash chains cannot describe it.',
        {'cose_sign1': hexv(D_SEQ0['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
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

    # 10. HPKE recipient binding (SPEC-PATCH-04 / KP-1): a package that names
    #     CAROL at C3, where she holds data/read through her claim and OWNER
    #     still owns the Resource, so every §25.2 authority check passes; its
    #     DEK is sealed with CAROL's info and the C3 AAD, but to BOB's X25519
    #     key. Only the HPKE open with CAROL's key fails.
    carol_info = cbor(['LFCP-KEY-v1', RESOURCE, 0, CAROL.pid])
    c3_aad = cbor([RESOURCE, 0, C3['id']])
    hp_wrong = hpke_seal_with_ephemeral(BOB.x_pk, hpke_derive_key_pair_x25519(h('LFCP-TV-HPKE-RECIPIENT-MISMATCH-IKM')),
                                        carol_info, c3_aad, DEK0)
    assert hpke_open(BOB.x_sk_raw, hp_wrong['enc'], carol_info, c3_aad, hp_wrong['ct']) == DEK0
    kp_wrong_obj = {**kp0_payload_obj, 2: CAROL.pid, 3: C3['id'], 5: hp_wrong['enc'], 6: hp_wrong['ct']}
    KP_WRONG = cose_sign1(kp_wrong_obj, OWNER)[0]
    try:
        hpke_open(CAROL.x_sk_raw, hp_wrong['enc'], carol_info, c3_aad, hp_wrong['ct'])
        raise AssertionError('HPKE recipient vector unexpectedly opens')
    except AssertionError:
        raise
    except Exception:
        pass
    neg('hpke_recipient_mismatch_KP0', 'key_package', 'A package naming CAROL at C3, where she is authorized, sealed to BOB',
        'KP0_bob_epoch0', 'recipient and Control Head (payload fields 2 and 3), sealed to BOB', 'BOB at C1', 'CAROL at C3',
        'LFCP-WIRE-01 §25.1, §25.2',
        'The HPKE `info` value is deterministic CBOR encoding of ["LFCP-KEY-v1", resource-id, data epoch, recipient]. '
        '[...] A package that does not open for its named recipient, or whose DEK does not match the commitment, '
        'is ignored and SHOULD be surfaced to the application. This is a client-local decision [...]',
        'HPKE info binds the recipient; a package that does not open for its named recipient delivers no key.',
        {'cose_sign1': hexv(KP_WRONG)},
        {'valid': False, 'disposition': 'reject'},
        context={'recipient_x25519_private': ref('principal_carol', 'x25519_private', 'inputs')},
        cddl=('key-package', 'pass'),
        note='Client-local rejection (SPEC-PATCH-01 / N5): the package is ignored and surfaced; there is no wire error code.')

    # 10b. HPKE enc of the wrong size (SPEC-PATCH-03 / G-KP3): KP0 with its
    #      enc cut to 31 bytes, re-signed by OWNER.
    KP_SHORT_ENC = cose_sign1({**kp0_payload_obj, 5: hp0['enc'][:31]}, OWNER)[0]
    neg('kp_enc_wrong_size_KP0', 'key_package', 'KP0 with a 31-byte HPKE enc',
        'KP0_bob_epoch0', 'HPKE enc length (payload field 5)', 32, 31,
        'LFCP-WIRE-01 §25',
        'With that suite `enc` is the 32-byte ephemeral X25519 public key, and the ciphertext is the 32-byte DEK followed by '
        'the 16-byte Poly1305 tag. (CDDL: `5 => bstr .size 32` and `6 => bstr .size 48`.)',
        'With the fixed suite every enc is a 32-byte X25519 key; any other length is structurally invalid and detectable without opening the package.',
        {'cose_sign1': hexv(KP_SHORT_ENC)},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
        cddl=('key-package', 'fail'))

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
        ('have_range_at_contiguous_plus_one', 'SNAPSHOT-02', 'BOB extra range', [[105, 107]], [[101, 107]],
         [bob(100, [[101, 107]]), carol], 'rule 5',
         '5. ranges MUST be strictly above `contiguous`; the first range MUST start at or above `contiguous + 2`, '
         'because a range starting at `contiguous + 1` extends the contiguous prefix and is absorbed into `contiguous`;'),
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
            f'{text} (§28.2: "A Snapshot verifier MUST reject a Snapshot whose frontier is not canonical, with '
            f'`MALFORMED_MESSAGE`.")',
            'Snapshot AAD and signature cover the frontier bytes, so replicas must agree on exactly one encoding of a frontier.',
            {'cose_sign1': hexv(cose)},
            {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
            cddl=('snapshot', 'pass'))
    cose = raw_snapshot([carol, bob(2)], 1, S1['plaintext'])
    neg('frontier_unsorted', 'snapshot', 'SNAPSHOT-01 with CAROL listed before BOB', 'SNAPSHOT-01',
        'frontier entry order', 'BOB, CAROL', 'CAROL, BOB',
        'LFCP-WIRE-01 §28.2',
        'Entries MUST be sorted by ascending raw 32-byte `principal-id`, compared lexicographically as unsigned bytes. '
        '[...] A Snapshot verifier MUST reject a Snapshot whose frontier is not canonical, with `MALFORMED_MESSAGE`.',
        'Snapshot AAD and signature cover the frontier bytes, so replicas must agree on exactly one entry order.',
        {'cose_sign1': hexv(cose)},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
        cddl=('snapshot', 'pass'))

    # 11b. Snapshot sequence 0 (SPEC-PATCH-03 / W5): SNAPSHOT-01 re-sealed
    #      and re-signed with Snapshot Sequence 0.
    cose = raw_snapshot([bob(2), carol], 0, S1['plaintext'])
    neg('snapshot_sequence_zero', 'snapshot', 'SNAPSHOT-01 with Snapshot Sequence 0', 'SNAPSHOT-01',
        'Snapshot Sequence (payload field 3)', 1, 0,
        'LFCP-WIRE-01 §29',
        'Snapshot Sequences begin at `1`.',
        'Sequence 0 is outside the publisher sequence space, as for actor sequences (§8).',
        {'cose_sign1': hexv(cose)},
        # SPEC-PATCH-04 / general code rule: a structural failure is MALFORMED_MESSAGE.
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
        cddl=('snapshot', 'pass'))

    # 11c. Snapshot beyond a closed epoch's cutoff (SPEC-PATCH-04 / G-EP4):
    #      BOB publishes epoch 0 at C5, where epoch 0 is still current, with a
    #      frontier covering his sequences 1..3. C6 later closes epoch 0 at
    #      BOB 2, so with C6 known the frontier covers D3, a unit beyond the
    #      cutoff. Snapshot Sequence 1 is unused in epoch 0 (SNAPSHOT-01 and
    #      SNAPSHOT-02 are in epoch 1).
    S_BEYOND = snapshot(BOB, 0, 1, C5['id'], canonical_frontier([actor_have(BOB.pid, 3)]),
                        b'LFCP snapshot beyond the epoch-0 cutoff', DEK0)
    neg('snapshot_beyond_cutoff', 'snapshot', 'A Snapshot of epoch 0 whose frontier covers BOB 1..3, beyond the C6 cutoff (BOB 2)',
        'SNAPSHOT-01', 'Data Epoch, Control Head and frontier', 'epoch 1 at C6: BOB 1..2, CAROL 1',
        'epoch 0 at C5: BOB 1..3',
        'LFCP-WIRE-01 §29; §19.1',
        'A Snapshot MUST NOT include Data Units beyond a closed epoch\'s cutoff. When the Snapshot\'s Data Epoch has been '
        'closed by a Key Epoch Record the verifier knows, every sequence its frontier covers MUST lie within that record\'s '
        'final frontier (Section 19.1); a verifier rejects a Snapshot whose frontier covers any unit beyond it with '
        '`STALE_DATA_EPOCH`.',
        'A Snapshot that includes stale work would merge it into every replica that loads it, bypassing the cutoff.',
        {'cose_sign1': hexv(S_BEYOND['cose'])},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'STALE_DATA_EPOCH'}},
        context={'cutoff_record': ref('C6_key_epoch_1', 'record_id'), 'closed_epoch': 0},
        cddl=('snapshot', 'pass'))

    # 12. Stale-epoch cutoff for an actor absent from the cutoff frontier:
    #     D4 moved to the closed epoch 0 (keys re-derived from DEK0).
    D_ABSENT = data_unit(CAROL, 0, 1, None, C6['id'], b'LFCP epoch-1 unit from Carol', DEK0)
    neg('stale_epoch_absent_actor', 'data_unit', 'CAROL Data Unit in closed epoch 0, where C6 records no CAROL entry',
        'D4_carol_epoch1_seq1', 'Data Epoch (payload field 1)', 1, 0,
        'LFCP-WIRE-01 §19.1; §88 step 7; §75',
        'If an actor is absent from the recorded frontier, no newly discovered Data Units from that actor in the closed '
        'epoch are automatically acceptable. Any later-arriving previous-epoch unit beyond that frontier MUST NOT be merged '
        'automatically. A server that receives such a unit in `DATA_PUT` responds `NACK(STALE_DATA_EPOCH)`; a client keeps '
        'it in quarantine. [...] It SHOULD be surfaced to the application as stale offline work [...]',
        'The cutoff frontier makes revocation deterministic; merging late closed-epoch work would let removed members keep writing.',
        {'cose_sign1': hexv(D_ABSENT['cose'])},
        {'valid': False, 'disposition': 'quarantine', 'error': {'code': 'STALE_DATA_EPOCH'}},
        context={'cutoff_record': ref('C6_key_epoch_1', 'record_id'), 'closed_epoch': 0},
        cddl=('data-unit', 'pass'))

    # 13. Non-canonical signed payload (SPEC-PATCH-01 / N7): D1's payload with
    #     the data epoch 0 encoded as 0x18 0x00 instead of 0x00, re-signed by
    #     BOB. The decoded value, AAD and ciphertext are unchanged.
    canonical_payload = D1['payload']
    epoch_at = 1 + 1 + 2 + 32  # map head, key 0, bstr head, resource id
    assert canonical_payload[epoch_at:epoch_at + 2] == b'\x01\x00'
    noncanon_payload = canonical_payload[:epoch_at + 1] + b'\x18\x00' + canonical_payload[epoch_at + 2:]
    protected_bob = cbor({COSE_HDR_ALG: COSE_ALG_EDDSA, COSE_HDR_KID: BOB.pid})
    nc_sig = BOB.ed_sk.sign(cbor(['Signature1', protected_bob, b'', noncanon_payload]))
    du_nc_payload = cbor([protected_bob, {}, noncanon_payload, nc_sig])
    neg('noncanonical_payload_D1', 'data_unit', 'D1 payload with a non-shortest integer encoding, re-signed',
        'D1_bob_epoch0_seq1', 'payload encoding of the data epoch (0)', hexv(b'\x00'), hexv(b'\x18\x00'),
        'LFCP-WIRE-01 §5.2, §10.3',
        'A receiver MUST also reject a persistent signed object whose protected-header bytes or payload bytes are not '
        'the deterministic encoding of their own decoded value. [...] any difference is rejected with `MALFORMED_MESSAGE`.',
        'Two byte forms of one payload would be two objects with different IDs for the same content.',
        {'cose_sign1': hexv(du_nc_payload)},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'MALFORMED_MESSAGE'}},
        cddl=('data-unit', 'pass'))

    # 14. Principal Descriptor with an extra field (SPEC-PATCH-02 / P1): BOB's
    #     descriptor plus field 3. No code: §7 names codes only for an ID
    #     mismatch, which depends on the receiving context (P2).
    extra_descriptor = cbor({**BOB.descriptor(), 3: b''})
    neg('descriptor_extra_field', 'principal', 'BOB Principal Descriptor with an additional field 3',
        'principal_bob', 'descriptor fields', '0, 1, 2', '0, 1, 2, 3 (empty bstr)',
        'LFCP-WIRE-01 §7',
        'A Principal Descriptor with any field other than `0`, `1` and `2` is invalid; the map is closed, as the CDDL above defines it.',
        'An open descriptor would let two byte forms describe one Principal and carry unauthenticated data next to its keys.',
        {'descriptor_cbor': hexv(extra_descriptor)},
        # SPEC-PATCH-03 / V2, P3: an invalid descriptor is MALFORMED_MESSAGE outside the session handshake.
        {'valid': False, 'disposition': 'reject', 'error': {
            'code': 'MALFORMED_MESSAGE',
            'detail': 'AUTH_FAILED when received in HELLO or AUTH (LFCP-WIRE-01 §7)'}},
        cddl=('principal-descriptor', 'fail'))

    # 15. Signature with a small-order R (SPEC-PATCH-03 / G-RS2): D1's exact
    #     payload and protected header, with R = the neutral element and
    #     S = k * a mod L for BOB's secret scalar a. Then [S]B = [k]A =
    #     R + [k]A, so the cofactorless equation holds and the cofactored
    #     (ZIP-215) equation holds too; only the small-order check of
    #     §10.5.1 rule 3 rejects it.
    r_small = bytes([1]) + bytes(31)
    assert ed_decode(r_small) == ED_IDENTITY and ed_small_order(ed_decode(r_small))
    so_message = cbor(['Signature1', protected_bob, b'', D1['payload']])
    so_k = int.from_bytes(hashlib.sha512(r_small + BOB.ed_pk + so_message).digest(), 'little') % ED_L
    so_s = so_k * ed_secret_scalar(BOB.ed_seed) % ED_L
    A_bob = ed_decode(BOB.ed_pk)
    assert ed_mul(so_s, ED_B) == ed_add(ed_decode(r_small), ed_mul(so_k, A_bob))  # cofactorless holds
    assert ed_mul(8, ed_mul(so_s, ED_B)) == ed_mul(8, ed_add(ed_decode(r_small), ed_mul(so_k, A_bob)))  # ZIP-215 holds
    du_small_r = cbor([protected_bob, {}, D1['payload'], r_small + so_s.to_bytes(32, 'little')])
    neg('small_order_r_signature_D1', 'data_unit', 'D1 signed with a small-order R that cofactored (ZIP-215) verification accepts',
        'D1_bob_epoch0_seq1', 'signature R (first 32 bytes)', hexv(D1['cose'][-64:-32]), hexv(r_small),
        'LFCP-WIRE-01 §10.5.1',
        'A verifier MUST reject the signature, with `INVALID_SIGNATURE`, when any of the following holds: [...] '
        '3. `A` or `R` is a point of small order;',
        'R is the neutral element and S = k·a, so both the cofactorless and the cofactored equations hold; '
        'only the small-order rule makes every implementation reject it alike.',
        {'cose_sign1': hexv(du_small_r)},
        {'valid': False, 'disposition': 'reject', 'error': {'code': 'INVALID_SIGNATURE'}},
        cddl=('data-unit', 'pass'))

    # 16. Principal Descriptor with a small-order Ed25519 key (SPEC-PATCH-03 /
    #     G-RS2, P3): the all-zero encoding is y = 0, a canonical point of
    #     order 4. The ID is recomputed over that key, so only the key check
    #     of §7 fails.
    small_key = bytes(32)
    P4 = ed_decode(small_key)
    assert P4 != ED_IDENTITY and ed_mul(4, P4) == ED_IDENTITY and ed_small_order(P4)
    small_pid = sha256(b'LFCP-PRINCIPAL-v1' + small_key + BOB.x_pk)
    neg('descriptor_small_order_key', 'principal', 'Principal Descriptor whose Ed25519 key is a point of small order',
        'principal_bob', 'Ed25519 public key (field 1), with the ID recomputed', hexv(BOB.ed_pk), hexv(small_key),
        'LFCP-WIRE-01 §7, §10.5.1',
        'A receiver MUST also validate the Ed25519 public key in field `1` whenever a descriptor is received: it MUST be a '
        'canonical point encoding and MUST NOT be a point of small order, as defined in Section 10.5.1. A descriptor whose '
        'key fails this check is invalid.',
        'A small-order key admits signatures that verify for many messages; rejecting it at receipt keeps such a Principal '
        'out of every authorization decision.',
        {'descriptor_cbor': hexv(cbor({0: small_pid, 1: small_key, 2: BOB.x_pk}))},
        {'valid': False, 'disposition': 'reject', 'error': {
            'code': 'MALFORMED_MESSAGE',
            'detail': 'AUTH_FAILED when received in HELLO or AUTH (LFCP-WIRE-01 §7)'}},
        cddl=('principal-descriptor', 'pass'))

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
    add_ctrl('C7_grant_carol_delegator', C7)
    add_ctrl('C8_grant_owner_delegated', C8)
    add_ctrl('C9_grant_invite_grandchild', C9)
    add_ctrl('C10_revoke_grandchild', C10)

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
            'hpke_ephemeral_ikm': hx(K['ephemeral_ikm']),
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

    # 17. Strict Ed25519 edge cases (SPEC-PATCH-04 / shared Ed25519 vectors):
    #     plain (public key, message, signature) triples for LFCP-WIRE-01
    #     §10.5.1, so every implementation can test its verifier directly.
    #     RFC 8032 TEST 1 is the valid anchor; the derived cases change one
    #     part of it. The two constructed cases are the ones a cofactored
    #     verifier accepts; they use the same scalars, nonces and messages as
    #     the sdk-ts strict-verification tests, so the bytes are shared.
    ED: list[dict[str, Any]] = []

    def ed_case(case_id, title, pk, msg, sig, valid, rule_section, rule_text, why,
                derivation=None, note=None):
        assert ed_verify_strict(pk, msg, sig) is valid, case_id
        ED.append({
            'id': case_id, 'description': title, 'note': note,
            'inputs': {'public_key': hexv(pk), 'message': hexv(msg), 'signature': hexv(sig)},
            'derivation': derivation,
            'expected': ({'valid': True} if valid else
                         {'valid': False, 'disposition': 'reject', 'error': {'code': 'INVALID_SIGNATURE'}}),
            'rule': {'section': rule_section, 'text': rule_text}, 'why': why,
        })

    t1_seed = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
    t1_key = Ed25519PrivateKey.from_private_bytes(t1_seed)
    t1_pk = t1_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    t1_msg = b''
    t1_sig = t1_key.sign(t1_msg)
    assert t1_pk.hex() == 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    assert t1_sig.hex() == ('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
    ED_RULE = 'LFCP-WIRE-01 §10.5.1'
    ed_case('ed25519_rfc8032_test1', 'RFC 8032 §7.1 TEST 1: a valid signature over the empty message',
            t1_pk, t1_msg, t1_sig, True, ED_RULE,
            'A verifier accepts the signature only when none of rules 1-4 rejects it.',
            'The anchor for the derived cases below; every strict verifier accepts it.',
            note='External standard vector (RFC 8032 §7.1 TEST 1).')

    def derived(case_id, title, field, old, new, pk, sig, rule_text, why):
        ed_case(case_id, title, pk, t1_msg, sig, False, ED_RULE, rule_text, why, derivation={
            'base_case': 'ed25519_rfc8032_test1',
            'mutation': {'field': field, 'from': hexv(old), 'to': hexv(new)},
            'rule': {'section': ED_RULE, 'text': rule_text},
            'why': why,
        })

    R1, S1 = t1_sig[:32], t1_sig[32:]
    L_le = ED_L.to_bytes(32, 'little')
    s_plus_l = (int.from_bytes(S1, 'little') + ED_L).to_bytes(32, 'little')
    y_ge_p = (ED_P + 1).to_bytes(32, 'little')  # y = p + 1, a non-canonical encoding of y = 1
    x0_sign = bytes([1]) + bytes(30) + bytes([0x80])  # y = 1 (x = 0) with the sign bit set
    identity = ed_encode(ED_IDENTITY)
    RULE1 = '1. `S` is not less than the group order `L`;'
    RULE2 = '2. `A` or `R` is not a canonical point encoding: its `y` coordinate is not less than `p`, it is not a point of the curve, or `x = 0` with the sign bit set;'
    RULE3 = '3. `A` or `R` is a point of small order;'
    derived('ed25519_s_equals_l', 'TEST 1 with S = L', 'S (signature bytes 32..63)', S1, L_le,
            t1_pk, R1 + L_le, RULE1, 'S must be reduced: S = L would let one signature have several encodings.')
    derived('ed25519_s_plus_l', 'TEST 1 with S + L in place of S', 'S (signature bytes 32..63)', S1, s_plus_l,
            t1_pk, R1 + s_plus_l, RULE1, 'S + L satisfies the equation like S; accepting it makes signatures malleable.')
    derived('ed25519_a_y_ge_p', 'TEST 1 with the public key A encoded as y = p + 1', 'public key A', t1_pk, y_ge_p,
            y_ge_p, t1_sig, RULE2, 'A non-canonical key encoding gives one Principal several key byte strings.')
    derived('ed25519_r_y_ge_p', 'TEST 1 with R encoded as y = p + 1', 'R (signature bytes 0..31)', R1, y_ge_p,
            t1_pk, y_ge_p + S1, RULE2, 'A non-canonical R gives one signature several byte strings.')
    derived('ed25519_a_x0_sign_bit', 'TEST 1 with the public key A = (x = 0, y = 1) and the sign bit set',
            'public key A', t1_pk, x0_sign, x0_sign, t1_sig, RULE2,
            'x = 0 has no sign; a set sign bit is a second encoding of the same point.')
    derived('ed25519_r_x0_sign_bit', 'TEST 1 with R = (x = 0, y = 1) and the sign bit set',
            'R (signature bytes 0..31)', R1, x0_sign, t1_pk, x0_sign + S1, RULE2,
            'x = 0 has no sign; a set sign bit is a second encoding of the same point.')
    derived('ed25519_small_order_a', 'TEST 1 with the public key A = the neutral element', 'public key A',
            t1_pk, identity, identity, t1_sig, RULE3,
            'A small-order key admits signatures that verify for many messages.')

    # Constructed: secret scalar a, A = [a]B, nonce r = 7777.
    ed_a = 0x1234567890abcdef * 977 % ED_L
    ed_A = ed_mul(ed_a, ED_B)
    T8 = ed_decode(bytes.fromhex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'))
    assert ed_small_order(T8) and ed_mul(4, T8) != ED_IDENTITY  # a point of order 8
    A_mixed = ed_encode(ed_add(ed_A, T8))
    assert not ed_small_order(ed_decode(A_mixed))
    R_r = ed_encode(ed_mul(7777, ED_B))
    m = 0
    while True:
        msg_mixed = f'mixed-order {m}'.encode()
        k_mixed = int.from_bytes(hashlib.sha512(R_r + A_mixed + msg_mixed).digest(), 'little') % ED_L
        if k_mixed % 8:
            break
        m += 1
    sig_mixed = R_r + ((7777 + k_mixed * ed_a) % ED_L).to_bytes(32, 'little')
    assert ed_verify_cofactored(A_mixed, msg_mixed, sig_mixed)
    ed_case('ed25519_mixed_order_a', 'A mixed-order key A = [a]B + T8 that the cofactored equation accepts',
            A_mixed, msg_mixed, sig_mixed, False, ED_RULE,
            '4. the cofactorless equation `[S]B = R + [k]A` does not hold, where `k` is SHA-512 of the exact `R` '
            'bytes, the exact `A` bytes and the message, reduced mod `L`.',
            'With k mod 8 != 0 only the cofactored equation holds; strict verification must reject it so all '
            'implementations agree.',
            note='Constructed: a = 0x1234567890abcdef * 977 mod L, T8 a point of order 8, R = [7777]B, the first '
                 'message "mixed-order N" with k mod 8 != 0, S = 7777 + k*a mod L. A is not itself of small order; '
                 'cofactored verification accepts it.')
    A_enc = ed_encode(ed_A)
    msg_small = b'small-order R'
    k_small = int.from_bytes(hashlib.sha512(identity + A_enc + msg_small).digest(), 'little') % ED_L
    sig_small = identity + (k_small * ed_a % ED_L).to_bytes(32, 'little')
    assert ed_verify_cofactored(A_enc, msg_small, sig_small)
    assert ed_mul(int.from_bytes(sig_small[32:], 'little'), ED_B) == ed_add(ED_IDENTITY, ed_mul(k_small, ed_A))
    ed_case('ed25519_small_order_r', 'R = the neutral element with S = k*a, which both equations accept',
            A_enc, msg_small, sig_small, False, ED_RULE, RULE3,
            'Both the cofactorless and the cofactored equations hold; only the small-order rule rejects it.',
            note='Constructed: a = 0x1234567890abcdef * 977 mod L, A = [a]B, R = the neutral element, '
                 'S = k*a mod L for the message "small-order R".')
    fixtures['ed25519'] = ED

    # 18. Actor chains across a sequence gap (SPEC-PATCH-05 / G-DP1-GAP,
    #     LFCP-WIRE-01 §26.2): CAROL's epoch-1 units at C6. Sequence 3 was
    #     reserved and abandoned, so sequence 4 links to sequence 2. Each case
    #     is received after the `accepted_*` units, in order.
    D_C2 = data_unit(CAROL, 1, 2, D_C1['id'], C6['id'], b'LFCP epoch-1 unit from Carol, seq 2', DEK1)
    D_C4 = data_unit(CAROL, 1, 4, D_C2['id'], C6['id'], b'LFCP epoch-1 unit from Carol, seq 4', DEK1)
    unknown_prev = h('LFCP-TV-UNKNOWN-PREVIOUS')
    D_C4_UNKNOWN = data_unit(CAROL, 1, 4, unknown_prev, C6['id'], b'LFCP epoch-1 unit from Carol, seq 4', DEK1)
    CHAIN_RULE = 'LFCP-WIRE-01 §26.2'
    CHAIN_TEXT = ('A unit links when its `previous` names the receiver\'s latest accepted unit of that actor '
                  '[...], even when sequences lie between the two. Such a sequence gap is a hole: it never blocks '
                  'the chain [...]. A unit that does not link MUST be reported to the sync engine and is held, '
                  'not merged, until it links [...]')
    chain_inputs = {
        'accepted_seq1_cose': hexv(D_C1['cose']),
        'accepted_seq2_cose': hexv(D_C2['cose']),
        'signer': 'CAROL',
        'dek': 'dek1',
    }
    CHAIN: list[dict[str, Any]] = [
        {
            'id': 'chain_gap_linked_seq4', 'description': 'CAROL seq 4 linked to seq 2 across the abandoned seq 3',
            'note': 'Receive accepted_seq1_cose, then accepted_seq2_cose, then cose_sign1. All three are accepted; '
                    'the Have Vector keeps the hole: CAROL 1..2 plus 4..4.',
            'inputs': {**chain_inputs, 'cose_sign1': hexv(D_C4['cose'])},
            'derivation': None,
            'expected': {'valid': True},
        },
        {
            'id': 'chain_prev_unknown_seq4', 'description': 'CAROL seq 4 whose previous names a unit the receiver does not have',
            'note': 'Receive accepted_seq1_cose, then accepted_seq2_cose, then cose_sign1: it is held (reported), '
                    'not merged.',
            'inputs': {**chain_inputs, 'cose_sign1': hexv(D_C4_UNKNOWN['cose'])},
            'derivation': {
                'base_case': 'chain_gap_linked_seq4',
                'mutation': {'field': 'previous Data Unit (payload field 4)', 'from': hexv(D_C2['id']),
                             'to': hexv(unknown_prev)},
                'rule': {'section': CHAIN_RULE, 'text': CHAIN_TEXT},
                'why': 'Only a link to the latest accepted unit completes the chain; a link to an unknown unit '
                       'waits for it.',
            },
            'expected': {'valid': False, 'disposition': 'report'},
        },
    ]
    fixtures['actor_chain'] = CHAIN

    # 19. Invitation URI parsing (SPEC-PATCH-05, LFCP-WIRE-01 §18.2): an
    #     undefined query parameter is ignored; a repeated grant is rejected.
    #     Client-local: no wire code.
    split = invite_uri.index('#')
    INVITE_PARSE = [
        {
            'id': 'invite_uri_unknown_parameter', 'description': 'The bearer URI with an undefined query parameter',
            'note': 'It parses to the same Resource, endpoint, grant and secret as invite_uri.',
            'inputs': {'uri': invite_uri[:split] + '&mode=readonly' + invite_uri[split:]},
            'derivation': None,
            'expected': {'valid': True},
        },
        {
            'id': 'invite_uri_duplicate_grant', 'description': 'The bearer URI with its grant parameter repeated',
            'note': 'Client-local rejection: no wire code.',
            'inputs': {'uri': invite_uri[:split] + '&grant=' + b64u(C2['id']) + invite_uri[split:]},
            'derivation': {
                'base_case': 'invite_uri_unknown_parameter',
                'mutation': {'field': 'query parameter after grant', 'from': 'mode=readonly',
                             'to': 'grant=' + b64u(C2['id'])},
                'rule': {'section': 'LFCP-WIRE-01 §18.2',
                         'text': 'A receiver ignores query parameters this section does not define, for forward '
                                 'compatibility, but rejects a URI whose query is not well-formed percent-encoding, '
                                 'that repeats `grant`, or whose `endpoint` or `grant` values are invalid.'},
                'why': 'Two grant values are ambiguous: the receiver cannot tell which grant the secret is for.',
            },
            'expected': {'valid': False, 'disposition': 'reject'},
        },
    ]
    fixtures['invite_parse'] = INVITE_PARSE

    # 20. The server's `previous` link check (SPEC-PATCH-09 / ADR 0008,
    #     LFCP-WIRE-01 §51.1): CAROL's epoch-1 units at C6, as in section 18.
    #     The server holds the `stored_*` units (and, where given, a Snapshot
    #     whose frontier is `stored_snapshot_frontier`), then receives
    #     `message_cbor`, a DATA_PUT.
    D_C2B = data_unit(CAROL, 1, 2, D_C1['id'], C6['id'], b'LFCP epoch-1 unit from Carol, seq 2, other', DEK1)
    D_C4B = data_unit(CAROL, 1, 4, D_C2B['id'], C6['id'], b'LFCP epoch-1 unit from Carol, seq 4, other', DEK1)
    D_C3_NULL = data_unit(CAROL, 1, 3, None, C6['id'], b'LFCP epoch-1 unit from Carol, seq 3, null previous', DEK1)
    PUT_RULE = 'LFCP-WIRE-01 §51.1'
    PUT_TEXT = ('A server MUST refuse a Data Unit whose `previous` is not `null` unless [...] the server stores a '
                'unit of that actor, at a sequence below `N`, whose Data Unit ID is `previous` [...]; an earlier '
                'unit of the same `DATA_PUT` is such a unit [...]; a Snapshot the server stores covers sequence '
                '`m` of that actor in its frontier, with `m < N`, and the server stores no unit of that actor at a '
                'sequence between `m` and `N`.')

    def data_put(label: str, units: list) -> dict:
        return hexv(wire_msg(33, msgid(f'DATA-PUT-{label}'), {0: RESOURCE, 1: [u['cose'] for u in units]}))

    def stored(units: dict) -> dict:
        return {f'stored_{k}_cose': hexv(u['cose']) for k, u in units.items()}

    def frontier(entries: list) -> dict:
        return {'stored_snapshot_frontier': hexv(cbor(canonical_frontier(entries)))}

    def refused(prev: bytes) -> dict:
        return {'valid': False, 'disposition': 'reject',
                'error': {'code': 'UNKNOWN_PREVIOUS', 'details': hexv(prev)}}

    PUT_PREVIOUS: list[dict[str, Any]] = [
        {
            'id': 'put_previous_stored', 'description': 'CAROL seq 4 naming seq 2, which the server stores',
            'note': 'Rule 1: `previous` is a stored unit of the actor at a lower sequence.',
            'inputs': {**stored({'seq1': D_C1, 'seq2': D_C2}), 'message_cbor': data_put('PREV-STORED', [D_C4])},
            'derivation': None,
            'expected': {'valid': True},
        },
        {
            'id': 'put_previous_unknown', 'description': 'CAROL seq 4 naming seq 2, which the server lost',
            'note': 'The server stores only seq 1: no rule holds. NACK details: the `previous` of seq 4.',
            'inputs': {**stored({'seq1': D_C1}), 'message_cbor': data_put('PREV-UNKNOWN', [D_C4])},
            'derivation': {
                'base_case': 'put_previous_stored',
                'mutation': {'field': 'units the server stores', 'from': 'CAROL seq 1 and seq 2',
                             'to': 'CAROL seq 1'},
                'rule': {'section': PUT_RULE, 'text': PUT_TEXT},
                'why': 'Accepting seq 4 would serve a unit that no receiver can link (§26.2).',
            },
            'expected': refused(D_C2['id']),
        },
        {
            'id': 'put_previous_same_put', 'description': 'CAROL seq 2 and seq 4 in one DATA_PUT, in that order',
            'note': 'Rule 2: seq 2, earlier in the same DATA_PUT, is the `previous` of seq 4.',
            'inputs': {**stored({'seq1': D_C1}), 'message_cbor': data_put('PREV-SAME-PUT', [D_C2, D_C4])},
            'derivation': None,
            'expected': {'valid': True},
        },
        {
            'id': 'put_previous_same_put_reversed', 'description': 'CAROL seq 4 before seq 2 in one DATA_PUT',
            'note': 'Units are evaluated in message order: seq 4 comes first and its `previous` is unknown; the '
                    'DATA_PUT is all-or-nothing (§51), so seq 2 is not stored either.',
            'inputs': {**stored({'seq1': D_C1}), 'message_cbor': data_put('PREV-REVERSED', [D_C4, D_C2])},
            'derivation': {
                'base_case': 'put_previous_same_put',
                'mutation': {'field': 'order of the DATA_PUT units', 'from': 'seq 2, seq 4', 'to': 'seq 4, seq 2'},
                'rule': {'section': PUT_RULE, 'text': PUT_TEXT},
                'why': 'Only an earlier unit of the same DATA_PUT counts.',
            },
            'expected': refused(D_C2['id']),
        },
        {
            'id': 'put_previous_equivocation_evidence',
            'description': 'CAROL seq 4 naming one unit of an equivocating pair at seq 2',
            'note': 'The server keeps both seq 2 units as evidence (§26.2); either counts as a stored unit.',
            'inputs': {**stored({'seq1': D_C1, 'seq2': D_C2, 'seq2_other': D_C2B}),
                       'message_cbor': data_put('PREV-EVIDENCE', [D_C4B])},
            'derivation': None,
            'expected': {'valid': True},
        },
        {
            'id': 'put_previous_snapshot_frontier',
            'description': 'CAROL seq 4 naming seq 2, covered by a stored Snapshot frontier',
            'note': 'Rule 3: the Snapshot covers CAROL 1..2 (m = 2 < 4) and the server stores no CAROL unit '
                    'above 2.',
            'inputs': {**frontier([actor_have(CAROL.pid, 2)]), 'message_cbor': data_put('PREV-SNAPSHOT', [D_C4])},
            'derivation': None,
            'expected': {'valid': True},
        },
        {
            'id': 'put_previous_snapshot_unit_between',
            'description': 'CAROL seq 4 naming seq 2 when the Snapshot covers only seq 1 and another seq 2 is stored',
            'note': 'Rule 3 fails: the server stores a CAROL unit at seq 2, between m = 1 and 4, and it is not '
                    'the `previous` of seq 4.',
            'inputs': {**frontier([actor_have(CAROL.pid, 1)]), **stored({'seq2_other': D_C2B}),
                       'message_cbor': data_put('PREV-BETWEEN', [D_C4])},
            'derivation': {
                'base_case': 'put_previous_snapshot_frontier',
                'mutation': {'field': 'Snapshot frontier and stored units', 'from': 'CAROL 1..2, none stored',
                             'to': 'CAROL 1..1, another seq 2 stored'},
                'rule': {'section': PUT_RULE, 'text': PUT_TEXT},
                'why': 'A stored unit between the frontier and N shows that the frontier does not stand for the '
                       'missing predecessor.',
            },
            'expected': refused(D_C2['id']),
        },
        {
            'id': 'put_previous_null', 'description': 'CAROL seq 3 with a null previous while seq 1 and 2 are stored',
            'note': 'A null `previous` is not checked by §51.1: a writer with no accepted unit of its own names '
                    'null (§26.2).',
            'inputs': {**stored({'seq1': D_C1, 'seq2': D_C2}), 'message_cbor': data_put('PREV-NULL', [D_C3_NULL])},
            'derivation': None,
            'expected': {'valid': True},
        },
    ]
    fixtures['data_put_previous'] = PUT_PREVIOUS

    # 21. Have Vector difference in both directions (SPEC-PATCH-09 / ADR 0008,
    #     LFCP-WIRE-01 §28, §68.1): what a replica requests from a peer and what
    #     it offers it, per actor, as minimal inclusive ranges in ascending
    #     order. `local_have_cbor` and `remote_have_cbor` are [* actor-have].
    def have(entries: list) -> dict:
        return hexv(cbor(canonical_frontier(entries)))

    def ranges(*items) -> list:
        return [{'actor': a, 'start': s0, 'end': e0} for a, s0, e0 in items]

    HAVE_DIFF: list[dict[str, Any]] = [
        {
            'id': 'have_difference_contiguous', 'description': 'Contiguous Have Vectors; each side lacks something',
            'note': 'Local BOB 1..100 and CAROL 1..8; remote BOB 1..104.',
            'inputs': {'local_have_cbor': have([actor_have(BOB.pid, 100), actor_have(CAROL.pid, 8)]),
                       'remote_have_cbor': have([actor_have(BOB.pid, 104)])},
            'expected': {'request': ranges(('BOB', 101, 104)), 'offer': ranges(('CAROL', 1, 8))},
        },
        {
            'id': 'have_difference_holes', 'description': 'Have Vectors with holes on both sides',
            'note': 'Local BOB 1..100 plus 105..107; remote BOB 1..102 plus 106..110.',
            'inputs': {'local_have_cbor': have([actor_have(BOB.pid, 100, [[105, 107]])]),
                       'remote_have_cbor': have([actor_have(BOB.pid, 102, [[106, 110]])])},
            'expected': {'request': ranges(('BOB', 101, 102), ('BOB', 108, 110)), 'offer': ranges(('BOB', 105, 105))},
        },
        {
            'id': 'have_difference_equal', 'description': 'Equal Have Vectors',
            'note': 'Nothing to request and nothing to offer.',
            'inputs': {'local_have_cbor': have([actor_have(BOB.pid, 100, [[105, 107]])]),
                       'remote_have_cbor': have([actor_have(BOB.pid, 100, [[105, 107]])])},
            'expected': {'request': [], 'offer': []},
        },
        {
            'id': 'have_difference_server_lost_unit', 'description': 'A server whose store lost the latest unit',
            'note': 'The drill of ADR 0008: the client holds CAROL 1..4, the restored server CAROL 1..3. The '
                    'client offers 4 before it writes 5 (§68.1).',
            'inputs': {'local_have_cbor': have([actor_have(CAROL.pid, 4)]),
                       'remote_have_cbor': have([actor_have(CAROL.pid, 3)])},
            'expected': {'request': [], 'offer': ranges(('CAROL', 4, 4))},
        },
    ]
    fixtures['have_difference'] = HAVE_DIFF

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
            {'hpke_ephemeral_ikm': hexv(k['hpke_ephemeral_ikm'])},
            {f: hexv(v) for f, v in k.items() if f != 'hpke_ephemeral_ikm'},
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
        # LFCP-WIRE-01 §10.5, §62 code 7 (SPEC-PATCH-01 / G1).
        'expected': {'valid': False, 'error': {'code': 'INVALID_SIGNATURE'}},
    })
    cases.append({
        'id': 'stale_epoch', 'type': 'validation', 'kind': 'data_unit',
        'inputs': {'unit_id': hexv(n['stale_epoch_unit_id'])},
        # LFCP-WIRE-01 section 62, error code 14.
        'expected': {'valid': False, 'error': {'code': 'STALE_DATA_EPOCH', 'detail': n['stale_epoch_expected']}},
    })
    for x in fixtures['negatives']:
        case = {'id': x['id'], 'type': 'validation', 'kind': x['kind'], 'description': x['description']}
        if x['note']:
            case['note'] = x['note']
        case['inputs'] = x['inputs']
        if x['context']:
            case['context'] = x['context']
        case['derivation'] = x['derivation']
        case['expected'] = x['expected']
        cases.append(case)

    for kind, key in (('actor_chain', 'actor_chain'), ('invite_uri', 'invite_parse')):
        for x in fixtures[key]:
            case = {'id': x['id'], 'type': 'validation', 'kind': kind, 'description': x['description']}
            if x['note']:
                case['note'] = x['note']
            case['inputs'] = x['inputs']
            if x['derivation']:
                case['derivation'] = x['derivation']
            case['expected'] = x['expected']
            cases.append(case)

    for x in fixtures['data_put_previous']:
        case = {'id': x['id'], 'type': 'validation', 'kind': 'data_put_previous', 'description': x['description'],
                'note': x['note'], 'inputs': {**x['inputs'], 'signer': 'CAROL'}}
        if x['derivation']:
            case['derivation'] = x['derivation']
        case['expected'] = x['expected']
        cases.append(case)

    for x in fixtures['have_difference']:
        cases.append({'id': x['id'], 'type': 'behavioral', 'kind': 'have_difference',
                      'description': x['description'], 'note': x['note'], 'inputs': x['inputs'],
                      'expected': x['expected']})

    for x in fixtures['ed25519']:
        case = {'id': x['id'], 'type': 'validation', 'kind': 'ed25519_signature', 'description': x['description']}
        if x['note']:
            case['note'] = x['note']
        case['inputs'] = x['inputs']
        if x['derivation']:
            case['derivation'] = x['derivation']
        case['expected'] = x['expected']
        cases.append(case)

    annotate_references(cases, fixtures)

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

def annotate_references(cases: list, fixtures: dict) -> None:
    """Make references machine-readable (SPEC-PATCH-03 / G-RS3, V1, V3).

    - G-RS3: every case whose own inputs or expected values hold a COSE_Sign1
      object names its signer in `inputs.signer` (read from the object's
      `kid`); `owner_transfer` names `offer_signer` and `accept_signer`.
    - V1: `invite_uri` names the Control Record case of its grant.
    - V3: every data_unit and snapshot case names its DEK fixture in
      `inputs.dek` (read from the payload's Data Epoch).
    """
    label_by_pid = {bytes.fromhex(p['principal_id']): label.upper() for label, p in fixtures['principals'].items()}
    unit_dek = {}

    def signer_of(cose_hex: str) -> str:
        cose_obj, _ = cbor_decode(bytes.fromhex(cose_hex))
        protected, _ = cbor_decode(cose_obj[0])
        return label_by_pid[protected[4]]

    def epoch_of(cose_hex: str) -> int:
        cose_obj, _ = cbor_decode(bytes.fromhex(cose_hex))
        payload, _ = cbor_decode(cose_obj[2])
        return payload[1]

    def add_inputs(case: dict, values: dict) -> None:
        inputs = dict(case.get('inputs') or {})
        for k, v in values.items():
            inputs.setdefault(k, v)
        rebuilt = {}
        for k, v in case.items():
            if k == 'expected' and 'inputs' not in case:
                rebuilt['inputs'] = inputs
            rebuilt[k] = inputs if k == 'inputs' else v
        if 'inputs' not in rebuilt:
            rebuilt['inputs'] = inputs
        case.clear()
        case.update(rebuilt)

    cose_fields = ('cose_sign1', 'auth_proof_cose_sign1', 'conflicting_D2_cose')
    for case in cases:
        values = {}
        objects = [v['hex'] for part in ('inputs', 'expected') for k, v in (case.get(part) or {}).items()
                   if k in cose_fields and isinstance(v, dict) and 'hex' in v]
        if case['kind'] == 'owner_transfer':
            values['offer_signer'] = signer_of(case['expected']['offer_cose_sign1']['hex'])
            values['accept_signer'] = signer_of(case['expected']['accept_cose_sign1']['hex'])
        elif objects:
            values['signer'] = signer_of(objects[0])
        if case['kind'] in ('data_unit', 'snapshot') and objects:
            values['dek'] = f'dek{epoch_of(objects[0])}'
            if case['type'] == 'bytes' and case['kind'] == 'data_unit':
                unit_dek[case['expected']['unit_id']['hex']] = values['dek']
        if case['id'] == 'invite_uri':
            values['grant_case'] = 'C2_invite_grant'
        if values:
            add_inputs(case, values)
    for case in cases:
        unit = (case.get('inputs') or {}).get('unit_id')
        if case['kind'] == 'data_unit' and unit and 'dek' not in case['inputs']:
            add_inputs(case, {'dek': unit_dek[unit['hex']]})

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
    a('- Production HPKE uses fresh randomness. The vectors publish a fixed ephemeral input keying material `ikmE` solely so sender-side output is reproducible; the ephemeral private key is `DeriveKeyPair(ikmE)` (RFC 9180 §7.1.3), as in RFC 9180 Appendix A.')
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
    a('C0 to C6 form the main chain. C7 to C10 continue it to pin the delegation and revocation rules of LFCP-WIRE-01 §17.2 and §17.3 (SPEC-PATCH-03); the session and transport messages in Section 16 still describe the Resource at head C6.')
    a('')
    ctrl_desc = [
        ('C0_genesis', 'GENESIS, owner=OWNER, profile=org.lfcp.test.raw.v1, epoch=0, route A'),
        ('C1_grant_bob', 'CAPABILITY_GRANT, BOB gets data/read + data/write + snapshot/publish'),
        ('C2_invite_grant', 'CAPABILITY_GRANT, one-time Invitation Principal gets data/read + data/write + invite/claim'),
        ('C3_invite_claim_carol', 'CAPABILITY_CLAIM, Invitation Principal transfers read/write to CAROL'),
        ('C4_owner_transfer_commit', 'OWNER_TRANSFER_COMMIT, ownership moves OWNER -> BOB'),
        ('C5_route_update', 'ROUTE_UPDATE, route version 1, coordinator moves to Server B'),
        ('C6_key_epoch_1', 'KEY_EPOCH, epoch 1, old epoch cutoff BOB<=2'),
        ('C7_grant_carol_delegator', 'CAPABILITY_GRANT by owner BOB: CAROL gets read, write, capability/grant and capability/revoke, may delegate read and capability/grant'),
        ('C8_grant_owner_delegated', 'CAPABILITY_GRANT by CAROL, parent C7: OWNER (former owner) gets read and capability/grant, may delegate read'),
        ('C9_grant_invite_grandchild', 'CAPABILITY_GRANT by OWNER, parent C8: INVITE gets read (a grandchild of C7)'),
        ('C10_revoke_grandchild', 'CAPABILITY_REVOKE by CAROL of C9, covered because C9 descends from C8, which CAROL issued'),
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
    a('The generator first verifies its HPKE implementation against RFC 9180 Appendix A.2.1, Base mode for X25519/HKDF-SHA256/ChaCha20Poly1305. Generation aborts if `DeriveKeyPair(ikmE)`, `enc`, shared secret, key, base nonce, or first ciphertext differ from the RFC fixture. This prevents LFCP-specific vectors from being built on an unverified HPKE implementation.')
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
            ('HPKE ephemeral input keying material (ikmE)', 'hpke_ephemeral_ikm'),
            ('HPKE ephemeral private key, DeriveKeyPair(ikmE)', 'hpke_ephemeral_private'),
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

    a('### 13.1 Have Vector difference')
    a('')
    a('`behavioral` cases of kind `have_difference` for `LFCP-WIRE-01` §28 and §68.1 (SPEC-PATCH-09, ADR 0008). Given a local and a remote Have Vector (`[* actor-have]`), a replica requests what the remote holds and it lacks, and offers what it holds and the remote lacks. Both are minimal inclusive ranges per actor, in ascending order.')
    a('')
    for x in f['have_difference']:
        a(f'#### {x["id"]}: {x["description"]}')
        a('')
        a(x['note'])
        a('')
        for side in ('request', 'offer'):
            rs = ', '.join(f'{r["actor"]} {r["start"]}..{r["end"]}' for r in x['expected'][side]) or 'nothing'
            a(f'- {side}: {rs}')
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
    a('The following bytes are a one-byte mutation of D1. Expected result: reject the object with `INVALID_SIGNATURE` (LFCP-WIRE-01 §10.5); it must not be assigned a valid Data Unit identity or merged.')
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
    a('Decrypt D1 with the same actor key and nonce but change any AAD field, for example `seq=2`. Expected result: ChaCha20-Poly1305 authentication failure. The client MUST NOT merge the unit; this is client-local and has no wire error code (LFCP-WIRE-01 §26.3).')
    a('')
    a('### 17.5 Wrong HPKE recipient')
    a('')
    a('Attempt to decrypt `KP0_bob_epoch0` using CAROL\'s X25519 private key. Expected result: HPKE/AEAD open failure; no DEK is returned and the package is ignored (client-local, no wire error code; LFCP-WIRE-01 §25.2).')
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
    a('Re-encode any signed payload using a non-preferred integer width or non-deterministic map ordering and sign those different bytes. Even with a mathematically valid Ed25519 signature, the receiver MUST reject the object with `MALFORMED_MESSAGE`: it re-encodes the decoded payload and the bytes differ (LFCP-WIRE-01 §5.2). Machine-readable vector: `noncanonical_payload_D1` (Section 17.10).')
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

    a('### 17.11 Strict Ed25519 edge cases')
    a('')
    a('Plain `(public key, message, signature)` triples for the strict verification of `LFCP-WIRE-01` §10.5.1, as `validation` cases of kind `ed25519_signature`. RFC 8032 §7.1 TEST 1 is the valid anchor; each derived case changes one part of it. The two constructed cases are accepted by the cofactored equation and must still be rejected. Every invalid case expects `INVALID_SIGNATURE`.')
    a('')
    a('| Case | Expected | Rule | Why |')
    a('|---|---|---|---|')
    for x in f['ed25519']:
        a(f'| `{x["id"]}` | {"valid" if x["expected"]["valid"] else "invalid, `INVALID_SIGNATURE`"} | {x["rule"]["text"]} | {x["why"]} |')
    a('')
    for x in f['ed25519']:
        a(f'#### {x["id"]}: {x["description"]}')
        a('')
        if x['note']:
            a(x['note'])
            a('')
        for k, v in x['inputs'].items():
            a(f'{k}:')
            a('')
            a(code_hex(v['hex']) if v['hex'] else '(empty)')
            a('')

    a('### 17.12 Actor chains across a sequence gap')
    a('')
    a('`validation` cases of kind `actor_chain` for `LFCP-WIRE-01` §26.2 (SPEC-PATCH-05 / G-DP1-GAP). CAROL publishes epoch-1 units at Control Head C6; her sequence 3 was reserved and abandoned, so her sequence 4 links to sequence 2. A receiver receives `accepted_seq1_cose` (D4), then `accepted_seq2_cose`, then `cose_sign1`, and reaches the expected outcome for `cose_sign1`: the gap-linked unit is accepted (the Have Vector keeps the hole, CAROL 1..2 and 4..4); a unit whose `previous` names an unknown unit is held and reported (`disposition` `report`), not merged.')
    a('')
    for x in f['actor_chain']:
        a(f'#### {x["id"]}: {x["description"]}')
        a('')
        a(x['note'])
        a('')
        for k in ('accepted_seq2_cose', 'cose_sign1'):
            a(f'{k}:')
            a('')
            a(code_hex(x['inputs'][k]['hex']))
            a('')
    a('### 17.13 Invitation URI parsing')
    a('')
    a('`validation` cases of kind `invite_uri` for `LFCP-WIRE-01` §18.2 (SPEC-PATCH-05): the bearer URI of Section 14 with an undefined query parameter parses (it is ignored); with its `grant` parameter repeated it is rejected. The rejection is client-local and has no wire code.')
    a('')
    for x in f['invite_parse']:
        a(f'#### {x["id"]}: {x["description"]}')
        a('')
        a('```text')
        a(x['inputs']['uri'])
        a('```')
        a('')
    a('### 17.14 The server\'s `previous` link check')
    a('')
    a('`validation` cases of kind `data_put_previous` for `LFCP-WIRE-01` §51.1 (SPEC-PATCH-09, ADR 0008). The server holds the Control Chain through C6, the `stored_*_cose` units of CAROL and, where `stored_snapshot_frontier` is given, a Snapshot with that frontier. It then receives `message_cbor`, a `DATA_PUT`, and reaches the expected outcome for the whole message. A refusal is `NACK(UNKNOWN_PREVIOUS)` whose details (field `2`) are `expected.error.details`, the `previous` of the first refused unit.')
    a('')
    for x in f['data_put_previous']:
        a(f'#### {x["id"]}: {x["description"]}')
        a('')
        a(x['note'])
        a('')
        exp = x['expected']
        a('Expected: accepted.' if exp['valid'] else
          f'Expected: `NACK(UNKNOWN_PREVIOUS)`, details `{exp["error"]["details"]["hex"]}`.')
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
        ('Control','linear chain C0→C10, owner transition at C4, route transition at C5, delegation and covered revocation at C7..C10'),
        ('HPKE','RFC 9180 A.2.1 self-test + all three LFCP Key Packages'),
        ('Data crypto','D1/D2/D4 decrypt; D3 decrypts cryptographically but is rejected semantically'),
        ('Anti-entropy','Have Vector hole 101..104 inferred correctly; every Section 13.1 difference requested and offered as expected'),
        ('Snapshot','SNAPSHOT-01/02 canonical frontier, exact AAD, key, nonce, decrypt, signature, Snapshot ID'),
        ('Invitation','URI decode, Principal reconstruction, C2 subject match, C3 claim'),
        ('Wire','HELLO→CHALLENGE→AUTH→READY exact decoding and signature verification; every Section 16 message decodes to its §33 body'),
        ('Negative','tamper, wrong recipient, equivocation, stale epoch, CAS mismatch, double claim; every Section 17.10 vector reaches its expected outcome; a server reaches every Section 17.14 outcome'),
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
