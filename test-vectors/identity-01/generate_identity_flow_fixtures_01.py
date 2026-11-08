#!/usr/bin/env python3
"""Generate IDENTITY-FLOW-FIXTURES-01 (IDENTITY-PROFILE-01 §12.3; LFCP-WIRE-01 §107 style).

State-machine and durable-operation fixtures for multi-device identity. Each
fixture is a sequence of steps. A step that sends or receives a protocol
object names its case in LFCP-IDENTITY-TEST-VECTORS-01 (`wire:<id>`) or in
IDENTITY-PROFILE-TEST-VECTORS-01 (`profile:<id>`), where the exact bytes and
the deciding rule are. The generator checks:

- that the outcome a step states is the outcome its case expects;
- that the steps of a fixture form one history per Resource and branch: the
  Control state a step's case is decided on contains the last Control Record
  an earlier step of the same branch committed (no step goes back to an
  older head or to a sibling record). A step on another branch says so
  (`branch`), and an `aside` step shows a rule on another head without being
  part of the history;
- that every durable-operation phase a step states is the one the table of
  IDENTITY-PROFILE-01 §9.2 gives on the Control state of its case.

Steps of the client procedures without a protocol object state the result
the profile requires (statuses of §6, ledger of §9.5).

Run after both corpora are generated:

    python3 generate_identity_flow_fixtures_01.py [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITE_ID = 'IDENTITY-FLOW-FIXTURES-01'
WIRE = json.loads((HERE.parent / 'lfcp-wire-01' / 'LFCP-IDENTITY-TEST-VECTORS-01.json').read_text(encoding='utf-8'))
PROF = json.loads((HERE / 'IDENTITY-PROFILE-TEST-VECTORS-01.json').read_text(encoding='utf-8'))
SUITES = {'wire': {c['id']: c for c in WIRE['cases']}, 'profile': {c['id']: c for c in PROF['cases']}}
CERTS = WIRE['fixtures']['certificates']
RES_BY_ID = {v['id']['hex']: k for k, v in WIRE['fixtures']['resources'].items()}
CASES: list[dict] = []


def case(ref: str) -> dict:
    suite, _, cid = ref.partition(':')
    c = SUITES[suite].get(cid)
    if c is None:
        raise SystemExit(f'unknown case {ref}')
    return c


def outcome_of(ref: str) -> str:
    c = case(ref)
    if c['type'] != 'validation':
        return 'exact bytes' if c['type'] == 'bytes' else 'see case'
    e = c['expected']
    if e['valid']:
        return 'accept'
    return e['error'].get('diagnostic') or e['error']['code']


def post(ref: str) -> dict:
    return case(ref)['expected'].get('post_state', {})


def dev(ref: str, label: str) -> dict:
    return post(ref)['devices'][label]


# ---------------------------------------------------------------------------
# The Control history a wire case is decided on.
# ---------------------------------------------------------------------------

def record_id(cid: str) -> str:
    return SUITES['wire'][cid]['inputs']['record_id']['hex']


def chain_of(ref: str) -> tuple[str, list[str]]:
    """(resource, record IDs of the Control history a wire case is decided on, its own record included when accepted)."""
    c = case(ref)
    ctx = c.get('context', {})
    res = RES_BY_ID.get(ctx.get('resource_id', {}).get('hex'))
    ids = [record_id(r['case']) for r in ctx.get('records', [])]
    if ctx.get('record_set'):
        ids += [hashlib.sha256(bytes.fromhex(r['hex'])).hexdigest() for r in WIRE['fixtures']['record_sets'][ctx['record_set']]['records']]
    ids += [record_id(r['case']) for r in ctx.get('records_after_set', [])]
    if c['kind'] == 'control_record' and c['expected']['valid'] and 'inputs' in c and c['inputs'].get('control_type') is not None:
        if c['inputs']['record_id']['hex'] not in ids:
            ids.append(c['inputs']['record_id']['hex'])
    return res, ids


# ---------------------------------------------------------------------------
# IDENTITY-PROFILE-01 §9.2, first match wins, on the post-state of a case.
# ---------------------------------------------------------------------------

def chain_issuers(root: str, device: str, cert: str, chain: list[str]) -> list[str]:
    """The devices that issued inside a planned chain (leaf first), after checking that it is one chain for `root`."""
    if not chain or chain[0] != cert or CERTS[cert]['device'] != device:
        raise SystemExit(f'the planned chain {chain} does not start with {cert} for {device}')
    for i, c in enumerate(chain):
        signer = CERTS[chain[i + 1]]['device'] if i + 1 < len(chain) else root
        if CERTS[c]['root'] != root or CERTS[c]['issuer'] != signer:
            raise SystemExit(f'the planned chain {chain} is not a chain of {root}: {c} is issued by {CERTS[c]["issuer"]}, not {signer}')
    return [CERTS[c]['device'] for c in chain[1:]]


def phase(kind: str, state_ref: str, **a) -> str:
    ps = post(state_ref)
    rv = ps.get('revoked', {})
    if kind == 'consume':
        r = rv.get(f"{a['root']}/{a['device']}")
        if r is None:
            return 'pending'
        return 'committed-own' if r['reason'] == 3 and r.get('approval', {}).get('hex') == a['digest'] else 'superseded'
    if kind == 'register':
        d = ps.get('devices', {}).get(a['device'])
        cert = a['certificate']
        # The issuers of c's chain are those of the planned chain, whatever the current binding holds (none before a
        # first registration, another leaf before a re-certification).
        issuers = chain_issuers(a['root'], a['device'], cert, a['chain'])
        if f"{a['root']}/{a['device']}" in rv or any(f"{a['root']}/{e}" in rv for e in issuers):
            return 'superseded'
        if d and d.get('leaf') == cert:
            return 'committed-own' if a.get('own') else 'complete'
        if d and d.get('leaf') and a.get('pairing_phase_2'):
            return 'superseded'
        return 'pending'
    if kind in ('cancel', 'revoke'):
        r = rv.get(f"{a['root']}/{a['device']}")
        if r is None:
            return 'pending'
        return 'superseded' if r['reason'] == 3 else 'complete'
    if kind == 'rotate':
        return 'complete' if ps['epoch'] > post(a['revoked_at'])['epoch'] else 'pending'
    raise SystemExit(kind)


# ---------------------------------------------------------------------------
# Steps and fixtures.
# ---------------------------------------------------------------------------

def step(action: str, ref: str | None = None, expect: str | None = None, *, branch: str | None = None, aside: bool = False,
         phase_of: tuple | None = None, **facts) -> dict:
    s = {'action': action}
    if ref:
        s['case'] = ref
        if ref.startswith('wire:'):
            ch = check_carrier(ref)
            if ch:
                s['expect_carries'] = {'change': ch['id'], 'change_hash': ch['inputs']['change_hash'], 'writer_class': ch['inputs']['writer_class']}
        got = outcome_of(ref)
        if expect is not None and expect != got:
            raise SystemExit(f'step {action!r}: expects {expect}, {ref} expects {got}')
        s['outcome'] = expect or got
    elif expect is not None:
        s['outcome'] = expect
    if branch:
        s['branch'] = branch
    if aside:
        s['aside'] = True
    if phase_of:
        kind, state_ref, args, want = phase_of
        got = phase(kind, state_ref, **args)
        if got != want:
            raise SystemExit(f'step {action!r}: phase {kind} on {state_ref} is {got}, not {want} (IDENTITY-PROFILE-01 §9.2)')
        s['expect_phase'] = got
        s['phase_input'] = {'phase': kind, 'state': state_ref, **{k: v for k, v in args.items()}}
    for k, v in facts.items():
        s[f'expect_{k}' if not k.startswith('in_') else k[3:]] = v
    return s


def writer_class_at(label: str, control_ref: str) -> str:
    """IDENTITY-PROFILE-01 §2.3 from the post-state of the wire case at control_ref."""
    ps = post(f'wire:{control_ref}')
    if ps['owner'] == label:
        return 'root'
    d = ps['devices'].get(label)
    return 'other' if d is None else {0: 'personal', 2: 'pairing'}.get(d['kind'], 'other')


def check_carrier(ref: str) -> dict | None:
    """A wire Data Unit that carries a profile change: same bytes, same writer, same writer class at its control_ref."""
    c = case(ref)
    carries = c.get('inputs', {}).get('carries')
    if not carries:
        return None
    ch = SUITES['profile'][carries.split()[-1]]
    if c['inputs']['plaintext_hex']['hex'] != ch['expected']['framed_cbor']['hex']:
        raise SystemExit(f'{ref}: its plaintext is not the framing of {carries}')
    if ch['inputs']['writer'] != c['inputs']['actor']:
        raise SystemExit(f'{ref}: {carries} is written by {ch["inputs"]["writer"]}, the unit by {c["inputs"]["actor"]}')
    if writer_class_at(c['inputs']['actor'], c['inputs']['control_ref']) != ch['inputs']['writer_class']:
        raise SystemExit(f'{ref}: the writer class at its control_ref differs from that of {carries}')
    return ch


def check_session(fid: str, steps: list[dict], pairing: str) -> None:
    """One pairing session through a flow: the link, the binding, the units' signers and the changes' pairing field."""
    for s in steps:
        ref = s.get('case')
        if not ref or s.get('aside'):
            continue
        c = case(ref)
        if c['kind'] == 'pair_uri' and c['type'] == 'bytes':
            if c['inputs']['device'] != pairing:
                raise SystemExit(f'{fid}: the link {ref} is of {c["inputs"]["device"]}, not {pairing}')
            b = post(f"wire:{c['inputs']['binding_head']}")['devices'][pairing]
            if not (b['kind'] == 2 and b['active'] and b['registered']):
                raise SystemExit(f'{fid}: {pairing} is not an active registered pairing device where the link is shown')
        writer = c.get('inputs', {}).get('writer') if ref.startswith('profile:') else c.get('inputs', {}).get('actor')
        cls = c.get('inputs', {}).get('writer_class')
        if ref.startswith('wire:') and c['kind'] == 'data_unit':
            cls = writer_class_at(writer, c['inputs']['control_ref'])
        if cls == 'pairing' and writer != pairing:
            raise SystemExit(f'{fid}: step {ref} is written by the pairing device {writer}, not {pairing}')


def check_history(fid: str, steps: list[dict], mode: str) -> None:
    if mode != 'sequence':
        return
    tips: dict[tuple, str] = {}
    for s in steps:
        ref = s.get('case')
        if not ref or not ref.startswith('wire:') or s.get('aside'):
            continue
        c = case(ref)
        if c['type'] != 'validation' or 'context' not in c or 'resource_id' not in c['context']:
            continue
        res, ids = chain_of(ref)
        key = (res, s.get('branch', 'main'))
        tip = tips.get(key)
        if tip is not None and tip not in ids:
            raise SystemExit(f'{fid} step {s["n"]} ({ref}): its Control history does not continue the record of the previous step on {key}')
        if ids:
            tips[key] = ids[-1]


def flow(fid: str, description: str, rule: tuple[str, str], steps: list[dict], final: dict, assertions: list[str],
         inputs: dict | None = None, mode: str = 'sequence', pairing: str | None = None) -> None:
    for i, s in enumerate(steps, 1):
        s['n'] = i
    check_history(fid, steps, mode)
    if pairing:
        check_session(fid, steps, pairing)
        inputs = {**(inputs or {}), 'pairing_device': pairing}
    split = lambda s: ({k: v for k, v in s.items() if k != 'outcome' and not k.startswith('expect_')},  # noqa: E731
                       {'n': s['n'], 'outcome': s.get('outcome', 'done'), **{k[7:]: v for k, v in s.items() if k.startswith('expect_')}})
    CASES.append({
        'id': fid, 'type': 'behavioral', 'kind': 'identity_flow', 'description': description,
        'rule': {'section': rule[0], 'text': rule[1]},
        'inputs': {'mode': mode, **(inputs or {}), 'steps': [split(s)[0] for s in steps]},
        'expected': {'steps': [split(s)[1] for s in steps], 'final': final},
        'assertions': assertions,
    })


def digest(cert: str) -> str:
    return CERTS[cert]['payload_digest']['hex']


def leaves_registered_for(device: str, ref: str) -> list[str]:
    """Leaf certificates of the accepted DEVICE_GRANTs for `device` in the history of a wire case, its own record included."""
    out = []
    c = case(ref)
    refs = [r['case'] for r in c['context'].get('records', [])] + [r['case'] for r in c['context'].get('records_after_set', [])]
    if c['expected']['valid']:
        refs.append(ref.split(':', 1)[1])
    for cid in refs:
        x = SUITES['wire'][cid]
        body = x['inputs'].get('body') or {}
        if x['inputs'].get('control_type') == 9 and body.get('chain') and CERTS[body['chain'][0]]['device'] == device:
            out.append(body['chain'][0])
    return out


def build() -> None:
    d_cert_b = digest('CERT_B')

    # 1.
    flow('F01_register_write_revoke_cutoff',
         'Register DEV_A, write, revoke it, accept an old-head unit, close the epoch, quarantine the unit beyond the frontier and rebuild',
         ('LFCP-WIRE-01 §17.5, §19.1, §26.3, §81', 'Revocation without rotation leaves old-head units acceptable until the closing KEY_EPOCH; beyond its frontier they are STALE_DATA_EPOCH and replicas rebuild without them.'),
         [step('replicas R1 and R2 accept the registration', 'wire:I1_device_grant_dev_a', 'accept'),
          step('DEV_A writes sequence 1 at I1', 'wire:D_dev_a_seq1', 'accept'),
          step('DEV_B self-registers and writes at I2', 'wire:D_dev_b_seq1', 'accept'),
          step('BRIDGE writes at I8', 'wire:D_bridge_writes_x', 'accept'),
          step('OWNER revokes DEV_A', 'wire:I9_device_revoke_dev_a', 'accept', exposing=True, suspended=['DEV_B']),
          step('R1 receives DEV_A sequence 2 at the old head I1, latest I9, and merges it', 'wire:D_dev_a_old_head_after_revoke', 'accept'),
          step('OWNER closes epoch 0', 'wire:K1_key_epoch', 'accept', frontier={'DEV_A': 1, 'DEV_B': 1, 'BRIDGE': 1}),
          step('R2 receives the same unit after K1', 'wire:D_dev_a_beyond_epoch_cutoff', 'STALE_DATA_EPOCH', disposition='quarantine'),
          step('R1 learns K1 and rebuilds without DEV_A sequence 2', expect='rebuilt', excluded=['D_dev_a_old_head_after_revoke'], surfaced_as_stale=True)],
         {'accepted_epoch_0_units_R1': ['D_dev_a_seq1', 'D_dev_b_seq1', 'D_bridge_writes_x'],
          'accepted_epoch_0_units_R2': ['D_dev_a_seq1', 'D_dev_b_seq1', 'D_bridge_writes_x'], 'replicas_converge': True},
         ['R1, which merged the unit before the revocation closed the epoch, and R2, which saw it only after, end with the same accepted set (LFCP-WIRE-01 §19.1).'])

    # 2.
    flow('F02_cascade_recertify', 'Revoking DEV_A suspends DEV_B by the cascade; re-certification by the root makes it active again; DEV_B units at each head',
         ('LFCP-WIRE-01 §17.5 (cascade), §17.4 rule 5', 'A suspended device is not revoked; the root or another managing device may re-certify it with a chain that avoids the revoked issuer.'),
         [step('DEV_B self-registers with [CERT_B, CERT_A]', 'wire:I2_device_grant_self_dev_b', 'accept', DEV_B=dev('wire:I2_device_grant_self_dev_b', 'DEV_B')),
          step('DEV_B writes at I2', 'wire:D_dev_b_seq1', 'accept'),
          step('OWNER revokes DEV_A', 'wire:I9_device_revoke_dev_a', 'accept', DEV_B=dev('wire:I9_device_revoke_dev_a', 'DEV_B')),
          step('DEV_B writes at I9', 'wire:D_dev_b_suspended', 'AUTHORIZATION_FAILED'),
          step('DEV_B cannot re-certify itself', 'wire:device_grant_self_recertify_suspended', 'AUTHORIZATION_FAILED'),
          step('OWNER re-certifies DEV_B with [CERT_B2]', 'wire:I10_recertify_dev_b', 'accept', DEV_B=dev('wire:I10_recertify_dev_b', 'DEV_B')),
          step('DEV_B writes at I10', 'wire:D_dev_b_recertified', 'accept')],
         {'DEV_B': dev('wire:I10_recertify_dev_b', 'DEV_B')}, ['The unit at I9 stays refused after I10: activity is evaluated at the head a unit references.'])

    # 3.
    flow('F03_stale_head_reevaluation', 'Self-registration proposed on a stale head, re-evaluated on the new head; the same DEVICE_GRANT proposed twice',
         ('LFCP-WIRE-01 §47; IDENTITY-PROFILE-01 §9.2, §9.3', 'A proposer that meets CONTROL_HEAD_MISMATCH synchronises and classifies its phase on the accepted chain; a repeated record is not a transition and the intent is complete.'),
         [step('The coordinator holds I1', 'wire:I1_device_grant_dev_a', 'accept'),
          step('DEV_B proposes its self-registration on J2 (a stale head)', expect='CONTROL_HEAD_MISMATCH', in_bytes_of='wire:flow.self_register_dev_b_on_j2',
               coordinator_head='I1_device_grant_dev_a'),
          step('DEV_B synchronises: its register phase is pending on I1', phase_of=('register', 'wire:I1_device_grant_dev_a', {'root': 'OWNER', 'device': 'DEV_B', 'certificate': 'CERT_B', 'chain': ['CERT_B', 'CERT_A']}, 'pending')),
          step('DEV_B proposes a fresh record on I1', 'wire:I2_device_grant_self_dev_b', 'accept'),
          step('A second installation with the same intent classifies it on I2', phase_of=('register', 'wire:I2_device_grant_self_dev_b',
               {'root': 'OWNER', 'device': 'DEV_B', 'certificate': 'CERT_B', 'chain': ['CERT_B', 'CERT_A'], 'own': False}, 'complete'), proposes=False),
          step('Had it proposed a fresh DEVICE_GRANT with the same leaf, rule 5 refuses it (shown for DEV_A on I1)', 'wire:device_grant_repeat_same_leaf_fresh',
               'AUTHORIZATION_FAILED', aside=True),
          step('The exact bytes of a committed record sent again', 'wire:device_grant_replay_exact_bytes', 'accept', aside=True, ack='same ACK', transition=False)],
         {'DEV_B_registered': True, 'records_added': 1}, ['No record is proposed twice as a new transition; a re-sent exact record gets the same ACK.'])

    # 4.
    flow('F04_root_standing_lost_regained', "The owner revokes BOB's grant: every device of BOB is inactive; a re-grant restores them without new device records",
         ('LFCP-WIRE-01 §7.2 N4, §17.5', "Revoking the root's standing silences all its devices; restoring it restores them without re-registration."),
         [step('OWNER revokes J1', 'wire:I11_revoke_root_grant_bob', 'accept', active={d: dev('wire:I11_revoke_root_grant_bob', d)['active'] for d in ('DEV_C', 'DEV_E', 'BRIDGE')}),
          step('DEV_C writes at I11', 'wire:D_dev_c_without_standing', 'AUTHORIZATION_FAILED'),
          step('DEV_C opens X at I11', 'wire:CONTROL_GET_by_root_without_standing', 'AUTHORIZATION_FAILED'),
          step('OWNER grants BOB again', 'wire:I12_regrant_bob', 'accept', active={d: dev('wire:I12_regrant_bob', d)['active'] for d in ('DEV_C', 'DEV_E', 'BRIDGE')}),
          step('DEV_C writes at I12', 'wire:D_dev_c_regranted', 'accept')],
         {'device_records_added': 0}, ['Activity returns with standing; no DEVICE_GRANT is needed.'])

    # 5.
    i_state = post('wire:P4_register_dev_b_approved')
    flow('F05_reconciliation', "Reconciliation of X against I's Control state: revocations first, then registrations, then keys; idempotent; two reconcilers race",
         ('IDENTITY-PROFILE-01 §7.1', 'Revocations first; registrations of personal devices active in I and not registered in X; keys by the ledger; a second run proposes nothing.'),
         [step("I's state at P4: DEV_A and DEV_B registered, (OWNER, PAIR_J) consumed", 'wire:P4_register_dev_b_approved', 'accept',
               revoked=i_state['revoked'], registered=sorted(d for d, f in i_state['devices'].items() if f['registered'])),
          step("X's state: DEV_B self-registered with [CERT_B, CERT_A], DEV_A bound only as an intermediate", 'wire:flow.self_register_dev_b_on_j2', 'accept',
               DEV_A=dev('wire:flow.self_register_dev_b_on_j2', 'DEV_A')),
          step("Step 1: I's revocation of (OWNER, PAIR_J), reason 3 propagated as 0", 'wire:flow.reconcile_revoke_pairing_in_x', 'accept', exposing=False),
          step("Step 2: DEV_A, bound only as an intermediate in X, is registered with I's chain; DEV_B has the same leaf certificate ID and needs nothing",
               'wire:flow.reconcile_register_dev_a', 'accept', DEV_A=dev('wire:flow.reconcile_register_dev_a', 'DEV_A'),
               phase=phase('register', 'wire:flow.reconcile_register_dev_a', root='OWNER', device='DEV_A', certificate='CERT_A', chain=['CERT_A'], own=True)),
          step('Step 3: the reconciler seals every epoch of X it holds to DEV_A and DEV_B unless its ledger records the package', expect='packages sent',
               in_ledger_before={'DEV_A': [], 'DEV_B': []}, ledger_after={'DEV_A': [0], 'DEV_B': [0]}),
          step('A second reconciler had proposed the same registration on the previous head: CONTROL_HEAD_MISMATCH; after synchronising its phase is',
               phase_of=('register', 'wire:flow.reconcile_register_dev_a', {'root': 'OWNER', 'device': 'DEV_A', 'certificate': 'CERT_A', 'chain': ['CERT_A'], 'own': False}, 'complete')),
          step('A second run of the reconciler', expect='nothing to propose', records=0, packages=0),
          step('The Identity Resource as its own target: steps 1 and 2 are vacuous, step 3 seals I\'s epochs to DEV_B', 'wire:flow.kp_dev_a_to_dev_b_in_i', 'accept'),
          step('A service device whose issuer I has revoked is never registered in X: the revocation reaches X first and X refuses the chain (shown at I9)',
               'wire:chain_through_revoked_issuer', 'AUTHORIZATION_FAILED', aside=True)],
         {'X_devices': post('wire:flow.reconcile_register_dev_a')['devices'], 'idempotent': True},
         ['Registration and key delivery are reconciled independently; an equal leaf certificate ID says nothing about packages.'])

    # 6.
    flow('F06_concurrent_revokes', 'OWNER and DEV_A revoke DEV_B on one head with different reasons: one record; the other phase is complete',
         ('IDENTITY-PROFILE-01 §9.2 (Revoke)', 'Revoked with any other reason, by anyone: complete; the operation continues with the rotation test.'),
         [step('X at I2', 'wire:I2_device_grant_self_dev_b', 'accept'),
          step('DEV_A proposes DEVICE_REVOKE {OWNER, DEV_B, 2} on I2', expect='CONTROL_HEAD_MISMATCH', in_bytes_of='wire:flow.f06_dev_a_stale_proposal'),
          step('OWNER\'s DEVICE_REVOKE {OWNER, DEV_B, 1} on I2 was committed first', 'wire:flow.f06_owner_revokes_dev_b', 'accept'),
          step('DEV_A synchronises and classifies its revoke phase',
               phase_of=('revoke', 'wire:flow.f06_owner_revokes_dev_b', {'root': 'OWNER', 'device': 'DEV_B'}, 'complete'), not_superseded=True),
          step('A fresh proposal of the same intent would be refused', 'wire:flow.f06_dev_a_fresh_revoke', 'AUTHORIZATION_FAILED'),
          step('DEV_A continues with the rotation test of §8.1', expect='rotation test')],
         {'device_revoke_records': 1}, ['A different reason recorded by another installation is complete, not superseded.'])

    # 7.
    flow('F07_invitation_accepted_by_device', 'An invitation accepted by a device of DAVE: the claim names the root, the device registers itself and keys its root',
         ('IDENTITY-PROFILE-01 §7.2; LFCP-WIRE-01 §18.1', 'The claimant is the root; the device self-registers, seals the DEKs it holds to its root and adds the Resource to the roster.'),
         [step('OWNER invites INVITE', 'wire:N1_invite_grant', 'accept'),
          step('DEV_D, a device of DAVE, claims with claimant DAVE, signed by INVITE', 'wire:flow.claim_for_root_dave', 'accept'),
          step('DEV_D registers itself', 'wire:flow.self_register_dev_d', 'accept', DEV_D=dev('wire:flow.self_register_dev_d', 'DEV_D')),
          step('DEV_D seals epoch 0 to DAVE', 'wire:flow.kp_dev_d_to_dave', 'accept'),
          step('DAVE opens X and reads', 'wire:flow.open_as_dave', 'accept'),
          step('DEV_D adds X to the roster of I', expect='roster entry written'),
          step('A device named as claimant would be refused (shown on I2)', 'wire:claim_by_bound_claimant', 'AUTHORIZATION_FAILED', aside=True)],
         {'claimant_role': post('wire:flow.claim_for_root_dave')['roles']['DAVE']}, ['The root is the member; its devices act for it.'])

    # 8.
    d_jl = 'flow.pl_consume_l'
    flow('F08_pairing_personal', 'Pairing DEV_B through PAIR_L in an Identity Resource already rotated to epoch 1: keys of both epochs, request, phases 1 and 2, reuse and equivocation',
         ('IDENTITY-PROFILE-01 §5.3, §9', 'A pairing session yields at most one approved payload; nothing is signed for D_B before the consume is committed (N9).'),
         [step('I at P1: DEV_A registered', 'wire:P1_device_grant_dev_a_i', 'accept'),
          step("The root's Data Unit with actor sequence 1 carries the initial change (epoch 0)", 'wire:flow.pl_root_unit_1', 'accept'),
          step("The root's Data Unit with actor sequence 2 carries the fill change (epoch 0)", 'wire:flow.pl_root_unit_2', 'accept'),
          step('I is rotated to epoch 1', 'wire:flow.pl_key_epoch_1', 'accept'),
          step('DEV_A holds both DEKs and the root\'s unit 1, and creates PAIR_L', 'wire:flow.pl_pairing_device_l', 'accept'),
          step('DEV_A seals the DEK of epoch 0 to PAIR_L', 'wire:flow.pl_kp_epoch0_to_pair_l', 'accept'),
          step('DEV_A seals the DEK of epoch 1 to PAIR_L', 'wire:flow.pl_kp_epoch1_to_pair_l', 'accept'),
          step('The link of PAIR_L is shown', 'profile:pair_uri_pair_l'),
          step("B opens the root's units 1 and 2 with the DEK of epoch 0 and replays their changes: the document of §5.1 (a Snapshot is used only after unit 1)",
               'profile:identity_doc_initial_then_fill', in_changes=['change.C0_initial', 'change.C1_fill']),
          step("A Snapshot whose initial change is not the root's unit 1 is not used", 'profile:identity_doc_initial_without_unit_1', aside=True),
          step('B writes its request as PAIR_L in epoch 1', 'wire:flow.pl_pair_l_request', 'accept'),
          step('The document admits the change the unit carries', 'profile:pairing_l_writes_own_request', 'accept'),
          step('A shows the fingerprint', 'profile:fingerprint_dev_b'),
          step('Phase 1: consume with digest(CERT_B)', 'wire:flow.pl_consume_l', 'accept',
               phase_of=('consume', f'wire:{d_jl}', {'root': 'OWNER', 'device': 'PAIR_L', 'digest': d_cert_b}, 'committed-own'), exposing=True),
          step('A second manager that approved another request of the session proposes its consume', 'wire:flow.pl_second_manager_consume', 'AUTHORIZATION_FAILED',
               phase_of=('consume', f'wire:{d_jl}', {'root': 'OWNER', 'device': 'PAIR_L', 'digest': digest("CERT_B'")}, 'superseded'), signs=False),
          step('A phase-2 record with another digest is refused', 'wire:flow.pl_register_wrong_digest', 'AUTHORIZATION_FAILED'),
          step('Phase 2', 'wire:flow.pl_register_dev_b', 'accept', DEV_B=dev('wire:flow.pl_register_dev_b', 'DEV_B'),
               phase=phase('register', 'wire:flow.pl_register_dev_b', root='OWNER', device='DEV_B', certificate='CERT_B', chain=['CERT_B', 'CERT_A'], own=True)),
          step('Lost ACK of phase 2: the exact bytes are re-sent', expect='same ACK', in_bytes_of='wire:flow.pl_register_dev_b'),
          step('DEV_A seals the DEK of epoch 0 to DEV_B', 'wire:flow.pl_kp_epoch0_to_dev_b', 'accept'),
          step('DEV_A seals the DEK of epoch 1 to DEV_B', 'wire:flow.pl_kp_epoch1_to_dev_b', 'accept')],
         {'DEV_B_registered_in_I': True, 'approved_payloads': 1, 'DEV_B_epochs': [0, 1]},
         ['Before the link is shown A holds, verified, the root\'s unit 1 and the DEK of every epoch of I, and seals them all to the pairing device (§5.3 step 1).',
          "One session: the link, the binding, the signer of every pairing unit and the pairing field of every request change name PAIR_L."], pairing='PAIR_L')
    flow('F08.link_reuse_and_equivocation', 'One link, two installations: sequential reuse, and concurrent equivocation',
         ('IDENTITY-PROFILE-01 §5.3 (Concurrency and failure); LFCP-WIRE-01 §26.2', 'Two installations given one link write as PAIR_L: the second writes sequence 2, or both units are excluded as equivocation and A sees no request.'),
         [step('The first installation writes PAIR_L sequence 1', 'wire:flow.pl_pair_l_request', 'accept'),
          step('Sequential reuse: the second installation sees it and writes sequence 2', 'wire:flow.pl_pair_l_reuse_seq2', 'accept', branch='reuse'),
          step('Concurrent: the second installation also writes sequence 1', 'wire:flow.pl_pair_l_request_second_install', 'ACTOR_EQUIVOCATION', branch='equivocation',
               excluded=['flow.pl_pair_l_request', 'flow.pl_pair_l_request_second_install'], request_seen_by_A=False)],
         {}, ['An equivocating pair is excluded with the changes depending on it (SHARED-OBJECTS-PROFILE-01 §14.1).'], mode='independent', pairing='PAIR_L')
    flow('F08.binding_limit', 'OWNER at 31 live devices in I: the pairing device takes the 32nd place, the consume frees it, D_B is registered; at 32 no link',
         ('LFCP-WIRE-01 §17.4 rule 8; IDENTITY-PROFILE-01 §5.3 step 1', 'Rule 8 counts live bindings; a revoked pairing device frees its place.'),
         [step('31 live devices of OWNER in I (DEV_A and LIMIT_OWNER_01..30)', 'wire:flow.p31_pairing_device', 'accept', in_record_set='owner_bindings_30_in_i'),
          step('At 32 live devices a further pairing device is refused: no link until a device is revoked', 'wire:flow.p31_second_pairing_refused', 'AUTHORIZATION_FAILED'),
          step('The consume of PAIR_M frees its place', 'wire:flow.p31_consume', 'accept'),
          step('DEV_B takes the 32nd place', 'wire:flow.p31_register_dev_b', 'accept')], {'live_devices_of_OWNER': 32}, [])
    flow('F08.forty_sessions', '40 sessions created and cancelled one after the other, then a session completes',
         ('LFCP-WIRE-01 §17.4 rule 8', 'Revoked pairing devices free their places.'),
         [step('40 pairing devices created and cancelled in I', 'wire:flow.p40_pairing_device', 'accept', in_record_set='forty_cancelled_sessions_in_i'),
          step('Phase 1 of the 41st session', 'wire:flow.p40_consume', 'accept'),
          step('Phase 2 completes', 'wire:flow.p40_register_dev_b', 'accept')], {'cancelled_sessions': 40, 'completed': True}, [])

    # 9.
    d0 = post('wire:P3s_consume_for_bridge_o')['revoked']['OWNER/PAIR_J']['approval']['hex']
    assert d0 == digest('CERT_SO')
    proven = lambda ref: d0 in [digest(c) for c in leaves_registered_for('BRIDGE_O', ref)]  # noqa: E731
    flow('F09_pairing_service', 'Pairing the service device BRIDGE_O: approved with C0 = CERT_SO (digest d), bound in I, C0\'s issuer revoked, re-certified as C1 = CERT_SO_R; the candidates',
         ('IDENTITY-PROFILE-01 §5.3 steps 6 and 8, §6', 'Only a certificate whose digest equals the approval proves the result; a candidate whose chain never carried that leaf is unproven; a timeout is never a decision.'),
         [step('Phase 1 with digest(CERT_SO)', 'wire:P3s_consume_for_bridge_o', 'accept', approval=d0),
          step('Phase 2: bind-only DEVICE_GRANT in I', 'wire:P4s_bind_bridge_o', 'accept', BRIDGE_O=dev('wire:P4s_bind_bridge_o', 'BRIDGE_O')),
          step('BRIDGE_O cannot write in I', 'wire:D_bridge_o_in_i', 'AUTHORIZATION_FAILED'),
          step('Every candidate is offline: B shows', expect='approved, waiting for registration'),
          step("C0's issuer DEV_A is revoked in I", 'wire:flow.f09_revoke_issuer_in_i', 'accept'),
          step('The root re-certifies BRIDGE_O as C1 (same kind, mask and scope)', 'wire:flow.f09_recertify_c1_in_i', 'accept'),
          step('Candidate X where C0 was never accepted: reconciliation step 1 propagates the consume of PAIR_J', 'wire:flow.f09a_revoke_pair_j', 'accept', branch='X never C0'),
          step('… and the revocation of DEV_A', 'wire:flow.f09a_revoke_dev_a', 'accept', branch='X never C0'),
          step('… then step 2 registers C1', 'wire:flow.f09a_register_c1', 'accept', branch='X never C0',
               leaves=leaves_registered_for('BRIDGE_O', 'wire:flow.f09a_register_c1'), proven=proven('wire:flow.f09a_register_c1'), status='approval not provable here'),
          step('Candidate X where C0 was registered first (before I revoked DEV_A)', 'wire:flow.register_bridge_o_in_x', 'accept', branch='X with C0'),
          step('Reconciliation step 1: the consume of PAIR_J', 'wire:flow.f09b_revoke_pair_j', 'accept', branch='X with C0'),
          step('… and the revocation of DEV_A, which suspends BRIDGE_O', 'wire:flow.f09b_revoke_dev_a', 'accept', branch='X with C0',
               BRIDGE_O=dev('wire:flow.f09b_revoke_dev_a', 'BRIDGE_O')),
          step('Step 2 re-certifies BRIDGE_O as C1: B takes C0 from the history as its result and uses C1', 'wire:flow.f09b_register_c1', 'accept', branch='X with C0',
               leaves=leaves_registered_for('BRIDGE_O', 'wire:flow.f09b_register_c1'), proven=proven('wire:flow.f09b_register_c1'), uses='CERT_SO_R',
               BRIDGE_O=dev('wire:flow.f09b_register_c1', 'BRIDGE_O')),
          step('The root seals the DEK of X to BRIDGE_O; with the certificate and the DEK it is ready', 'wire:flow.f09b_kp_owner_to_bridge_o', 'accept', branch='X with C0', status='ready'),
          step('Candidate X where another issuer registered C* (scope [X, Y], another digest)', 'wire:flow.f09_x_register_cstar', 'accept', branch='X with C*',
               leaves=leaves_registered_for('BRIDGE_O', 'wire:flow.f09_x_register_cstar'), proven=proven('wire:flow.f09_x_register_cstar'), used=False, Y='never shown as granted'),
          step('B restarts: it resumes from its persisted candidates', expect='candidates resumed'),
          step('A crashes after the bind-only DEVICE_GRANT was accepted, before its ACK was persisted',
               phase_of=('register', 'wire:P4s_bind_bridge_o', {'root': 'OWNER', 'device': 'BRIDGE_O', 'certificate': 'CERT_SO', 'chain': ['CERT_SO', 'CERT_A'], 'own': True}, 'committed-own'), proposes=False)],
         {'registered_in_I': False, 'approved_scope': ['X']},
         ['The first verified certificate decides: until B holds one, no candidate outcome is known; a candidate absent from the scope is not granted.'],
         pairing='PAIR_J')

    # 10.
    flow('F10_request_feasibility', 'Request validation and the feasibility check before anything is committed',
         ('IDENTITY-PROFILE-01 §5.3 step 4, §4', 'A preset whose complete future chain fails W §7.3 steps 1 and 4 and W §17.4 rules 4 to 6 and 8 is not offered.'),
         [step('A valid request', 'profile:request_valid', 'accept'),
          step('A request written by another pairing device into this one', 'profile:pairing_edits_foreign_request_label', 'UNAUTHORIZED_WRITER'),
          step('The descriptor changes between display and confirmation', expect='re-confirmation'),
          step('A manager with a chain of three certificates: Full is not offered', 'wire:device_grant_feasibility_full_depth_4', 'MALFORMED_MESSAGE', offered=['Edit', 'Read']),
          step('A manager whose mask lacks 3 cannot issue Edit', 'wire:device_grant_feasibility_mask_exceeds_issuer', 'AUTHORIZATION_FAILED'),
          step('An Edit device cannot issue at all', 'wire:device_grant_feasibility_edit_issuer', 'AUTHORIZATION_FAILED'),
          step('A service scope trimmed to nothing', expect='no consume; session cancelled'),
          step("The manager's own authority is re-checked after a head change", expect='re-checked')],
         {'consume_proposed_for_infeasible_preset': False}, ['No consume is proposed for a preset that fails the check.'], mode='independent')

    # 11.
    flow('F11_revoker_chain_through_target', 'DEV_E, issued by DEV_C, revokes DEV_C: it re-certifies first, then revokes, then retires',
         ('IDENTITY-PROFILE-01 §8.1', "The revoker's own chain MUST NOT pass through D; it first obtains a fresh chain from the root or a managing device whose chain avoids D, and only then revokes."),
         [step('X at I8: DEV_E active with chain [CERT_E, CERT_C]', 'wire:I8_bridge_grant', 'accept', DEV_E=dev('wire:I8_bridge_grant', 'DEV_E')),
          step('Without re-certification the revocation would suspend DEV_E itself: the pre-check refuses it', 'wire:flow.f11_dev_e_revokes_dev_c_unrecertified', 'accept',
               branch='prevented', DEV_E=dev('wire:flow.f11_dev_e_revokes_dev_c_unrecertified', 'DEV_E'), client='refused by the pre-check'),
          step('BOB re-certifies DEV_E with [CERT_E2]', 'wire:flow.f11_recertify_dev_e', 'accept', DEV_E=dev('wire:flow.f11_recertify_dev_e', 'DEV_E')),
          step('DEV_E revokes DEV_C and stays active', 'wire:flow.f11_dev_e_revokes_dev_c', 'accept', DEV_E=dev('wire:flow.f11_dev_e_revokes_dev_c', 'DEV_E'),
               exposing=post('wire:flow.f11_dev_e_revokes_dev_c')['exposing']),
          step('DEV_E retires itself; rotation is left to another installation', 'wire:flow.f11_dev_e_retires', 'accept', rotates=False)],
         {}, ['A device never re-certifies itself (device_grant_self_recertify_active_managing).'])

    # 12.
    rot = case('wire:flow.rotator_test')['expected']['tables']
    flow('F12_rotation_with_open_session', 'Rotating I while PAIR_J and PAIR_K are open, then closing J; the rotator test on concrete states',
         ('IDENTITY-PROFILE-01 §8.2, §8.1', 'The new DEK is sealed to every Principal with holds(P, 1) at the new head, open pairing devices included; consumed or cancelled ones receive nothing.'),
         [step('I at P2: PAIR_J open', 'wire:P2_pairing_device', 'accept'),
          step('PAIR_K open', 'wire:P2k_pairing_device_k', 'accept'),
          step('DEV_A rotates I to epoch 1', 'wire:flow.f12_i_key_epoch_1', 'accept'),
          step('The new DEK to OWNER', 'wire:flow.f12_kp_epoch1_to_owner', 'accept'),
          step('The new DEK to PAIR_J', 'wire:flow.f12_kp_epoch1_to_pair_j', 'accept'),
          step('The new DEK to PAIR_K', 'wire:flow.f12_kp_epoch1_to_pair_k', 'accept'),
          step("J's session is cancelled", 'wire:flow.f12_cancel_j', 'accept', exposing=True),
          step('A cancelled pairing device receives nothing', 'wire:flow.f12_kp_epoch1_to_pair_j_after_cancel', 'AUTHORIZATION_FAILED'),
          step("K's request continues in epoch 1", 'wire:flow.f12_pair_k_writes_request', 'accept'),
          step('The rotator test of §8.1 in X (CAROL is a foreign reader) and in I', 'wire:flow.rotator_test', tables=rot)],
         {'rotators': {res: sorted(c for c, f in t['candidates'].items() if f['rotator']) for res, t in rot.items()}},
         ['7 without 6 in a Resource with a foreign reader, or 6 without 7: awaiting rotation, no KEY_EPOCH committed; both, or 7 alone in I where every reader is of the root: rotates.'])

    # 13.
    payload_b = CERTS['CERT_B']['payload_cbor']['hex']
    assert hashlib.sha256(bytes.fromhex(payload_b)).hexdigest() == d_cert_b
    assert case('wire:P4_register_dev_b_approved')['inputs']['body']['chain'][0] == 'CERT_B'
    pkg = lambda ref: case(ref)['inputs']['object_id']['hex']  # noqa: E731
    journal_approval = {'phase': 'consume', 'resource': 'I', 'pairing_device': 'PAIR_J', 'certificate_payload_cbor': payload_b,
                        'certificate_payload_digest': d_cert_b, 'next_record': 'P3_consume_for_dev_b'}
    flow('F13_durable_phases', 'Crash and concurrency around every ACK of a pairing approval (I) and of revoke plus rotate (X)',
         ('IDENTITY-PROFILE-01 §9.1 to §9.5', 'Phases are classified against the accepted chain by the table of §9.2; a phase is repeated only with its exact bytes; a KEY_EPOCH is rebuilt, never re-proposed.'),
         [step('Approval journal before phase 1: the complete certificate payload of DEV_B and its digest, and the exact bytes of P3; the chain is at P2',
               'wire:P2_pairing_device', 'accept', in_journal=journal_approval,
               phase_of=('consume', 'wire:P2_pairing_device', {'root': 'OWNER', 'device': 'PAIR_J', 'digest': d_cert_b}, 'pending')),
          step('Crash after sending P3; after restart the chain holds P3', 'wire:P3_consume_for_dev_b', 'accept',
               phase_of=('consume', 'wire:P3_consume_for_dev_b', {'root': 'OWNER', 'device': 'PAIR_J', 'digest': d_cert_b}, 'committed-own')),
          step('Its ACK was lost: the exact bytes of P3 are re-sent', expect='same ACK', in_bytes_of='wire:P3_consume_for_dev_b'),
          step('Phase 2 after the restart: the certificate is signed from the journaled payload (CERT_B, whose payload digest is the approval)',
               phase_of=('register', 'wire:P3_consume_for_dev_b', {'root': 'OWNER', 'device': 'DEV_B', 'certificate': 'CERT_B', 'chain': ['CERT_B', 'CERT_A']}, 'pending'),
               in_journal={'phase': 'register', 'certificate_payload_cbor': payload_b, 'next_record': 'P4_register_dev_b_approved'},
               signed_certificate='CERT_B', chain=['CERT_B', 'CERT_A'], certificate_payload_matches_journal=CERTS['CERT_B']['payload_cbor']['hex'] == payload_b),
          step('Crash after the ACK of P4 and before it was persisted', 'wire:P4_register_dev_b_approved', 'accept',
               phase_of=('register', 'wire:P4_register_dev_b_approved', {'root': 'OWNER', 'device': 'DEV_B', 'certificate': 'CERT_B', 'chain': ['CERT_B', 'CERT_A'], 'own': True}, 'committed-own')),
          step('Exact-byte retry of P4', expect='same ACK', in_bytes_of='wire:P4_register_dev_b_approved'),
          step('Revoke journal in X: revoke (OWNER, DEV_A) with reason 1; the chain is at I8', 'wire:I8_bridge_grant', 'accept',
               phase_of=('revoke', 'wire:I8_bridge_grant', {'root': 'OWNER', 'device': 'DEV_A'}, 'pending')),
          step('After the ACK of I9 (or after a crash), the revoke phase', 'wire:I9_device_revoke_dev_a', 'accept',
               phase_of=('revoke', 'wire:I9_device_revoke_dev_a', {'root': 'OWNER', 'device': 'DEV_A'}, 'complete')),
          step('The rotate phase after the revocation at I9', phase_of=('rotate', 'wire:I9_device_revoke_dev_a', {'revoked_at': 'wire:I9_device_revoke_dev_a'}, 'pending')),
          step('A rotation planned at I8 had sealed its DEK to DEV_A, a reader at I8 and not at I9, the head the KEY_EPOCH is committed on: that DEK is not used',
               expect='fresh DEK (§9.4)', DEV_A_reads={'I8': dev('wire:I8_bridge_grant', 'DEV_A')['reads'], 'I9': dev('wire:I9_device_revoke_dev_a', 'DEV_A')['reads']}),
          step('The KEY_EPOCH with a fresh DEK is committed on I9', 'wire:K1_key_epoch', 'accept',
               phase_of=('rotate', 'wire:K1_key_epoch', {'revoked_at': 'wire:I9_device_revoke_dev_a'}, 'complete')),
          step('Partial delivery: the package of epoch 1 to BOB is sent and recorded, then the rotator crashes', 'wire:flow.f13_kp_epoch1_to_bob', 'accept',
               branch='partial delivery', in_ledger=[{'resource': 'X', 'epoch': 1, 'recipient': 'BOB', 'package_id': pkg('wire:flow.f13_kp_epoch1_to_bob')}]),
          step('After the restart the package phases are classified by the ledger: BOB complete, CAROL pending; the package to CAROL is sent',
               'wire:flow.f13_kp_epoch1_to_carol', 'accept', branch='partial delivery', package_phases={'BOB': 'complete', 'CAROL': 'pending'},
               ledger_after=[{'resource': 'X', 'epoch': 1, 'recipient': r, 'package_id': pkg(f'wire:flow.f13_kp_epoch1_to_{r.lower()}')} for r in ('BOB', 'CAROL')]),
          step('DEV_B, suspended at K1, is not a reader and is skipped', 'wire:flow.f13_kp_epoch1_to_dev_b_suspended', 'AUTHORIZATION_FAILED', branch='partial delivery'),
          step('Alternative: the rotator of K1 crashed before any package; readers hold epoch 1 in KEY_BLOCKED', expect='awaiting key holder', branch='no package',
               in_ledger=[]),
          step('After a bounded wait a second rotator commits epoch 2 with a fresh DEK', 'wire:flow.f13_second_rotator_epoch_2', 'accept', branch='no package')],
         {}, ['No installation reconstructs a DEK it does not hold; journals hold no secrets (§9.8): the certificate payload is not a secret.'])

    m2 = {'root': 'OWNER', 'device': 'DEV_M2', 'certificate': 'CERT_M2', 'chain': ['CERT_M2', 'CERT_A']}
    b1 = {'root': 'OWNER', 'device': 'DEV_B', 'certificate': "CERT_B'", 'chain': ["CERT_B'", 'CERT_A']}
    b2 = {'root': 'OWNER', 'device': 'DEV_B', 'certificate': 'CERT_B2', 'chain': ['CERT_B2']}
    flow('F13.issuer_revoked_before_resume', "An issuer of the planned chain is revoked between planning and resuming: a first registration and a re-certification are superseded",
         ('IDENTITY-PROFILE-01 §9.2 (Register or re-certify)', "(R, D) revoked, or an issuer of c's chain revoked: superseded; the issuers are those of the planned chain c, not of the current binding."),
         [step('X at I8: a first registration of DEV_M2 with [CERT_M2, CERT_A] is planned (DEV_M2 is not bound in X)', 'wire:I8_bridge_grant', 'accept',
               phase_of=('register', 'wire:I8_bridge_grant', m2, 'pending'), DEV_M2_bound='DEV_M2' in post('wire:I8_bridge_grant')['devices']),
          step("… and a re-certification of DEV_B with [CERT_B', CERT_A] (DEV_B's current leaf is CERT_B)",
               phase_of=('register', 'wire:I8_bridge_grant', b1, 'pending'), DEV_B_leaf=dev('wire:I8_bridge_grant', 'DEV_B')['leaf']),
          step('Before either operation resumes, OWNER revokes DEV_A, the issuer in both planned chains', 'wire:I9_device_revoke_dev_a', 'accept'),
          step('The first registration resumes: superseded, nothing is signed or proposed', phase_of=('register', 'wire:I9_device_revoke_dev_a', m2, 'superseded'),
               proposes=False),
          step('The re-certification resumes: superseded, nothing is signed or proposed', phase_of=('register', 'wire:I9_device_revoke_dev_a', b1, 'superseded'),
               proposes=False),
          step("Control: a re-certification of DEV_B by the root with [CERT_B2], which avoids DEV_A, is pending on I9",
               phase_of=('register', 'wire:I9_device_revoke_dev_a', b2, 'pending')),
          step('… and committed-own once I10 is accepted', 'wire:I10_recertify_dev_b', 'accept', phase_of=('register', 'wire:I10_recertify_dev_b', {**b2, 'own': True}, 'committed-own'))],
         {'superseded': ['DEV_M2 first registration', 'DEV_B re-certification through DEV_A']},
         ['A phase is classified on the chain it would commit; the current binding of the device does not name the issuers of a chain not yet committed.'])

    # 14.
    fr = case('wire:flow.y_key_epoch_1')['inputs']['body']['frontier']
    flow('F14_frontier_from_verified_set', "The final frontier comes from the rotator's verified accepted set, extra ranges included",
         ('LFCP-WIRE-01 §19, §19.1, §28.1; IDENTITY-PROFILE-01 §8.3', "A Have Vector is a fetch hint; a sequence the rotator could not fetch and verify stays outside the frontier; an accepted range after a hole is kept as an extra range."),
         [step('DEV_A sequence 1 in Y', 'wire:flow.y_dev_a_seq1', 'accept'),
          step('DEV_A sequence 2', 'wire:flow.y_dev_a_seq2', 'accept'),
          step('DEV_A sequence 4, previous = sequence 2 (sequence 3 never written)', 'wire:flow.y_dev_a_seq4', 'accept'),
          step('An advertised unit that fails authorization (BRIDGE in Y) is not counted', 'wire:D_bridge_in_y', 'AUTHORIZATION_FAILED', counted=False),
          step('The server advertises DEV_A 1..100; only 1, 2 and 4 are fetchable and verify', expect='verified accepted set DEV_A {1, 2, 4}'),
          step('A frontier that writes the range after the hole as [3, 4] is not canonical', 'wire:flow.y_key_epoch_noncanonical_range', 'MALFORMED_MESSAGE'),
          step('DEV_A closes epoch 0 with the frontier {0: DEV_A, 1: 2, 2: [[4, 4]]}', 'wire:flow.y_key_epoch_1', 'accept', frontier=fr),
          step('Sequence 4 received after the KEY_EPOCH: inside the extra range', 'wire:flow.y_dev_a_seq4_after_epoch', 'accept'),
          step('A sequence 3 arriving after the KEY_EPOCH: in the hole', 'wire:flow.y_dev_a_seq3_after_epoch', 'STALE_DATA_EPOCH', disposition='quarantine'),
          step('Sequence 5 after the KEY_EPOCH: beyond the frontier', 'wire:flow.y_dev_a_seq5_after_epoch', 'STALE_DATA_EPOCH', disposition='quarantine')],
         {'frontier': fr, 'frontier_rule': 'the verified accepted sequences of each actor: the contiguous prefix plus every accepted range after a hole (W §28.1 extra ranges)'},
         ['A replica that merged sequence 4 keeps it when it learns the KEY_EPOCH; only units outside the recorded frontier are rebuilt out.'])

    # 15.
    exp = {r: post(f'wire:{r}')['exposing'] for r in ('I9_device_revoke_dev_a', 'V2_revoke_dev_c', 'Vu1_revoke_unbound', 'W2',
                                                      'flow.revoke_out_of_scope_bridge_in_y', 'flow.revoke_suspended_dev_b')}
    flow('F15_rotation_policy_by_exposure', 'Rotation follows exposing revocations only (independent cases, one per kind of revocation)',
         ('LFCP-WIRE-01 §17.5 (exposure); IDENTITY-PROFILE-01 §8.4', 'A revocation that removes no registered reader never triggers a rotation; one rotation covers every exposing revocation since the last.'),
         [step('An exposing revocation', 'wire:I9_device_revoke_dev_a', 'accept', exposing=exp['I9_device_revoke_dev_a'], rotations=1),
          step('An unbound tombstone without descendants', 'wire:Vu1_revoke_unbound', 'accept', exposing=exp['Vu1_revoke_unbound'], rotations=0),
          step('An out-of-scope binding revoked', 'wire:flow.revoke_out_of_scope_bridge_in_y', 'accept', exposing=exp['flow.revoke_out_of_scope_bridge_in_y'], rotations=0),
          step('An already suspended device revoked', 'wire:flow.revoke_suspended_dev_b', 'accept', exposing=exp['flow.revoke_suspended_dev_b'], rotations=0),
          step('A never-reading device revoked', 'wire:W2', 'accept', exposing=exp['W2'], rotations=0),
          step('An intermediate-only device with a reading descendant revoked', 'wire:V2_revoke_dev_c', 'accept', exposing=exp['V2_revoke_dev_c'], rotations=1,
               descendant_receives_new_epoch=False),
          step('Three exposing revocations in one epoch', expect='one rotation'),
          step('A former member cannot issue the tombstone at all', 'wire:device_revoke_by_former_member', 'AUTHORIZATION_FAILED')],
         {'exposing': exp}, ["Exposure is computed from the Resource's own chain alone."], mode='independent')

    # 16.
    flow('F16_device_grant_fork', 'Two valid competing DEVICE_GRANTs on one prev',
         ('LFCP-WIRE-01 §13.2; IDENTITY-PROFILE-01 §9.7', 'Neither is the head; approval and reconciliation are suspended; no branch is chosen by time, order or ACK.'),
         [step('X at I1', 'wire:I1_device_grant_dev_a', 'accept'),
          step('Rd1 on I1, delivered to one manager', 'wire:Rd1', 'accept', branch='Rd1'),
          step('W1 on I1, delivered to another manager', 'wire:W1', 'accept', branch='W1'),
          step('Both branches known', expect='CONTROL_CONFLICT', competing=['Rd1', 'W1']),
          step('Approval, reconciliation and automatic rotation taking I or X as input', expect='suspended')],
         {'state': 'CONTROL_CONFLICT'}, ['A validator given both records reports CONTROL_CONFLICT and applies neither.'],
         {'records': ['wire:J0_genesis', 'wire:J1_grant_bob', 'wire:J2_grant_carol', 'wire:I1_device_grant_dev_a', 'wire:Rd1', 'wire:W1']})

    # 17.
    flow('F17_revoked_device', 'A revoked device reconnects',
         ('IDENTITY-PROFILE-01 §8.6; LFCP-WIRE-01 §41', 'Access refused alone, or revocation proven through the Control read for a revoked reader; uploads are checked by object.'),
         [step('DEV_A was offline during I9 and reconnects at I10', 'wire:CONTROL_GET_by_revoked_reader', 'accept', status='revocation proven', head='I9_device_revoke_dev_a'),
          step('DEV_A requests data', 'wire:DATA_GET_by_revoked_session', 'AUTHORIZATION_FAILED'),
          step('DEV_A re-supplies a valid foreign Key Package the server lost', 'wire:KEY_PACKAGE_PUT_by_revoked_session_foreign_package', 'accept'),
          step('A device that never read (DEV_W at W2)', 'wire:CONTROL_GET_by_never_reader', 'AUTHORIZATION_FAILED', branch='never reader', status='access refused'),
          step('Online: pushes stop before the revoking record is pushed (W §69)', expect='unsubscribed before push')],
         {}, ['The device never creates Data Units for the Resource again and is never re-paired under the same Principal.'])

    # 18.
    barrier = {'type 9': 'wire:I1_device_grant_dev_a', 'type 10': 'wire:I9_device_revoke_dev_a', 'Genesis field 5': 'wire:G1_genesis_by_dev_a', 'commit field 2': 'wire:T1_commit'}
    pre = {'type 9': 'INVALID_CONTROL_CHAIN', 'type 10': 'INVALID_CONTROL_CHAIN', 'Genesis field 5': 'MALFORMED_MESSAGE', 'commit field 2': 'MALFORMED_MESSAGE'}
    flow('F18_barrier', 'The four barrier entries against a pre-identity validator, a herald and an identity-aware one (independent cases)',
         ('LFCP-WIRE-01 §100.1, §37', 'A pre-identity client rejects the barrier and blocks the Resource; a herald persists the blocked state with the update message; an identity-aware client accepts.'),
         [step(f'{name}', ref, 'accept', pre_identity=pre[name], herald='blocked at this head (persisted)', identity_aware='accept') for name, ref in barrier.items()]
         + [step('A blocked client writes on its last validated head', expect='accepted until the epoch closes')],
         {'server_without_identity_01': {name: pre[name] for name in barrier}}, ['A server whose READY lacks identity-01 rejects these records as a pre-identity receiver does.'],
         mode='independent')

    # 19.
    flow('F19_key_bootstrap', 'Devices that never received their first packages get every epoch from the next reconciling manager (independent cases)',
         ('IDENTITY-PROFILE-01 §7.1 step 3', 'Key delivery is unconditional: no complaint, no data/write and no DEK of I is needed on the recipient side.'),
         [step('A Read device in X', 'wire:flow.kp_owner_to_dev_r', 'accept'),
          step('A device registered in I whose approver crashed before its first package', 'wire:flow.kp_dev_a_to_dev_b_in_i', 'accept'),
          step('A service device bound in I and registered in X', 'wire:flow.kp_dev_a_to_bridge_o_in_x', 'accept'),
          step('None of them wrote missing_keys', expect='served anyway')],
         {'I_is_a_target': True}, ['The ledger, not a complaint, drives the delivery.'], mode='independent')


def suite() -> dict:
    return {
        'format': 'lfcp-vector-format/1',
        'suite': {
            'id': SUITE_ID, 'version': '01',
            'specification': {'id': 'IDENTITY-PROFILE-01', 'profile': 'org.openlfcp.identity.v1', 'revision': 'working-draft'},
            'description': 'State-machine and durable-operation fixtures of multi-device identity (IDENTITY-PROFILE-01 §12.3; LFCP-WIRE-01 §107).',
            'depends_on': ['LFCP-IDENTITY-TEST-VECTORS-01', 'IDENTITY-PROFILE-TEST-VECTORS-01', 'LFCP-WIRE-01', 'IDENTITY-PROFILE-01'],
            'conventions': {
                'steps': "inputs.steps are performed in order; expected.steps gives each step's outcome and the facts it asserts.",
                'references': "A step case `wire:<id>` names a case of LFCP-IDENTITY-TEST-VECTORS-01, `profile:<id>` one of IDENTITY-PROFILE-TEST-VECTORS-01; the step outcome equals that case's expected outcome. `bytes_of` names a case whose exact bytes a step sends in another context, with the outcome the step states.",
                'history': "inputs.mode `sequence`: the steps of each Resource and `branch` form one history; the Control state a step's case is decided on contains the last record an earlier step of the same branch committed. An `aside` step shows a rule on another head and is not part of the history. Mode `independent`: each step stands alone.",
                'phases': "expected `phase` is the state of IDENTITY-PROFILE-01 §9.2 on the Control state of the step's case (`phase_input`), first match wins.",
                'client_outcomes': 'Outcomes without a case are client-procedure results (phase states of IDENTITY-PROFILE-01 §9.2, statuses of §6); they have no wire code.',
            },
        },
        'cases': CASES,
    }


def markdown(doc: dict) -> str:
    lines = [f'# {SUITE_ID}', '', 'Generated by `generate_identity_flow_fixtures_01.py`; do not edit by hand. Each step names the case whose bytes it sends',
             'and whose outcome it expects (`wire:` LFCP-IDENTITY-TEST-VECTORS-01, `profile:` IDENTITY-PROFILE-TEST-VECTORS-01).', '']
    for c in doc['cases']:
        lines += [f"## {c['id']}", '', c['description'] + f" ({c['rule']['section']}; mode {c['inputs']['mode']})", '',
                  '| # | Step | Case | Outcome | Phase |', '|---|---|---|---|---|']
        for s, e in zip(c['inputs']['steps'], c['expected']['steps']):
            where = ('`' + s['case'] + '`') if 'case' in s else (('bytes of `' + s['bytes_of'] + '`') if 'bytes_of' in s else '')
            tag = ' (aside)' if s.get('aside') else (f" ({s['branch']})" if s.get('branch') else '')
            lines.append(f"| {s['n']} | {s['action']}{tag} | {where} | {e['outcome']} | {e.get('phase', '')} |")
        lines.append('')
    return '\n'.join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=f'Generate {SUITE_ID}.')
    parser.add_argument('--out-dir', type=Path, default=HERE)
    args = parser.parse_args()
    build()
    doc = suite()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / f'{SUITE_ID}.json').write_text(json.dumps(doc, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    (args.out_dir / f'{SUITE_ID}.md').write_text(markdown(doc), encoding='utf-8')
    print(args.out_dir / f'{SUITE_ID}.json')


if __name__ == '__main__':
    main()
