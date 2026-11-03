#!/usr/bin/env python3
"""Generate IDENTITY-FLOW-FIXTURES-01 (IDENTITY-PROFILE-01 §12.3; LFCP-WIRE-01 §107 style).

State-machine and durable-operation fixtures for multi-device identity. Each
fixture is a sequence of steps. A step that sends or receives a protocol
object names its case in LFCP-IDENTITY-TEST-VECTORS-01 (`wire:<id>`) or in
IDENTITY-PROFILE-TEST-VECTORS-01 (`profile:<id>`), where the exact bytes and
the deciding rule are; the generator checks that the outcome a step states is
the outcome that case expects. Steps of the client procedures (phase states
of IDENTITY-PROFILE-01 §9.2, statuses of §6, reconciliation of §7.1) state
the result those sections require.

Run after both corpora are generated:

    python3 generate_identity_flow_fixtures_01.py [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITE_ID = 'IDENTITY-FLOW-FIXTURES-01'
WIRE = json.loads((HERE.parent / 'lfcp-wire-01' / 'LFCP-IDENTITY-TEST-VECTORS-01.json').read_text(encoding='utf-8'))
PROF = json.loads((HERE / 'IDENTITY-PROFILE-TEST-VECTORS-01.json').read_text(encoding='utf-8'))
SUITES = {'wire': {c['id']: c for c in WIRE['cases']}, 'profile': {c['id']: c for c in PROF['cases']}}
CASES: list[dict] = []


def outcome_of(ref: str) -> str:
    suite, _, cid = ref.partition(':')
    c = SUITES[suite].get(cid)
    if c is None:
        raise SystemExit(f'unknown case {ref}')
    if c['type'] != 'validation':
        return 'exact bytes' if c['type'] == 'bytes' else 'see case'
    e = c['expected']
    if e['valid']:
        return 'accept'
    return e['error'].get('diagnostic') or e['error']['code']


def post(ref: str) -> dict:
    suite, _, cid = ref.partition(':')
    return SUITES[suite][cid]['expected'].get('post_state', {})


def step(action: str, ref: str | None = None, expect: str | None = None, **facts) -> dict:
    s = {'action': action}
    if ref:
        s['case'] = ref
        got = outcome_of(ref)
        if expect is not None and expect != got:
            raise SystemExit(f'step {action!r}: expects {expect}, {ref} expects {got}')
        s['outcome'] = expect or got
    elif expect is not None:
        s['outcome'] = expect
    s.update(facts)
    return s


def flow(fid: str, description: str, rule: tuple[str, str], steps: list[dict], final: dict, assertions: list[str], inputs: dict | None = None) -> None:
    for i, s in enumerate(steps, 1):
        s['n'] = i
    CASES.append({
        'id': fid, 'type': 'behavioral', 'kind': 'identity_flow', 'description': description,
        'rule': {'section': rule[0], 'text': rule[1]},
        'inputs': {**(inputs or {}), 'steps': [{k: v for k, v in s.items() if k not in ('outcome',) and not k.startswith('expect_')} for s in steps]},
        'expected': {'steps': [{'n': s['n'], 'outcome': s.get('outcome', 'done'), **{k[7:]: v for k, v in s.items() if k.startswith('expect_')}} for s in steps],
                     'final': final},
        'assertions': assertions,
    })


def ex(**facts) -> dict:
    return {f'expect_{k}': v for k, v in facts.items()}


def dev(ref: str, label: str) -> dict:
    return post(ref)['devices'][label]


def build() -> None:
    # 1. register -> write -> revoke -> old-head unit -> KEY_EPOCH -> beyond the frontier -> rebuild.
    assert post('wire:I9_device_revoke_dev_a')['exposing'] is True
    flow('F01_register_write_revoke_cutoff',
         'Register DEV_A, write, revoke it, accept an old-head unit, close the epoch, quarantine the unit beyond the frontier and rebuild',
         ('LFCP-WIRE-01 §17.5, §19.1, §26.3, §81', 'Revocation without rotation leaves old-head units acceptable until the closing KEY_EPOCH; beyond its frontier they are STALE_DATA_EPOCH and replicas rebuild without them.'),
         [step('replicas R1 and R2 accept the registration', 'wire:I1_device_grant_dev_a', 'accept'),
          step('DEV_A writes sequence 1 at I1', 'wire:D_dev_a_seq1', 'accept'),
          step('DEV_B self-registers and writes; BRIDGE writes at I8', 'wire:D_dev_b_seq1', 'accept'),
          step('BRIDGE writes at I8', 'wire:D_bridge_writes_x', 'accept'),
          step('OWNER revokes DEV_A', 'wire:I9_device_revoke_dev_a', 'accept', **ex(exposing=True, suspended=['DEV_B'])),
          step('R1 receives DEV_A sequence 2 at the old head I1, latest I9, and merges it', 'wire:D_dev_a_old_head_after_revoke', 'accept'),
          step('OWNER closes epoch 0', 'wire:K1_key_epoch', 'accept', **ex(frontier={'DEV_A': 1, 'DEV_B': 1, 'BRIDGE': 1})),
          step('R2 receives the same unit after K1', 'wire:D_dev_a_beyond_epoch_cutoff', 'STALE_DATA_EPOCH', **ex(disposition='quarantine')),
          step('R1 learns K1 and rebuilds without DEV_A sequence 2', expect='rebuilt', **ex(excluded=['D_dev_a_old_head_after_revoke'], surfaced_as_stale=True))],
         {'accepted_epoch_0_units_R1': ['D_dev_a_seq1', 'D_dev_b_seq1', 'D_bridge_writes_x'],
          'accepted_epoch_0_units_R2': ['D_dev_a_seq1', 'D_dev_b_seq1', 'D_bridge_writes_x'], 'replicas_converge': True},
         ['R1, which merged the unit before the revocation closed the epoch, and R2, which saw it only after, end with the same accepted set (LFCP-WIRE-01 §19.1).'])

    # 2. cascade and re-certification.
    flow('F02_cascade_recertify', 'Revoking DEV_A suspends DEV_B by the cascade; re-certification by the root makes it active again; DEV_B units at each head',
         ('LFCP-WIRE-01 §17.5 (cascade), §17.4 rule 5', 'A suspended device is not revoked; the root or a managing device may re-certify it with a chain that avoids the revoked issuer.'),
         [step('DEV_B self-registers with [CERT_B, CERT_A]', 'wire:I2_device_grant_self_dev_b', 'accept', **ex(DEV_B=dev('wire:I2_device_grant_self_dev_b', 'DEV_B'))),
          step('DEV_B writes at I2', 'wire:D_dev_b_seq1', 'accept'),
          step('OWNER revokes DEV_A', 'wire:I9_device_revoke_dev_a', 'accept', **ex(DEV_B=dev('wire:I9_device_revoke_dev_a', 'DEV_B'))),
          step('DEV_B writes at I9', 'wire:D_dev_b_suspended', 'AUTHORIZATION_FAILED'),
          step('DEV_B cannot re-certify itself', 'wire:device_grant_self_recertify_suspended', 'AUTHORIZATION_FAILED'),
          step('OWNER re-certifies DEV_B with [CERT_B2]', 'wire:I10_recertify_dev_b', 'accept', **ex(DEV_B=dev('wire:I10_recertify_dev_b', 'DEV_B'))),
          step('DEV_B writes at I10', 'wire:D_dev_b_recertified', 'accept')],
         {'DEV_B': dev('wire:I10_recertify_dev_b', 'DEV_B')}, ['The unit at I9 stays refused after I10: activity is evaluated at the head a unit references.'])

    # 3. stale head and the same DEVICE_GRANT twice.
    flow('F03_stale_head_reevaluation', 'Self-registration proposed on a stale head, re-evaluated on the new head; the same DEVICE_GRANT proposed twice',
         ('LFCP-WIRE-01 §47; IDENTITY-PROFILE-01 §9.2, §9.3', 'A proposer that meets CONTROL_HEAD_MISMATCH synchronises and classifies its phase on the accepted chain; a repeated record is not a transition and the intent is complete.'),
         [step('DEV_B proposes its self-registration on J2 while the coordinator head is I1', expect='CONTROL_HEAD_MISMATCH',
               bytes_of='wire:flow.self_register_dev_b_on_j2', **ex(coordinator_head='I1_device_grant_dev_a')),
          step('DEV_B synchronises, classifies the register phase as pending and proposes a fresh record on I1', 'wire:I2_device_grant_self_dev_b', 'accept', **ex(phase='pending')),
          step('A second installation of the same intent finds devices[DEV_B].leaf_id = id(CERT_B)', expect='complete', **ex(phase='complete', proposes=False)),
          step('Had it proposed a fresh DEVICE_GRANT with the same leaf, rule 5 refuses it (shown for DEV_A)', 'wire:device_grant_repeat_same_leaf_fresh', 'AUTHORIZATION_FAILED'),
          step('The exact bytes of a committed record sent again', 'wire:device_grant_replay_exact_bytes', 'accept', **ex(ack='same ACK', transition=False))],
         {'DEV_B_registered': True, 'records_added': 1}, ['No record is proposed twice as a new transition; a re-sent exact record gets the same ACK.'])

    # 4. root standing.
    flow('F04_root_standing_lost_regained', "The owner revokes BOB's grant: every device of BOB is inactive; a re-grant restores them without new device records",
         ('LFCP-WIRE-01 §7.2 N4, §17.5', 'Revoking the root\'s standing silences all its devices; restoring it restores them without re-registration.'),
         [step('OWNER revokes J1', 'wire:I11_revoke_root_grant_bob', 'accept', **ex(active={d: dev('wire:I11_revoke_root_grant_bob', d)['active'] for d in ('DEV_C', 'DEV_E', 'BRIDGE')})),
          step('DEV_C writes at I11', 'wire:D_dev_c_without_standing', 'AUTHORIZATION_FAILED'),
          step('DEV_C opens X at I11', 'wire:CONTROL_GET_by_root_without_standing', 'AUTHORIZATION_FAILED'),
          step('OWNER grants BOB again', 'wire:I12_regrant_bob', 'accept', **ex(active={d: dev('wire:I12_regrant_bob', d)['active'] for d in ('DEV_C', 'DEV_E', 'BRIDGE')})),
          step('DEV_C writes at I12', 'wire:D_dev_c_regranted', 'accept')],
         {'device_records_added': 0}, ['Activity returns with standing; no DEVICE_GRANT is needed.'])

    # 5. reconciliation.
    i_state = post('wire:P4_register_dev_b_approved')
    flow('F05_reconciliation', "Reconciliation of X against I's Control state: revocations first, then registrations, then keys; idempotent",
         ('IDENTITY-PROFILE-01 §7.1', 'Revocations first; registrations of personal devices active in I and not registered in X; keys by the ledger; a second run proposes nothing.'),
         [step("I's state at P4: DEV_A and DEV_B registered, (OWNER, PAIR_J) consumed", 'wire:P4_register_dev_b_approved', 'accept',
               **ex(revoked=i_state['revoked'], registered=[d for d, f in i_state['devices'].items() if f['registered']])),
          step("X's state: DEV_B self-registered with [CERT_B, CERT_A], DEV_A bound only as an intermediate", 'wire:flow.self_register_dev_b_on_j2', 'accept',
               **ex(DEV_A=dev('wire:flow.self_register_dev_b_on_j2', 'DEV_A'))),
          step("Step 1: I's revocation of (OWNER, PAIR_J) is proposed on X with reason 0", 'wire:flow.reconcile_revoke_pairing_in_x', 'accept', **ex(exposing=False)),
          step('Step 2: DEV_A (intermediate-only in X) is registered with I\'s chain; DEV_B has the same leaf certificate ID and needs nothing', 'wire:flow.reconcile_register_dev_a', 'accept',
               **ex(DEV_A=dev('wire:flow.reconcile_register_dev_a', 'DEV_A'))),
          step('Step 3: every epoch of X the reconciler holds is sealed to DEV_A and DEV_B unless the ledger records it', expect='packages sent', **ex(recipients=['DEV_A', 'DEV_B'], epochs=[0])),
          step('A service device whose issuer I has revoked is never registered in X: the revocation reaches X first and X refuses the chain (as chain_through_revoked_issuer)', 'wire:chain_through_revoked_issuer', 'AUTHORIZATION_FAILED'),
          step('The Identity Resource as its own target: steps 1 and 2 are vacuous, step 3 seals I\'s epochs to DEV_B', 'wire:flow.kp_dev_a_to_dev_b_in_i', 'accept'),
          step('A second run', expect='nothing to propose', **ex(records=0, packages=0)),
          step('Two reconcilers race: the loser meets CONTROL_HEAD_MISMATCH, synchronises and classifies its phases as complete', expect='complete', **ex(phase='complete'))],
         {'X_devices': post('wire:flow.reconcile_register_dev_a')['devices'], 'idempotent': True},
         ['Registration and key delivery are reconciled independently; an equal leaf certificate ID says nothing about packages.'])

    # 6. concurrent revokes.
    flow('F06_concurrent_revokes', 'Two managing devices revoke DEV_A concurrently with different reasons: one record; the other phase is complete',
         ('IDENTITY-PROFILE-01 §9.2 (Revoke)', 'Revoked with any other reason, by anyone: complete; the operation continues with the rotation test.'),
         [step('OWNER revokes DEV_A with reason 1', 'wire:I9_device_revoke_dev_a', 'accept'),
          step('DEV_A2 (also managing) had proposed DEVICE_REVOKE {OWNER, DEV_A, 2} on I8: CONTROL_HEAD_MISMATCH', expect='CONTROL_HEAD_MISMATCH'),
          step('After synchronising, a fresh revocation would be refused', 'wire:device_revoke_twice', 'AUTHORIZATION_FAILED'),
          step('DEV_A2 classifies its revoke phase', expect='complete', **ex(phase='complete', not_superseded=True)),
          step('DEV_A2 continues with the rotation test of §8.1', expect='rotation test')],
         {'device_revoke_records': 1}, ['A different reason recorded by another installation is complete, not superseded.'])

    # 7. invitation accepted by a device.
    flow('F07_invitation_accepted_by_device', 'An invitation accepted by a device of DAVE: the claim names the root, the device registers itself and keys its root',
         ('IDENTITY-PROFILE-01 §7.2; LFCP-WIRE-01 §18.1', 'The claimant is the root; the device self-registers, seals the DEKs it holds to its root and adds the Resource to the roster.'),
         [step('OWNER invites INVITE', 'wire:N1_invite_grant', 'accept'),
          step('DEV_D, a device of DAVE, claims with claimant DAVE, signed by INVITE', 'wire:flow.claim_for_root_dave', 'accept'),
          step('DEV_D registers itself', 'wire:flow.self_register_dev_d', 'accept', **ex(DEV_D=dev('wire:flow.self_register_dev_d', 'DEV_D'))),
          step('DEV_D seals epoch 0 to DAVE', 'wire:flow.kp_dev_d_to_dave', 'accept'),
          step('DAVE opens X and reads', 'wire:flow.open_as_dave', 'accept'),
          step('DEV_D adds X to the roster of I', expect='roster entry written')],
         {'claimant_role': post('wire:flow.claim_for_root_dave')['roles']['DAVE']},
         ['A device claimant would be refused (claim_by_bound_claimant); the root is the member.'],
         {'negative': 'wire:claim_by_bound_claimant'})

    # 8. pairing, personal.
    flow('F08_pairing_personal', 'Pairing a personal device DEV_B through PAIR_J in I: phases 1 and 2, keys, request, limits, reuse and retries',
         ('IDENTITY-PROFILE-01 §5.3, §9', 'A pairing session yields at most one approved payload; nothing is signed for D_B before the consume is committed (N9).'),
         [step('DEV_A creates the pairing device', 'wire:P2_pairing_device', 'accept'),
          step('DEV_A seals every epoch of I to PAIR_J (same root) and makes the root\'s unit 1 retrievable before showing the link', 'wire:flow.kp_dev_a_to_pair_j_in_i', 'accept'),
          step('The link', 'profile:pair_uri_roundtrip'),
          step('B verifies the initial change (from a Snapshot only after the root\'s unit 1)', 'profile:identity_doc_initial_without_unit_1'),
          step('B writes its request as PAIR_J', 'profile:pairing_writes_own_request', 'accept'),
          step('A shows the fingerprint', 'profile:fingerprint_dev_b'),
          step('Phase 1: consume with digest(CERT_B)', 'wire:P3_consume_for_dev_b', 'accept', **ex(phase='committed-own', exposing=True)),
          step('Phase 2: DEVICE_GRANT with field 2', 'wire:P4_register_dev_b_approved', 'accept', **ex(DEV_B=dev('wire:P4_register_dev_b_approved', 'DEV_B'))),
          step('Keys of I to DEV_B', 'wire:flow.kp_dev_a_to_dev_b_in_i', 'accept'),
          step('A consumed PAIR_J receives nothing', 'wire:flow.kp_dev_a_to_pair_j_after_consume', 'AUTHORIZATION_FAILED'),
          step('B learns the consume through the revoked-reader prefix', 'wire:CONTROL_GET_by_consumed_pairing', 'accept'),
          step('A manager that lacks a DEK of I or the root\'s unit 1 offers no link', expect='no link'),
          step('40 sessions created and cancelled one after another, then a session completes: cancelled pairing devices free their places', 'wire:device_grant_binding_limit.after_revoke', 'accept'),
          step('R at 32 live devices: no link until one is revoked', 'wire:device_grant_binding_limit', 'AUTHORIZATION_FAILED'),
          step('Two managers approve different requests of one session: the loser classifies phase 1 as superseded and signs nothing', 'wire:device_revoke_consume_twice', 'AUTHORIZATION_FAILED', **ex(phase='superseded')),
          step('A phase-2 record for another digest is refused', 'wire:device_grant_approval_mismatch', 'AUTHORIZATION_FAILED'),
          step('Lost ACK of phase 2: the exact bytes are re-sent and answered with the same ACK', expect='same ACK'),
          step('Crash between phase 1 and phase 2: resume from the journaled payload; the signed certificate equals the journaled one', expect='committed-own then pending phase 2', **ex(digest_equals='profile:approval_digest_cert_b'))],
         {'DEV_B_registered_in_I': True, 'approved_payloads': 1},
         ['One link used by two installations: sequential reuse writes sequence 2 of PAIR_J; concurrent equivocation excludes both units and A sees no request.',
          'R at 31 live devices: PAIR_J takes the 32nd place, the consume frees it and D_B is registered (W §17.4 rule 8 counts live bindings).'])

    # 9. pairing, service.
    flow('F09_pairing_service', 'Pairing a service device BRIDGE_O: bind-only in I, results learnt from the scoped Resources',
         ('IDENTITY-PROFILE-01 §5.3 steps 6 and 8, §6', 'A service device is bound in I and never registered there; only a certificate whose digest equals the approval proves the result; a timeout is never a decision.'),
         [step('Phase 1: consume with digest(CERT_SO)', 'wire:P3s_consume_for_bridge_o', 'accept'),
          step('Phase 2: bind-only DEVICE_GRANT in I', 'wire:P4s_bind_bridge_o', 'accept', **ex(BRIDGE_O=dev('wire:P4s_bind_bridge_o', 'BRIDGE_O'))),
          step('BRIDGE_O cannot write in I', 'wire:D_bridge_o_in_i', 'AUTHORIZATION_FAILED'),
          step('Registration in X, a candidate of the approved scope', 'wire:flow.register_bridge_o_in_x', 'accept'),
          step('Every candidate unreachable after approval', expect='approved, waiting for registration', **ex(status='approved, waiting for registration')),
          step('The first verified certificate with digest d arrives from X', expect='ready in X', **ex(removed_resource='not granted', other_candidates='pending registration')),
          step('A certificate for BRIDGE_O with another digest', expect='reported, not used'),
          step('A candidate where BRIDGE_O is registered but no leaf with digest d was ever accepted', expect='unproven', **ex(status='approval not provable here')),
          step('A crashes after the bind-only DEVICE_GRANT was accepted, before its ACK was persisted; on restart the register phase is', expect='committed-own', **ex(proposes=False))],
         {'registered_in_I': False, 'scope': ['X']}, ['B restarts and resumes from its persisted candidates; neither path depends on PAIR_J after its revocation.'])

    # 10. request validation and feasibility.
    flow('F10_request_feasibility', 'Request validation and the feasibility check before anything is committed',
         ('IDENTITY-PROFILE-01 §5.3 step 4, §4', 'A preset whose complete future chain fails W §7.3 steps 1 and 4 and W §17.4 rules 4 to 6 and 8 is not offered.'),
         [step('A valid request', 'profile:request_valid', 'accept'),
          step('A request written by another pairing device into this one', 'profile:pairing_edits_foreign_request_label', 'UNAUTHORIZED_WRITER'),
          step('The descriptor changes between display and confirmation', expect='re-confirmation'),
          step('A manager with a chain of three certificates: Full is not offered', 'wire:device_grant_feasibility_full_depth_4', 'MALFORMED_MESSAGE', **ex(offered=['Edit', 'Read'])),
          step('A manager whose mask lacks 3 cannot issue Edit', 'wire:device_grant_feasibility_mask_exceeds_issuer', 'AUTHORIZATION_FAILED'),
          step('An Edit device cannot issue at all', 'wire:device_grant_feasibility_edit_issuer', 'AUTHORIZATION_FAILED'),
          step('A service scope trimmed to nothing', expect='no consume; session cancelled'),
          step("The manager's own authority is re-checked after a head change", expect='re-checked')],
         {'consume_proposed_for_infeasible_preset': False}, ['No consume is proposed for a preset that fails the check.'])

    # 11. revocation by a device whose chain passes through the target.
    flow('F11_revoker_chain_through_target', 'A revoker whose chain passes through the target re-certifies first',
         ('IDENTITY-PROFILE-01 §8.1', "The revoker's own chain MUST NOT pass through D; it first obtains a fresh chain from the root."),
         [step('DEV_B (chain [CERT_B, CERT_A]) wants to revoke DEV_A: the pre-check refuses', expect='refused locally'),
          step('OWNER re-certifies DEV_B with [CERT_B2]', 'wire:I10_recertify_dev_b', 'accept'),
          step('The revocation then proceeds (shown by the root)', 'wire:I9_device_revoke_dev_a', 'accept'),
          step('Self-retirement leaves rotation to another installation', 'wire:device_revoke_self', 'accept', **ex(rotates=False))],
         {}, ['A device cannot re-certify itself (device_grant_self_recertify_suspended).'])

    # 12. rotation of I with an open session.
    readers_p2 = [d for d, f in post('wire:P2k_pairing_device_k')['devices'].items() if f['reads']]
    flow('F12_rotation_with_open_session', 'Rotating I while pairing sessions are open',
         ('IDENTITY-PROFILE-01 §8.2, §8.1', 'The new DEK is sealed to every Principal with holds(P, 1) at the new head, open pairing devices included; consumed or cancelled ones receive nothing.'),
         [step('Two open sessions PAIR_J and PAIR_K', 'wire:P2k_pairing_device_k', 'accept', **ex(readers=['OWNER'] + readers_p2)),
          step('A rotation of I seals the new DEK to OWNER, DEV_A, PAIR_J and PAIR_K', expect='packages to every reader'),
          step('One session closed (PAIR_J cancelled): the other continues', 'wire:P3c_cancel_pairing', 'accept', **ex(exposing=True)),
          step('A consumed or cancelled pairing device receives nothing', 'wire:flow.kp_dev_a_to_pair_j_after_consume', 'AUTHORIZATION_FAILED'),
          step('A foreign reader in I and a rotator without 6', expect='awaiting rotation'),
          step('A revoker with 7 but not 6 in a Resource with a foreign reader', expect='awaiting rotation', **ex(commits=False)),
          step('With both 6 and 7', expect='rotates and seals to every reader'),
          step('In I, where every reader is of the root, 7 alone suffices', expect='rotates')],
         {}, ['The rotator test of §8.1 decides; no assumption that every reader of I is a personal device replaces it.'])

    # 13. durable phases.
    flow('F13_durable_phases', 'Crash and concurrency at every ACK of pairing approval and of revoke plus rotate',
         ('IDENTITY-PROFILE-01 §9.1 to §9.5', 'Phases are classified against the accepted chain; a KEY_EPOCH is rebuilt, never re-proposed as it was.'),
         [step('Crash before the consume ACK; the chain lacks the record', expect='pending'),
          step('Crash after the consume ACK; the chain holds it with this digest', 'wire:P3_consume_for_dev_b', 'accept', **ex(phase='committed-own')),
          step('Crash after the revoke ACK', 'wire:I9_device_revoke_dev_a', 'accept', **ex(phase='committed-own')),
          step('A concurrent rotation by another writer after the revocation', 'wire:K1_key_epoch', 'accept', **ex(phase='complete')),
          step('A reader revoked between planning and sending packages', expect='fresh DEK (§9.4)'),
          step('Partial package delivery', expect='repaired by the ledger rule (§9.5)'),
          step('A rotator crashes after the KEY_EPOCH ACK and before any package', expect='awaiting key holder', **ex(readers='KEY_BLOCKED'))],
         {}, ['A second rotator may commit the next KEY_EPOCH after a bounded wait; no installation reconstructs a DEK it does not hold.'])

    # 14. frontier.
    flow('F14_frontier_from_verified_set', "The final frontier comes from the rotator's verified accepted set",
         ('LFCP-WIRE-01 §19; IDENTITY-PROFILE-01 §8.3', "A server's Have Vector is a fetch hint; a sequence the rotator could not fetch and verify stays outside the frontier."),
         [step('The server advertises DEV_A 1..100; only 1..2 are fetchable and verify', expect='frontier DEV_A <= 2'),
          step('A hole: 1, 2 and 4 verified', expect='frontier DEV_A <= 2'),
          step('An advertised unit that fails authorization (DEV_B at I9)', 'wire:D_dev_b_suspended', 'AUTHORIZATION_FAILED', **ex(counted=False))],
         {'frontier_rule': 'contiguous verified accepted sequences only'}, ['The frontier never trusts an advertised range.'])

    # 15. rotation policy by exposure.
    exp = {r: post(f'wire:{r}')['exposing'] for r in ('I9_device_revoke_dev_a', 'V2_revoke_dev_c', 'Vu1_revoke_unbound', 'W2',
                                                      'flow.revoke_out_of_scope_bridge_in_y', 'flow.revoke_suspended_dev_b')}
    flow('F15_rotation_policy_by_exposure', 'Rotation follows exposing revocations only',
         ('LFCP-WIRE-01 §17.5 (exposure); IDENTITY-PROFILE-01 §8.4', 'A revocation that removes no registered reader never triggers a rotation; one rotation covers every exposing revocation since the last.'),
         [step('An exposing revocation', 'wire:I9_device_revoke_dev_a', 'accept', **ex(exposing=exp['I9_device_revoke_dev_a'], rotations=1)),
          step('An unbound tombstone without descendants', 'wire:Vu1_revoke_unbound', 'accept', **ex(exposing=exp['Vu1_revoke_unbound'], rotations=0)),
          step('An out-of-scope binding revoked', 'wire:flow.revoke_out_of_scope_bridge_in_y', 'accept', **ex(exposing=exp['flow.revoke_out_of_scope_bridge_in_y'], rotations=0)),
          step('An already suspended device revoked', 'wire:flow.revoke_suspended_dev_b', 'accept', **ex(exposing=exp['flow.revoke_suspended_dev_b'], rotations=0)),
          step('A never-reading device revoked', 'wire:W2', 'accept', **ex(exposing=exp['W2'], rotations=0)),
          step('An intermediate-only device with a reading descendant revoked', 'wire:V2_revoke_dev_c', 'accept', **ex(exposing=exp['V2_revoke_dev_c'], rotations=1,
               descendant_receives_new_epoch=False)),
          step('Three exposing revocations in one epoch', expect='one rotation'),
          step('A former member cannot issue the tombstone at all', 'wire:device_revoke_by_former_member', 'AUTHORIZATION_FAILED')],
         {'exposing': exp}, ['Exposure is computed from the Resource\'s own chain alone.'])

    # 16. forks.
    flow('F16_device_grant_fork', 'Two valid competing DEVICE_GRANTs on one prev',
         ('LFCP-WIRE-01 §13.2; IDENTITY-PROFILE-01 §9.7', 'Neither is the head; approval and reconciliation are suspended; no branch is chosen by time, order or ACK.'),
         [step('Rd1 on I1', 'wire:Rd1', 'accept'),
          step('W1 on I1, delivered to another manager', 'wire:W1', 'accept'),
          step('Both branches known', expect='CONTROL_CONFLICT', **ex(competing=['Rd1', 'W1'])),
          step('Approval, reconciliation and automatic rotation taking I or X as input', expect='suspended')],
         {'state': 'CONTROL_CONFLICT'}, ['A validator given both records reports CONTROL_CONFLICT and applies neither.'],
         {'records': ['wire:J0_genesis', 'wire:J1_grant_bob', 'wire:J2_grant_carol', 'wire:I1_device_grant_dev_a', 'wire:Rd1', 'wire:W1']})

    # 17. the revoked device.
    flow('F17_revoked_device', 'A revoked device reconnects',
         ('IDENTITY-PROFILE-01 §8.6; LFCP-WIRE-01 §41', 'Access refused alone, or revocation proven through the Control read for a revoked reader; uploads are checked by object.'),
         [step('DEV_A was offline during I9 and reconnects: RESOURCE_OPEN', 'wire:CONTROL_GET_by_revoked_reader', 'accept', **ex(status='revocation proven', head='I9_device_revoke_dev_a')),
          step('DEV_A requests data', 'wire:DATA_GET_by_revoked_session', 'AUTHORIZATION_FAILED'),
          step('A never-reader', 'wire:CONTROL_GET_by_never_reader', 'AUTHORIZATION_FAILED', **ex(status='access refused')),
          step('DEV_A re-supplies a valid foreign Key Package the server lost', 'wire:KEY_PACKAGE_PUT_by_revoked_session_foreign_package', 'accept'),
          step('Online: pushes stop before the revoking record is pushed (W §69)', expect='unsubscribed before push')],
         {}, ['The device never creates Data Units for the Resource again and is never re-paired under the same Principal.'])

    # 18. barrier.
    barrier = {'type 9': 'wire:I1_device_grant_dev_a', 'type 10': 'wire:I9_device_revoke_dev_a', 'Genesis field 5': 'wire:G1_genesis_by_dev_a', 'commit field 2': 'wire:T1_commit'}
    pre = {'type 9': 'INVALID_CONTROL_CHAIN', 'type 10': 'INVALID_CONTROL_CHAIN', 'Genesis field 5': 'MALFORMED_MESSAGE', 'commit field 2': 'MALFORMED_MESSAGE'}
    flow('F18_barrier', 'The four barrier entries against a pre-identity validator, a herald and an identity-aware one',
         ('LFCP-WIRE-01 §100.1, §37', 'A pre-identity client rejects the barrier and blocks the Resource; a herald persists the blocked state with the update message; an identity-aware client accepts.'),
         [step(f'{name}: pre-identity validator', ref, expect=None, **ex(pre_identity=pre[name], herald='blocked at this head (persisted)', identity_aware='accept'))
          for name, ref in barrier.items()]
         + [step('A blocked client writes on its last validated head', expect='accepted until the epoch closes')],
         {'server_without_identity_01': {name: pre[name] for name in barrier}}, ['A server whose READY lacks identity-01 rejects these records as a pre-identity receiver does.'])

    # 19. key bootstrap.
    flow('F19_key_bootstrap', 'Devices that never received their first packages get every epoch from the next reconciling manager',
         ('IDENTITY-PROFILE-01 §7.1 step 3', 'Key delivery is unconditional: no complaint, no data/write and no DEK of I is needed on the recipient side.'),
         [step('A Read device in X', 'wire:flow.kp_owner_to_dev_r', 'accept'),
          step('A device registered in I whose approver crashed before its first package', 'wire:flow.kp_dev_a_to_dev_b_in_i', 'accept'),
          step('A service device bound in I and registered in X', 'wire:flow.kp_dev_a_to_bridge_o_in_x', 'accept'),
          step('None of them wrote missing_keys', expect='served anyway')],
         {'I_is_a_target': True}, ['The ledger, not a complaint, drives the delivery.'])


def suite() -> dict:
    return {
        'format': 'lfcp-vector-format/1',
        'suite': {
            'id': SUITE_ID, 'version': '01',
            'specification': {'id': 'IDENTITY-PROFILE-01', 'profile': 'org.openlfcp.identity.v1', 'revision': 'working-draft'},
            'description': 'State-machine and durable-operation fixtures of multi-device identity (IDENTITY-PROFILE-01 §12.3; LFCP-WIRE-01 §107).',
            'depends_on': ['LFCP-IDENTITY-TEST-VECTORS-01', 'IDENTITY-PROFILE-TEST-VECTORS-01', 'LFCP-WIRE-01', 'IDENTITY-PROFILE-01'],
            'conventions': {
                'steps': 'inputs.steps are performed in order; expected.steps gives each step\'s outcome and the facts it asserts.',
                'references': 'A step case `wire:<id>` names a case of LFCP-IDENTITY-TEST-VECTORS-01, `profile:<id>` one of IDENTITY-PROFILE-TEST-VECTORS-01; the step outcome equals that case\'s expected outcome. `bytes_of` names a case whose exact bytes a step sends in another context, with the outcome the step states.',
                'client_outcomes': 'Outcomes without a case are client-procedure results (phase states of IDENTITY-PROFILE-01 §9.2, statuses of §6); they have no wire code.',
            },
        },
        'cases': CASES,
    }


def markdown(doc: dict) -> str:
    lines = [f'# {SUITE_ID}', '', 'Generated by `generate_identity_flow_fixtures_01.py`; do not edit by hand. Each step names the case whose bytes it sends',
             'and whose outcome it expects (`wire:` LFCP-IDENTITY-TEST-VECTORS-01, `profile:` IDENTITY-PROFILE-TEST-VECTORS-01).', '']
    for c in doc['cases']:
        lines += [f"## {c['id']}", '', c['description'] + f" ({c['rule']['section']})", '', '| # | Step | Case | Outcome |', '|---|---|---|---|']
        for s, e in zip(c['inputs']['steps'], c['expected']['steps']):
            lines.append(f"| {s['n']} | {s['action']} | {('`' + s['case'] + '`') if 'case' in s else ''} | {e['outcome']} |")
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
