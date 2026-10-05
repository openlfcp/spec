import argparse, hashlib, json, base64, struct, zipfile, os
from pathlib import Path

_parser = argparse.ArgumentParser(description='Generate SHARED-OBJECTS-TEST-VECTORS-01 JSON, Markdown and the Automerge reference script.')
_parser.add_argument('--out-dir', type=Path, default=Path(__file__).resolve().parent,
                     help="directory to write the vector files into (default: this script's directory)")
_parser.add_argument('--bundle', action='store_true',
                     help='also write SHARED-OBJECTS-TEST-VECTORS-01-bundle.zip (not committed to the repository)')
_args = _parser.parse_args()
OUT = _args.out_dir
OUT.mkdir(parents=True, exist_ok=True)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def h(b: bytes) -> str:
    return b.hex()

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def label32(label: str) -> bytes:
    return sha256(label.encode('ascii'))

# Minimal canonical CBOR encoder sufficient for the framing vectors in this suite.
def cbor_uint(n: int, major: int = 0) -> bytes:
    if n < 24: return bytes([(major << 5) | n])
    if n < 256: return bytes([(major << 5) | 24, n])
    if n < 65536: return bytes([(major << 5) | 25]) + struct.pack('>H', n)
    if n < 2**32: return bytes([(major << 5) | 26]) + struct.pack('>I', n)
    return bytes([(major << 5) | 27]) + struct.pack('>Q', n)

def cbor_bytes(b: bytes) -> bytes:
    return cbor_uint(len(b), 2) + b

def cbor_text(s: str) -> bytes:
    b = s.encode('utf-8'); return cbor_uint(len(b), 3) + b

def cbor_array(items) -> bytes:
    return cbor_uint(len(items), 4) + b''.join(cbor(x) for x in items)

def cbor_map(m: dict) -> bytes:
    # RFC 8949 deterministic ordering by length of encoded key then lexicographic bytes.
    pairs=[]
    for k,v in m.items():
        ek=cbor(k); ev=cbor(v); pairs.append((ek,ev))
    pairs.sort(key=lambda kv:(len(kv[0]), kv[0]))
    return cbor_uint(len(pairs),5)+b''.join(k+v for k,v in pairs)

def cbor(x):
    if isinstance(x,bool): return b'\xf5' if x else b'\xf4'
    if x is None: return b'\xf6'
    if isinstance(x,int):
        if x>=0: return cbor_uint(x,0)
        return cbor_uint(-1-x,1)
    if isinstance(x,bytes): return cbor_bytes(x)
    if isinstance(x,str): return cbor_text(x)
    if isinstance(x,list) or isinstance(x,tuple): return cbor_array(x)
    if isinstance(x,dict): return cbor_map(x)
    raise TypeError(type(x))

# Deterministic fixture identities.
resource = label32('OPENLFCP-SHARED-OBJECTS-TV01-RESOURCE-A')
resource_b = label32('OPENLFCP-SHARED-OBJECTS-TV01-RESOURCE-B')
andrey = label32('OPENLFCP-SHARED-OBJECTS-TV01-PRINCIPAL-ANDREY')
pavel = label32('OPENLFCP-SHARED-OBJECTS-TV01-PRINCIPAL-PAVEL')
masha = label32('OPENLFCP-SHARED-OBJECTS-TV01-PRINCIPAL-MASHA')

ACTOR_DOMAIN = b'OPENLFCP-SHARED-OBJECTS-ACTOR-v1'
def actor(resource_id, principal_id): return sha256(ACTOR_DOMAIN + resource_id + principal_id)

# Fixed valid UUIDv7 values. These are canonical strings and deliberately stable fixtures.
obj_task_1 = '019a2f85-7b31-7c42-b85a-fc843e2f40ad'
obj_task_2 = '019a2f85-7b31-7c42-a43c-4b693e77d36b'
obj_unknown = '019a2f85-7b31-7c42-9f24-8f933f2a91c0'

pref = lambda p: 'p:' + b64u(p)

synthetic_change = bytes.fromhex('00010203a0ff')
synthetic_snapshot = bytes.fromhex('aabbccddeeff00112233')
change_frame = cbor([1, synthetic_change])
snapshot_frame = cbor([1, synthetic_snapshot])

initial_task = {
    'id': obj_task_1,
    'type': 'task',
    'lifecycle': 'active',
    'created_by': pref(andrey),
    'created_at': '2026-10-04T05:30:00Z',
    'title': 'Prepare API contract',
    'status': 'todo',
    'priority': 'normal',
    'tags': {},
    'assignees': {},
    'extensions': {}
}

vectors = {
  'suite': 'SHARED-OBJECTS-TEST-VECTORS-01',
  'profile': 'org.openlfcp.shared-objects.v1',
  'wire_dependency': ['LFCP-WIRE-01'],
  'automerge_reference_target': '3.5.0',
  'normative_rule': 'Byte equality is required only where this suite marks a vector deterministic_bytes=true. Automerge semantic scenarios require cross-implementation apply/merge compatibility and identical logical/conflict outcomes, not identical independently-generated change bytes.',
  'fixtures': {
    'resource_a_hex': h(resource),
    'resource_b_hex': h(resource_b),
    'principals': {
      'andrey': {'id_hex': h(andrey), 'ref': pref(andrey), 'actor_a_hex': h(actor(resource,andrey)), 'actor_b_hex': h(actor(resource_b,andrey))},
      'pavel': {'id_hex': h(pavel), 'ref': pref(pavel), 'actor_a_hex': h(actor(resource,pavel))},
      'masha': {'id_hex': h(masha), 'ref': pref(masha), 'actor_a_hex': h(actor(resource,masha))},
    },
    'objects': {'task_1': obj_task_1, 'task_2': obj_task_2, 'unknown_1': obj_unknown}
  },
  'deterministic_vectors': [
    {
      'id':'D01-actor-andrey-resource-a', 'kind':'actor_id', 'deterministic_bytes':True,
      'input': {'resource_hex':h(resource), 'principal_hex':h(andrey)},
      'expected_hex':h(actor(resource,andrey))
    },
    {
      'id':'D02-actor-andrey-resource-b', 'kind':'actor_id', 'deterministic_bytes':True,
      'input': {'resource_hex':h(resource_b), 'principal_hex':h(andrey)},
      'expected_hex':h(actor(resource_b,andrey))
    },
    {
      'id':'D03-principal-ref-andrey', 'kind':'principal_ref', 'deterministic_bytes':True,
      'input_hex':h(andrey), 'expected':pref(andrey)
    },
    {
      'id':'D04-change-frame', 'kind':'profile_change_framing', 'deterministic_bytes':True,
      'note':'Synthetic bytes test framing only; payload is intentionally not claimed to be a valid Automerge change.',
      'automerge_change_hex':h(synthetic_change), 'expected_cbor_hex':h(change_frame), 'expected_sha256':h(sha256(change_frame))
    },
    {
      'id':'D05-snapshot-frame', 'kind':'profile_snapshot_framing', 'deterministic_bytes':True,
      'note':'Synthetic bytes test framing only; payload is intentionally not claimed to be a valid Automerge save image.',
      'automerge_save_hex':h(synthetic_snapshot), 'expected_cbor_hex':h(snapshot_frame), 'expected_sha256':h(sha256(snapshot_frame))
    },
    {
      'id':'D06-uuidv7-valid', 'kind':'object_id_validation', 'deterministic_bytes':True,
      'input':obj_task_1, 'expected_valid':True
    },
    {
      'id':'D07-uuid-invalid-uppercase', 'kind':'object_id_validation', 'deterministic_bytes':True,
      'input':obj_task_1.upper(), 'expected_valid':False, 'error':'PROFILE_INVALID', 'diagnostic':'INVALID_OBJECT_ID'
    },
    {
      'id':'D08-uuid-invalid-version', 'kind':'object_id_validation', 'deterministic_bytes':True,
      'input':'019a2f85-7b31-6c42-b85a-fc843e2f40ad', 'expected_valid':False, 'error':'PROFILE_INVALID', 'diagnostic':'INVALID_OBJECT_ID'
    },
  ],
  'behavioral_scenarios': []
}

# Helper scenario entries. These are intentionally logical, not tied to an Automerge implementation's private bytes.
def sc(id, title, base, branches, expected, assertions, notes=None):
    vectors['behavioral_scenarios'].append({
      'id':id,'title':title,'base_state':base,'branches':branches,'expected':expected,'assertions':assertions,
      **({'notes':notes} if notes else {})
    })

sc('S01','Create Task', {}, [
  {'actor':'andrey','intent':'task.create','args':initial_task}
], {'objects':{obj_task_1:initial_task}}, [
  'Task exists under objects[object_id].','Object id field equals the map key.','Required maps tags, assignees, extensions exist.'
])

sc('S02','Independent field concurrency', initial_task, [
  {'actor':'andrey','from':'base','intent':'task.complete','writes':{'status':'done','completion_date':'2026-10-08'}},
  {'actor':'pavel','from':'base','intent':'task.set_title','writes':{'title':'Prepare final API contract'}}
], {
  'title':'Prepare final API contract','status':'done','completion_date':'2026-10-08','conflicts':{}
}, ['No semantic conflict exists because different scalar fields were changed.'])

sc('S03','Concurrent status conflict', initial_task, [
  {'actor':'andrey','from':'base','intent':'task.complete','writes':{'status':'done','completion_date':'2026-10-08'}},
  {'actor':'pavel','from':'base','intent':'task.cancel','writes':{'status':'cancelled'}}
], {
  'status_conflict_set':['cancelled','done'],
  'must_report_conflict':True,
  'completion_date_values_may_include':['2026-10-08']
}, ['Both status values remain discoverable through Automerge conflict APIs.','UI/headless API must not report status as resolved.'])

sc('S04','Resolve status conflict', {'derived_from':'S03 merged state'}, [
  {'actor':'masha','from':'merged','intent':'task.resolve_status_conflict','writes':{'status':'done'}}
], {'status':'done','status_conflict_set':['done'],'must_report_conflict':False}, [
  'Resolver change causally descends from a merged state containing all conflicting values.'
])

sc('S05','Concurrent due-date conflict', initial_task, [
  {'actor':'andrey','from':'base','intent':'task.set_due','writes':{'due':'2026-10-10'}},
  {'actor':'pavel','from':'base','intent':'task.set_due','writes':{'due':'2026-10-12'}}
], {'due_conflict_set':['2026-10-10','2026-10-12'],'must_report_conflict':True}, [
  'Both due values remain accessible until explicit resolution.'
])

sc('S06','Tag add/add union', initial_task, [
  {'actor':'andrey','from':'base','intent':'task.add_tag','tag':'backend'},
  {'actor':'pavel','from':'base','intent':'task.add_tag','tag':'important'}
], {'tags':['backend','important']}, ['Both tags are present after convergence.'])

sc('S07','Tag concurrent add/remove is add-wins', {'task':{**initial_task,'tags':{'backend':True}}}, [
  {'actor':'andrey','from':'base','intent':'task.remove_tag','tag':'backend'},
  {'actor':'pavel','from':'base','intent':'task.add_tag','tag':'backend','fresh_write':True}
], {'tags':['backend']}, ['Concurrent add of the same tag wins over removal.'])

sc('S08','Assignee concurrent add/remove is add-wins', {'task':{**initial_task,'assignees':{pref(pavel):True}}}, [
  {'actor':'andrey','from':'base','intent':'task.unassign','principal':pref(pavel)},
  {'actor':'masha','from':'base','intent':'task.assign','principal':pref(pavel),'fresh_write':True}
], {'assignees':[pref(pavel)]}, ['Concurrent assignment wins over removal.'])

sc('S09','Delete versus independent title edit', initial_task, [
  {'actor':'andrey','from':'base','intent':'task.delete','writes':{'lifecycle':'deleted'}},
  {'actor':'pavel','from':'base','intent':'task.set_title','writes':{'title':'Final API contract'}}
], {'lifecycle':'deleted','title':'Final API contract','object_present':True}, [
  'Object remains in objects map.','Concurrent title edit is retained under tombstone.'
])

sc('S10','Delete versus restore conflict', initial_task, [
  {'actor':'andrey','from':'base','intent':'task.delete','writes':{'lifecycle':'deleted'}},
  {'actor':'pavel','from':'base','intent':'task.restore','writes':{'lifecycle':'active'}}
], {'lifecycle_conflict_set':['active','deleted'],'must_report_conflict':True}, [
  'Lifecycle conflict is surfaced.'
])

sc('S11','Unknown field preservation', {'task':{**initial_task,'extensions':{'com.example.tracker':{'ticket':'ABC-42'}},'x_future_scalar':'future-value'}}, [
  {'actor':'pavel','from':'base','intent':'task.set_status','writes':{'status':'in_progress'}}
], {'status':'in_progress','preserve':{'x_future_scalar':'future-value','extensions.com.example.tracker.ticket':'ABC-42'}}, [
  'Client must not delete unknown map fields or extension namespaces.'
])

unknown_obj = {
  'id':obj_unknown,'type':'com.example.poll','lifecycle':'active','created_by':pref(andrey),'extensions':{},
  'question':'Ship on Friday?','answers':{'yes':1}
}
sc('S12','Unknown object type preservation', {'objects':{obj_unknown:unknown_obj}}, [
  {'actor':'pavel','operation':'load-save-roundtrip-without-understanding-type'}
], {'objects':{obj_unknown:unknown_obj}}, [
  'Unknown object type remains addressable and unchanged.'
])

sc('S13','Object ID collision detection', {'objects':{}}, [
  {'actor':'andrey','from':'base','operation':'create','object':{**initial_task,'title':'A'}},
  {'actor':'pavel','from':'base','operation':'create','object':{**initial_task,'title':'B','created_by':pref(pavel)}}
], {'profile_error':'OBJECT_ID_COLLISION','must_not_silently_treat_as_same_object':True}, [
  'Collision is surfaced for repair.'
])

sc('S14','Snapshot plus post-snapshot change', {'build':'Apply S01 then S06 and save full Automerge image'}, [
  {'operation':'snapshot_save_load_roundtrip'},
  {'actor':'pavel','after_snapshot':True,'intent':'task.set_status','writes':{'status':'in_progress'}}
], {'task_status':'in_progress','snapshot_roundtrip_preserves_objects':True}, [
  'Snapshot full-save image loads successfully.','Changes after snapshot frontier apply normally.'
], 'Snapshot bytes need not be independently byte-identical; logical state and acceptance are normative.')

# Profile invalid cases
vectors['invalid_cases'] = [
  {'id':'I01','mutation':{'object_key':obj_task_1,'field':'id','value':obj_task_2},'expected':'PROFILE_INVALID','diagnostic':'OBJECT_ID_MISMATCH'},
  {'id':'I02','mutation':{'object_key':'NOT-A-UUID','value':initial_task},'expected':'PROFILE_INVALID','diagnostic':'INVALID_OBJECT_ID'},
  {'id':'I03','mutation':{'object_key':obj_task_1,'field':'title','value':42},'expected':'PROFILE_INVALID','diagnostic':'INVALID_FIELD_TYPE'},
  {'id':'I04','mutation':{'object_key':obj_task_1,'field':'due','value':'2026-13-50'},'expected':'PROFILE_INVALID','diagnostic':'INVALID_LOCAL_DATE'},
  {'id':'I05','mutation':{'object_key':obj_task_1,'field':'tags','value':['backend']},'expected':'PROFILE_INVALID','diagnostic':'INVALID_COLLECTION_REPRESENTATION'},
  {'id':'I06','mutation':{'object_key':obj_task_1,'field':'assignees','value':{'not-a-principal':True}},'expected':'PROFILE_INVALID','diagnostic':'INVALID_PRINCIPAL_REF'},
  {'id':'I07','mutation':{'object_key':obj_task_1,'field':'type','value':'decision'},'expected':'PROFILE_INVALID','diagnostic':'IMMUTABLE_FIELD_MUTATED'},
]

# Conformance obligations
vectors['conformance'] = {
  'deterministic': [
    'All Dxx expected bytes/strings must match exactly.',
    'Actor IDs are exactly 32 bytes from the domain-separated SHA-256 formula.',
    'PrincipalRef is lowercase prefix p: plus unpadded base64url of raw 32-byte principal id.',
    'Change/snapshot outer framing must match deterministic CBOR vectors exactly.'
  ],
  'automerge_interop': [
    'A valid change produced by implementation A must be accepted by implementation B when dependencies are present.',
    'Applying the same complete change set in any valid order must converge to the same logical state.',
    'Conflict sets required by S03/S05/S10 must remain discoverable.',
    'A full-save image produced by implementation A must load in implementation B for the declared Automerge compatibility target.',
    'Independent implementations are not required to generate byte-identical changes or save images for the same semantic intent.'
  ]
}

# Machine-readable output in lfcp-vector-format/1 (spec: schemas/). Values are
# copied unchanged from `vectors`; only their placement differs.
def to_vector_format(v):
    def hexv(x): return {'hex': x}
    cases = []
    for d in v['deterministic_vectors']:
        case = {'id': d['id'], 'kind': d['kind']}
        if d['kind'] == 'actor_id':
            case.update(type='bytes',
                        inputs={'resource_hex': hexv(d['input']['resource_hex']), 'principal_hex': hexv(d['input']['principal_hex'])},
                        expected={'actor_id': hexv(d['expected_hex'])})
        elif d['kind'] == 'principal_ref':
            case.update(type='bytes', inputs={'principal_id': hexv(d['input_hex'])}, expected={'principal_ref': d['expected']})
        elif d['kind'] == 'profile_change_framing':
            case.update(type='bytes', note=d['note'], inputs={'automerge_change_hex': hexv(d['automerge_change_hex'])},
                        expected={'framed_cbor': hexv(d['expected_cbor_hex']), 'sha256': hexv(d['expected_sha256'])})
        elif d['kind'] == 'profile_snapshot_framing':
            case.update(type='bytes', note=d['note'], inputs={'automerge_save_hex': hexv(d['automerge_save_hex'])},
                        expected={'framed_cbor': hexv(d['expected_cbor_hex']), 'sha256': hexv(d['expected_sha256'])})
        elif d['kind'] == 'object_id_validation':
            expected = {'valid': d['expected_valid']}
            if 'error' in d:
                expected['error'] = {'code': d['error']}
                if 'diagnostic' in d:
                    expected['error']['diagnostic'] = d['diagnostic']
            case.update(type='validation', inputs={'object_id': d['input']}, expected=expected)
        else:
            raise ValueError('unmapped deterministic vector kind: ' + d['kind'])
        cases.append({k: case[k] for k in ('id', 'type', 'kind', 'note', 'inputs', 'expected') if k in case})
    for sc_ in v['behavioral_scenarios']:
        case = {'id': sc_['id'], 'type': 'behavioral', 'kind': 'shared_object_scenario', 'description': sc_['title']}
        if 'notes' in sc_:
            case['note'] = sc_['notes']
        case['inputs'] = {'base_state': sc_['base_state'], 'branches': sc_['branches']}
        case['expected'] = sc_['expected']
        case['assertions'] = sc_['assertions']
        cases.append(case)
    for ic in v['invalid_cases']:
        cases.append({'id': ic['id'], 'type': 'validation', 'kind': 'profile_validation',
                      'inputs': {'mutation': ic['mutation']},
                      'expected': {'valid': False, 'error': {'code': ic['expected'], 'diagnostic': ic['diagnostic']}}})
    return {
        'format': 'lfcp-vector-format/1',
        'suite': {
            'id': v['suite'],
            'version': '01',
            'specification': {'id': 'SHARED-OBJECTS-PROFILE-01', 'profile': v['profile'], 'revision': 'working-draft'},
            'description': 'Shared Objects Profile interoperability vectors: byte-exact identifier and framing '
                           'vectors, validation cases and behavioral Automerge scenarios.',
            'depends_on': v['wire_dependency'],
            'conventions': {'automerge_reference_target': v['automerge_reference_target']},
            'conformance': {'rule': v['normative_rule'], **v['conformance']},
        },
        'fixtures': v['fixtures'],
        'cases': cases,
    }

json_path = OUT/'SHARED-OBJECTS-TEST-VECTORS-01.json'
json_path.write_text(json.dumps(to_vector_format(vectors), indent=2, ensure_ascii=False) + '\n', encoding='utf-8')

# JS reference corpus generator, intentionally dependent on official package; not executed by this Python generator.
js = r'''// SHARED-OBJECTS-TEST-VECTORS-01 Automerge reference corpus generator
// Compatibility target: @automerge/automerge 3.5.0
// Run in a clean directory:
//   npm install @automerge/automerge@3.5.0
//   node generate_automerge_reference_01.mjs
//
// This generator is supplementary. Conformance does NOT require independently
// generated changes to have identical bytes. The generated corpus is useful for
// cross-binding apply/load tests.

import * as A from "@automerge/automerge";
import fs from "node:fs";
import crypto from "node:crypto";

const vectors = JSON.parse(fs.readFileSync(new URL("./SHARED-OBJECTS-TEST-VECTORS-01.json", import.meta.url)));
const hex = s => Buffer.from(s, "hex");
const outHex = u8 => Buffer.from(u8).toString("hex");

const actor = vectors.fixtures.principals.andrey.actor_a_hex;
const pavelActor = vectors.fixtures.principals.pavel.actor_a_hex;
const id = vectors.fixtures.objects.task_1;
const andreyRef = vectors.fixtures.principals.andrey.ref;

function init(actorId) { return A.init({ actor: actorId }); }
function oneChange(oldDoc, newDoc) {
  const changes = A.getChanges(oldDoc, newDoc);
  if (changes.length !== 1) throw new Error(`expected exactly one change, got ${changes.length}`);
  return changes[0];
}

let d0 = init(actor);
let d1 = A.change(d0, "profile init", d => {
  d.schema = "org.openlfcp.shared-objects.v1";
  d.objects = {};
});
const c0 = oneChange(d0, d1);

let d2 = A.change(d1, "task.create", d => {
  d.objects[id] = {
    id,
    type: "task",
    lifecycle: "active",
    created_by: andreyRef,
    created_at: "2026-10-04T05:30:00Z",
    title: "Prepare API contract",
    status: "todo",
    priority: "normal",
    tags: {}, assignees: {}, extensions: {}
  };
});
const c1 = oneChange(d1, d2);

// Fork two actors from common ancestry for a status conflict.
let aBase = A.clone(d2, { actor });
let pBase = A.clone(d2, { actor: pavelActor });
let aDone = A.change(aBase, "task.complete", d => { d.objects[id].status = "done"; d.objects[id].completion_date = "2026-10-08"; });
let pCancel = A.change(pBase, "task.cancel", d => { d.objects[id].status = "cancelled"; });
const cDone = oneChange(aBase, aDone);
const cCancel = oneChange(pBase, pCancel);
let merged = A.merge(aDone, pCancel);
const conflicts = A.getConflicts(merged.objects[id], "status");

const save = A.save(merged);
const reloaded = A.load(save, { actor });

const corpus = {
  automerge_version_target: "3.5.0",
  changes: {
    init: outHex(c0),
    create_task: outHex(c1),
    status_done: outHex(cDone),
    status_cancelled: outHex(cCancel)
  },
  hashes: {
    init: crypto.createHash("sha256").update(c0).digest("hex"),
    create_task: crypto.createHash("sha256").update(c1).digest("hex"),
    status_done: crypto.createHash("sha256").update(cDone).digest("hex"),
    status_cancelled: crypto.createHash("sha256").update(cCancel).digest("hex"),
    snapshot: crypto.createHash("sha256").update(save).digest("hex")
  },
  status_conflicts: Object.values(conflicts ?? {}).sort(),
  snapshot_hex: outHex(save),
  reloaded_status: reloaded.objects[id].status
};
fs.writeFileSync("SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json", JSON.stringify(corpus, null, 2) + "\n");
console.log("wrote SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json");
'''
(OUT/'generate_automerge_reference_01.mjs').write_text(js,encoding='utf-8')

md = f'''# SHARED-OBJECTS-TEST-VECTORS-01

**Status:** Working Draft 0.1  
**Profile:** `org.openlfcp.shared-objects.v1`  
**Date:** 2026-10-04  
**Companion specification:** `SHARED-OBJECTS-PROFILE-01.md`  
**Wire dependency:** `LFCP-WIRE-01`  
**Reference Automerge compatibility target:** `@automerge/automerge 3.5.0`

> This document defines interoperability vectors for the OpenLFCP Shared Objects profile. It deliberately distinguishes byte-deterministic profile rules from CRDT behavioral interoperability.

---

## 1. Why this suite has two kinds of vectors

Not every conforming implementation must emit identical Automerge bytes for the same human intent.

LFCP Shared Objects therefore tests two different properties:

### 1.1 Deterministic profile vectors

These MUST match exactly across implementations:

- Principal reference encoding;
- LFCP Principal + Resource -> Automerge actor derivation;
- canonical UUIDv7 validation;
- Shared Objects outer CBOR framing;
- deterministic hashes of that framing.

### 1.2 Behavioral Automerge vectors

These test:

- whether changes produced by one implementation can be applied by another;
- whether all replicas converge after receiving the same changes;
- whether required conflicts remain discoverable;
- whether add-wins collections converge according to the profile;
- whether tombstones preserve concurrent edits;
- whether snapshots round-trip across implementations.

Two independent implementations are **not** required to produce byte-identical Automerge changes or full-save images from the same semantic intent.

The normative result for those scenarios is the resulting state, conflict set, validation result, and cross-implementation acceptance behavior.

---

## 2. Automerge compatibility target

This suite uses Automerge `3.5.0` as the initial reference corpus target.

The profile itself remains defined by `SHARED-OBJECTS-PROFILE-01`; the reference package version exists so implementers can generate and exchange a concrete binary corpus while the project's long-term Automerge binary-version compatibility policy is finalized.

An implementation MAY use another compatible binding/version if it can:

1. consume the reference change corpus;
2. produce changes accepted by the reference implementation;
3. preserve the required logical/conflict semantics;
4. load/save interoperable documents for the declared compatibility range.

---

## 3. Deterministic fixture derivation

The suite derives fixed 32-byte test values as:

```text
fixture(label) = SHA-256(ASCII(label))
```

### 3.1 Resource A

```text
label = OPENLFCP-SHARED-OBJECTS-TV01-RESOURCE-A
resource_id = {h(resource)}
```

### 3.2 Resource B

```text
label = OPENLFCP-SHARED-OBJECTS-TV01-RESOURCE-B
resource_id = {h(resource_b)}
```

### 3.3 Principals

| Principal | Principal ID hex | PrincipalRef |
|---|---|---|
| Andrey | `{h(andrey)}` | `{pref(andrey)}` |
| Pavel | `{h(pavel)}` | `{pref(pavel)}` |
| Masha | `{h(masha)}` | `{pref(masha)}` |

PrincipalRef is exactly:

```text
"p:" + base64url-no-padding(raw_32_byte_principal_id)
```

---

# Part I. Deterministic vectors

## D01. Automerge actor ID: Andrey / Resource A

Actor derivation:

```text
SHA-256(
  ASCII("OPENLFCP-SHARED-OBJECTS-ACTOR-v1") ||
  resource_id ||
  principal_id
)
```

Input:

```text
resource  = {h(resource)}
principal = {h(andrey)}
```

Expected:

```text
actor_id = {h(actor(resource,andrey))}
```

The result is exactly 32 bytes.

---

## D02. Resource separation

The same Principal in Resource B MUST derive a different actor ID.

```text
actor_id = {h(actor(resource_b,andrey))}
```

An implementation producing the Resource-A actor for Resource B fails this vector.

---

## D03. PrincipalRef

Input raw Principal ID:

```text
{h(andrey)}
```

Expected text:

```text
{pref(andrey)}
```

No `=` padding is permitted.

---

## D04. Data Unit plaintext framing

This vector checks only Shared Objects framing. The enclosed bytes are intentionally synthetic and MUST NOT be interpreted as a valid Automerge change.

Synthetic change bytes:

```text
{h(synthetic_change)}
```

Logical framing:

```cddl
[
  1,
  h'{h(synthetic_change)}'
]
```

Expected deterministic CBOR:

```text
{h(change_frame)}
```

SHA-256 of the expected deterministic framed CBOR:

```text
{h(sha256(change_frame))}
```

---

## D05. Snapshot plaintext framing

Synthetic full-save bytes:

```text
{h(synthetic_snapshot)}
```

Logical framing:

```cddl
[
  1,
  h'{h(synthetic_snapshot)}'
]
```

Expected deterministic CBOR:

```text
{h(snapshot_frame)}
```

SHA-256 of the expected deterministic framed CBOR:

```text
{h(sha256(snapshot_frame))}
```

---

## D06. Canonical Object ID

Valid:

```text
{obj_task_1}
```

Requirements checked:

```text
lowercase
canonical hyphens
version = 7
RFC 4122/RFC 9562 variant bits
```

---

## D07. Uppercase UUID is not canonical

Input:

```text
{obj_task_1.upper()}
```

Expected:

```text
PROFILE_INVALID
INVALID_OBJECT_ID
```

---

## D08. Wrong UUID version

Input:

```text
019a2f85-7b31-6c42-b85a-fc843e2f40ad
```

Expected:

```text
PROFILE_INVALID
INVALID_OBJECT_ID
```

---

# Part II. Base Task fixture

The main test Task is:

```json
{json.dumps(initial_task,indent=2,ensure_ascii=False)}
```

Object map key:

```text
objects["{obj_task_1}"]
```

The contained `id` MUST equal that key.

---

# Part III. Behavioral interoperability scenarios

## S01. Create Task

Andrey creates the base Task in one application transaction / one Automerge change.

Expected materialized state:

```text
objects[{obj_task_1}] exists
id = {obj_task_1}
type = task
lifecycle = active
status = todo
priority = normal
tags = {{}}
assignees = {{}}
extensions = {{}}
```

The change generated by implementation A MUST be applicable by implementation B.

---

## S02. Independent-field concurrency

Both peers start from S01.

Andrey, offline:

```text
task.complete
status = done
completion_date = 2026-10-08
```

Pavel, concurrently:

```text
task.set_title
title = Prepare final API contract
```

After exchanging changes:

```text
status = done
completion_date = 2026-10-08
title = Prepare final API contract
```

Expected semantic conflicts:

```text
none
```

Concurrent edits to different scalar properties do not create an application conflict merely because they were concurrent.

---

## S03. Concurrent status conflict

Start from S01.

Andrey:

```text
status = done
completion_date = 2026-10-08
```

Pavel concurrently:

```text
status = cancelled
```

After merge, the application MUST be able to observe the status conflict set:

```text
{{ done, cancelled }}
```

Ordering of conflict-map internals is not normative.

The client MUST report:

```text
status conflicted = true
```

It MAY use Automerge's deterministic selected scalar for provisional rendering, but MUST NOT claim the field is resolved.

---

## S04. Explicit status conflict resolution

Start from the merged S03 state containing both values.

Masha explicitly chooses:

```text
done
```

The resolver writes:

```text
status = done
```

from a document containing all known conflicting values.

Expected result:

```text
status = done
status conflict = false
```

A resolver that writes from only one pre-merge branch does NOT satisfy this vector.

---

## S05. Concurrent due dates

Andrey:

```text
due = 2026-10-10
```

Pavel concurrently:

```text
due = 2026-10-12
```

Expected conflict set:

```text
{{ 2026-10-10, 2026-10-12 }}
```

Both values remain available until explicit resolution.

---

## S06. Tag add/add

Andrey concurrently adds:

```text
backend
```

Pavel adds:

```text
important
```

Expected:

```text
tags = {{ backend, important }}
```

---

## S07. Tag add/remove add-wins

Base state contains:

```text
tags = {{ backend }}
```

Andrey removes `backend` by deleting the map key.

Pavel concurrently performs a fresh add of `backend` by writing:

```text
tags["backend"] = true
```

Expected:

```text
tags = {{ backend }}
```

A `false` scalar MUST NOT be used to model removal.

---

## S08. Assignee add/remove add-wins

Base state assigns Pavel:

```text
assignees = {{ {pref(pavel)} }}
```

Andrey removes Pavel.

Masha concurrently writes a fresh assignment of Pavel.

Expected:

```text
assignees = {{ {pref(pavel)} }}
```

---

## S09. Delete versus independent edit

Andrey:

```text
lifecycle = deleted
```

Pavel concurrently:

```text
title = Final API contract
```

Expected:

```text
object remains present
lifecycle = deleted
title = Final API contract
```

The title change is retained beneath the tombstone.

Physical removal of the object fails this vector.

---

## S10. Delete versus restore

Andrey concurrently writes:

```text
lifecycle = deleted
```

Pavel writes:

```text
lifecycle = active
```

Expected lifecycle conflict set:

```text
{{ active, deleted }}
```

The conflict MUST be surfaced.

---

## S11. Unknown field preservation

Base object additionally contains:

```json
{{
  "x_future_scalar": "future-value",
  "extensions": {{
    "com.example.tracker": {{
      "ticket": "ABC-42"
    }}
  }}
}}
```

An older client that only understands standardized Task fields changes:

```text
status = in_progress
```

After its change, merge, and save/load round-trip, both unknown values MUST still exist unchanged.

---

## S12. Unknown object type preservation

Resource contains:

```json
{json.dumps(unknown_obj,indent=2,ensure_ascii=False)}
```

A client that does not understand `com.example.poll` MAY omit it from normal UI.

It MUST preserve the object through load, unrelated mutations, synchronization, and snapshot generation.

---

## S13. Object ID collision

Two actors concurrently create semantically different objects under exactly:

```text
{obj_task_1}
```

Expected profile result:

```text
OBJECT_ID_COLLISION
```

The client MUST NOT silently present the merged map as though the two users intentionally created one object.

Repair is outside this vector; a conforming repair creates a new Object ID for one logical object.

---

## S14. Snapshot + post-snapshot change

1. Build a valid document containing the S01 Task and later tag changes.
2. Produce an Automerge full-save image.
3. Frame it as `[1, save-bytes]` when used as LFCP Snapshot plaintext.
4. Load the save image in an independent implementation.
5. Apply a later change:

```text
status = in_progress
```

Expected:

```text
all pre-snapshot objects preserved
status = in_progress
```

Independent implementations are not required to produce identical full-save bytes for equivalent logical state. They ARE required to load compatible reference images and obtain equivalent state.

---

# Part IV. Invalid profile states

## I01. Object key / id mismatch

Map key:

```text
{obj_task_1}
```

Contained `id`:

```text
{obj_task_2}
```

Expected:

```text
PROFILE_INVALID
OBJECT_ID_MISMATCH
```

Only the affected object should be quarantined where safe.

---

## I02. Invalid Object ID

```text
NOT-A-UUID
```

Expected:

```text
PROFILE_INVALID
INVALID_OBJECT_ID
```

---

## I03. Non-text title

```text
title = 42
```

Expected diagnostic:

```text
INVALID_FIELD_TYPE
```

---

## I04. Invalid Local Date

```text
due = 2026-13-50
```

Expected:

```text
INVALID_LOCAL_DATE
```

---

## I05. Invalid tag representation

Invalid:

```json
["backend"]
```

Expected:

```text
INVALID_COLLECTION_REPRESENTATION
```

Version 1 requires an Automerge map used as an add-wins set.

---

## I06. Invalid assignee key

```text
not-a-principal
```

Expected:

```text
INVALID_PRINCIPAL_REF
```

---

## I07. Immutable field mutation

An existing Task is changed from:

```text
type = task
```

to:

```text
type = decision
```

Expected:

```text
PROFILE_INVALID
IMMUTABLE_FIELD_MUTATED
```

---

# Part V. Reference binary corpus

The companion file:

```text
generate_automerge_reference_01.mjs
```

is intended to generate a concrete binary corpus using:

```text
@automerge/automerge 3.5.0
```

The corpus includes reference changes for:

```text
profile initialization
Task creation
concurrent done
concurrent cancelled
merged status conflict
full save image
```

A conforming second implementation SHOULD demonstrate:

```text
reference JS change -> second implementation accepts it
second implementation change -> JS reference accepts it
reference save image -> second implementation loads it
second implementation save image -> JS reference loads it
```

This is stronger than comparing independently generated bytes, because it tests actual binary interoperability.

---

# Part VI. Implementation-neutral test runner contract

The machine-readable file `SHARED-OBJECTS-TEST-VECTORS-01.json` is normative for fixture values and scenario inputs/expected outputs. It is laid out as an `lfcp-vector-format/1` suite (`schemas/lfcp-vector-format-1.schema.json` in the spec repository).

A test runner should expose operations similar to:

```text
newReplica(resource_id, principal_id)
applyIntent(replica, intent)
exportChanges(replica, since_heads)
applyChanges(replica, changes)
merge(replicaA, replicaB)
readObject(object_id)
readConflicts(object_id, field)
save(replica)
load(bytes, resource_id, principal_id)
validateObject(object_id)
```

The exact programming API is not standardized.

---

# Part VII. Cross-language conformance matrix

For each SDK pair:

```text
TypeScript <-> Rust
TypeScript <-> future Swift
Rust       <-> future Swift
```

run at least:

| Test | A produces / B consumes | B produces / A consumes | Same logical result |
|---|---:|---:|---:|
| Init change | REQUIRED | REQUIRED | REQUIRED |
| Task create | REQUIRED | REQUIRED | REQUIRED |
| Scalar update | REQUIRED | REQUIRED | REQUIRED |
| Concurrent conflict | REQUIRED | REQUIRED | REQUIRED |
| Tag add/remove | REQUIRED | REQUIRED | REQUIRED |
| Tombstone/edit | REQUIRED | REQUIRED | REQUIRED |
| Snapshot load | REQUIRED | REQUIRED | REQUIRED |
| Unknown fields | REQUIRED | REQUIRED | REQUIRED |

---

# Part VIII. Conformance rules

An implementation claiming `SHARED-OBJECTS-TEST-VECTORS-01` conformance MUST:

1. match D01-D08 exactly;
2. pass S01-S14 semantically;
3. expose the mandatory conflict sets;
4. implement add-wins tags and assignees;
5. retain tombstoned objects;
6. preserve unknown fields and unknown object types;
7. detect I01-I07 without corrupting unrelated valid objects;
8. exchange at least one concrete Automerge change corpus with an independent implementation;
9. exchange at least one Automerge full-save image with an independent implementation;
10. avoid assuming that same semantic intent implies identical Automerge binary bytes.

---

# Part IX. Explicit non-requirements

This suite does NOT require:

- Markdown;
- Obsidian;
- LFCP server transport;
- LFCP encryption;
- LFCP Control Plane;
- globally identical Automerge save bytes;
- globally identical conflict-map iteration order;
- a particular UI rendering of a conflict.

The suite tests the Shared Objects application profile in isolation.

---

# Part X. Files in this vector release

```text
SHARED-OBJECTS-TEST-VECTORS-01.md
SHARED-OBJECTS-TEST-VECTORS-01.json
generate_shared_objects_test_vectors_01.py
generate_automerge_reference_01.mjs
```

The Python generator reproduces deterministic fixture values and the machine-readable vector manifest without requiring Automerge.

The JavaScript generator produces the supplementary Automerge binary reference corpus when the reference dependency is installed.

---

# Appendix A. Compact expected conflict table

| Scenario | Field | Expected |
|---|---|---|
| S03 | `status` | `{{done, cancelled}}` |
| S04 | `status` | resolved `done` |
| S05 | `due` | `{{2026-10-10, 2026-10-12}}` |
| S10 | `lifecycle` | `{{active, deleted}}` |

---

# Appendix B. Compact collection table

| Scenario | Collection | Expected |
|---|---|---|
| S06 | tags | `{{backend, important}}` |
| S07 | tags | `{{backend}}` |
| S08 | assignees | `{{Pavel}}` |

---

# Appendix C. Core invariant

The test suite exists to verify the central application-level promise:

```text
same valid set of Shared Objects changes
              +
profile-prescribed conflict semantics
              ↓
      same observable shared state
```

regardless of which conforming editor, SDK, or LFCP server transported those changes.
'''

md_path = OUT/'SHARED-OBJECTS-TEST-VECTORS-01.md'
md_path.write_text(md,encoding='utf-8')

print('MD', md_path, len(md.splitlines()), md_path.stat().st_size, hashlib.sha256(md_path.read_bytes()).hexdigest())
print('JSON', json_path, json_path.stat().st_size, hashlib.sha256(json_path.read_bytes()).hexdigest())

# Optional distribution bundle; zips are not committed to the repository.
if _args.bundle:
    bundle=OUT/'SHARED-OBJECTS-TEST-VECTORS-01-bundle.zip'
    with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as z:
        for name in ['SHARED-OBJECTS-TEST-VECTORS-01.md','SHARED-OBJECTS-TEST-VECTORS-01.json','generate_automerge_reference_01.mjs']:
            z.write(OUT/name, arcname=name)
        z.write(Path(__file__).resolve(), arcname='generate_shared_objects_test_vectors_01.py')
    print('BUNDLE', bundle, bundle.stat().st_size, hashlib.sha256(bundle.read_bytes()).hexdigest())
