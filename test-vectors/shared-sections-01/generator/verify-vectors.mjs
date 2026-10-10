import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import {A,PROFILE,hash,actor,ids,inspect,assertExpected,str,snapshotCounts} from './section-model.mjs';
import {admitReplay,changeInfo} from './admission.mjs';
const out=process.argv[2]||'generated';
const suite=JSON.parse(fs.readFileSync(path.join(out,'SHARED-SECTIONS-TEST-VECTORS-01.json'),'utf8'));
const adapterAt=process.argv.indexOf('--adapter');
const adapter=adapterAt<0?null:await import(pathToFileURL(path.resolve(process.argv[adapterAt+1])).href);
assert.equal(suite.format,'lfcp-vector-format/1');
assert.equal(suite.suite.specification.profile,PROFILE);
function decode(v) {
  const b=Buffer.from(v.b64url,'base64url');
  assert.equal(b.toString('base64url'),v.b64url);
  assert.equal(b.length,v.length);assert.equal(hash(b),v.sha256);
  return b;
}
function unframe(v) {
  const b=decode(v);assert.equal(b[0],0x82);assert.equal(b[1],1);
  let off=3,len;
  if(b[2]>=0x40&&b[2]<0x58)len=b[2]-0x40;
  else if(b[2]===0x58){len=b[3];off=4;assert(len>=24);}
  else if(b[2]===0x59){len=b.readUInt16BE(3);off=5;assert(len>=256);}
  else if(b[2]===0x5a){len=b.readUInt32BE(3);off=7;assert(len>=65536);}
  else throw Error('invalid byte-string framing');
  assert.equal(b.length,off+len);return b.subarray(off);
}
const reports=[];
for(const vector of suite.cases) {
  // The case as the reference model writes it: inputs and expected values.
  const c={id:vector.id,...vector.inputs,expected:vector.expected.state,assertions:vector.expected.requirements,
    expected_heads:vector.expected.heads,reference_snapshot:vector.expected.reference_snapshot,
    reference_snapshot_plaintext:vector.expected.reference_snapshot_plaintext};
  assert.equal(vector.type,'behavioral');
  const base=decode(c.base_snapshot), target=decode(c.reference_snapshot);
  const ordered=[...c.base_changes,...c.branches.A,...c.branches.B,...c.after_merge];
  const changes=ordered.map(x=>{
    // Read from the header when Automerge cannot or must not decode it (§11.1, §11.3 rule 2).
    const b=decode(x),dc=changeInfo(b);
    assert.equal(dc.hash,x.change_hash);assert.equal(dc.actor,x.actor);assert.equal(dc.seq,x.seq);assert.deepEqual(dc.deps,x.deps);
    assert.deepEqual(unframe(x.framed_plaintext),b);
    return x.signer?{bytes:b,signer:x.signer}:b;
  });
  // Replay stored bytes through admission (§14.1), in order, in reverse with
  // duplicates, and from the base Snapshot plus the tail.
  // The Snapshot floor cases (SS55, SS56) replay once outside CI; CI
  // (the CI environment variable) replays every case all three ways.
  const full=!c.expected.snapshot||!!process.env.CI;
  const normal=admitReplay(changes,actor('verify-normal'));
  const reverse=full?admitReplay([...changes].reverse().flatMap(b=>[b,b]),actor('verify-reverse')):normal;
  const delta=[...c.branches.A,...c.branches.B,...c.after_merge].map(x=>x.signer?{bytes:decode(x),signer:x.signer}:decode(x));
  const loaded=A.load(base,{actor:actor('verify-checkpoint')});
  const checkpoint=full?admitReplay([...A.getAllChanges(loaded),...delta],actor('verify-checkpoint')):normal;
  const saved=A.load(target,{actor:actor('verify-save')});
  // SHARED-OBJECTS-PROFILE-01 §13.1 counts, for the cases that record them.
  const counts=d=>c.expected.snapshot?{snapshot:snapshotCounts(d)}:{};
  const summaries=[...new Set([normal,reverse,checkpoint])].map(r=>[r.doc,{...inspect(r.doc),refused:r.refused,held:r.held,...counts(r.doc)}]);
  summaries.push([saved,{...inspect(saved),refused:normal.refused,held:normal.held,...counts(saved)}]);
  for(const [d,summary] of summaries) {
    assert.deepEqual(summary,c.expected,'state mismatch '+c.id);
    assert.deepEqual(A.getHeads(d).sort(),c.expected_heads,'heads mismatch '+c.id);
    assertExpected(summary,c.assertions,assert);
  }
  assert.deepEqual(unframe(c.reference_snapshot_plaintext),target);
  if(c.id==='SS08')assert(c.branches.B.length===1,'restore was optimized away');
  if(c.id==='SS18')assert.equal(str(saved.nodes[ids.para].extensions['com.example.future'].value),'keep-me');
  if(c.id==='SS23')assert.equal(Object.keys(saved.objects).length,200);
  if(c.id==='SS28')assert.equal(c.branches.A[0].seq,3);
  for(const x of c.branches.A)assert.equal(x.actor,suite.fixtures.identities.actors.A.actor_hex);
  for(const x of c.branches.B)assert.equal(x.actor,suite.fixtures.identities.actors.B.actor_hex);
  for(const x of c.after_merge)assert.equal(x.actor,suite.fixtures.identities.actors.C.actor_hex);
  if(adapter) {
    const result=await adapter.runCase({id:c.id,profile:suite.suite.specification.profile,identities:suite.fixtures.identities,
      base_snapshot:c.base_snapshot,base_changes:c.base_changes,branches:c.branches,after_merge:c.after_merge});
    // Internal error strings are reference diagnostics, not a portable error-message contract.
    for(const key of Object.keys(c.expected).filter(k=>k!=='errors'))
      assert.deepEqual(result[key],c.expected[key],c.id+' adapter '+key);
  }
  reports.push({id:c.id,result:'pass',checks:['hashes','CBOR plaintext framing','normal replay','reverse duplicate replay','snapshot plus tail','reference save load','handwritten semantic assertions']});
}
const report={suite:suite.suite.id,engine:{package:suite.suite.conventions.engine_package,version:suite.suite.conventions.engine_version},executed:'JavaScript reference model and binary replay only',cases:reports,passed:reports.length,failed:0,
  independent_adapter_executed:!!adapter,
  not_executed:adapter?['LFCP signatures/encryption/network','Obsidian UI/clipboard/platform matrix']:['production SDK','Rust independent replay','LFCP signatures/encryption/network','Obsidian UI/clipboard/platform matrix']};
fs.writeFileSync(path.join(out,'vector-validation-report.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({suite:suite.suite.id,passed:reports.length,failed:0}));
