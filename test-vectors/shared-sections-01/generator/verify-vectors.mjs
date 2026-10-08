import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import {A,PROFILE,hash,actor,ids,inspect,assertExpected,str} from './section-model.mjs';
const out=process.argv[2]||'generated';
const suite=JSON.parse(fs.readFileSync(path.join(out,'SHARED-SECTIONS-TEST-VECTORS-01.json'),'utf8'));
const adapterAt=process.argv.indexOf('--adapter');
const adapter=adapterAt<0?null:await import(pathToFileURL(path.resolve(process.argv[adapterAt+1])).href);
assert.equal(suite.profile,PROFILE);
function decode(v) {
  const b=Buffer.from(v.base64,'base64');
  assert.equal(b.toString('base64'),v.base64);
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
for(const c of suite.cases) {
  const base=decode(c.base_snapshot), target=decode(c.reference_snapshot);
  const ordered=[...c.base_changes,...c.branches.A,...c.branches.B,...c.after_merge];
  const changes=ordered.map(x=>{
    const b=decode(x),dc=A.decodeChange(b);
    assert.equal(dc.hash,x.change_hash);assert.equal(dc.actor,x.actor);assert.equal(dc.seq,x.seq);assert.deepEqual(dc.deps,x.deps);
    assert.deepEqual(unframe(x.framed_plaintext),b);return b;
  });
  // Independently replay stored bytes, including reverse delivery and duplicates.
  let normal=A.init({actor:actor('verify-normal')});
  [normal]=A.applyChanges(normal,changes);
  let reverse=A.init({actor:actor('verify-reverse')});
  for(const b of [...changes].reverse()) [reverse]=A.applyChanges(reverse,[b,b]);
  assert.deepEqual(A.getMissingDeps(normal),[]);assert.deepEqual(A.getMissingDeps(reverse),[]);
  const delta=[...c.branches.A,...c.branches.B,...c.after_merge].map(decode);
  let checkpoint=A.load(base,{actor:actor('verify-checkpoint')});
  [checkpoint]=A.applyChanges(checkpoint,delta);
  const saved=A.load(target,{actor:actor('verify-save')});
  for(const d of [normal,reverse,checkpoint,saved]) {
    assert.deepEqual(inspect(d),c.expected,'state mismatch '+c.id);
    assert.deepEqual(A.getHeads(d).sort(),c.expected_heads,'heads mismatch '+c.id);
    assertExpected(inspect(d),c.assertions,assert);
  }
  assert.deepEqual(unframe(c.reference_snapshot_plaintext),target);
  if(c.id==='SS08')assert(c.branches.B.length===1,'restore was optimized away');
  if(c.id==='SS18')assert.equal(str(saved.nodes[ids.para].extensions['com.example.future'].value),'keep-me');
  if(c.id==='SS23')assert.equal(Object.keys(saved.objects).length,200);
  if(c.id==='SS28')assert.equal(c.branches.A[0].seq,3);
  for(const x of c.branches.A)assert.equal(x.actor,suite.identities.actors.A.actor_hex);
  for(const x of c.branches.B)assert.equal(x.actor,suite.identities.actors.B.actor_hex);
  for(const x of c.after_merge)assert.equal(x.actor,suite.identities.actors.C.actor_hex);
  if(adapter) {
    const result=await adapter.runCase({id:c.id,profile:suite.profile,identities:suite.identities,
      base_snapshot:c.base_snapshot,base_changes:c.base_changes,branches:c.branches,after_merge:c.after_merge});
    // Internal error strings are reference diagnostics, not a portable error-message contract.
    for(const key of Object.keys(c.expected).filter(k=>k!=='errors'))
      assert.deepEqual(result[key],c.expected[key],c.id+' adapter '+key);
  }
  reports.push({id:c.id,result:'pass',checks:['hashes','CBOR plaintext framing','normal replay','reverse duplicate replay','snapshot plus tail','reference save load','handwritten semantic assertions']});
}
const report={suite:suite.suite,engine:suite.engine,executed:'JavaScript reference model and binary replay only',cases:reports,passed:reports.length,failed:0,
  independent_adapter_executed:!!adapter,
  not_executed:adapter?['LFCP signatures/encryption/network','Obsidian UI/clipboard/platform matrix']:['production SDK','Rust independent replay','LFCP signatures/encryption/network','Obsidian UI/clipboard/platform matrix']};
fs.writeFileSync(path.join(out,'vector-validation-report.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({suite:suite.suite,passed:reports.length,failed:0}));
