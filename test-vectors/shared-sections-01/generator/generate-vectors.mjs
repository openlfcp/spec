import fs from 'node:fs';
import {createRequire} from 'node:module';
import path from 'node:path';
import assert from 'node:assert/strict';
import {A,PROFILE,hash,resource,principal,actor,pref,uid,ids,S,str,plain,fork,change,place,add,setLife,textEdit,initial,inspect,assertExpected} from './section-model.mjs';
import {admitReplay} from './admission.mjs';
const out=process.argv[2]||path.dirname(path.dirname(new URL(import.meta.url).pathname));
// The engine that generated the corpus: the installed package, not a literal.
const ENGINE=(()=>{
  let dir=path.dirname(createRequire(import.meta.url).resolve('@automerge/automerge'));
  for(;;){
    const p=path.join(dir,'package.json');
    if(fs.existsSync(p)){const j=JSON.parse(fs.readFileSync(p,'utf8'));if(j.name==='@automerge/automerge')return j.version;}
    const up=path.dirname(dir);if(up===dir)throw new Error('cannot find @automerge/automerge package.json');dir=up;
  }
})();
fs.mkdirSync(out,{recursive:true});
const seeds=initial();
const cases=[];
const visible=[ids.task,ids.para,ids.x,ids.y];
const bytesInfo=b=>({base64:Buffer.from(b).toString('base64'),sha256:hash(b),length:b.length});
function frame(b){
  let h;if(b.length<24)h=Buffer.from([0x40+b.length]);
  else if(b.length<256)h=Buffer.from([0x58,b.length]);
  else if(b.length<65536){h=Buffer.alloc(3);h[0]=0x59;h.writeUInt16BE(b.length,1);}
  else{h=Buffer.alloc(5);h[0]=0x5a;h.writeUInt32BE(b.length,1);}
  return Buffer.concat([Buffer.from([0x82,0x01]),h,b]);
}
function summarizeChange(b){
  const c=A.decodeChange(b);
  return {...bytesInfo(b),change_hash:c.hash,actor:c.actor,seq:c.seq,deps:c.deps,framed_plaintext:bytesInfo(frame(b))};
}
function record(id,title,{base=seeds,a=[],b=[],after=[],requirements={},coverage='model',notes=[]}={}){
  let da=fork(base,'A'),db=fork(base,'B');
  for(const [label,fn]of a)da=change(da,id+'/'+label,fn);
  for(const [label,fn]of b)db=change(db,id+'/'+label,fn);
  const ca=A.getChanges(base,da),cb=A.getChanges(base,db);
  let merged=A.merge(fork(da,'merge'),db);
  let resolved=fork(merged,'C');
  for(const [label,fn]of after)resolved=change(resolved,id+'/'+label,fn);
  const cc=A.getChanges(merged,resolved);
  // §14.1: every change goes through admission; refused changes and their
  // dependents never enter the reference document.
  const all=[...A.getAllChanges(base),...ca,...cb,...cc];
  const replay=admitReplay(all,actor('reference'));
  resolved=replay.doc;
  const summary={...inspect(resolved),refused:replay.refused,held:replay.held};
  assertExpected(summary,requirements,assert);
  const value={id,title,coverage,notes,
    base_snapshot:bytesInfo(A.save(base)),
    base_changes:A.getAllChanges(base).map(summarizeChange),
    branches:{A:ca.map(summarizeChange),B:cb.map(summarizeChange)},
    after_merge:cc.map(summarizeChange),
    assertions:requirements,expected:summary,
    expected_heads:A.getHeads(resolved).sort(),
    reference_snapshot:bytesInfo(A.save(resolved)),
    reference_snapshot_plaintext:bytesInfo(frame(A.save(resolved)))
  };
  cases.push(value);
}
record('SS01','Task with paragraph and stable structure',{requirements:{visible,classification:'VALID',slotCount:4,nodeCount:4}});
record('SS02','Concurrent sibling insertion after the same Task',{
  a:[['insert-A',d=>add(d,ids.a,'paragraph',ids.section,ids.task,'SS02-A','A note','A')]],
  b:[['insert-B',d=>add(d,ids.b,'paragraph',ids.section,ids.task,'SS02-B','B note','B')]],
  requirements:{visible:[...visible,ids.a,ids.b],classification:'VALID',nodeCount:6,treeCount:6}});
record('SS03','Independent checkbox and child text edits',{
  a:[['complete',d=>{d.objects[ids.task].status=S('done');}]],
  b:[['text',d=>textEdit(d,ids.para,0,0,'Final ')]],
  requirements:{classification:'VALID',tasks:{[ids.task]:{status:'done'}},texts:{[ids.para]:'Final Draft contract'}}});
record('SS04','Concurrent moves to different parents',{
  a:[['move-X',d=>place(d,ids.task,ids.x,null,'SS04-A','A')]],
  b:[['move-Y',d=>place(d,ids.task,ids.y,null,'SS04-B','B')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',absent:[ids.task,ids.para],recovery:{[ids.task]:'PLACEMENT_CONFLICT',[ids.para]:'BLOCKED_PARENT'}}});
record('SS05','Concurrent moves produce a parent cycle',{
  a:[['X-under-Y',d=>place(d,ids.x,ids.y,null,'SS05-A','A')]],
  b:[['Y-under-X',d=>place(d,ids.y,ids.x,null,'SS05-B','B')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',recovery:{[ids.x]:'PARENT_CYCLE',[ids.y]:'PARENT_CYCLE'},visible:[ids.task,ids.para]}});
record('SS06','Parent deletion versus child edit',{
  a:[['delete',d=>setLife(d,ids.task,'deleted')]],
  b:[['child-edit',d=>textEdit(d,ids.para,0,0,'Retained ')]],
  requirements:{hidden:[ids.task,ids.para],texts:{[ids.para]:'Retained Draft contract'},retainedConcurrentEdits:[ids.para]}});
record('SS07','Child moved out of concurrently deleted parent',{
  a:[['delete',d=>setLife(d,ids.task,'deleted')]],
  b:[['move-out',d=>place(d,ids.para,ids.section,ids.y,'SS07-B','B')]],
  requirements:{hidden:[ids.task],visible:[ids.para,ids.x,ids.y],classification:'VALID'}});
record('SS08','Delete versus explicit same-value restore',{
  a:[['delete',d=>setLife(d,ids.task,'deleted')]],
  b:[['explicit-restore',d=>setLife(d,ids.task,'active')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',scalarConflict:{id:ids.task,field:'lifecycle'},recovery:{[ids.task]:'LIFECYCLE_CONFLICT'}},
  notes:['The restore must emit a fresh assignment; direct same-value assignment produces no change in the pinned binding.']});
record('SS09','Repeated moves keep one identity and historical slots',{
  a:[['move-X',d=>place(d,ids.task,ids.x,null,'SS09-1')],
     ['move-Y',d=>place(d,ids.task,ids.y,null,'SS09-2')],
     ['move-root',d=>place(d,ids.task,ids.section,ids.y,'SS09-3')]],
  requirements:{classification:'VALID',visible,treeCount:4,slotCount:7,nodeCount:4}});
record('SS10','Detach has no shared mutation',{coverage:'model-noop-plus-adapter-contract',requirements:{classification:'VALID',visible,slotCount:4},notes:['The empty shared delta is checked. No Obsidian detach UI or file operation is executed by this corpus.']});
record('SS11','Task field edit from another projection',{
  a:[['rename',d=>{d.objects[ids.task].title=S('Final contract');}]],
  requirements:{tasks:{[ids.task]:{title:'Final contract'}},texts:{[ids.para]:'Draft contract'},visible},
  notes:['Tests the model operation; projection UI itself is tested by Markdown fixtures.']});
const snapBase=change(fork(seeds,'A'),'SS12/checkpoint',d=>textEdit(d,ids.para,0,0,'Snapshot '));
record('SS12','Snapshot checkpoint and later change',{
  base:snapBase,a:[['post-checkpoint',d=>{d.objects[ids.task].status=S('done');}]],
  requirements:{tasks:{[ids.task]:{status:'done'}},texts:{[ids.para]:'Snapshot Draft contract'},classification:'VALID'}});
record('SS13','Invalid mutation of immutable placement parent',{
  a:[['corrupt-parent',d=>{d.placements[uid('slot-task')].parent_id=S(ids.x);}]],
  requirements:{classification:'VALID',refused:['IMMUTABLE_FIELD_MUTATED'],visible},coverage:'negative-admission',
  notes:['A3. Rewritten for ADR 0009 P2 (LFCP-02-010): the planning corpus expected the whole section PROFILE_INVALID with an empty tree; under SHARED-SECTIONS-PROFILE-01 §14.1 the change is refused at admission, is never merged, and the section stays VALID.']});
record('SS14','Concurrent Unicode text edit using scalar-index bridge',{
  base:change(fork(seeds,'A'),'SS14/base',d=>A.updateText(d,['nodes',ids.para,'text'],'А😀Б')),
  a:[['after-emoji',d=>textEdit(d,ids.para,2,0,'!')]],
  b:[['prefix',d=>textEdit(d,ids.para,0,0,'Я: ')]],
  requirements:{texts:{[ids.para]:'Я: А😀!Б'},classification:'VALID'},
  notes:['Both writers use Automerge JS '+ENGINE+'. This is a Rust-consumer fixture, not evidence of a Rust run.']});
record('SS15','Explicit placement conflict resolution',{
  a:[['move-X',d=>place(d,ids.task,ids.x,null,'SS15-A','A')]],
  b:[['move-Y',d=>place(d,ids.task,ids.y,null,'SS15-B','B')]],
  after:[['resolve-root',d=>place(d,ids.task,ids.section,null,'SS15-C','C')]],
  requirements:{classification:'VALID',visible,treeCount:4,slotCount:7}});
record('SS16','Paragraph split keeps prefix identity',{
  a:[['split',d=>{
    const old=d.nodes[ids.para].text;
    textEdit(d,ids.para,6,Array.from(old).length-6,'');
    add(d,ids.extra,'paragraph',ids.task,ids.para,'SS16-extra',Array.from(old).slice(6).join(''));
  }]],
  requirements:{texts:{[ids.para]:'Draft ',[ids.extra]:'contract'},visible:[...visible,ids.extra],classification:'VALID'}});
const joinBase=change(fork(seeds,'A'),'SS17/base',d=>add(d,ids.extra,'paragraph',ids.task,ids.para,'SS17-extra','Second note'));
record('SS17','Paragraph join retains tombstoned source Text',{
  base:joinBase,a:[['join',d=>{
    textEdit(d,ids.para,Array.from(d.nodes[ids.para].text).length,0,'\n'+d.nodes[ids.extra].text);
    setLife(d,ids.extra,'deleted');
  }]],
  requirements:{texts:{[ids.para]:'Draft contract\nSecond note',[ids.extra]:'Second note'},hidden:[ids.extra],classification:'VALID'}});
record('SS18','Unknown extension survives mutation and snapshot',{
  base:change(fork(seeds,'A'),'SS18/base',d=>{d.nodes[ids.para].extensions['com.example.future']={value:S('keep-me')};}),
  a:[['status',d=>{d.objects[ids.task].status=S('done');}]],
  requirements:{classification:'VALID'},notes:['Verifier separately checks the extension in loaded snapshots.']});
record('SS19','Duplicate placement list entry is invalid',{
  a:[['duplicate',d=>d.section.children.push(S(uid('slot-task')))]],
  requirements:{classification:'VALID',refused:['PLACEMENT_NOT_ATOMIC'],visible},coverage:'negative-admission',
  notes:['A2: the inserted PlacementId is not created by the change. Rewritten for ADR 0009 P2 (LFCP-02-010): the planning corpus expected the whole section PROFILE_INVALID with an empty tree; under SHARED-SECTIONS-PROFILE-01 §14.1 the change is refused at admission, is never merged, and the section stays VALID.']});
record('SS20','Replacing Text with a scalar is invalid',{
  a:[['scalar-instead-of-text',d=>{d.nodes[ids.para].text=S('Wrong type');}]],
  requirements:{classification:'VALID',refused:['CONTAINER_REPLACED'],visible,texts:{[ids.para]:'Draft contract'}},coverage:'negative-admission',
  notes:['A4, which precedes A5: the change replaces a node\'s Text. Rewritten for ADR 0009 P2 (LFCP-02-010): the planning corpus expected the whole section PROFILE_INVALID with an empty tree; under SHARED-SECTIONS-PROFILE-01 §14.1 the change is refused at admission, is never merged, and the section stays VALID.']});
record('SS21','Deleting an old ordering slot is invalid',{
  a:[['delete-slot',d=>d.section.children.splice(0,1)]],
  requirements:{classification:'VALID',refused:['CHILDREN_LIST_MUTATED'],visible},coverage:'negative-admission',
  notes:['A1. Rewritten for ADR 0009 P2 (LFCP-02-010): the planning corpus expected the whole section PROFILE_INVALID with an empty tree; under SHARED-SECTIONS-PROFILE-01 §14.1 the change is refused at admission, is never merged, and the section stays VALID.']});
record('SS22','Same destination concurrent moves still retain both intents',{
  a:[['move-X',d=>place(d,ids.task,ids.x,null,'SS22-A','A')]],
  b:[['move-X',d=>place(d,ids.task,ids.x,null,'SS22-B','B')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',recovery:{[ids.task]:'PLACEMENT_CONFLICT'}}});
record('SS23','Two hundred Tasks and paragraph children',{
  a:[['bulk-create',d=>{
    let after=ids.y;
    for(let i=1;i<200;i++){
      const t=uid('load-task-'+i),p=uid('load-para-'+i);
      add(d,t,'task',ids.section,after,'load-slot-'+i,'Задача '+i);
      add(d,p,'paragraph',t,null,'load-body-slot-'+i,'Notes '+i+' 😀');
      after=t;
    }
  }]],
  requirements:{classification:'VALID',nodeCount:402,treeCount:402,slotCount:402},
  coverage:'model-load-fixture',notes:['Exactly 200 Tasks, 200 paragraphs and two ordinary items. No editor performance claim.']});
record('SS24','Concurrent child insertion under deleted ancestor',{
  a:[['delete',d=>setLife(d,ids.task,'deleted')]],
  b:[['new-child',d=>add(d,ids.extra,'paragraph',ids.task,ids.para,'SS24-extra','Retained new child','B')]],
  requirements:{hidden:[ids.task,ids.para,ids.extra],retainedConcurrentEdits:[ids.extra],texts:{[ids.extra]:'Retained new child'}}});
record('SS25','Restore ancestor keeps independently deleted child hidden',{
  base:change(fork(seeds,'A'),'SS25/base',d=>{setLife(d,ids.task,'deleted');setLife(d,ids.para,'deleted');}),
  a:[['restore-parent',d=>setLife(d,ids.task,'active')]],
  requirements:{visible:[ids.task,ids.x,ids.y],hidden:[ids.para],classification:'VALID'}});
record('SS26','Explicit resolution breaks a concurrent parent cycle',{
  a:[['X-under-Y',d=>place(d,ids.x,ids.y,null,'SS26-A','A')]],
  b:[['Y-under-X',d=>place(d,ids.y,ids.x,null,'SS26-B','B')]],
  after:[['resolve-X-root',d=>place(d,ids.x,ids.section,ids.task,'SS26-C','C')]],
  requirements:{classification:'VALID',visible,treeCount:4}});
record('SS27','Resolve lifecycle conflict to active',{
  a:[['delete',d=>setLife(d,ids.task,'deleted')]],
  b:[['restore',d=>setLife(d,ids.task,'active')]],
  after:[['resolve-active',d=>setLife(d,ids.task,'active')]],
  requirements:{classification:'VALID',visible,tasks:{[ids.task]:{lifecycle:'active'}}}});
const restored=A.load(A.save(seeds),{actor:actor('A')});
record('SS28','Continue an actor safely from a full snapshot',{
  base:restored,a:[['continue-after-load',d=>{d.objects[ids.task].priority=S('high');}]],
  requirements:{classification:'VALID',tasks:{[ids.task]:{priority:'high'}}}});
const doc={
  suite:'SHARED-SECTIONS-TEST-VECTORS-01',schema_version:1,date:'2026-10-07',
  status:'working-draft-reference-corpus',profile:PROFILE,
  engine:{package:'@automerge/automerge',version:ENGINE,role:'corpus reference engine; the version spec pins in package.json'},
  wire_coverage:'application plaintext framing only; no signatures, encryption, server or network',
  identities:{resource_hex:resource.toString('hex'),resource_ref:resource.toString('base64url'),ids,
    actors:Object.fromEntries(['A','B','C'].map(n=>[n,{principal_hex:principal(n).toString('hex'),principal_ref:pref(n),actor_hex:actor(n)}]))},
  cases
};
fs.writeFileSync(path.join(out,'SHARED-SECTIONS-TEST-VECTORS-01.json'),JSON.stringify(doc,null,2)+'\n');
console.log(JSON.stringify({generated:cases.length,engine:doc.engine.version,output:out}));
