import fs from 'node:fs';
import {createRequire} from 'node:module';
import path from 'node:path';
import assert from 'node:assert/strict';
import {A,PROFILE,hash,resource,principal,actor,pref,uid,ids,S,str,plain,fork,change,place,add,setLife,textEdit,initial,genesis,inspect,assertExpected,snapshotCounts} from './section-model.mjs';
import {admitReplay,changeInfo} from './admission.mjs';
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
const bytesInfo=b=>({b64url:Buffer.from(b).toString('base64url'),sha256:hash(b),length:b.length});
function frame(b){
  let h;if(b.length<24)h=Buffer.from([0x40+b.length]);
  else if(b.length<256)h=Buffer.from([0x58,b.length]);
  else if(b.length<65536){h=Buffer.alloc(3);h[0]=0x59;h.writeUInt16BE(b.length,1);}
  else{h=Buffer.alloc(5);h[0]=0x5a;h.writeUInt32BE(b.length,1);}
  return Buffer.concat([Buffer.from([0x82,0x01]),h,b]);
}
function summarizeChange(b,signer){
  // A change above an expansion limit is read from its header (expansion.mjs).
  const c=changeInfo(b);
  return {...bytesInfo(b),change_hash:c.hash,actor:c.actor,seq:c.seq,deps:c.deps,framed_plaintext:bytesInfo(frame(b)),...(signer?{signer}:{})};
}
function record(id,title,{base=seeds,a=[],b=[],after=[],inject,requirements={},coverage='model',notes=[],snapshot=false}={}){
  let da=fork(base,'A'),db=fork(base,'B');
  for(const [label,fn]of a)da=change(da,id+'/'+label,fn);
  for(const [label,fn]of b)db=change(db,id+'/'+label,fn);
  const ca=A.getChanges(base,da),cb=A.getChanges(base,db);
  let merged=A.merge(fork(da,'merge'),db);
  let resolved=fork(merged,'C');
  for(const [label,fn]of after)resolved=change(resolved,id+'/'+label,fn);
  const cc=A.getChanges(merged,resolved);
  // Crafted Data Units on branch A, each with the Principal that signs it.
  const crafted=inject?inject(da):[];
  // §14.1: every change goes through admission; refused changes and their
  // dependents never enter the reference document.
  const all=[...A.getAllChanges(base),...ca,...crafted,...cb,...cc];
  const replay=admitReplay(all,actor('reference'));
  resolved=replay.doc;
  const summary={...inspect(resolved),refused:replay.refused,held:replay.held,...(snapshot?{snapshot:snapshotCounts(resolved)}:{})};
  assertExpected(summary,requirements,assert);
  // lfcp-vector-format/1, a behavioral case: the inputs are the stored
  // changes; the expected values are the reference state after admission.
  const value={id,type:'behavioral',kind:'section_scenario',description:title,
    inputs:{
      base_snapshot:bytesInfo(A.save(base)),
      base_changes:A.getAllChanges(base).map(b=>summarizeChange(b)),
      branches:{A:[...ca.map(b=>summarizeChange(b)),...crafted.map(x=>summarizeChange(x.bytes,x.signer))],B:cb.map(b=>summarizeChange(b))},
      after_merge:cc.map(b=>summarizeChange(b))
    },
    expected:{
      state:summary,
      heads:A.getHeads(resolved).sort(),
      reference_snapshot:bytesInfo(A.save(resolved)),
      reference_snapshot_plaintext:bytesInfo(frame(A.save(resolved))),
      requirements,coverage,notes
    }
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
// LFCP-02-010: readiness and import (§12), admission (§14.1), isolation
// (§14.2) and the Text budget (§16).
const empty=genesis();
const importChunk=(from,to)=>d=>{
  let after=from>1?uid('imp-task-'+(from-1)):null;
  for(let i=from;i<=to;i++){
    const t=uid('imp-task-'+i);
    add(d,t,'task',ids.section,after,'imp-slot-'+i,'Import '+i);
    add(d,uid('imp-para-'+i),'paragraph',t,null,'imp-body-'+i,'Notes '+i);
    after=t;
  }
};
record('SS29','Import in three changes, ready written last',{base:empty,
  a:[['chunk-1',importChunk(1,3)],['chunk-2',importChunk(4,6)],['ready',d=>{d.section.ready=true;}]],
  requirements:{classification:'VALID',nodeCount:12,treeCount:12},coverage:'import',
  notes:['§12.1: each change of the import is consistent on its own; the section is projected once its creator writes ready in the last change.']});
record('SS30','An import without ready projects nothing',{base:empty,
  a:[['chunk-1',importChunk(1,3)]],
  requirements:{classification:'IMPORTING',nodeCount:6,treeCount:0},coverage:'import',
  notes:['§12.1: a reader shows the section as being imported and projects none of its content.']});
record('SS31','Ready written by another actor is refused',{base:empty,
  a:[['chunk-1',importChunk(1,3)]],
  b:[['ready-by-B',d=>{d.section.ready=true;}]],
  requirements:{classification:'IMPORTING',refused:['IMMUTABLE_FIELD_MUTATED'],treeCount:0},coverage:'negative-admission',
  notes:['§12.1: only the actor of the section\'s created_by writes ready.']});
record('SS32','Deleting ready is refused',{
  a:[['delete-ready',d=>{delete d.section.ready;}]],
  requirements:{classification:'VALID',refused:['IMMUTABLE_FIELD_MUTATED'],visible},coverage:'negative-admission'});
record('SS33','A placement created but not inserted is refused',{
  a:[['orphan-placement',d=>{
    const n=ids.a,p=uid('SS33-slot');
    d.nodes[n]={id:S(n),kind:S('paragraph'),created_by:S(pref('A')),lifecycle:S('active'),placement:S(p),children:[],extensions:{},text:'Orphan'};
    d.placements[p]={id:S(p),node_id:S(n),parent_id:S(ids.section),created_by:S(pref('A'))};
  }]],
  requirements:{classification:'VALID',refused:['PLACEMENT_NOT_ATOMIC'],visible,nodeCount:4},coverage:'negative-admission',
  notes:['A2: a placement is created, inserted exactly once and assigned in one change.']});
record('SS34','Changing a node\'s kind is refused',{
  a:[['retype',d=>{d.nodes[ids.x].kind=S('paragraph');}]],
  requirements:{classification:'VALID',refused:['IMMUTABLE_FIELD_MUTATED'],visible},coverage:'negative-admission',notes:['A3.']});
record('SS35','Replacing a node\'s children list is refused',{
  a:[['new-list',d=>{d.nodes[ids.x].children=[];}]],
  requirements:{classification:'VALID',refused:['CONTAINER_REPLACED'],visible},coverage:'negative-admission',notes:['A4.']});
record('SS36','A Task title written as Text is refused',{
  a:[['text-title',d=>{d.objects[ids.task].title='Collaborative title';}]],
  requirements:{classification:'VALID',refused:['INVALID_FIELD_TYPE'],visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:['A5: Task fields are scalar strings (SHARED-OBJECTS-PROFILE-01 §30).']});
record('SS37','A change after a refused one is held',{
  a:[['delete-slot',d=>d.section.children.splice(0,1)],['edit-after',d=>textEdit(d,ids.para,0,0,'Held: ')]],
  requirements:{classification:'VALID',refused:['CHILDREN_LIST_MUTATED'],heldCount:1,visible,texts:{[ids.para]:'Draft contract'}},coverage:'negative-admission',
  notes:['§14.1: a refused change blocks the changes that depend on it (SHARED-OBJECTS-PROFILE-01 §14.1).']});
record('SS38','A Task node whose Task is missing is isolated with its subtree',{
  a:[['dangling-task',d=>{
    const n=ids.a,p=uid('SS38-slot');
    d.nodes[n]={id:S(n),kind:S('task'),task_id:S(n),list_style:S('bullet'),created_by:S(pref('A')),lifecycle:S('active'),placement:S(p),children:[],extensions:{}};
    d.placements[p]={id:S(p),node_id:S(n),parent_id:S(ids.section),created_by:S(pref('A'))};
    d.section.children.push(S(p));
    add(d,ids.b,'paragraph',n,null,'SS38-child','Under a missing Task');
  }]],
  requirements:{classification:'STRUCTURAL_ATTENTION',invalid:{[ids.a]:'INVALID_REFERENCE'},recovery:{[ids.b]:'BLOCKED_PARENT'},visible,absent:[ids.a,ids.b]},coverage:'isolation',
  notes:['§14.2: the invalid node and its subtree are not projected; the rest of the section is.']});
record('SS39','An item placed under a paragraph is isolated',{
  a:[['under-paragraph',d=>add(d,ids.a,'item',ids.para,null,'SS39-slot','Misplaced')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',invalid:{[ids.a]:'INVALID_REFERENCE'},visible,absent:[ids.a]},coverage:'isolation'});
const long='абвгдежзий'.repeat(2000);
record('SS40','A 20,000-character insertion split under the Text budget',{
  a:[['run-1',d=>textEdit(d,ids.para,14,0,long.slice(0,8192))],
     ['run-2',d=>textEdit(d,ids.para,14+8192,0,long.slice(8192,16384))],
     ['run-3',d=>textEdit(d,ids.para,14+16384,0,long.slice(16384))]],
  requirements:{classification:'VALID',visible,texts:{[ids.para]:'Draft contract'+long}},coverage:'budget',
  notes:['§12.3, §16.2: consecutive contiguous runs of at most 8,192 Text operations each.']});
record('SS41','One change inserting 16,385 characters is refused',{
  a:[['too-long',d=>textEdit(d,ids.para,14,0,'ж'.repeat(16385))]],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible,texts:{[ids.para]:'Draft contract'}},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §11.1: more than 16,384 values in a column; the reference model counts operations.']});
// LFCP-02-010, inherited admission (SHARED-OBJECTS-PROFILE-01 §8, §11,
// §11.2, §14.1) with this profile's actor domain.
const leb=n=>{const o=[];do{let b=n&0x7f;n>>>=7;if(n)b|=0x80;o.push(b);}while(n);return o;};
/** The same change as a compressed chunk (type 2): one stored DEFLATE block. */
const compressedChunk=change=>{
  const headerLen=9+leb(change.length-9).length;
  const data=change.subarray(headerLen),len=data.length;
  const stored=Uint8Array.from([0x01,len&0xff,len>>8,~len&0xff,(~len>>8)&0xff,...data]);
  return Uint8Array.from([...change.subarray(0,8),2,...leb(stored.length),...stored]);
};
/** A's next change on `doc`: a title edit. */
const nextOfA=(doc,label)=>{
  const next=change(doc,label,d=>{d.objects[ids.task].title=S('Edited by A');});
  return A.getLastLocalChange(next);
};
record('SS42','A change signed by another Principal is refused',{
  inject:d=>[{bytes:nextOfA(d,'SS42/foreign'),signer:'B'}],
  requirements:{classification:'VALID',refused:['CHANGE_ACTOR_MISMATCH'],visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:['§2 (SHARED-OBJECTS-PROFILE-01 §8, §11): a change of A\'s actor in a Data Unit signed by B.']});
record('SS43','A change skipping a sequence number is refused',{
  inject:d=>{const c=A.decodeChange(nextOfA(d,'SS43/gap'));return [{bytes:A.encodeChange({...c,seq:c.seq+1}),signer:'A'}];},
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §14.1: with every dependency present, the sequence number is the actor\'s next one.']});
record('SS44','A compressed change chunk is refused',{
  inject:d=>[{bytes:compressedChunk(nextOfA(d,'SS44/compressed')),signer:'A'}],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §11: a Data Unit carries an uncompressed change chunk (type 1).']});
record('SS45','A change with a wrong checksum is refused',{
  inject:d=>{const b=Uint8Array.from(nextOfA(d,'SS45/checksum'));b[4]^=0x01;return [{bytes:b,signer:'A'}];},
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §11: the chunk checksum is verified even when Automerge would parse the bytes.']});
record('SS46','A change nesting an object 257 levels deep is refused',{
  inject:d=>{
    const next=change(d,'SS46/deep',x=>{
      let value={};const root=value;
      for(let i=2;i<257;i++){value.d={};value=value.d;}
      x.extensions['org.example.deep']=root;
    });
    return [{bytes:A.getLastLocalChange(next),signer:'A'}];
  },
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §11.2: the extensions map has depth 1, its new map depth 2, and the change nests to depth 257.']});
// LFCP-02-010: concurrent split and join (§10), and concurrent creations
// of one ID (§14.2, SOP §21).
const splitAt=(at,id,label)=>d=>{
  const old=Array.from(d.nodes[ids.para].text);
  textEdit(d,ids.para,at,old.length-at,'');
  add(d,id,'paragraph',ids.task,ids.para,label,old.slice(at).join(''));
};
const joinExtra=d=>{
  textEdit(d,ids.para,Array.from(d.nodes[ids.para].text).length,0,'\n'+d.nodes[ids.extra].text);
  setLife(d,ids.extra,'deleted');
};
record('SS47','Concurrent splits of one paragraph keep both results',{
  a:[['split-6',splitAt(6,ids.a,'SS47-A')]],b:[['split-5',splitAt(5,ids.b,'SS47-B')]],
  requirements:{classification:'VALID',visible:[...visible,ids.a,ids.b],texts:{[ids.para]:'Draft',[ids.a]:'contract',[ids.b]:' contract'}},coverage:'split-join',
  notes:['§10: both new nodes are kept with the suffix each writer observed; the prefix keeps the union of the deletions. Neither result is discarded.']});
record('SS48','A split and a concurrent edit of the suffix',{
  a:[['split',splitAt(6,ids.a,'SS48-A')]],b:[['append',d=>textEdit(d,ids.para,14,0,' v2')]],
  requirements:{classification:'VALID',visible:[...visible,ids.a],texts:{[ids.para]:'Draft  v2',[ids.a]:'contract'}},coverage:'split-join',
  notes:['§10: the concurrent characters stay in the original node\'s Text; they are not moved to the new node.']});
record('SS49','A join and a concurrent edit of the second paragraph',{
  base:joinBase,a:[['join',joinExtra]],b:[['edit-second',d=>textEdit(d,ids.extra,11,0,'!')]],
  requirements:{classification:'VALID',hidden:[ids.extra],texts:{[ids.para]:'Draft contract\nSecond note',[ids.extra]:'Second note!'},retainedConcurrentEdits:[ids.extra]},coverage:'split-join',
  notes:['§10: the unseen edit is retained under the tombstone and exposed for recovery, not merged into the copied text.']});
record('SS50','Concurrent joins of the same pair',{
  base:joinBase,a:[['join',joinExtra]],b:[['join',joinExtra]],
  requirements:{classification:'VALID',hidden:[ids.extra],texts:{[ids.para]:'Draft contract\nSecond note\nSecond note'}},coverage:'split-join',
  notes:['§10: each join appends the text it observed, so the text appears twice; both writers delete the second paragraph, which is not a lifecycle conflict (§14.3: equal values agree).']});
record('SS51','A split and a concurrent join',{
  base:joinBase,a:[['split',splitAt(6,ids.a,'SS51-A')]],b:[['join',joinExtra]],
  requirements:{classification:'VALID',visible:[ids.task,ids.para,ids.a],hidden:[ids.extra],texts:{[ids.para]:'Draft \nSecond note',[ids.a]:'contract'}},coverage:'split-join'});
record('SS52','Two writers create one node ID',{
  a:[['create',d=>add(d,ids.a,'paragraph',ids.section,ids.y,'SS52-A','From A','A')]],
  b:[['create',d=>add(d,ids.a,'item',ids.section,ids.y,'SS52-B','From B','B')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',visible,absent:[ids.a]},coverage:'collision',
  notes:['§14.2, SOP §21: each change is admissible on its own; the merged node map has two concurrent values, an OBJECT_ID_COLLISION. The node is not projected and neither value is chosen.']});
record('SS53','Two writers create one Task ID, with a child each',{
  a:[['create',d=>{add(d,ids.b,'task',ids.section,ids.y,'SS53-A','Task from A','A');add(d,ids.a,'paragraph',ids.b,null,'SS53-child','Under the Task','A');}]],
  b:[['create',d=>add(d,ids.b,'task',ids.section,ids.y,'SS53-B','Task from B','B')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',visible,absent:[ids.a,ids.b],recovery:{[ids.a]:'BLOCKED_PARENT'}},coverage:'collision',
  notes:['§14.2, SOP §21: the Task and its node collide; the node is not projected and its subtree is blocked.']});
record('SS54','Two nodes claim one placement ID',{
  a:[['create',d=>add(d,ids.a,'paragraph',ids.section,ids.y,'SS54-slot','From A','A')]],
  b:[['create',d=>add(d,ids.b,'paragraph',ids.section,ids.y,'SS54-slot','From B','B')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',visible,absent:[ids.a,ids.b]},coverage:'collision',
  notes:['§14.2, SOP §21: the placement collides; both nodes that select it are not projected, and the children list holding the PlacementId twice emits nothing for it.']});
// LFCP-02-010: Text history at the Snapshot floor (SHARED-OBJECTS-PROFILE-01
// §13.1). Each change replaces the previous run of 4,096 characters with a
// new one: 8,192 Text operations, the budget of §16.2. The text stays short
// while every inserted character remains an operation of the history.
const RUN=4096;
const churn=k=>['run-'+(k+1),d=>{
  if(k)textEdit(d,ids.para,14,RUN,'');
  textEdit(d,ids.para,14,0,String.fromCharCode(97+k%26).repeat(RUN));
}];
const churned=n=>Array.from({length:n},(_,k)=>churn(k));
record('SS55','Text history just within the Snapshot floor',{
  a:churned(63),snapshot:true,
  requirements:{classification:'VALID',visible,texts:{[ids.para]:'Draft contract'+'k'.repeat(RUN)}},coverage:'snapshot-floor',
  notes:['SHARED-OBJECTS-PROFILE-01 §13.1: 63 changes of 8,192 Text operations leave a history of 258,162 operation rows, within the floor of 262,144: every receiver accepts its Snapshot.']});
record('SS56','Text history past the Snapshot floor',{
  a:churned(64),snapshot:true,
  requirements:{classification:'VALID',visible,texts:{[ids.para]:'Draft contract'+'l'.repeat(RUN)}},coverage:'snapshot-floor',
  notes:['SHARED-OBJECTS-PROFILE-01 §13.1: one more change passes the floor (262,258 rows), with 4,110 characters of visible text. A receiver with floor limits rejects the Snapshot (INVALID_AUTOMERGE_BYTES) and falls back to the units, which it accepts; a publisher should not publish it. The reference snapshot is given for that check.']});
// SPEC-PATCH-10 (SHARED-OBJECTS-PROFILE-01 §11.3, §11.4, ADR 0010),
// inherited unchanged: the forms an external review found (F3d, F3b) and a
// non-canonical change.
/** A's change `label` written by `fn`, decoded. */
const decodedOfA=(d,label,fn)=>A.decodeChange(A.getLastLocalChange(change(d,label,fn)));
/** The change chunk `bytes` with 10 more rows in its insert column than it has operations (finding F3a). */
const extraRows=bytes=>{
  const b=Buffer.from(bytes);
  let pos=9;
  const u=()=>{let v=0,scale=1;for(;;){const x=b[pos++];v+=(x&0x7f)*scale;if(!(x&0x80))return v;scale*=128;}};
  const s=()=>{let v=0,scale=1;for(;;){const x=b[pos++];v+=(x&0x7f)*scale;scale*=128;if(!(x&0x80))return x&0x40?v-scale:v;}};
  const skip=n=>{pos+=n;};
  u();const start=pos;skip(u()*32);skip(u());u();u();s();skip(u());
  const others=u();for(let i=0;i<others;i++)skip(u());
  const headerEnd=pos;
  const metas=Array.from({length:u()},()=>[u(),u()]);
  const cols=metas.map(([spec,length])=>{const data=b.subarray(pos,pos+length);pos+=length;return [spec,data];});
  const extra=b.subarray(pos);
  const n=A.decodeChange(bytes).ops.length;
  const INSERT=(3<<4)|4;
  if(Buffer.from(cols.find(([spec])=>spec===INSERT)[1]).toString('hex')!==Buffer.from(leb(n)).toString('hex'))throw new Error('expected no insertions');
  const next=cols.map(([spec,data])=>[spec,spec===INSERT?Buffer.from(leb(n+10)):data]);
  const body=Buffer.concat([b.subarray(start,headerEnd),Buffer.from(leb(next.length)),
    Buffer.from(next.flatMap(([spec,data])=>[...leb(spec),...leb(data.length)])),...next.map(([,data])=>Buffer.from(data)),extra]);
  const len=Buffer.from(leb(body.length));
  const sum=Buffer.from(hash(Buffer.concat([Buffer.from([1]),len,body])),'hex').subarray(0,4);
  return Uint8Array.from(Buffer.concat([b.subarray(0,4),sum,Buffer.from([1]),len,body]));
};
record('SS57','A deletion without a predecessor is refused',{
  inject:d=>{
    const c=decodedOfA(d,'SS57/delete',x=>{x.objects[ids.task].title=S('Edited by A');});
    return [{bytes:A.encodeChange({...c,ops:[...c.ops,{action:'del',obj:'_root',key:'nodes',pred:[]}]}),signer:'A'}];
  },
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §11.4 (R7): a deletion names the operations it removes. Automerge applies this one, and its save then does not load ("missing ops").']});
record('SS58','A Text deletion naming the next element as its predecessor is refused',{
  inject:d=>{
    const c=decodedOfA(d,'SS58/delete',x=>textEdit(x,ids.para,0,1,''));
    const ops=c.ops.map(op=>{
      if(op.action!=='del')return op;
      const [ctr,who]=op.elemId.split('@');
      return {...op,pred:[`${Number(ctr)+1}@${who}`]};
    });
    return [{bytes:A.encodeChange({...c,ops}),signer:'A'}];
  },
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible,texts:{[ids.para]:'Draft contract'}},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §11.4 (R6): a predecessor is on the same object and key; for a sequence the key is the element. Automerge applies this one, and its save then does not load.']});
record('SS59','A change that is not in its canonical encoding is refused',{
  inject:d=>[{bytes:extraRows(nextOfA(d,'SS59/rows')),signer:'A'}],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §11.3 (4): every operation column has one row per operation; the insert column has 10 more (finding F3a). Automerge applies it, and its save then does not load: the heads mismatch.']});
record('SS60','Delete versus restore of a paragraph with a concurrent edit',{
  a:[['restore',d=>setLife(d,ids.para,'active')],['edit',d=>textEdit(d,ids.para,0,0,'Kept ')]],
  b:[['edit-X',d=>textEdit(d,ids.x,0,0,'Unrelated ')],['delete',d=>setLife(d,ids.para,'deleted')]],
  requirements:{classification:'STRUCTURAL_ATTENTION',recovery:{[ids.para]:'LIFECYCLE_CONFLICT'},absent:[ids.para],notHidden:[ids.para],notRetained:[ids.para],texts:{[ids.para]:'Kept Draft contract'}},
  notes:['§7.6: a lifecycle conflict blocks its branch; no value is chosen, whichever one the engine shows provisionally, so the node is not hidden and its concurrent edit is not under a deleted ancestor. The delete by B comes after an unrelated edit, so its operation ID is the larger and it is the value Automerge shows provisionally. Found by the seeded schedules (LFCP-02-024, seed 2): the two SDKs differed.']});
// B18, hostile bytes on the section receive path (SHARED-OBJECTS-PROFILE-01
// §11.1, as in its expansion corpus): A's next change, valid in every
// other respect, whose operations exceed a change limit. The limits are
// checked before the engine; the refused change is named by its hash, the
// SHA-256 of its chunk from the type byte on, which needs no expansion.
const hostileOfA=(doc,label,n,{key='k',preds=()=>[]}={})=>{
  const c=A.decodeChange(nextOfA(doc,label));
  return A.encodeChange({...c,ops:Array.from({length:n},()=>({action:'set',obj:'_root',key,value:null,pred:preds(c)}))});
};
const hostileNotes=(what)=>[`SHARED-OBJECTS-PROFILE-01 §11.1: ${what}; the limits are checked before the engine, so the change is never expanded.`,
  'The refused change is named by its hash, the SHA-256 of its chunk from the type byte on (the bytes after the magic number and checksum), which a receiver computes without decoding the operations.'];
record('SS61','A change expanding to 1,000,000 operations is refused',{
  inject:d=>[{bytes:hostileOfA(d,'SS61/rle-bomb',1_000_000),signer:'A'}],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:hostileNotes('one run-length-encoded column of 1,000,000 operations in about a hundred bytes, above 16,384 rows')});
record('SS62','An operation with 16,385 predecessors is refused',{
  inject:d=>[{bytes:hostileOfA(d,'SS62/preds-bomb',1,{preds:c=>Array.from({length:16385},(_,i)=>`${i+1}@${c.actor}`)}),signer:'A'}],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:hostileNotes('one operation whose predecessor group sums above 16,384')});
record('SS63','A change carrying more than 4 MiB of key strings is refused',{
  inject:d=>[{bytes:hostileOfA(d,'SS63/strings-bomb',16384,{key:'x'.repeat(257)}),signer:'A'}],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:hostileNotes('16,384 rows of a 257-byte key, above 4 MiB of strings')});
// R10 (finding D1): a table made and written into on the section receive
// path; refused before the engine, which aborts applying it.
record('SS64','A change making a table is refused',{
  inject:d=>{
    const c=A.decodeChange(nextOfA(d,'SS64/table'));
    const made=`${c.startOp}@${c.actor}`;
    return [{bytes:A.encodeChange({...c,ops:[
      {action:'makeTable',obj:'_root',key:'t',pred:[]},
      {action:'set',obj:made,key:'x',value:1,datatype:'int',pred:[]}]}),signer:'A'}];
  },
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §11.4 R10: no operation makes a table; automerge 0.12 aborts applying a write into one (finding D1), so the change is refused before the engine.']});
// D4 (differential fuzzing): §12.1 also binds the change that creates the
// section; a ready other than true there is refused like any later one.
record('SS65','A section created with ready false is refused',{base:A.init({actor:actor('A')}),
  inject:()=>[{bytes:A.getLastLocalChange(change(A.init({actor:actor('A')}),'SS65/genesis',x=>{
    x.profile=S(PROFILE);
    x.section={id:S(ids.section),title:S('Joint launch'),created_by:S(pref('A')),ready:false,children:[],extensions:{}};
    x.objects={};x.nodes={};x.placements={};x.extensions={};
  })),signer:'A'}],
  requirements:{refused:['IMMUTABLE_FIELD_MUTATED']},coverage:'negative-admission',
  notes:['§12.1: ready is true when written, also in the change that creates the section (finding D4 of the differential fuzzing: one SDK checked only later changes).']});
// D2 (differential fuzzing): SHARED-OBJECTS-PROFILE-01 §11.3 rule 2 bounds
// the sequence number below 2^53 and the time between -2^53 and 2^53, which
// a JavaScript number holds exactly. The bytes alone decide it, so the
// change is refused when it arrives (§14.1): before its actor is checked,
// and while a dependency is missing, instead of waiting.
const ulebBig=v=>{const o=[];do{let b=Number(v&0x7fn);v>>=7n;if(v)b|=0x80;o.push(b);}while(v);return o;};
const slebBig=v=>{const o=[];for(;;){const b=Number(v&0x7fn);v>>=7n;const done=(v===0n&&!(b&0x40))||(v===-1n&&(b&0x40));o.push(done?b:b|0x80);if(done)return o;}};
/** The change chunk `bytes` with its header's `seq`, `time` or dependencies replaced (BigInts, hex hashes), its checksum recomputed. */
const withHeader=(bytes,{seq,time,deps})=>{
  const b=Buffer.from(bytes);
  let pos=9;
  const u=()=>{let v=0n,shift=0n;for(;;){const x=b[pos++];v|=BigInt(x&0x7f)<<shift;shift+=7n;if(!(x&0x80))return v;}};
  const s=()=>{let v=0n,shift=0n,x;do{x=b[pos++];v|=BigInt(x&0x7f)<<shift;shift+=7n;}while(x&0x80);return x&0x40?v-(1n<<shift):v;};
  u();const start=pos;
  const oldDeps=Array.from({length:Number(u())},()=>{const h=b.subarray(pos,pos+32).toString('hex');pos+=32;return h;});
  const actorStart=pos;const actorLength=Number(u());pos+=actorLength;const actorEnd=pos;
  const oldSeq=u(),startOp=u(),oldTime=s();
  const rest=b.subarray(pos);
  const ds=(deps??oldDeps).slice().sort();
  const body=Buffer.concat([Buffer.from(ulebBig(BigInt(ds.length))),...ds.map(h=>Buffer.from(h,'hex')),b.subarray(actorStart,actorEnd),
    Buffer.from([...ulebBig(seq??oldSeq),...ulebBig(startOp),...slebBig(time??oldTime)]),rest]);
  const len=Buffer.from(ulebBig(BigInt(body.length)));
  const sum=Buffer.from(hash(Buffer.concat([Buffer.from([1]),len,body])),'hex').subarray(0,4);
  return Uint8Array.from(Buffer.concat([b.subarray(0,4),sum,Buffer.from([1]),len,body]));
};
const MISSING='ff'.repeat(32); // a dependency no replica holds
const depsOf=bytes=>A.decodeChange(bytes).deps;
const d2Notes=what=>[`SHARED-OBJECTS-PROFILE-01 §11.3 rule 2: ${what}. Automerge JS does not decode it (a JavaScript number cannot hold the value exactly), so every receiver refuses it with INVALID_AUTOMERGE_BYTES (finding D2 of the differential fuzzing).`,
  'SHARED-OBJECTS-PROFILE-01 §14.1, SHARED-SECTIONS-PROFILE-01 §14.1: the bytes alone decide it, so the change is refused when it arrives, before its actor is checked and whether or not its dependencies are present.'];
record('SS66','A change whose time is 2^53 is refused',{
  inject:d=>[{bytes:withHeader(nextOfA(d,'SS66/time'),{time:2n**53n}),signer:'A'}],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],heldCount:0,visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:d2Notes('the time is 2^53, one more than the largest time a change may have')});
record('SS67','A change with a missing dependency and the time 2^56 - 1 is refused, not held',{
  inject:d=>{const c=nextOfA(d,'SS67/missing-time');return [{bytes:withHeader(c,{time:2n**56n-1n,deps:[...depsOf(c),MISSING]}),signer:'A'}];},
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],heldCount:0,visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:d2Notes('the time is 2^56 - 1, and one dependency is a hash no replica holds (the D2b form)')});
record('SS68','A change with a missing dependency and the sequence number 2^53 is refused, not held',{
  inject:d=>{const c=nextOfA(d,'SS68/missing-seq');return [{bytes:withHeader(c,{seq:2n**53n,deps:[...depsOf(c),MISSING]}),signer:'A'}];},
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],heldCount:0,visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:d2Notes('the sequence number is 2^53, and one dependency is a hash no replica holds')});
record('SS69','A change signed by another Principal whose sequence number is 2^53 is refused for its bytes, not its actor',{
  inject:d=>[{bytes:withHeader(nextOfA(d,'SS69/foreign-seq'),{seq:2n**53n}),signer:'B'}],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],heldCount:0,visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:[...d2Notes('A\'s change, signed by B, with the sequence number 2^53 (the D7 form)'),'§14.1: INVALID_AUTOMERGE_BYTES comes before CHANGE_ACTOR_MISMATCH.']});
// D5 (differential fuzzing): an Automerge author in the extra bytes of a
// change other than the actor's first; automerge 0.12 asserts it away.
/** The change chunk `bytes` with `extra` appended after its columns, its length and checksum recomputed. */
const withExtra=(bytes,extra)=>{
  const b=Buffer.from(bytes);
  let pos=9;
  while(b[pos++]&0x80);
  const body=Buffer.concat([b.subarray(pos),Buffer.from(extra)]);
  const len=Buffer.from(ulebBig(BigInt(body.length)));
  const sum=Buffer.from(hash(Buffer.concat([Buffer.from([1]),len,body])),'hex').subarray(0,4);
  return Uint8Array.from(Buffer.concat([b.subarray(0,4),sum,Buffer.from([1]),len,body]));
};
record('SS70','A later change carrying an Automerge author is refused',{
  inject:d=>[{bytes:withExtra(nextOfA(d,'SS70/author'),[0x01,0x02,0xa1,0xb2]),signer:'A'}],
  requirements:{classification:'VALID',refused:['INVALID_AUTOMERGE_BYTES'],heldCount:0,visible,tasks:{[ids.task]:{title:'Prepare contract'}}},coverage:'negative-admission',
  notes:['SHARED-OBJECTS-PROFILE-01 §14.1: a change whose extra bytes begin with an Automerge author (1, a length of 2, two bytes) has the sequence number 1; this is A\'s third change. automerge 0.12 aborts applying it (finding D5 of the differential fuzzing), so it is refused before the engine.',
    'SHARED-OBJECTS-PROFILE-01 §11.3 rule 4 allows extra bytes: the change is canonical, and refused only by the author rule.']});
const doc={
  format:'lfcp-vector-format/1',
  suite:{
    id:'SHARED-SECTIONS-TEST-VECTORS-01',version:'01',
    specification:{id:'SHARED-SECTIONS-PROFILE-01',profile:PROFILE,revision:'working-draft'},
    description:'Behavioral cases of the shared sections profile: Automerge changes produced by the reference model, their admission (SHARED-SECTIONS-PROFILE-01 §14.1), the effective tree, isolation and model facts after convergence.',
    depends_on:['SHARED-OBJECTS-PROFILE-01','LFCP-WIRE-01'],
    conventions:{
      date:'2026-10-08',status:'working-draft-reference-corpus',
      engine_package:'@automerge/automerge',engine_version:ENGINE,engine_role:'corpus reference engine; the version spec pins in package.json',
      wire_coverage:'application plaintext framing only; no signatures, encryption, server or network',
      byte_records:'A byte record is {b64url, sha256, length}: the bytes as unpadded base64url, their SHA-256 in hex and their length. A change record adds the decoded Automerge change_hash, actor, seq and deps, the framed_plaintext record of the application plaintext framing and, for a crafted Data Unit, its signer.',
      expected:'expected.state is the reference state after admission; heads, the reference snapshot and its plaintext are byte values of the reference document; requirements are handwritten semantic checks; coverage and notes explain the case.'
    }
  },
  fixtures:{identities:{resource_hex:resource.toString('hex'),resource_ref:resource.toString('base64url'),ids,
    actors:Object.fromEntries(['A','B','C'].map(n=>[n,{principal_hex:principal(n).toString('hex'),principal_ref:pref(n),actor_hex:actor(n)}]))}},
  cases
};
fs.writeFileSync(path.join(out,'SHARED-SECTIONS-TEST-VECTORS-01.json'),JSON.stringify(doc,null,2)+'\n');
console.log(JSON.stringify({generated:cases.length,engine:ENGINE,output:out}));
