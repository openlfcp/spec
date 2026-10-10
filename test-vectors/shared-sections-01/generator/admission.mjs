// Reference admission for SHARED-SECTIONS-PROFILE-01 §14.1 (ADR 0009, P2):
// the structural rules A1-A5 and the readiness rule of §12.1, decided for
// one change against the state of its causal history. Reference test
// support, not a production validator: it compares the state before and
// after the change rather than walking the change's operations, which
// decides the same rules for the changes of this corpus.
import {A,PROFILE,actor,pref,str,canon} from './section-model.mjs';
import {beyondSafeNumbers,changeHeader,expansionRefusal,hasAuthor,refusalName} from './expansion.mjs';

/** Diagnostics in their order of precedence (§14.1). */
export const ADMISSION_ORDER=['INVALID_AUTOMERGE_BYTES','CHANGE_ACTOR_MISMATCH','CONTAINER_REPLACED','CHILDREN_LIST_MUTATED','PLACEMENT_NOT_ATOMIC','IMMUTABLE_FIELD_MUTATED','INVALID_FIELD_TYPE'];
const ROOT_CONTAINERS=['section','objects','nodes','placements','extensions'];
const TEXT_KINDS=new Set(['paragraph','item','raw']);
const NODE_IMMUTABLE=['id','kind','created_by','task_id'];
const TASK_IMMUTABLE=['id','type','created_by'];
const NAMES=['A','B','C'];
const MAKE=new Set(['makeMap','makeList','makeText','makeTable']);

const oid=(obj,key)=>obj==null?null:A.getObjectId(obj,key);
/** Whether `v` is an Automerge map or list (not a scalar such as an ImmutableString, a counter or a date). */
const isObject=v=>{if(v===null||typeof v!=='object'||A.isImmutableString(v))return false;try{return /@|^_root$/.test(A.getObjectId(v)??'');}catch{return false;}};
const isText=(obj,key)=>{const v=obj?.[key];return v!==undefined&&!A.isImmutableString(v)&&typeof v==='string'&&!!oid(obj,key);};
const lanes=doc=>{
  const out=[];
  if(doc.section?.children)out.push([doc.section.id?str(doc.section.id):'section',doc.section.children]);
  for(const [n,node]of Object.entries(doc.nodes||{}))if(node?.children)out.push([n,node.children]);
  return out;
};
/** Whether `before` is a subsequence of `after`. */
const subsequence=(before,after)=>{let i=0;for(const x of after)if(x===before[i])i++;return i===before.length;};
/** The entries of `after` that are not matched by `before`, as a multiset. */
function inserted(before,after){
  const left=new Map();for(const x of before)left.set(x,(left.get(x)||0)+1);
  const out=[];for(const x of after){const k=left.get(x)||0;if(k)left.set(x,k-1);else out.push(x);}
  return out;
}
const conflictValues=(obj,key)=>{const c=obj?A.getConflicts(obj,key):undefined;return c?Object.values(c):obj?.[key]===undefined?[]:[obj[key]];};

/**
 * The §14.1 diagnostic for applying `bytes` to `prev`, the document of its
 * causal history, or null when the change is admitted.
 */
export function admit(prev,bytes){
  const [next]=A.applyChanges(A.clone(prev),[bytes]);
  const found=new Set();
  const decoded=A.decodeChange(bytes);
  const changeActor=decoded.actor;
  // SHARED-OBJECTS-PROFILE-01 §11.1, approximated by the operation count:
  // the action column holds one value per operation.
  if(decoded.ops.length>16384)return 'INVALID_AUTOMERGE_BYTES';
  if(prev.section){
    // A4: root containers and the profile.
    for(const key of ROOT_CONTAINERS)if(oid(prev,key)&&oid(prev,key)!==oid(next,key))found.add('CONTAINER_REPLACED');
    if(str(prev.profile)!==str(next.profile))found.add('CONTAINER_REPLACED');
    for(const key of ['children','extensions'])if(oid(prev.section,key)&&oid(prev.section,key)!==oid(next.section,key))found.add('CONTAINER_REPLACED');
    // A3: the section's immutable fields and the ready marker (§12.1).
    for(const key of ['id','created_by'])if(str(prev.section[key])!==str(next.section?.[key]))found.add('IMMUTABLE_FIELD_MUTATED');
    const before=conflictValues(prev.section,'ready'),after=conflictValues(next.section,'ready');
    if(JSON.stringify(before)!==JSON.stringify(after)){
      const creator=NAMES.find(n=>pref(n)===str(next.section?.created_by));
      if(after.length===0||after.some(v=>v!==true)||!creator||actor(creator)!==changeActor)found.add('IMMUTABLE_FIELD_MUTATED');
    }
  }else if(next.section){
    // §12.1 for the change that creates the section: ready, if it writes
    // it, is true and written by the creator (an import leaves it absent).
    const after=conflictValues(next.section,'ready');
    const creator=NAMES.find(n=>pref(n)===str(next.section.created_by));
    if(after.length>0&&(after.some(v=>v!==true)||!creator||actor(creator)!==changeActor))found.add('IMMUTABLE_FIELD_MUTATED');
  }
  // Existing nodes: their map, containers and immutable fields.
  for(const [n,old]of Object.entries(prev.nodes||{})){
    const now=next.nodes?.[n];
    if(!now||oid(prev.nodes,n)!==oid(next.nodes,n)){found.add('CONTAINER_REPLACED');continue;}
    for(const key of ['children','extensions'])if(oid(old,key)&&oid(old,key)!==oid(now,key))found.add('CONTAINER_REPLACED');
    if(oid(old,'text')&&oid(old,'text')!==oid(now,'text'))found.add('CONTAINER_REPLACED');
    for(const key of NODE_IMMUTABLE)if(str(old[key])!==str(now[key]))found.add('IMMUTABLE_FIELD_MUTATED');
  }
  for(const [id,old]of Object.entries(prev.objects||{})){
    const now=next.objects?.[id];
    if(!now)continue;
    for(const key of TASK_IMMUTABLE)if(str(old[key])!==str(now[key]))found.add('IMMUTABLE_FIELD_MUTATED');
  }
  // A3: placements are immutable once created.
  for(const [p,old]of Object.entries(prev.placements||{}))
    if(!next.placements?.[p]||canon(old)!==canon(next.placements[p]))found.add('IMMUTABLE_FIELD_MUTATED');
  // A1 and A2: children lists are insert-only, and every inserted entry is a
  // placement this change creates under that list's owner.
  const prevLanes=new Map(lanes(prev).map(([o,l])=>[o,l]));
  const created=Object.keys(next.placements||{}).filter(p=>!prev.placements?.[p]);
  const insertions=new Map(created.map(p=>[p,[]]));
  for(const [owner,list]of lanes(next)){
    const old=prevLanes.get(owner);
    const before=old?[...old].map(str):[];
    const after=[...list];
    if(old&&!subsequence(before,after.map(str)))found.add('CHILDREN_LIST_MUTATED');
    for(const v of inserted(before,after.map(str))){
      const raw=after.find(x=>str(x)===v);
      if(!A.isImmutableString(raw))found.add('INVALID_FIELD_TYPE');
      if(!insertions.has(v))found.add('PLACEMENT_NOT_ATOMIC');
      else insertions.get(v).push(owner);
    }
  }
  for(const p of created){
    const slot=next.placements[p],owners=insertions.get(p);
    const parent=str(slot.parent_id),node=str(slot.node_id);
    if(owners.length!==1||owners[0]!==parent)found.add('PLACEMENT_NOT_ATOMIC');
    if(!conflictValues(next.nodes?.[node],'placement').map(str).includes(p))found.add('PLACEMENT_NOT_ATOMIC');
  }
  // A5: no Text but a node's text, in any field, whether or not the profile
  // defines it (finding D3); a node's text is Text.
  const newText=(old,now,except)=>Object.keys(now||{}).some(key=>key!==except&&isText(now,key)&&(!old||oid(old,key)!==oid(now,key)));
  if(next.section&&newText(prev.section,next.section))found.add('INVALID_FIELD_TYPE');
  for(const p of created)if(newText(null,next.placements[p]))found.add('INVALID_FIELD_TYPE');
  for(const [n,now]of Object.entries(next.nodes||{})){
    const old=prev.nodes?.[n];
    if(newText(old,now,'text'))found.add('INVALID_FIELD_TYPE');
    if(TEXT_KINDS.has(str(now.kind))&&now.text!==undefined&&!oid(now,'text')&&(!old||str(old.text)!==str(now.text)||oid(old,'text')))found.add('INVALID_FIELD_TYPE');
  }
  // SOP §30: no Text anywhere in a Task, its nested maps and lists included.
  const before=new Set(),walk=(obj,out)=>{const stack=[obj];while(stack.length){const o=stack.pop();
    for(const key of Object.keys(o)){const v=o[key];if(isText(o,key))out.add(oid(o,key));else if(isObject(v))stack.push(v);}}};
  for(const t of Object.values(prev.objects||{}))if(t&&typeof t==='object')walk(t,before);
  const after=new Set();
  for(const t of Object.values(next.objects||{}))if(t&&typeof t==='object')walk(t,after);
  if([...after].some(x=>!before.has(x)))found.add('INVALID_FIELD_TYPE');
  return ADMISSION_ORDER.find(d=>found.has(d))||null;
}

/**
 * SHARED-OBJECTS-PROFILE-01's checks of the bytes alone, made when a change
 * arrives, before its dependencies are looked for (§14.1): §11, §11.1,
 * §11.3, then the actor (§8).
 */
function bytesRefusal(bytes,signer){
  // §11.1: the expansion limits, on the raw bytes, before anything is decoded.
  if(expansionRefusal(bytes)!==null)return 'INVALID_AUTOMERGE_BYTES';
  // §11: an uncompressed change chunk (type 1) whose checksum matches.
  if(bytes[8]!==1)return 'INVALID_AUTOMERGE_BYTES';
  // §11.3 rule 2: header numbers a JavaScript number holds exactly.
  if(beyondSafeNumbers(bytes))return 'INVALID_AUTOMERGE_BYTES';
  const d=A.decodeChange(bytes);
  if(Buffer.from(bytes.subarray(4,8)).toString('hex')!==d.hash.slice(0,8))return 'INVALID_AUTOMERGE_BYTES';
  // §11.3: the canonical encoding, up to the extra bytes (rule 4 allows
  // any). Re-encoding with Automerge is a way to check it for the changes
  // of this corpus, not the definition.
  const again=A.encodeChange(d),h=changeHeader(bytes),g=changeHeader(again);
  if(again.length-g.end!==0||!Buffer.from(again.subarray(g.bodyStart,g.end)).equals(Buffer.from(bytes.subarray(h.bodyStart,h.end))))return 'INVALID_AUTOMERGE_BYTES';
  // §8: the change is the signer's.
  if(signer!==undefined&&actor(signer)!==d.actor)return 'CHANGE_ACTOR_MISMATCH';
  return null;
}

/**
 * SHARED-OBJECTS-PROFILE-01's checks that read the causal history, once
 * every dependency is present (§11.2, §11.4, §14.1).
 */
function sopRefusal(history,bytes){
  // `history`: the decoded changes of the causal history.
  const d=A.decodeChange(bytes);
  // §14.1: the actor's next sequence number.
  const own=history.filter(c=>c.actor===d.actor);
  const latest=own.reduce((m,c)=>Math.max(m,c.seq),0);
  if(d.seq!==latest+1)return 'INVALID_AUTOMERGE_BYTES';
  // §14.1: an author only in the actor's first change (automerge 0.12
  // aborts on one in a later change, finding D5).
  if(d.seq!==1&&hasAuthor(bytes))return 'INVALID_AUTOMERGE_BYTES';
  // §11.2: no object deeper than 256 below the root.
  const depth=new Map([['_root',0]]);
  for(const c of [...history,d]){
    // The objects a change creates, cached on its decoded form.
    c.made??=c.ops.flatMap((op,i)=>MAKE.has(op.action)?[[(c.startOp+i)+'@'+c.actor,op.obj]]:[]);
    for(const [id,obj]of c.made)depth.set(id,(depth.get(obj)??0)+1);
  }
  for(const v of depth.values())if(v>256)return 'INVALID_AUTOMERGE_BYTES';
  // §11.4: operations refer only to the change's causal history.
  if(referenceRule(history,d))return 'INVALID_AUTOMERGE_BYTES';
  return null;
}

/**
 * The §11.4 rule (R1-R7) the decoded change `d` breaks against its decoded
 * causal history, or null.
 */
export function referenceRule(history,d){
  // R1: the actor's previous change is in the history.
  if(d.seq>1&&!history.some(c=>c.actor===d.actor&&c.seq===d.seq-1))return 'R1';
  // R2: the start op follows the history's largest counter.
  const top=history.reduce((m,c)=>Math.max(m,c.startOp+c.ops.length-1),0);
  if(d.startOp!==top+1)return 'R2';
  // An operation of the history (or earlier in the change), found by its
  // actor's changes and their counter ranges; deletions are not targets.
  const byActor=new Map();
  for(const c of history){if(!byActor.has(c.actor))byActor.set(c.actor,[]);byActor.get(c.actor).push(c);}
  const slotOf=(op,id)=>op.insert?id:op.elemId??op.key;
  let upTo=d.startOp;
  const target=id=>{
    const at=id.indexOf('@'),ctr=Number(id.slice(0,at)),who=id.slice(at+1);
    const c=who===d.actor&&ctr>=d.startOp&&ctr<upTo?d:(byActor.get(who)||[]).find(x=>ctr>=x.startOp&&ctr<x.startOp+x.ops.length);
    const op=c?.ops[ctr-c.startOp];
    if(op===undefined||op.action==='del')return undefined;
    return {obj:op.obj,slot:slotOf(op,id),insert:!!op.insert,make:MAKE.has(op.action)?op.action:null,action:op.action,datatype:op.datatype};
  };
  const MAPS=new Set(['makeMap','makeTable']);
  for(const [i,op]of d.ops.entries()){
    const id=`${d.startOp+i}@${d.actor}`;
    // R3: a made object, with the key form of its type.
    const made=op.obj==='_root'?null:target(op.obj)?.make;
    const sequence=op.obj==='_root'?false:made?!MAPS.has(made):undefined;
    if(sequence===undefined)return 'R3';
    if(!sequence&&(op.insert||op.key===undefined))return op.insert?'R4':'R3';
    if(sequence&&op.key!==undefined)return 'R3';
    const element=e=>{const t=target(e);return t!==undefined&&t.insert&&t.obj===op.obj;};
    // R4: insertions after the head or an element of the same object.
    if(op.insert&&(op.pred.length>0||(op.elemId!=='_head'&&!element(op.elemId))))return 'R4';
    // R5: other sequence operations name an element of the same object.
    if(sequence&&!op.insert&&(op.elemId==='_head'||!element(op.elemId)))return 'R5';
    // R6: predecessors on the same object and key.
    const slot=slotOf(op,id);
    for(const p of op.pred){const t=target(p);if(t===undefined||t.obj!==op.obj||t.slot!==slot)return 'R6';}
    // R7: a deletion has a predecessor.
    if(op.action==='del'&&op.pred.length===0)return 'R7';
    // R8: an increment names the puts of a counter value it adds to.
    if(op.action==='inc'&&(op.pred.length===0||op.pred.some(p=>{const t=target(p);return t?.action!=='set'||t.datatype!=='counter';})))return 'R8';
    // R9: no marks.
    if(/^mark/.test(op.action))return 'R9';
    // R10: no tables.
    if(op.action==='makeTable')return 'R10';
    upTo=d.startOp+i+1;
  }
  return null;
}

/**
 * Replays `changes` (dependencies first) through admission: each change is
 * checked against the admitted changes of its causal history. Returns the
 * admitted document, the refused changes with their diagnostic, and the
 * changes held because a dependency was refused or held.
 */
/**
 * A change's hash and dependencies. A change above an expansion limit
 * (§11.1) is read from its header only: decoding it is what the limits
 * prevent. Any other change, including a malformed one, is decoded.
 */
export function changeInfo(b){
  if(fromHeader(b)){const h=changeHeader(b);return {hash:h.hash,deps:h.deps,actor:h.actor,seq:h.seq};}
  const d=A.decodeChange(b);
  return {hash:d.hash,deps:d.deps,actor:d.actor,seq:d.seq,decoded:d};
}
/** A change read from its header only: above a §11.1 limit, or with header numbers Automerge JS does not decode (§11.3 rule 2). */
const fromHeader=b=>isExpansionBomb(b)||beyondSafeNumbers(b);
/** A type 1 change chunk whose header reads, above a §11.1 limit. */
const bombs=new WeakMap();
export function isExpansionBomb(b){
  if(!bombs.has(b)){const r=expansionRefusal(b);bombs.set(b,r!==null&&b[8]===1&&!r.startsWith('malformed'));}
  return bombs.get(b);
}

export function admitReplay(changes,initActor){
  // An entry is the change bytes, or {bytes, signer} for a Data Unit whose
  // signer the corpus names.
  const byHash=new Map(),order=[],signers=new Map();
  for(const item of changes){
    const b=item instanceof Uint8Array?item:item.bytes;
    const h=changeInfo(b).hash;
    if(!byHash.has(h)){byHash.set(h,b);order.push(h);if(item.signer!==undefined)signers.set(h,item.signer);}
  }
  const decoded=new Map();
  const decode=h=>{if(!decoded.has(h))decoded.set(h,A.decodeChange(byHash.get(h)));return decoded.get(h);};
  const deps=h=>fromHeader(byHash.get(h))?changeHeader(byHash.get(h)).deps:decode(h).deps;
  // `refusedKeys`: the replay's keys of refused changes; `refused` reports
  // them by name, without one for bytes that are not named (§14.1).
  const admitted=new Set(),refused=[],refusedKeys=new Set(),held=new Set();
  // Causal order: a change after its dependencies, whatever the input order.
  const placed=new Set(),sorted=[];
  const visit=h=>{if(placed.has(h)||!byHash.has(h))return;placed.add(h);for(const d of deps(h))visit(d);sorted.push(h);};
  for(const h of order)visit(h);
  // The document of the admitted changes so far: the causal history of a
  // change whose history is exactly those changes, as in a linear run.
  let running=A.init({actor:initActor});
  const refuse=(h,diagnostic)=>{
    refusedKeys.add(h);
    const name=refusalName(byHash.get(h));
    refused.push(name===null?{diagnostic}:{change:name,diagnostic});
  };
  for(const h of sorted){
    // §14.1: what the bytes alone decide, when the change arrives, whether
    // or not its dependencies are present.
    const early=bytesRefusal(byHash.get(h),signers.get(h));
    if(early){refuse(h,early);continue;}
    if(deps(h).some(d=>held.has(d)||refusedKeys.has(d)||!byHash.has(d))){held.add(h);continue;}
    const past=new Set();const collect=x=>{if(past.has(x))return;past.add(x);for(const d of deps(x))collect(d);};
    for(const d of deps(h))collect(d);
    const linear=past.size===admitted.size&&[...past].every(x=>admitted.has(x));
    const prev=linear?running:A.applyChanges(A.init({actor:initActor}),sorted.filter(x=>past.has(x)).map(x=>byHash.get(x)))[0];
    const history=sorted.filter(x=>past.has(x)).map(decode);
    const diagnostic=sopRefusal(history,byHash.get(h))??admit(prev,byHash.get(h));
    if(diagnostic)refuse(h,diagnostic);
    else{admitted.add(h);running=A.applyChanges(running,[byHash.get(h)])[0];}
  }
  return {doc:running,refused,held:[...held].sort()};
}
