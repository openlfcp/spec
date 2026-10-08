// Reference admission for SHARED-SECTIONS-PROFILE-01 §14.1 (ADR 0009, P2):
// the structural rules A1-A5 and the readiness rule of §12.1, decided for
// one change against the state of its causal history. Reference test
// support, not a production validator: it compares the state before and
// after the change rather than walking the change's operations, which
// decides the same rules for the changes of this corpus.
import {A,PROFILE,actor,pref,str,canon} from './section-model.mjs';

/** Diagnostics in their order of precedence (§14.1). */
export const ADMISSION_ORDER=['INVALID_AUTOMERGE_BYTES','CONTAINER_REPLACED','CHILDREN_LIST_MUTATED','PLACEMENT_NOT_ATOMIC','IMMUTABLE_FIELD_MUTATED','INVALID_FIELD_TYPE'];
const ROOT_CONTAINERS=['section','objects','nodes','placements','extensions'];
const TEXT_KINDS=new Set(['paragraph','item','raw']);
const NODE_IMMUTABLE=['id','kind','created_by','task_id'];
const NODE_SCALARS=['id','kind','created_by','lifecycle','placement','task_id','list_style'];
const TASK_IMMUTABLE=['id','type','created_by'];
const TASK_SCALARS=['id','type','created_by','lifecycle','title','status','priority','due','scheduled','completion_date','created_at'];
const NAMES=['A','B','C'];

const oid=(obj,key)=>obj==null?null:A.getObjectId(obj,key);
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
  // A5: scalars stay scalar, node text is Text.
  for(const [n,now]of Object.entries(next.nodes||{})){
    const old=prev.nodes?.[n];
    for(const key of NODE_SCALARS)if(isText(now,key)&&(!old||oid(old,key)!==oid(now,key)))found.add('INVALID_FIELD_TYPE');
    if(TEXT_KINDS.has(str(now.kind))&&now.text!==undefined&&!oid(now,'text')&&(!old||str(old.text)!==str(now.text)||oid(old,'text')))found.add('INVALID_FIELD_TYPE');
  }
  for(const [id,now]of Object.entries(next.objects||{})){
    const old=prev.objects?.[id];
    for(const key of TASK_SCALARS)if(isText(now,key)&&(!old||oid(old,key)!==oid(now,key)))found.add('INVALID_FIELD_TYPE');
  }
  return ADMISSION_ORDER.find(d=>found.has(d))||null;
}

/**
 * Replays `changes` (dependencies first) through admission: each change is
 * checked against the admitted changes of its causal history. Returns the
 * admitted document, the refused changes with their diagnostic, and the
 * changes held because a dependency was refused or held.
 */
export function admitReplay(changes,initActor){
  const byHash=new Map(),order=[];
  for(const b of changes){const h=A.decodeChange(b).hash;if(!byHash.has(h)){byHash.set(h,b);order.push(h);}}
  const deps=h=>A.decodeChange(byHash.get(h)).deps;
  const admitted=new Set(),refused=[],held=new Set();
  // Causal order: a change after its dependencies, whatever the input order.
  const placed=new Set(),sorted=[];
  const visit=h=>{if(placed.has(h)||!byHash.has(h))return;placed.add(h);for(const d of deps(h))visit(d);sorted.push(h);};
  for(const h of order)visit(h);
  for(const h of sorted){
    if(deps(h).some(d=>held.has(d)||refused.some(r=>r.change===d)||!byHash.has(d))){held.add(h);continue;}
    const past=new Set();const collect=x=>{if(past.has(x))return;past.add(x);for(const d of deps(x))collect(d);};
    for(const d of deps(h))collect(d);
    const [prev]=A.applyChanges(A.init({actor:initActor}),sorted.filter(x=>past.has(x)).map(x=>byHash.get(x)));
    const diagnostic=admit(prev,byHash.get(h));
    if(diagnostic)refused.push({change:h,diagnostic});else admitted.add(h);
  }
  const [doc]=A.applyChanges(A.init({actor:initActor}),sorted.filter(h=>admitted.has(h)).map(h=>byHash.get(h)));
  return {doc,refused,held:[...held].sort()};
}
