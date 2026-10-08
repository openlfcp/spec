// Reference corpus model, not the production LFCP SDK.
import * as A from '@automerge/automerge';
import { createHash } from 'node:crypto';
export { A };
export const PROFILE = 'org.openlfcp.shared-sections.v1';
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const resource = createHash('sha256').update('LFCP-SS-01/resource').digest();
export const principal = name => createHash('sha256').update('LFCP-SS-01/principal/' + name).digest();
export const actor = name => hash(Buffer.concat([Buffer.from('OPENLFCP-SHARED-SECTIONS-ACTOR-v1'), resource, principal(name)]));
export const pref = name => 'p:' + principal(name).toString('base64url');
export function uid(label) {
  const b = createHash('sha256').update('LFCP-SS-01/id/' + label).digest().subarray(0,16);
  b[6] = (b[6] & 15) | 0x70; b[8] = (b[8] & 63) | 0x80;
  const h=b.toString('hex');
  return [h.slice(0,8),h.slice(8,12),h.slice(12,16),h.slice(16,20),h.slice(20)].join('-');
}
export const ids=Object.fromEntries(['section','task','para','x','y','a','b','extra'].map(x=>[x,uid(x)]));
export const S = value => new A.ImmutableString(value);
export const str = value => value === undefined ? undefined : String(value);
export function plain(value) {
  if (A.isImmutableString(value)) return String(value);
  if (Array.isArray(value)) return value.map(plain);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k=>[k,plain(value[k])]));
  return value;
}
export const canon = value => JSON.stringify(plain(value));
export const fork = (doc,name) => A.clone(doc,{actor:actor(name)});
export const change = (doc,label,fn) => A.change(doc,{time:0,message:label},fn);
export const values = (obj,key) => {
  if(obj==null)return [];
  const c=A.getConflicts(obj,key);
  return c ? Object.values(c).map(str).sort() : obj[key] === undefined ? [] : [str(obj[key])];
};
export const lane = (d,p) => p===ids.section ? d.section.children : d.nodes[p].children;
export function place(d,n,p,after,label,author='A') {
  const pid=uid(label);
  const l=lane(d,p);
  const at=after ? l.findIndex(x=>str(x)===str(d.nodes[after].placement))+1 : 0;
  if(after && at===0) throw new Error('predecessor not in target lane');
  d.placements[pid]={id:S(pid),node_id:S(n),parent_id:S(p),created_by:S(pref(author))};
  l.splice(at,0,S(pid));
  d.nodes[n].placement=S(pid);
}
export function add(d,n,kind,p,after,label,text='',author='A') {
  if(d.nodes[n]) throw new Error('duplicate node');
  const node={id:S(n),kind:S(kind),created_by:S(pref(author)),lifecycle:S('active'),placement:S(uid(label)),children:[],extensions:{}};
  if(kind==='task') {
    node.task_id=S(n); node.list_style=S('bullet');
    d.objects[n]={id:S(n),type:S('task'),created_by:S(pref(author)),lifecycle:S('active'),
      title:S(text),status:S('todo'),priority:S('normal'),tags:{},assignees:{},extensions:{}};
  } else {
    node.text=text;
    if(kind==='item') node.list_style=S('bullet');
  }
  d.nodes[n]=node;
  place(d,n,p,after,label,author);
}
export function setLife(d,n,value) {
  const o=str(d.nodes[n].kind)==='task' ? d.objects[n] : d.nodes[n];
  // Force a fresh semantic write even if the binding would suppress a same-value set.
  if(str(o.lifecycle)===value) o.lifecycle=S(value==='active'?'deleted':'active');
  o.lifecycle=S(value);
}
export function textEdit(d,n,scalarIndex,removeScalars,insert) {
  const t=d.nodes[n].text;
  const chars=Array.from(t);
  const start=chars.slice(0,scalarIndex).join('').length;
  const count=chars.slice(scalarIndex,scalarIndex+removeScalars).join('').length;
  A.splice(d,['nodes',n,'text'],start,count,insert);
}
/** The creator's first change: the root and an empty section, not yet ready (§12.1). */
export function genesis() {
  return change(A.init({actor:actor('A')}),'genesis-profile',x=>{
    x.profile=S(PROFILE);
    x.section={id:S(ids.section),title:S('Joint launch'),created_by:S(pref('A')),children:[],extensions:{}};
    x.objects={};x.nodes={};x.placements={};x.extensions={};
  });
}
export function initial() {
  const d=genesis();
  // The creator's last initialization change writes the readiness marker (§12.1).
  return change(d,'initial-content',x=>{
    x.section.ready=true;
    add(x,ids.task,'task',ids.section,null,'slot-task','Prepare contract');
    add(x,ids.para,'paragraph',ids.task,null,'slot-para','Draft contract');
    add(x,ids.x,'item',ids.section,ids.task,'slot-x','Group X');
    add(x,ids.y,'item',ids.section,ids.x,'slot-y','Group Y');
  });
}
const subsequence=(before,after)=>{let i=0;for(const x of after)if(x===before[i])i++;return i===before.length;};
export function historyAudit(doc) {
  let prev=A.init({actor:actor('audit')});
  const errors=[],events=[],deps={};
  for(const bytes of A.getAllChanges(doc)) {
    const ch=A.decodeChange(bytes);deps[ch.hash]=ch.deps;
    const [next]=A.applyChanges(prev,[bytes]);
    if(prev.section && next.section) {
      for(const key of ['section','objects','nodes','placements','extensions'])
        if(A.getObjectId(prev,key)!==A.getObjectId(next,key)) errors.push('root-object-replaced:'+key);
      if(str(prev.profile)!==str(next.profile))errors.push('profile-changed');
      for(const key of ['id','created_by'])if(str(prev.section[key])!==str(next.section[key]))errors.push('section-immutable:'+key);
    }
    for(const n of Object.keys(next.nodes||{})) {
      const old=prev.nodes?.[n], now=next.nodes[n];
      if(old) {
        for(const key of ['id','kind','created_by','task_id'])if(str(old[key])!==str(now[key]))errors.push('node-immutable:'+n+':'+key);
        if(A.getObjectId(prev.nodes,n)!==A.getObjectId(next.nodes,n))errors.push('node-map-replaced:'+n);
        if(old.text!==undefined && A.getObjectId(old,'text')!==A.getObjectId(now,'text'))errors.push('text-object-replaced:'+n);
      }
      const oldEntity=old ? (str(old.kind)==='task'?prev.objects[n]:old) : undefined;
      const entity=str(now.kind)==='task'?next.objects[n]:now;
      if(entity && str(entity.lifecycle)==='deleted' && (!oldEntity||str(oldEntity.lifecycle)!=='deleted'))
        events.push({hash:ch.hash,node:n,type:'delete'});
      if(!old || (str(now.kind)==='task' ? str(prev.objects[n]?.title)!==str(next.objects[n]?.title) || str(prev.objects[n]?.status)!==str(next.objects[n]?.status) : old.text!==now.text))
        events.push({hash:ch.hash,node:n,type:'content'});
    }
    for(const p of Object.keys(prev.placements||{}))
      if(!next.placements?.[p] || canon(prev.placements[p])!==canon(next.placements[p]))errors.push('placement-immutable:'+p);
    if(prev.section && next.section) {
      const parents=[ids.section,...Object.keys(prev.nodes||{})];
      for(const p of parents) {
        if(p!==ids.section && !next.nodes[p]){errors.push('node-removed:'+p);continue;}
        const before=lane(prev,p), after=lane(next,p);
        if(A.getObjectId(before)!==A.getObjectId(after) || !subsequence(before.map(str),after.map(str)))
          errors.push('lane-not-insert-only:'+p);
      }
    }
    prev=next;
  }
  return {errors:[...new Set(errors)].sort(),events,deps};
}
export function inspect(doc) {
  // Structural violations are refused at admission (admission.mjs, §14.1);
  // what remains invalid here is isolated per node and subtree (§14.2).
  const audit=historyAudit(doc);
  const errors=[], invalid=new Map(), blocked=new Map(), parents={}, hidden=new Set(), nodes=doc.nodes||{};
  // §12.1: a section without ready is being imported and projects nothing.
  const importing=!!doc.section&&doc.section.ready!==true;
  if(str(doc.profile)!==PROFILE)errors.push('INVALID_ROOT');
  for(const key of ['section','objects','nodes','placements','extensions'])if(!doc[key]||typeof doc[key]!=='object')errors.push('INVALID_ROOT');
  if(doc.section&&!Array.isArray(doc.section.children))errors.push('INVALID_ROOT');
  const life=n=>str(nodes[n].kind)==='task'?doc.objects[n]:nodes[n];
  const fail=(n,diagnostic)=>{if(!invalid.has(n))invalid.set(n,diagnostic);};
  for(const n of Object.keys(nodes).sort()) {
    const o=nodes[n],kind=str(o.kind);
    if(!['task','paragraph','item','raw'].includes(kind)){fail(n,'INVALID_ENUM_VALUE');continue;}
    if(kind==='task' && (str(o.task_id)!==n || !doc.objects[n]))fail(n,'INVALID_REFERENCE');
    if(kind!=='task' && (!A.getObjectId(o,'text') || A.isImmutableString(o.text)))fail(n,'INVALID_FIELD_TYPE');
    if(!A.isImmutableString(o.placement))fail(n,'INVALID_FIELD_TYPE');
    if(values(o,'placement').length>1)blocked.set(n,'PLACEMENT_CONFLICT');
    const s=doc.placements?.[str(o.placement)];
    if(!s||str(s.node_id)!==n){if(!blocked.has(n))fail(n,'INVALID_REFERENCE');continue;}
    parents[n]=str(s.parent_id);
    if(parents[n]!==ids.section && (!nodes[parents[n]]||['paragraph','raw'].includes(str(nodes[parents[n]].kind))))fail(n,'INVALID_REFERENCE');
    if(values(life(n),'lifecycle').length>1)blocked.set(n,'LIFECYCLE_CONFLICT');
  }
  for(const n of invalid.keys())blocked.delete(n);
  // Detect all cycle members, independently of traversal order.
  for(const start of Object.keys(nodes).sort()) {
    const path=[],seen=new Map();let n=start;
    while(n!==ids.section && nodes[n] && !blocked.has(n)) {
      if(seen.has(n)){for(const c of path.slice(seen.get(n)))blocked.set(c,'PARENT_CYCLE');break;}
      seen.set(n,path.length);path.push(n);n=parents[n];
    }
  }
  const out=n=>blocked.has(n)||invalid.has(n);
  let again=true;
  while(again){again=false;for(const n of Object.keys(nodes))if(!out(n)&&out(parents[n])){blocked.set(n,'BLOCKED_PARENT');again=true;}}
  for(const n of Object.keys(nodes)) {
    let p=n;const seen=new Set();
    while(p!==ids.section && nodes[p]&&!seen.has(p)) {
      seen.add(p);if(str(life(p)?.lifecycle)==='deleted'){hidden.add(n);break;}p=parents[p];
    }
  }
  const isAncestor=(a,b,seen=new Set())=>{
    if(a===b)return true;if(seen.has(b))return false;seen.add(b);
    return (audit.deps[b]||[]).some(p=>isAncestor(a,p,seen));
  };
  const attention=new Set();
  for(const ev of audit.events.filter(e=>e.type==='content'&&hidden.has(e.node))) {
    let p=ev.node;const seen=new Set();
    while(p!==ids.section && nodes[p]&&!seen.has(p)) {
      seen.add(p);
      for(const del of audit.events.filter(e=>e.type==='delete'&&e.node===p))
        if(!isAncestor(del.hash,ev.hash)&&!isAncestor(ev.hash,del.hash)) attention.add(ev.node);
      p=parents[p];
    }
  }
  const tree=[];
  function walk(p,depth){
    if(depth>Object.keys(nodes).length)throw new Error('oracle recursion bound');
    for(const raw of lane(doc,p)) {
      const s=str(raw),slot=doc.placements[s],n=slot&&str(slot.node_id);
      if(!n||!nodes[n]||out(n)||hidden.has(n)||str(nodes[n].placement)!==s)continue;
      tree.push({id:n,parent:p,depth,kind:str(nodes[n].kind)});walk(n,depth+1);
    }
  }
  if(!errors.length&&!importing)walk(ids.section,0);
  const scalarConflicts=[];
  for(const [n,obj] of Object.entries(doc.objects||{}))for(const field of ['title','status','lifecycle','due','priority']){
    const v=values(obj,field);if(v.length>1)scalarConflicts.push({id:n,field,values:v});
  }
  return {
    classification:errors.length?'PROFILE_INVALID':importing?'IMPORTING':blocked.size||invalid.size?'STRUCTURAL_ATTENTION':'VALID',
    errors:[...new Set(errors)].sort(),tree,hidden:[...hidden].sort(),
    invalid:[...invalid].sort(([a],[b])=>a.localeCompare(b)).map(([id,diagnostic])=>({id,diagnostic})),
    recovery:[...blocked].sort(([a],[b])=>a.localeCompare(b)).map(([id,code])=>({id,code})),
    retainedConcurrentEdits:[...attention].sort(),scalarConflicts,
    texts:Object.fromEntries(Object.keys(nodes).sort().filter(n=>nodes[n].text!==undefined).map(n=>[n,str(nodes[n].text)])),
    tasks:Object.fromEntries(Object.keys(doc.objects||{}).sort().map(n=>[n,plain(doc.objects[n])])),
    slotCount:Object.keys(doc.placements||{}).length,
    nodeCount:Object.keys(nodes).length,
    types:{taskTitleScalar:!doc.objects?.[ids.task]||A.isImmutableString(doc.objects[ids.task].title),paragraphText:!nodes[ids.para]||!!A.getObjectId(nodes[ids.para],'text')}
  };
}
export function assertExpected(actual, requirements, assert) {
  const present=actual.tree.map(x=>x.id);
  for(const n of requirements.visible||[])assert(present.includes(n),'not visible: '+n);
  for(const n of requirements.absent||[])assert(!present.includes(n),'unexpected visible: '+n);
  for(const n of requirements.hidden||[])assert(actual.hidden.includes(n),'not retained hidden: '+n);
  for(const [n,code] of Object.entries(requirements.recovery||{}))assert(actual.recovery.some(x=>x.id===n&&x.code===code),'missing recovery '+code);
  for(const [n,d] of Object.entries(requirements.invalid||{}))assert(actual.invalid.some(x=>x.id===n&&x.diagnostic===d),'missing invalid '+n+' '+d);
  for(const d of requirements.refused||[])assert(actual.refused?.some(x=>x.diagnostic===d),'missing refusal '+d);
  if(requirements.heldCount!==undefined)assert.equal(actual.held?.length,requirements.heldCount);
  for(const [n,t] of Object.entries(requirements.texts||{}))assert.equal(actual.texts[n],t);
  for(const [n,fields] of Object.entries(requirements.tasks||{}))for(const [k,v] of Object.entries(fields))assert.deepEqual(actual.tasks[n][k],v);
  for(const n of requirements.retainedConcurrentEdits||[])assert(actual.retainedConcurrentEdits.includes(n));
  if(requirements.classification)assert.equal(actual.classification,requirements.classification);
  if(requirements.slotCount!==undefined)assert.equal(actual.slotCount,requirements.slotCount);
  if(requirements.nodeCount!==undefined)assert.equal(actual.nodeCount,requirements.nodeCount);
  if(requirements.treeCount!==undefined)assert.equal(actual.tree.length,requirements.treeCount);
  if(requirements.scalarConflict)assert(actual.scalarConflicts.some(x=>x.id===requirements.scalarConflict.id&&x.field===requirements.scalarConflict.field));
}
