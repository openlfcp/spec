// MARKDOWN-SECTIONS-FIXTURES-01: golden before/observed/after files for
// MARKDOWN-SECTIONS-01 (LFCP-02-010). Rewritten from the MVP 0.2 planning
// fixtures for the grammar decisions M1-M7: the start marker follows the
// heading, Task refs inside sections are child-line, unsupported blocks are
// raw nodes, comments follow the sender's setting, an inline ref tolerates a
// Tasks suffix. Identities MS01-MS26 are kept; MS27-MS44 are added.
import fs from 'node:fs';
import path from 'node:path';
import {resource,ids,uid,hash} from './section-model.mjs';
const out=process.argv[2]||path.dirname(path.dirname(new URL(import.meta.url).pathname));
fs.mkdirSync(out,{recursive:true});
const R=resource.toString('base64url'), S=ids.section;
const start='<!-- lfcp-section: lfcp1:'+R+'#section:'+S+' -->';
const end='<!-- /lfcp-section: lfcp1:'+R+'#section:'+S+' -->';
const ref=id=>'<!-- lfcp-ref: lfcp1:'+R+'#task:'+id+' -->';
const node=(kind,id)=>'<!-- lfcp-node: '+kind+':'+id+' -->';
const privateBefore='PRIVATE_BEFORE_8f3a: budget and personal thoughts.';
const privateAfter='PRIVATE_AFTER_71c2: do not transmit.';
const task='- [ ] Prepare contract\n  '+ref(ids.task);
const paragraph='  '+node('paragraph',ids.para)+'\n  Draft contract';
const item='  - Check details\n    '+node('item',ids.x);
const body=task+'\n'+paragraph+'\n\n'+item;
// M4: the heading, then the start marker on the next line.
const section=(content=body,title='Joint launch')=>'## '+title+'\n'+start+'\n'+content+'\n'+end+'\n';
const note=(content=body)=>privateBefore+'\n\n'+section(content)+'\n'+privateAfter+'\n';
const base=note(), fixtures=[];
function add(id,title,{before=base,observed,after,kind='scan',intents=[],diagnostics=[],publication='none',
  baseStatus='trusted',checks={},extra={},execution='lexical-and-contract-only',rationale}={}){
  const beforeFiles=typeof before==='string'?{'note.md':before}:before;
  const observedFiles=observed===undefined?beforeFiles:typeof observed==='string'?{'note.md':observed}:observed;
  const afterFiles=after===undefined?observedFiles:typeof after==='string'?{'note.md':after}:after;
  fixtures.push({id,title,execution,projection_base:baseStatus,...(rationale?{rationale}:{}),before_files:beforeFiles,
    event:{kind,observed_files:observedFiles,...extra},
    expected:{after_files:afterFiles,diagnostics,publication,intents,...checks},
    files_sha256:Object.fromEntries(Object.entries({before:beforeFiles,observed:observedFiles,after:afterFiles})
      .map(([stage,files])=>[stage,Object.fromEntries(Object.entries(files).map(([f,t])=>[f,hash(Buffer.from(t))]))]))});
}
add('MS01','Complete section with Task, paragraph and child item',{checks:{lexical:{sections:1,task_refs:1,node_refs:2},private_canaries:[privateBefore,privateAfter]}});
const both=privateBefore+'\n\n'+section(task)+'\n'+section('- [ ] Prepare contract '+ref(ids.task))+'\n'+privateAfter+'\n';
add('MS02','Remote completion preserves both ref placements',{before:both,kind:'remote_complete',after:both.replaceAll('- [ ] Prepare contract','- [x] Prepare contract'),
  checks:{lexical:{sections:2,task_refs:2,node_refs:0},private_canaries:[privateBefore,privateAfter]},extra:{task_id:ids.task},execution:'golden-operation-smoke'});
const rawNew=base.replace('\n'+end,'\n- [ ] New task\n'+end);
add('MS03','New unbound Task inside section gets an identity',{kind:'local_insert',observed:rawNew,
  after:rawNew.replace('- [ ] New task\n','- [ ] New task\n  '+ref(ids.extra)+'\n'),
  publication:'semantic',intents:[{type:'task.create_in_section',id:ids.extra,parent_id:S,title:'New task'}],
  extra:{allocated_ids:[ids.extra]},checks:{lexical:{sections:1,task_refs:2,node_refs:2}}});
const outside=base+'\n- [ ] New private task\n';
add('MS04','Unbound Task outside section stays local',{kind:'local_insert',observed:outside,checks:{lexical:{sections:1,task_refs:1,node_refs:2}}});
add('MS05','Missing end marker never captures following private content',{kind:'source_edit',observed:base.replace(end,''),
  publication:'suspended',diagnostics:['SECTION_BOUNDARY_MISSING'],checks:{lexical:{sections:0},private_canaries:[privateBefore,privateAfter]}});
const fenced='Example only:\n\n```markdown\n'+section()+'```\n';
add('MS06','Fenced example is not a live section',{before:fenced,checks:{lexical:{sections:0,task_refs:0,node_refs:0}}});
add('MS07','Copy complete section creates another projection',{before:{'source.md':base},observed:{'source.md':base,'destination.md':'Private destination\n\n'+section()},
  kind:'copy_complete_section',checks:{lexical:{sections:2,task_refs:2,node_refs:4},same_shared_identity:true}});
const duplicate=base.replace('\n'+end,'\n'+task+'\n'+end);
add('MS08','Duplicate Task ID inside one projection blocks publication',{kind:'source_edit',observed:duplicate,
  publication:'suspended',diagnostics:['NODE_BINDING_DUPLICATE'],checks:{lexical:{sections:1,task_refs:2,node_refs:2}}});
add('MS09','Heading title/level change preserves section identity',{kind:'source_edit',observed:base.replace('## Joint launch','### Launch revised'),
  publication:'semantic',intents:[{type:'section.set_title',id:S,title:'Launch revised'}],checks:{lexical:{sections:1},same_shared_identity:true}});
add('MS10-delete','Delete child paragraph is a shared lifecycle intent',{kind:'source_edit',observed:base.replace(paragraph+'\n',''),
  publication:'semantic',intents:[{type:'node.delete',id:ids.para}],checks:{lexical:{sections:1,task_refs:1,node_refs:1}}});
const plain=base.split('\n').filter(l=>!l.includes('<!-- lfcp-')&&!l.includes('<!-- /lfcp-')).join('\n');
add('MS10-detach','Detach keeps readable text without shared deletion',{kind:'detach_section',after:plain,
  checks:{lexical:{sections:0,task_refs:0,node_refs:0},private_canaries:[privateBefore,privateAfter]},execution:'golden-operation-smoke'});
add('MS11','Index rebuild does not infer edits without a causal base',{kind:'rebuild_index',observed:base.replace('Draft contract','Unbased local edit'),
  baseStatus:'unknown',publication:'suspended',diagnostics:['PROJECTION_BASE_UNKNOWN'],checks:{lexical:{sections:1}}});
const crlf=base.replace('Prepare contract','Договор 😀').replaceAll('\n','\r\n');
add('MS12','CRLF and Unicode survive a remote completion',{before:crlf,kind:'remote_complete',after:crlf.replace('- [ ] Договор 😀','- [x] Договор 😀'),
  extra:{task_id:ids.task},checks:{lexical:{sections:1},line_endings:'CRLF',private_canaries:[privateBefore,privateAfter]},execution:'golden-operation-smoke'});
const ordered='1. [ ] Contract\n   '+ref(ids.task)+'\n   '+node('paragraph',ids.para)+'\n   Details.\n\n   1. Check details\n      '+node('item',ids.x);
add('MS13','Ordered Task and nested ordinary item indentation',{before:note(ordered),checks:{lexical:{sections:1,task_refs:1,node_refs:2}},extra:{requires_ast_assertions:{task_content_indent:3,item_content_indent:6}}});
add('MS14','Remote structural conflict retains last safe source',{kind:'remote_structure_conflict',extra:{model_diagnostics:['PARENT_CYCLE']},
  publication:'suspended',diagnostics:['PARENT_CYCLE'],checks:{lexical:{sections:1},source_rewrite_allowed:false}});
add('MS15','Rendered clipboard excludes UI decorations',{kind:'copy_rendered',execution:'editor-integration-contract',
  checks:{lexical:{sections:1},clipboard:{plain_text:'Prepare contract',forbidden_fragments:['<svg','data-lfcp-ui','Changes accepted by server','Shared with'],rich_text_must_exclude_decorations:true}},
  extra:{selection:'task-title-only',rendered_decorations:['double-check SVG','sync tooltip','participant popover']}});
const fence='```js\nconsole.log("shared")\n```';
const typedFence=base.replace('\n'+end,'\n'+fence+'\n'+end);
add('MS16','A fence typed inside the region becomes a raw node',{kind:'local_insert',observed:typedFence,
  after:typedFence.replace(fence,node('raw',ids.extra)+'\n'+fence),
  publication:'semantic',intents:[{type:'raw.create',id:ids.extra,parent_id:S,text:fence}],extra:{allocated_ids:[ids.extra]},
  checks:{lexical:{sections:1,task_refs:1,node_refs:3},payload_contains:['console.log("shared")']},
  rationale:'Decision M6 (MARKDOWN-SECTIONS-01 §4.4): unsupported blocks are carried as raw nodes instead of suspending the section. The planning fixture expected SECTION_UNSUPPORTED_SYNTAX and a suspension.'});
add('MS17-empty','Empty paragraph retains its binding',{before:note(task+'\n  '+node('paragraph',ids.para)+'\n\n'),checks:{lexical:{sections:1,task_refs:1,node_refs:1}}});
add('MS17-transient','Transient damaged Task syntax is not a new object',{kind:'source_edit',observed:base.replace('- [ ] Prepare contract','- [ Prepare contract'),
  publication:'suspended',diagnostics:['NODE_BINDING_LOST'],checks:{lexical:{sections:1}},extra:{prior_bound_task:ids.task}});
add('MS17-undo','Undo completion makes a compensating semantic edit',{before:base.replace('- [ ] Prepare contract','- [x] Prepare contract'),
  observed:base,kind:'undo_completion',publication:'semantic',intents:[{type:'task.reopen',id:ids.task}],
  extra:{earlier_change_already_acknowledged:true},checks:{lexical:{sections:1},retract_history:false}});
add('MS18','Ambiguous external cut and paste preserves content for repair',{
  before:{'source.md':base,'destination.md':'Private destination\n'},
  observed:{'source.md':base.replace(task+'\n',''),'destination.md':'Private destination\n'+task+'\n'},
  kind:'external_cut_paste',publication:'suspended',diagnostics:['NODE_BINDING_LOST'],
  checks:{lexical:{sections:1},physical_shared_deletion:false},extra:{transaction_mapping_available:false}});
add('MS19','Mismatched end reference blocks extraction',{kind:'source_edit',observed:base.replace(end,end.replace(S,uid('other-section'))),
  publication:'suspended',diagnostics:['SECTION_BOUNDARY_MISMATCH'],checks:{lexical:{sections:0}}});
const foreignR=Buffer.alloc(32,7).toString('base64url');
add('MS20','Foreign Resource Task ref is not silently adopted',{kind:'source_edit',observed:base.replace(ref(ids.task),ref(ids.task).replace(R,foreignR)),
  publication:'suspended',diagnostics:['FOREIGN_RESOURCE_REF'],checks:{lexical:{sections:1,task_refs:1,node_refs:2}}});
add('MS21','Removing only a Task ref does not make a private exception',{kind:'source_edit',observed:base.replace('  '+ref(ids.task)+'\n',''),
  publication:'suspended',diagnostics:['NODE_BINDING_LOST'],checks:{lexical:{sections:1,task_refs:0,node_refs:2}},extra:{prior_bound_task:ids.task}});
add('MS22','Nested section boundaries suspend both ranges',{kind:'source_edit',observed:base.replace('\n'+end,'\n'+section(task)+'\n'+end),
  publication:'suspended',diagnostics:['SECTION_BOUNDARY_OVERLAP'],checks:{lexical:{sections:0}}});
add('MS23','Heading cannot be inferred when missing',{kind:'source_edit',observed:base.replace('## Joint launch','Joint launch without heading'),
  publication:'suspended',diagnostics:['SECTION_HEADING_INVALID'],checks:{lexical:{sections:1}}});
add('MS24','Payload extraction excludes surrounding private text',{kind:'inspect_owned_payload',
  checks:{lexical:{sections:1},private_canaries:[privateBefore,privateAfter],payload_contains:['Prepare contract','Draft contract','Check details'],payload_excludes:[privateBefore,privateAfter]}});
add('MS25','Readable-copy action strips metadata only in output',{kind:'copy_readable_section',extra:{selection:'whole-section'},
  checks:{lexical:{sections:1},clipboard:{plain_text:section().split('\n').filter(l=>!l.includes('<!-- lfcp-')&&!l.includes('<!-- /lfcp-')).join('\n'),source_unchanged:true}}});
add('MS26','Deleting a local file does not delete the collaboration',{kind:'delete_host_file',observed:{},after:{},
  checks:{lexical:{sections:0},physical_shared_deletion:false}});

// Added for the grammar decisions and host facts (MARKDOWN-SECTIONS-01 §15).
const enterTyped='- [ ] Prepare contract\n- [ ] \n  '+ref(ids.task);
add('MS27','Enter after a Task with a child-line ref keeps the ref with its Task',{before:note(task),kind:'editor_enter',
  observed:note(enterTyped),after:note(task+'\n- [ ] '),execution:'editor-integration-contract',
  extra:{transaction:'insert "\\n- [ ] " at the end of the Task line',user_event:'input'},checks:{lexical:{sections:1,task_refs:1,node_refs:0}},
  rationale:'Decision M1: child-line refs inside sections; the adapter keeps the binding with the Task in the editor transaction (ADR 0001 S1). An empty new Task is not published until it has a title.'});
const withPara=task+'\n'+paragraph;
add('MS28','Enter after a Task with a nested paragraph keeps the ref and the paragraph',{before:note(withPara),kind:'editor_enter',
  observed:note('- [ ] Prepare contract\n- [ ] \n  '+ref(ids.task)+'\n'+paragraph),
  after:note(withPara+'\n- [ ] '),execution:'editor-integration-contract',
  extra:{transaction:'insert "\\n- [ ] " at the end of the Task line',user_event:'input'},checks:{lexical:{sections:1,task_refs:1,node_refs:1}}});
const done='- [x] Prepare contract ✅ 2026-10-08\n  '+ref(ids.task);
add('MS29','Tasks completing a Task leaves its child-line ref untouched (H6)',{kind:'external_plugin_edit',observed:base.replace(task,done),
  publication:'semantic',intents:[{type:'task.complete',id:ids.task,completion_date:'2026-10-08'}],
  extra:{plugin:'obsidian-tasks-plugin 8.4.0',user_event:null},checks:{lexical:{sections:1,task_refs:1,node_refs:2}}});
const recurring='- [ ] Water plants 🔁 every week 📅 2026-10-08\n  '+ref(ids.task);
const recurDone='- [ ] Water plants 🔁 every week 📅 2026-10-15\n- [x] Water plants 🔁 every week 📅 2026-10-08 ✅ 2026-10-08\n  '+ref(ids.task);
add('MS30','Tasks completing a recurring Task: the next occurrence is new shared content (H6)',{before:note(recurring),kind:'external_plugin_edit',
  observed:note(recurDone),
  after:note('- [ ] Water plants 🔁 every week 📅 2026-10-15\n  '+ref(ids.extra)+'\n- [x] Water plants 🔁 every week 📅 2026-10-08 ✅ 2026-10-08\n  '+ref(ids.task)),
  publication:'semantic',intents:[{type:'task.create_in_section',id:ids.extra,parent_id:S,title:'Water plants',due:'2026-10-15',before:ids.task},
    {type:'task.complete',id:ids.task,completion_date:'2026-10-08'}],
  extra:{plugin:'obsidian-tasks-plugin 8.4.0',user_event:null,allocated_ids:[ids.extra]},checks:{lexical:{sections:1,task_refs:2,node_refs:0}}});
const tabbed='- [ ] Prepare contract\n\t'+ref(ids.task)+'\n\t'+node('paragraph',ids.para)+'\n\tDraft contract\n\n\t- Check details\n\t\t'+node('item',ids.x);
add('MS31','Tab-indented nesting parses to the same tree as spaces (M2, H2)',{before:note(tabbed),
  checks:{lexical:{sections:1,task_refs:1,node_refs:2},payload_contains:['Draft contract','Check details']},extra:{same_tree_as:'MS01'}});
add('MS32','A line between the heading and its start marker fails closed (H4)',{kind:'source_edit',
  observed:base.replace('## Joint launch\n','## Joint launch\nMoved here by an Outline drag\n'),
  publication:'suspended',diagnostics:['SECTION_HEADING_INVALID'],checks:{lexical:{sections:1},private_canaries:[privateBefore,privateAfter]}});
const table='| Milestone | Date |\n| --- | --- |\n| Launch | TBD |';
add('MS33','A table and a fence round-trip as raw nodes (M6)',{before:note(body+'\n\n'+node('raw',ids.a)+'\n'+table+'\n\n'+node('raw',ids.b)+'\n'+fence),
  checks:{lexical:{sections:1,task_refs:1,node_refs:4},payload_contains:['| Launch | TBD |','console.log("shared")']}});
add('MS34','A heading inside the region blocks sharing until the section is split',{kind:'source_edit',
  observed:base.replace('\n'+end,'\n### Sub-heading\n'+end),publication:'suspended',diagnostics:['SECTION_UNSUPPORTED_SYNTAX'],
  checks:{lexical:{sections:1}}});
const tokens='- [ ] Prepare contract 🔼 ➕ 2026-10-01 🛫 2026-10-02\n  '+ref(ids.task);
add('MS35','Tasks-local tokens stay local (M7)',{before:note(tokens),kind:'inspect_owned_payload',
  checks:{lexical:{sections:1,task_refs:1,node_refs:0},task_title:'Prepare contract',shared_task_fields_exclude:['priority-sign','created','start']}});
const tail=privateBefore+'\n\n'+section()+'Private tail between the end marker and the next heading.\n\n## Next heading\n';
add('MS36','Fold, drag and embed carry private text after the end marker: the share preview warns (H5)',{before:tail,kind:'share_preview',
  execution:'editor-integration-contract',checks:{lexical:{sections:1},preview_warning:'private-text-before-next-heading',private_canaries:[privateBefore]}});
add('MS37','The standalone Detach command inside a section is refused',{kind:'detach_task_command',extra:{task_id:ids.task},
  execution:'editor-integration-contract',checks:{lexical:{sections:1},command_refused:true}});
const comments='%% private note %%\n\n<!-- a private\n\nmulti-line note -->';
add('MS38','Comments inside the region stay local (MARKDOWN-SECTIONS-01 §4.5)',{before:note(body+'\n\n'+comments),kind:'inspect_owned_payload',
  diagnostics:['SECTION_UNSUPPORTED_SYNTAX'],
  checks:{lexical:{sections:1,task_refs:1,node_refs:2},payload_contains:['Draft contract'],payload_excludes:['private note','multi-line note']}});

// The sender's section comments setting (§4.5): new comments are shared as
// raw nodes under `shared`; a comment with a raw marker stays shared under
// either value; a received comment is projected as a raw node.
const shareNote='%% shared note %%', shareHtml='<!-- a shared\n\nmulti-line note -->';
const commentA=uid('comment-a'), commentB=uid('comment-b');
const typedComments=base.replace('\n'+end,'\n\n'+shareNote+'\n\n'+shareHtml+'\n'+end);
add('MS39','Under the shared comment setting, new comments become raw nodes (§4.5)',{kind:'local_insert',observed:typedComments,
  after:typedComments.replace(shareNote,node('raw',commentA)+'\n'+shareNote).replace(shareHtml,node('raw',commentB)+'\n'+shareHtml),
  publication:'semantic',intents:[{type:'raw.create',id:commentA,parent_id:S,text:shareNote},{type:'raw.create',id:commentB,parent_id:S,text:shareHtml}],
  extra:{settings:{section_comments:'shared'},allocated_ids:[commentA,commentB]},
  checks:{lexical:{sections:1,task_refs:1,node_refs:4},payload_contains:['shared note','multi-line note']},
  rationale:'Owner decision on comments (MARKDOWN-SECTIONS-01 §4.5): sharing comments is a per-section setting of the sender, local by default.'});
add('MS40','Under the local comment setting, a marked comment stays shared and a new one stays local (§4.5)',{
  before:note(body+'\n\n'+node('raw',commentA)+'\n'+shareNote+'\n\n%% private note %%'),kind:'inspect_owned_payload',
  diagnostics:['SECTION_UNSUPPORTED_SYNTAX'],extra:{settings:{section_comments:'local'}},
  checks:{lexical:{sections:1,task_refs:1,node_refs:3},payload_contains:['shared note','Draft contract'],payload_excludes:['private note']}});
const received=base.replace('\n'+end,'\n\n'+node('raw',commentA)+'\n'+shareNote+'\n'+end);
add('MS41','A received comment is projected as a raw node under the local setting (§4.5)',{kind:'remote_insert',after:received,
  extra:{settings:{section_comments:'local'},remote_intents:[{type:'raw.create',id:commentA,parent_id:S,text:shareNote}]},
  checks:{lexical:{sections:1,task_refs:1,node_refs:3},payload_contains:['shared note']}});

// Binding placement and the Tasks suffix after an inline ref (§4.1).
const inline=(line,tail='')=>line+' '+ref(ids.task)+tail;
const inlineDone='- [x] Prepare contract';
add('MS42','Tasks appends a completion date after an inline ref: a Tasks suffix (§4.1, H6)',{before:note(inline('- [ ] Prepare contract')),
  kind:'external_plugin_edit',observed:note(inline(inlineDone,' ✅ 2026-10-08')),after:note(inline(inlineDone+' ✅ 2026-10-08')),
  publication:'semantic',intents:[{type:'task.complete',id:ids.task,completion_date:'2026-10-08'}],
  extra:{plugin:'obsidian-tasks-plugin 8.4.0',user_event:null,settings:{binding_placement:'inline'}},
  checks:{lexical:{sections:1,task_refs:1,node_refs:0},observed_diagnostics:[]},
  rationale:'Owner decision on M1 (MARKDOWN-SECTIONS-01 §4.1): both ref placements inside sections, child-line by default; an inline ref tolerates the Tasks suffix.'});
const water='- [ ] Water plants';
add('MS43','Recurrence and a due date after an inline ref: a Tasks suffix, the recurrence stays local (§4.1)',{before:note(inline(water+' 🔁 every week 📅 2026-10-08')),
  kind:'source_edit',observed:note(inline(water,' 🔁 every week 📅 2026-10-15')),after:note(inline(water+' 🔁 every week 📅 2026-10-15')),
  publication:'semantic',intents:[{type:'task.set_due',id:ids.task,due:'2026-10-15'}],extra:{settings:{binding_placement:'inline'}},
  checks:{lexical:{sections:1,task_refs:1,node_refs:0},observed_diagnostics:[],shared_task_fields_exclude:['recurrence']}});
const stray=note(inline('- [ ] Prepare contract',' call Anna first'));
add('MS44','Other text after an inline ref is not a Tasks suffix (§4.1)',{before:note(inline('- [ ] Prepare contract')),
  kind:'source_edit',observed:stray,publication:'suspended',diagnostics:['LFCP_REF_NOT_AT_LINE_END'],
  extra:{settings:{binding_placement:'inline'}},checks:{lexical:{sections:1,task_refs:1,node_refs:0}}});

const result={suite:'MARKDOWN-SECTIONS-FIXTURES-01',schema_version:1,date:'2026-10-08',
  profile:'org.openlfcp.shared-sections.v1',status:'golden expectations for MARKDOWN-SECTIONS-01 (Working Draft); reference lexical/smoke checks only',
  identifiers:{resource:R,section:S,ids},fixtures};
fs.writeFileSync(path.join(out,'MARKDOWN-SECTIONS-FIXTURES-01.json'),JSON.stringify(result,null,2)+'\n');
fs.rmSync(path.join(out,'markdown-files'),{recursive:true,force:true});
for(const f of fixtures)for(const [stage,files]of Object.entries({before:f.before_files,observed:f.event.observed_files,after:f.expected.after_files}))
  for(const [name,text]of Object.entries(files)){
    const target=path.join(out,'markdown-files',f.id,stage,name);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,text);
  }
console.log(JSON.stringify({generated:fixtures.length,output:out}));
