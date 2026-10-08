import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import MarkdownIt from 'markdown-it';
import {hash} from './section-model.mjs';
const out=process.argv[2]||path.dirname(path.dirname(new URL(import.meta.url).pathname));
const suite=JSON.parse(fs.readFileSync(path.join(out,'MARKDOWN-SECTIONS-FIXTURES-01.json'),'utf8'));
const md=new MarkdownIt({html:true});
const uuid='[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
// MARKDOWN-SECTIONS-01 §2: fixed parts, one or more spaces or tabs between them.
const W='[ \\t]+';
const boundary=new RegExp('^<!--'+W+'(/?lfcp-section):'+W+'(lfcp1:([A-Za-z0-9_-]{43})#section:('+uuid+'))'+W+'-->[ \\t]*$');
const taskRef=new RegExp('<!--'+W+'lfcp-ref:'+W+'lfcp1:([A-Za-z0-9_-]{43})#task:('+uuid+')'+W+'-->','g');
const nodeRef=new RegExp('<!--'+W+'lfcp-node:'+W+'(item|paragraph|raw):('+uuid+')'+W+'-->');
const lfcpComment=/<!--[ \t]+\/?lfcp-/;
function lex(source) {
  const lines=source.split(/\r?\n/),tokens=md.parse(source,{});
  const literal=new Set(),blocks=[],ranges=[];
  function visit(ts){for(const t of ts){
    if(t.map&&['fence','code_block'].includes(t.type))for(let i=t.map[0];i<t.map[1];i++)literal.add(i);
    if(t.map&&['fence','code_block','table_open','blockquote_open'].includes(t.type))blocks.push(t.map);
    if(t.map&&t.type==='html_block'&&t.content.startsWith('<!--')&&!lfcpComment.test(t.content))
      ranges.push([t.map[0],t.map[1]-1]);
    if(t.children)visit(t.children);
  }}visit(tokens);
  // Obsidian comments: from a line opening %% through the line closing it (§4.5).
  let open=-1;
  for(let i=0;i<lines.length;i++){
    if(literal.has(i))continue;
    const n=(lines[i].match(/%%/g)||[]).length;
    if(open<0&&n){if(n%2)open=i;else ranges.push([i,i]);}
    else if(open>=0&&n%2){ranges.push([open,i]);open=-1;}
  }
  if(open>=0)ranges.push([open,lines.length-1]);
  // A comment right after a raw marker is a shared raw node (§4.4, §4.5);
  // any other comment is local.
  const comments=new Set(),shared=new Set();
  for(const [a,b]of ranges){
    const target=(lines[a-1]||'').match(nodeRef)?.[1]==='raw'?shared:comments;
    for(let i=a;i<=b;i++)target.add(i);
  }
  const diagnostics=new Set(),sections=[];let current=null,depth=0;
  for(let i=0;i<lines.length;i++){
    if(literal.has(i)||comments.has(i))continue;
    const m=lines[i].match(boundary);
    if(!m)continue;
    if(Buffer.from(m[3],'base64url').toString('base64url')!==m[3]){diagnostics.add('SECTION_BOUNDARY_MISMATCH');continue;}
    if(m[1]==='lfcp-section'){
      if(current){current.overlap=true;depth++;diagnostics.add('SECTION_BOUNDARY_OVERLAP');}
      else{current={from:i,reference:m[2],resource:m[3],overlap:false};depth=1;}
    } else if(!current)diagnostics.add('SECTION_BOUNDARY_MISSING');
    else {
      depth--;
      if(depth===0){
        if(current.reference!==m[2])diagnostics.add('SECTION_BOUNDARY_MISMATCH');
        else if(!current.overlap)sections.push({...current,to:i});
        current=null;
      }
    }
  }
  if(current)diagnostics.add('SECTION_BOUNDARY_MISSING');
  let task_refs=0,node_refs=0;const owned=[];
  for(const s of sections){
    // M4: the heading is the line right before the start marker.
    if(!/^#{1,6} /.test(lines[s.from-1]||''))diagnostics.add('SECTION_HEADING_INVALID');
    // M6: a block is a raw node when the line before it is a raw marker.
    for(const [a]of blocks){
      if(a<=s.from||a>=s.to)continue;
      const marker=(lines[a-1]||'').match(nodeRef);
      if(!marker||marker[1]!=='raw')diagnostics.add('SECTION_UNSUPPORTED_SYNTAX');
    }
    const seen=new Set();
    for(let i=s.from+1;i<s.to;i++){
      if(comments.has(i)){diagnostics.add('SECTION_UNSUPPORTED_SYNTAX');continue;}
      if(shared.has(i)){owned.push(lines[i]);continue;}
      const line=lines[i];
      if(!literal.has(i)&&/^#{1,6} /.test(line))diagnostics.add('SECTION_UNSUPPORTED_SYNTAX');
      if(!literal.has(i)){
        for(const m of line.matchAll(taskRef)){
          task_refs++;
          if(m[1]!==s.resource)diagnostics.add('FOREIGN_RESOURCE_REF');
          if(seen.has(m[2]))diagnostics.add('NODE_BINDING_DUPLICATE');seen.add(m[2]);
        }
        const n=line.match(nodeRef);
        if(n){node_refs++;if(seen.has(n[2]))diagnostics.add('NODE_BINDING_DUPLICATE');seen.add(n[2]);}
      }
      if(!line.includes('<!-- lfcp-')&&!line.includes('<!-- /lfcp-'))owned.push(line);
    }
  }
  // Comments are local: a section with only comment diagnostics still extracts the rest.
  const blocking=[...diagnostics].filter(d=>d!=='SECTION_UNSUPPORTED_SYNTAX'||[...sections].some(s=>
    lines.slice(s.from+1,s.to).some((l,k)=>!comments.has(s.from+1+k)&&!literal.has(s.from+1+k)&&/^#{1,6} /.test(l))||
    blocks.some(([a])=>a>s.from&&a<s.to&&!((lines[a-1]||'').match(nodeRef)?.[1]==='raw'))));
  return {sections:sections.length,task_refs,node_refs,diagnostics:[...diagnostics].sort(),owned:blocking.length?'':owned.join('\n'),tokens};
}
function goldenSmoke(f) {
  const files={...f.before_files};
  if(f.event.kind==='detach_section'){
    for(const [name,text]of Object.entries(files))files[name]=text.split('\n').filter(l=>!l.includes('<!-- lfcp-')&&!l.includes('<!-- /lfcp-')).join('\n');
  }else if(f.event.kind==='remote_complete'){
    for(const [name,text]of Object.entries(files)){
      const eol=text.includes('\r\n')?'\r\n':'\n';
      const lines=text.split(eol);
      for(let i=0;i<lines.length;i++)if(lines[i].includes('#task:'+f.event.task_id+' -->')){
        const target=/^\s*(?:[-+*]|\d+[.)]) \[[ xX]\]/.test(lines[i])?i:i-1;
        assert(target>=0);assert(/^\s*(?:[-+*]|\d+[.)]) \[[ xX]\]/.test(lines[target]));
        lines[target]=lines[target].replace('[ ]','[x]');
      }
      files[name]=lines.join(eol);
    }
  }else throw new Error('no smoke executor');
  return files;
}
const adapterArg=process.argv.indexOf('--adapter');
const adapter=adapterArg<0?null:await import(pathToFileURL(path.resolve(process.argv[adapterArg+1])).href);
const reports=[];
const lexicalCodes=new Set(['SECTION_BOUNDARY_MISSING','SECTION_BOUNDARY_MISMATCH','SECTION_BOUNDARY_OVERLAP','SECTION_HEADING_INVALID','SECTION_UNSUPPORTED_SYNTAX','FOREIGN_RESOURCE_REF','NODE_BINDING_DUPLICATE']);
for(const f of suite.fixtures){
  for(const [stage,files]of Object.entries({before:f.before_files,observed:f.event.observed_files,after:f.expected.after_files}))
    for(const [name,text]of Object.entries(files)){
      assert.equal(hash(Buffer.from(text)),f.files_sha256[stage][name]);
      assert.equal(fs.readFileSync(path.join(out,'markdown-files',f.id,stage,name),'utf8'),text);
    }
  const lexed=Object.values(f.expected.after_files).map(lex);
  const counts={sections:0,task_refs:0,node_refs:0};
  for(const l of lexed)for(const key of Object.keys(counts))counts[key]+=l[key];
  for(const [key,value]of Object.entries(f.expected.lexical||{}))assert.equal(counts[key],value,f.id+' '+key);
  const actualDiagnostics=[...new Set(lexed.flatMap(l=>l.diagnostics))].sort();
  const requiredDiagnostics=f.expected.diagnostics.filter(d=>lexicalCodes.has(d)).sort();
  assert.deepEqual(actualDiagnostics,requiredDiagnostics,f.id+' lexical diagnostics');
  if(f.expected.line_endings==='CRLF')for(const s of Object.values(f.expected.after_files))assert(!/(?<!\r)\n/.test(s));
  for(const canary of f.expected.private_canaries||[]){
    const before=Object.values(f.before_files).join(''),after=Object.values(f.expected.after_files).join('');
    assert(before.includes(canary));assert(after.includes(canary));
    assert(!lexed.some(l=>l.owned.includes(canary)),f.id+' private canary included in owned text');
  }
  for(const text of f.expected.payload_contains||[])assert(lexed.some(l=>l.owned.includes(text)),f.id+' payload contains '+text);
  for(const text of f.expected.payload_excludes||[])assert(!lexed.some(l=>l.owned.includes(text)),f.id+' payload excludes '+text);
  if(f.execution==='golden-operation-smoke')assert.deepEqual(goldenSmoke(f),f.expected.after_files,f.id+' smoke');
  if(f.expected.publication==='suspended')assert.equal(f.expected.intents.length,0);
  for(const text of f.expected.payload_excludes||[])assert(!Object.values(f.expected.after_files).some(t=>lex(t).owned.includes(text)),f.id+' excluded text extracted');
  if(adapter){
    // Do not supply golden expectations to the implementation under test.
    const result=await adapter.runFixture({id:f.id,identifiers:suite.identifiers,before_files:f.before_files,event:f.event,projection_base:f.projection_base});
    for(const key of ['after_files','diagnostics','intents','publication'])assert.deepEqual(result[key],f.expected[key],f.id+' adapter '+key);
    if(f.expected.clipboard?.plain_text!==undefined)assert.equal(result.clipboard?.plain_text,f.expected.clipboard.plain_text);
    for(const bad of f.expected.clipboard?.forbidden_fragments||[])assert(!String(result.clipboard?.plain_text||'').includes(bad)&&!String(result.clipboard?.rich_text||'').includes(bad));
  }
  reports.push({id:f.id,result:'pass',lexical_checks:true,golden_operation_smoke:f.execution==='golden-operation-smoke',production_adapter_executed:!!adapter,
    pending_without_adapter:f.expected.diagnostics.filter(x=>!lexicalCodes.has(x))});
}
const report={suite:suite.suite,lexer:'markdown-it 14.1.0 plus reference metadata scanner',passed:reports.length,failed:0,
  scope:'Static golden consistency, lexical boundary checks, private canaries and three narrow projection smoke cases; not complete plugin verification',
  cases:reports,production_adapter_executed:!!adapter,
  not_executed:adapter?[]:['full Markdown AST-to-model translation','Obsidian Live Preview/reading modes','clipboard DOM serialization','Tasks plugin compatibility','macOS/Windows/Linux matrix']};
fs.writeFileSync(path.join(out,'markdown-validation-report.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({suite:suite.suite,passed:reports.length,adapter_executed:!!adapter}));
