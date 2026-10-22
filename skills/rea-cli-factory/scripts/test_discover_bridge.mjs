import test from 'node:test';
import assert from 'node:assert/strict';
import {parse} from '@babel/parser';
import {createHash} from 'node:crypto';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {discover} from './discover_bridge.mjs';
const name='src/preload.js';
const header="const {contextBridge,ipcRenderer}=require('electron');\n";
function evidence(source) {
  const nodes=[];
  const digest=createHash('sha256').update(source).digest('hex');
  function walk(node) {
    if (!node || typeof node!=='object') return;
    if (node.type==='CallExpression' && node.callee.type==='MemberExpression' && ['invoke','send'].includes(node.callee.property.name)) {
      const loc=node.loc;
      nodes.push({kind:'ipc-channel',observations:[{properties:{side:'renderer',operation:node.callee.property.name,resolution:'literal',channel:node.arguments[0]?.value},evidence:{artifact:{available:true,sha256:digest},location:{available:true,value:{kind:'source-range',source:name,start:{line:loc.start.line,column:loc.start.column},end:{line:loc.end.line,column:loc.end.column}}}}}]});
    }
    for (const [k,v] of Object.entries(node)) if(k!=='loc') {if(Array.isArray(v))v.forEach(walk);else if(v&&typeof v==='object')walk(v);}
  }
  const ast=parse(source,{sourceType:'unambiguous'});
  walk(ast);
  nodes.push({kind:'source-file',observations:[{properties:{},evidence:{artifact:{available:true,sha256:digest},location:{available:true,value:{kind:'source-range',source:name,start:{line:ast.program.loc.start.line,column:ast.program.loc.start.column},end:{line:ast.program.loc.end.line,column:ast.program.loc.end.column}}}}}]});
  return {operation:'analyze_javascript_application',evidence_id:'ev_'+'a'.repeat(64),normalized_result:{graph:{coverage:{status:'partial',truncated:false,omitted_count:null,limits:[]},nodes}}};
}
const run=source=>discover(source,name,evidence(source));
test('function declaration shorthand, const arrow, inline arrow and nested literal',()=>{
  const source=header+"function save(value){return ipcRenderer.invoke('save',{value})}\nconst ping=()=>ipcRenderer.send('ping');\nconst api={save,ping,nested:{read:()=>ipcRenderer.invoke('read')}};\ncontextBridge.exposeInMainWorld('fixture',api);";
  const result=run(source);
  assert.deepEqual(result.candidates.map(c=>c.apiPath),[['fixture','save'],['fixture','ping'],['fixture','nested','read']]);
  assert.deepEqual(result.candidates[0].params,['value']);
  assert.equal(result.candidates[0].arity,1);
  assert.equal(result.candidates[1].transport,'send');
  assert.ok(result.candidates.every(c=>c.status==='candidate'));
  assert.equal(result.coverage.status,'partial');
  assert.deepEqual(result.unsupported,[]);
});
test('namespace and renamed destructuring bindings',()=>{
  for(const source of ["const electron=require('electron');electron.contextBridge.exposeInMainWorld('fixture',{read:()=>electron.ipcRenderer.invoke('read')});", "const {contextBridge:bridge,ipcRenderer:ipc}=require('electron');bridge.exposeInMainWorld('fixture',{read:()=>ipc.invoke('read')});"])
    assert.equal(run(source).candidates.length,1);
});
test('fake electron, shadowed require and local IPC or bridge shadow cannot produce candidates',()=>{
  const sources=[
    "const {contextBridge,ipcRenderer}=require('fake');contextBridge.exposeInMainWorld('fixture',{read:()=>ipcRenderer.invoke('read')});",
    "const require=()=>({});"+header+"contextBridge.exposeInMainWorld('fixture',{read:()=>ipcRenderer.invoke('read')});",
    header+"contextBridge.exposeInMainWorld('fixture',{read:(ipcRenderer)=>ipcRenderer.invoke('read')});",
    header+"function scope(contextBridge){contextBridge.exposeInMainWorld('fixture',{read:()=>ipcRenderer.invoke('read')})}",
  ];
  for (const source of sources) {const r=run(source);assert.equal(r.candidates.length,0);assert.ok(r.unsupported.length>0);}
});
test('API, function and electron mutations or alias escapes are rejected',()=>{
  const base=header+"const read=()=>ipcRenderer.invoke('read');const api={read};contextBridge.exposeInMainWorld('fixture',api);";
  for(const tail of ["api.read=()=>0;","read=()=>0;","read.x=1;","Object.assign(api,{});","const alias=api;alias.read=()=>0;","other=api;","api.mutate();","const ipcAlias=ipcRenderer;ipcAlias.invoke=()=>0;","const holder={api};holder.api.read=()=>0;","function leak(){return api} leak().read=()=>0;","({x:ipcRenderer.invoke}=other);","for(ipcRenderer of other){}","eval(unknown);"])
    assert.equal(run(base+tail).candidates.length,0,tail);
});
test('default/rest parameters, events, dynamic channel, complex bodies remain unsupported',()=>{
  for(const method of ["(channel)=>ipcRenderer.invoke(channel)","(callback)=>ipcRenderer.on('read',callback)","(x=1)=>ipcRenderer.invoke('read',x)","(...x)=>ipcRenderer.invoke('read',x)","()=>{sideEffect();return ipcRenderer.invoke('read')}"]){
    // Ensure source identity is represented even when this unsupported method has no IPC entry.
    const source=header+"function unexposed(){return ipcRenderer.invoke('identity')}contextBridge.exposeInMainWorld('fixture',{read:"+method+"});";
    assert.equal(run(source).candidates.length,0);
    assert.ok(run(source).unsupported.length>0);
  }
});
test('spread getter duplicate keys and dynamic/duplicate exposes are rejected',()=>{
  const call="()=>ipcRenderer.invoke('read')";
  for(const object of ["{read:"+call+",...other}","{read:"+call+",get extra(){return 1}}","{read:"+call+",read:"+call+"}"])
    assert.equal(run(header+"contextBridge.exposeInMainWorld('fixture',"+object+");").candidates.length,0);
  for(const exposure of ["contextBridge.exposeInMainWorld(name,{read:"+call+"});","contextBridge['exposeInMainWorld']('fixture',{read:"+call+"});","contextBridge.exposeInMainWorld('fixture',{read:"+call+"});contextBridge.exposeInMainWorld('fixture',{read:"+call+"});"]){
    const r=run(header+exposure);assert.equal(r.candidates.length,0);assert.ok(r.unsupported.length);
  }
});
test('changed source bytes or unknown source fail before extracting',()=>{
  const source=header+"contextBridge.exposeInMainWorld('fixture',{read:()=>ipcRenderer.invoke('read')});";
  assert.throws(()=>discover(source+' ',name,evidence(source)),{code:'SOURCE_DIGEST_MISMATCH'});
  assert.throws(()=>discover(source,'other.js',evidence(source)),{code:'SOURCE_NOT_IN_EVIDENCE'});
  assert.throws(()=>discover(source,'/private/source.js',evidence(source)),{code:'INVALID_SOURCE'});
  const ev=evidence(source);ev.normalized_result.graph.nodes[0].observations[0].evidence.location.value.start.column++;
  assert.equal(discover(source,name,ev).candidates.length,0);
});
test('CLI never overwrites existing output and emits only contract to new file',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'bridge-fixture-'));
  try {
    const source=header+"contextBridge.exposeInMainWorld('fixture',{read:()=>ipcRenderer.invoke('read')});";
    const input=join(dir,'source.js'), ev=join(dir,'evidence.json'), out=join(dir,'contract.json');
    await writeFile(input,source);await writeFile(ev,JSON.stringify(evidence(source)));
    const args=[fileURLToPath(new URL('./discover_bridge.mjs',import.meta.url)),'--source',input,'--source-name',name,'--evidence',ev,'--out',out];
    const first=spawnSync(process.execPath,args,{encoding:'utf8'});assert.equal(first.status,0,first.stderr);
    const before=await readFile(out,'utf8');assert.equal(JSON.parse(before).candidates.length,1);
    const second=spawnSync(process.execPath,args,{encoding:'utf8'});assert.equal(second.status,2);assert.equal(JSON.parse(second.stderr).error.code,'EEXIST');assert.equal(await readFile(out,'utf8'),before);
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('unique immutable top-level var and let Electron bindings are candidates',()=>{
  for (const kind of ['var','let']) {
    for (const source of [
      `${kind} electron=require('electron');electron.contextBridge.exposeInMainWorld('fixture',{read:()=>electron.ipcRenderer.invoke('read')});`,
      `${kind} {contextBridge:bridge,ipcRenderer:ipc}=require('electron');bridge.exposeInMainWorld('fixture',{read:()=>ipc.invoke('read')});`,
    ]) {
      const result=run(source);
      assert.equal(result.candidates.length,1);
      assert.deepEqual(result.unsupported,[]);
      assert.equal(result.candidates[0].channel,'read');
    }
  }
});
test('var and let support does not relax redeclaration, reassignment, shadowing or escape checks',()=>{
  const body="electron.contextBridge.exposeInMainWorld('fixture',{read:()=>electron.ipcRenderer.invoke('read')});";
  for (const tail of ["var electron;", "electron=other;", "electron.ipcRenderer.invoke=other;", "function scope(electron){}", "const alias=electron;", "unknown(electron);"]) {
    assert.equal(run("var electron=require('electron');"+body+tail).candidates.length,0,tail);
  }
  for (const tail of ["electron=other;", "function scope(electron){}", "electron.contextBridge=other;"]) {
    assert.equal(run("let electron=require('electron');"+body+tail).candidates.length,0,tail);
  }
});
test('imported wrapper calls get actionable diagnostics without becoming candidates',()=>{
  const source=header+"const wrapper=require('./wrapper.cjs');contextBridge.exposeInMainWorld('fixture',{read:()=>wrapper.invokeApi(wrapper.channels.read)});";
  const result=run(source);
  assert.equal(result.candidates.length,0);
  assert.equal(result.unsupported[0].reason,'imported-wrapper-call');
  assert.match(result.unsupported[0].nextStep,/imported wrapper source/);
  assert.equal(result.unsupported[0].sourceRange.source,name);
  assert.equal(result.unsupported[0].sourceRange.start.column,source.split('\n')[1].indexOf('wrapper.invokeApi'));
});
test('factory-created and conditionally mutated API objects remain unsupported with next steps',()=>{
  const factory=run(header+"const createApi=require('./factory.cjs');const api=createApi();contextBridge.exposeInMainWorld('fixture',api);");
  assert.equal(factory.candidates.length,0);
  assert.equal(factory.unsupported[0].reason,'factory-created-api');
  assert.match(factory.unsupported[0].nextStep,/factory/);
  const mutated=run(header+"const api={read:()=>ipcRenderer.invoke('read')};if(flag)api.extra=()=>1;contextBridge.exposeInMainWorld('fixture',api);");
  assert.equal(mutated.candidates.length,0);
  assert.equal(mutated.unsupported[0].reason,'unsupported-or-mutated-object');
  assert.match(mutated.unsupported[0].nextStep,/mutated/);
});
test('namespace destructuring aliases diagnose the unresolved binding conservatively',()=>{
  const result=run("const {contextBridge}=require('electron');const electron=require('electron');const {ipcRenderer}=electron;contextBridge.exposeInMainWorld('fixture',{read:()=>ipcRenderer.invoke('read')});");
  assert.equal(result.candidates.length,0);
  assert.equal(result.unsupported[0].reason,'unsupported-electron-alias');
  assert.match(result.unsupported[0].nextStep,/binding/);
});
test('source with no exposed API reports an empty candidate set and explicit discovery next step',()=>{
  const source="const electron=require('electron');function read(){return electron.ipcRenderer.invoke('read')}";
  const result=run(source);
  assert.deepEqual(result.candidates,[]);
  assert.equal(result.unsupported[0].reason,'no-exposed-api');
  assert.match(result.unsupported[0].nextStep,/Locate a preload/);
  assert.equal(result.unsupported[0].sourceRange.start.line,1);
  assert.throws(()=>discover(source+' ',name,evidence(source)),{code:'SOURCE_DIGEST_MISMATCH'});
});
