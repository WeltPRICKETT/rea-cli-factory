import test from 'node:test';
import assert from 'node:assert/strict';
import {parse} from '@babel/parser';
import {createHash} from 'node:crypto';
import {discoverModules} from './discover_modules.mjs';

function evidence(sources) {
  const nodes=[];
  for(const [source,text] of Object.entries(sources)) {
    const ast=parse(text,{sourceType:'script'}), digest=createHash('sha256').update(text).digest('hex');
    const observation=(node,properties)=>({properties,evidence:{artifact:{available:true,sha256:digest},location:{available:true,value:{kind:'source-range',source,start:{line:node.loc.start.line,column:node.loc.start.column},end:{line:node.loc.end.line,column:node.loc.end.column}}}}});
    nodes.push({kind:'source',observations:[observation(ast.program,{})]});
    function walk(n) {
      if(!n||typeof n!=='object')return;
      if(n.type==='CallExpression'&&n.callee.type==='MemberExpression'&&['invoke','send'].includes(n.callee.property.name)) {
        const a=n.arguments[0];nodes.push({kind:'ipc-channel',observations:[observation(n,{side:'renderer',operation:n.callee.property.name,resolution:a?.type==='StringLiteral'?'literal':'dynamic',channel:a?.type==='StringLiteral'?a.value:null})]});
      }
      for(const [k,v] of Object.entries(n))if(k!=='loc') {if(Array.isArray(v))v.forEach(walk);else if(v&&typeof v==='object')walk(v);}
    }
    walk(ast);
  }
  return {operation:'analyze_javascript_application',evidence_id:'ev_'+'a'.repeat(64),normalized_result:{graph:{coverage:{status:'partial',truncated:false},nodes}}};
}
const wrapper=`const electron=require('electron');
const channels={read:'sample:read', write:'sample:write'};
function request(channel,...args){const payload=args[0];return electron.ipcRenderer.invoke(channel,payload).then(result=>{if(result.ok){return result.data;}throw new Error(result.error);});}
exports.channels=channels;exports.request=request;`;
const entry=`const electron=require('electron');const wire=require('./wire.cjs');
function factory(){return {read(path){return wire.request(wire.channels.read,path);},write(value){return wire.request(wire.channels.write,{value});}};}
const api={files:factory()};electron.contextBridge.exposeInMainWorld('sample',api);`;
const fixture=(main=entry,wire=wrapper)=>({'preload/main.cjs':main,'preload/wire.cjs':wire});
const run=(sources=fixture(),ev=evidence(sources))=>discoverModules(sources,'preload/main.cjs',ev);

test('cross-module factory methods trace one IPC and retain wrapper provenance',()=>{
  const r=run();assert.equal(r.candidates.length,2);const c=r.candidates[0];assert.deepEqual(c.apiPath,['sample','files','read']);assert.equal(c.channel,'sample:read');assert.deepEqual(c.params,['path']);assert.equal(c.provenance.reaResolution,'dynamic');assert.equal(c.provenance.channelResolution,'scoped-static-inference');assert.equal(c.provenance.sources.length,2);
});
test('factory arguments preserve wrapper closure and parameter scope',()=>{
  const main=`const {contextBridge,ipcRenderer}=require('electron');const channels={read:'sample:read'};
  function factory(input){return {read(payload){return input.invoke(channels.read,payload);}};}
  const api=factory({invoke:(channel,...args)=>ipcRenderer.invoke(channel,...args)});contextBridge.exposeInMainWorld('sample',api);`;
  const r=run(fixture(main));assert.equal(r.candidates.length,1);assert.equal(r.candidates[0].channel,'sample:read');
  const shadow=main.replace('read(payload){return input.invoke(channels.read,payload);}','read(input){return input.invoke(channels.read,input);}');
  assert.equal(run(fixture(shadow)).candidates.length,0);
});
test('constant CommonJS module.exports and relative extension resolution',()=>{
  const s=fixture(entry.replace('./wire.cjs','./wire'),wrapper.replace('exports.channels=channels;exports.request=request;','module.exports={channels,request};'));
  assert.equal(run(s).candidates.length,2);
});
test('unrelated conditional property mutation keeps proven siblings',()=>{
  const s=fixture(entry.replace("electron.contextBridge.expose", "if(unknown()){api.browser=unknownFactory();}electron.contextBridge.expose"));
  assert.equal(run(s).candidates.length,2);
});
test('aliased mutations invalidate only the touched subtree',()=>{
  const s=fixture(entry.replace("electron.contextBridge.expose", "const alias=api.files;alias.read=other;electron.contextBridge.expose"));
  assert.deepEqual(run(s).candidates.map(c=>c.apiPath.at(-1)),['write']);
  const all=fixture(entry.replace("electron.contextBridge.expose", "const alias=api;alias[key]=other;electron.contextBridge.expose"));
  assert.equal(run(all).candidates.length,0);
});
test('channel mutation through import, alias or callback cannot bypass rejection',()=>{
  for(const mutation of ['wire.channels.read="changed";','const alias=wire.channels;alias.read="changed";','unknown(wire.channels);','function mutate(){wire.channels.read="changed";}']) {
    const r=run(fixture(entry.replace('const api=',mutation+'const api=')));
    assert.ok(!r.candidates.some(c=>c.apiPath.at(-1)==='read'),mutation);
  }
});
test('factory aliases passed to impure functions are invalidated',()=>{
  const s=fixture(entry.replace('const api=', 'function change(input){input.read="changed";}change(wire.channels);const api='));
  assert.equal(run(s).candidates.length,0);
});
test('dynamic channels and extra operations are never candidates',()=>{
  const dynamic=entry.replace('wire.channels.read,path','path,path');
  assert.deepEqual(run(fixture(dynamic)).candidates.map(c=>c.apiPath.at(-1)),['write']);
  for(const change of [
    'sideEffect();return wire.request(wire.channels.read,path);',
    'state.value=1;return wire.request(wire.channels.read,path);',
    'wire.request(wire.channels.read,path);return wire.request(wire.channels.read,path);'
  ]) {
    const r=run(fixture(entry.replace('return wire.request(wire.channels.read,path);',change)));
    assert.ok(!r.candidates.some(c=>c.apiPath.at(-1)==='read'),change);
  }
});
test('response wrappers cannot hide second operations or unsafe constructors',()=>{
  for(const body of ['sideEffect(result);return result;','electron.ipcRenderer.send("extra",result);return result;','throw new Custom(result);']) {
    const s=fixture(entry,wrapper.replace('if(result.ok){return result.data;}throw new Error(result.error);',body));
    assert.equal(run(s).candidates.length,0,body);
  }
});
test('simple Error subclasses in retained response wrappers are supported',()=>{
  const w=wrapper.replace('function request', 'class Failure extends Error{code;constructor(details){super(details.message);this.code=details.code;}}\nfunction request').replace('new Error(result.error)','new Failure(result.error)');
  assert.equal(run(fixture(entry,w)).candidates.length,2);
  const unsafe=w.replace('this.code=details.code;','sideEffect(details);this.code=details.code;');
  assert.equal(run(fixture(entry,unsafe)).candidates.length,0);
});
test('changed digest, missing evidence and mismatched IPC location fail closed',()=>{
  const s=fixture(),ev=evidence(s);assert.throws(()=>run({...s,'preload/wire.cjs':wrapper+' '},ev),/SOURCE_DIGEST_MISMATCH/);
  const missing=structuredClone(ev);missing.normalized_result.graph.nodes=missing.normalized_result.graph.nodes.filter(n=>n.observations[0].evidence.location.value.source!=='preload/wire.cjs');
  assert.throws(()=>run(s,missing),/SOURCE_NOT_IN_EVIDENCE/);
  const moved=structuredClone(ev);for(const n of moved.normalized_result.graph.nodes)if(n.kind==='ipc-channel')n.observations[0].evidence.location.value.start.column++;
  assert.equal(run(s,moved).candidates.length,0);
});
test('missing relative modules, cycles and root traversal are rejected',()=>{
  assert.throws(()=>run({'preload/main.cjs':entry}),/MISSING_MODULE/);
  const cycle=fixture(entry,wrapper+'require("./main.cjs");');assert.throws(()=>run(cycle),/CYCLIC_MODULE/);
  assert.throws(()=>run(fixture(entry.replace('./wire.cjs','../../outside.cjs'))),/UNSAFE_MODULE_PATH/);
});
test('spreads, getters, duplicate properties and recursive factories stay unsupported',()=>{
  for(const replacement of ['return {...unknown};','return {get read(){return other;}};','return {read:()=>wire.request(wire.channels.read),read:other};','return factory();']) {
    const main=entry.replace(/return \{read\(path\).*?\}\};/,replacement);
    assert.equal(run(fixture(main)).candidates.length,0,replacement);
  }
});
test('shadowed Electron and require are not trusted',()=>{
  const s=fixture(entry.replace("const electron=require('electron');","const electron=unknown;"));assert.equal(run(s).candidates.length,0);
  assert.throws(()=>run(fixture(entry+'require=other;')),/OPAQUE_MODULE_BINDING/);
});
test('conditional duplicate exposure invalidates root',()=>{
  const s=fixture(entry+'if(flag){electron.contextBridge.exposeInMainWorld("sample",other);}');assert.equal(run(s).candidates.length,0);
});
test('exports aliases and conditional overwrites cannot bypass rejection',()=>{
  for(const mutation of ['const alias=exports;alias.request=other;','if(flag){exports.request=other;}']) {
    assert.equal(run(fixture(entry,wrapper+mutation)).candidates.length,0,mutation);
  }
});
test('bounded input rejects excessive sources and bytes without evaluation',()=>{
  const many=Object.fromEntries(Array.from({length:33},(_,i)=>['file'+i+'.cjs','']));assert.throws(()=>discoverModules(many,'file0.cjs',{}),/SOURCE_LIMIT_EXCEEDED/);
  assert.throws(()=>run(fixture(' '.repeat(2*1024*1024+1))),/SOURCE_LIMIT_EXCEEDED/);
});

test('Electron namespace mutations and destructuring assignment fail closed',()=>{
  for(const mutation of ['electron.ipcRenderer.invoke=other;', 'const alias=electron.ipcRenderer;alias.invoke=other;', '({x:wire.channels.read}=other);', '[wire.channels.read]=other;']) {
    const r=run(fixture(entry.replace('const api=',mutation+'const api=')));
    assert.ok(!r.candidates.some(c=>c.apiPath.at(-1)==='read'),mutation);
  }
});

test('loop writes, assignment escapes and nested object or closure escapes are blocked',()=>{
  for(const mutation of ['for(api.files.read of values){}','other=api;','other.api=api;','const holder={api};leak(holder);','const callback=()=>api;leak(callback);']) {
    const main=entry.replace('electron.contextBridge.expose',mutation+'electron.contextBridge.expose');
    assert.ok(!run(fixture(main)).candidates.some(c=>c.apiPath.at(-1)==='read'),mutation);
  }
});
test('conditional module.exports replacement and module alias replacement are blocked',()=>{
  for(const change of ['if(flag)module.exports={request:other};','const alias=module;alias.exports={request:other};'])
    assert.equal(run(fixture(entry,wrapper+change)).candidates.length,0,change);
});

test('IPC payloads cannot hide spreads, getters, dynamic keys or functions',()=>{
  for(const payload of ['{...sideEffect()}','{get x(){return sideEffect();}}','{[sideEffect()]:1}','{nested:{x:unknown}}','{callback:()=>sideEffect()}']) {
    const main=entry.replace('wire.channels.read,path','wire.channels.read,'+payload);
    assert.ok(!run(fixture(main)).candidates.some(c=>c.apiPath.at(-1)==='read'),payload);
  }
});
test('send cannot be treated as an invoke promise',()=>{
  const main="const {contextBridge,ipcRenderer}=require('electron');contextBridge.exposeInMainWorld('sample',{read:()=>ipcRenderer.send('read').then(r=>r)});";
  assert.equal(run(fixture(main)).candidates.length,0);
});

test('cached method and literal aliases cannot retain pre-mutation candidates',()=>{
  const header="const {contextBridge,ipcRenderer}=require('electron');";
  const mains=[
    header+"const api={read:()=>ipcRenderer.invoke('old')};api.read=()=>ipcRenderer.invoke('new');const read=api.read;contextBridge.exposeInMainWorld('sample',{read});",
    header+"const constants={channel:'old'};constants.channel='new';const channel=constants.channel;function make(c){return()=>ipcRenderer.invoke(c)}contextBridge.exposeInMainWorld('sample',{read:make(channel)});"
  ];
  for(const main of mains)assert.equal(run(fixture(main)).candidates.length,0);
});

test('ignored unknown initializers and expressions may not hide getters or failures',()=>{
  for(const prefix of ['const ignored=external.config;','external.config;','const ignored=require("node:fs").readFileSync;','const ignored={nested:{value:external.config}};']) {
    const main=entry.replace('return wire.request(wire.channels.read,path);',prefix+'return wire.request(wire.channels.read,path);');
    assert.ok(!run(fixture(main)).candidates.some(c=>c.apiPath.at(-1)==='read'),prefix);
  }
});

test('factory returns with eagerly evaluated unknown properties are rejected',()=>{
  const main=entry.replace('return {read(path)', 'return {metadata:external.config,read(path)');
  assert.equal(run(fixture(main)).candidates.length,0);
});
