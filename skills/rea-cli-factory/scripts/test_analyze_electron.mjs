import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {parse} from '@babel/parser';
import {analyze,runBounded} from './analyze_electron.mjs';
function archive(source){
 const pkg=Buffer.from('{"name":"synthetic-fixture"}'),code=Buffer.from(source);
 const header=Buffer.from(JSON.stringify({files:{'package.json':{size:pkg.length,offset:'0'},'preload.js':{size:code.length,offset:String(pkg.length)}}}));
 const size=8+header.length+(4-header.length%4)%4,prefix=Buffer.alloc(16);
 prefix.writeUInt32LE(4,0);prefix.writeUInt32LE(size,4);prefix.writeUInt32LE(size-4,8);prefix.writeUInt32LE(header.length,12);
 return Buffer.concat([prefix,header,Buffer.alloc((4-header.length%4)%4),pkg,code]);
}
function evidence(source){
 const nodes=[],digest=createHash('sha256').update(source).digest('hex');
 function walk(n){if(!n||typeof n!=='object')return;if(n.type==='CallExpression'&&n.callee?.property?.name==='invoke'){nodes.push({kind:'ipc-channel',observations:[{properties:{side:'renderer',operation:'invoke',resolution:'literal',channel:n.arguments[0]?.value},evidence:{artifact:{available:true,sha256:digest},location:{available:true,value:{kind:'source-range',source:'preload.js',start:{line:n.loc.start.line,column:n.loc.start.column},end:{line:n.loc.end.line,column:n.loc.end.column}}}}}]});}for(const [k,v] of Object.entries(n))if(k!=='loc'){if(Array.isArray(v))v.forEach(walk);else if(v&&typeof v==='object')walk(v);}}
 walk(parse(source));return {operation:'analyze_javascript_application',evidence_id:'ev_'+'f'.repeat(64),normalized_result:{graph:{nodes,coverage:{status:'complete',truncated:false}}}};
}
async function fixture(fn){const dir=await fs.mkdtemp(path.join(os.tmpdir(),'factory-pipeline-'));try{await fn(dir);}finally{await fs.rm(dir,{recursive:true,force:true});}}
const HEADER="const electron=require('electron');";
async function inputs(dir,source,producer){const asar=path.join(dir,'fixture.asar'),reaCli=path.join(dir,'fake-rea.mjs');await fs.writeFile(asar,archive(source));await fs.writeFile(reaCli,producer||`process.stdout.write(${JSON.stringify(JSON.stringify(evidence(source)))});`);return {asar,reaCli,out:path.join(dir,'result')};}
test('prepared source to candidate report is one inert workflow, never a verified CLI',()=>fixture(async dir=>{
 const marker=path.join(dir,'must-not-exist');const source=HEADER+`require('node:fs').writeFileSync(${JSON.stringify(marker)},'executed');electron.contextBridge.exposeInMainWorld('fixture',{read:()=>electron.ipcRenderer.invoke('read')});`;
 const args=await inputs(dir,source);const result=await analyze(args);
 assert.equal(result.status,'candidate');assert.equal(result.candidateCount,1);assert.equal(result.verified,false);assert.equal(result.runtimeObserved,false);
 await assert.rejects(fs.stat(marker),{code:'ENOENT'});
 const c=JSON.parse(await fs.readFile(path.join(args.out,result.records[0].contract),'utf8'));assert.deepEqual(c.candidates[0].apiPath,['fixture','read']);
 const before=await fs.readFile(path.join(args.out,'analysis-summary.json'));await assert.rejects(analyze(args),{code:'OUTPUT_EXISTS'});assert.deepEqual(await fs.readFile(path.join(args.out,'analysis-summary.json')),before);
}));
test('zero candidates stops with a blocked report and concrete unsupported ranges',()=>fixture(async dir=>{
 const source=HEADER+"function identity(){return electron.ipcRenderer.invoke('identity')}const other=require('./other');electron.contextBridge.exposeInMainWorld('fixture',{read:()=>other.invoke('read')});";
 const result=await analyze(await inputs(dir,source));assert.equal(result.status,'blocked');assert.equal(result.ok,false);assert.equal(result.candidateCount,0);assert.ok(result.records[0].nextSteps.length);assert.ok(result.records[0].unsupported);
}));
test('analyzer failure is retained and cannot become an empty success',()=>fixture(async dir=>{
 const args=await inputs(dir,HEADER,"process.stderr.write('synthetic failure');process.exitCode=9;");await assert.rejects(analyze(args),{code:'REA_FAILED'});
 const failure=JSON.parse(await fs.readFile(path.join(args.out,'analysis-failure.json')));assert.equal(failure.phase,'rea');assert.equal(failure.runtimeObserved,false);assert.equal(await fs.readFile(path.join(args.out,'rea.stderr'),'utf8'),'synthetic failure');await assert.rejects(fs.stat(path.join(args.out,'contracts')),{code:'ENOENT'});
}));
test('source mismatch remains an incomplete analysis, never a usable candidate',()=>fixture(async dir=>{
 const source=HEADER+"electron.contextBridge.exposeInMainWorld('fixture',{read:()=>electron.ipcRenderer.invoke('read')});";
 const args=await inputs(dir,source,`process.stdout.write(${JSON.stringify(JSON.stringify(evidence(source+' ')))});`);const r=await analyze(args);assert.equal(r.status,'incomplete');assert.equal(r.records[0].error.code,'SOURCE_DIGEST_MISMATCH');
}));
test('subprocess timeout and oversized output terminate the owned analyzer',async()=>{
 await assert.rejects(runBounded(process.execPath,['-e','setInterval(()=>{},1000)'],{timeoutMs:100}),{code:'ANALYSIS_TIMEOUT'});
 await assert.rejects(runBounded(process.execPath,['-e',"process.stdout.write('x'.repeat(100000))"],{maxOutput:100}),{code:'ANALYSIS_OUTPUT_LIMIT'});
});
test('timeout settles even when a detached descendant retains the output pipes',async()=>{
 const started=Date.now();let descendant;
 try {
  await assert.rejects(runBounded(process.execPath,['-e',"const {spawn}=require('node:child_process');const child=spawn(process.execPath,['-e','setTimeout(()=>{},10000)'],{stdio:['ignore',1,2],detached:true});console.log(child.pid);child.unref();"],{timeoutMs:300}),e=>{assert.equal(e.code,'ANALYSIS_TIMEOUT');descendant=Number(e.result.stdout.toString().trim());assert.ok(Number.isInteger(descendant)&&descendant>0);return true;});
  assert.ok(Date.now()-started<3000,'must not wait for descendant to close inherited pipes');
 }finally{if(descendant)try{process.kill(descendant,'SIGKILL');}catch{}}
});
