#!/usr/bin/env node
/** Prepare selected sources, run an explicit REA CLI, and preserve every discovery outcome. */
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {createHash} from 'node:crypto';
import {discover} from './discover_bridge.mjs';
import {discoverModules} from './discover_modules.mjs';
import {readBytes,readJson,error} from './bridge_runtime.mjs';
const HERE=path.dirname(fileURLToPath(import.meta.url));
const SHA=b=>createHash('sha256').update(b).digest('hex');

export function discoverCombined(sources,name,evidence){
 const direct=discover(sources[name],name,evidence),modules=discoverModules(sources,name,evidence);
 const methods=new Map(),conflicts=new Set();
 for(const candidate of [...direct.candidates,...modules.candidates]){
  const key=candidate.apiPath.join('.'),existing=methods.get(key);
  if(existing&&['params','arity','transport','channel'].some(k=>JSON.stringify(existing[k])!==JSON.stringify(candidate[k])))conflicts.add(key);
  methods.set(key,candidate);
 }
 for(const key of conflicts)methods.delete(key);
 const names=new Set(methods.keys());
 const unsupported=[...(modules.candidates.length?modules.unsupported:direct.unsupported),...Array.from(conflicts,name=>({reason:'conflicting-static-descriptors',apiPath:name.split('.')}))].filter(x=>!x.apiPath||!names.has(x.apiPath.join('.')));
 return {...modules,candidates:[...methods.values()],unsupported,analysis:{...modules.analysis,directCandidates:direct.candidates.length,moduleCandidates:modules.candidates.length,conflicts:conflicts.size}};
}

// Bounds both output streams and kills the owned process group on timeout/overflow.
export async function runBounded(command,args,{timeoutMs=180000,maxOutput=64*1024*1024}={}) {
 return new Promise((resolve,reject)=>{
  const child=spawn(command,args,{stdio:['ignore','pipe','pipe'],detached:process.platform!=='win32'});
  let stdout=[],stderr=[],bytes=0,errBytes=0,settled=false;
  const result=code=>({code,stdout:Buffer.concat(stdout),stderr:Buffer.concat(stderr)});
  const stop=code=>{if(settled)return;settled=true;clearTimeout(timer);const failure=error(code,'Analysis subprocess stopped; inspect retained phase result');failure.result=result(null);try{process.kill(process.platform==='win32'?child.pid:-child.pid,'SIGKILL');}catch{}child.stdout.destroy();child.stderr.destroy();reject(failure);};
  const timer=setTimeout(()=>stop('ANALYSIS_TIMEOUT'),timeoutMs);
  child.stdout.on('data',b=>{bytes+=b.length;if(bytes>maxOutput)stop('ANALYSIS_OUTPUT_LIMIT');else stdout.push(b);});
  child.stderr.on('data',b=>{errBytes+=b.length;if(errBytes>1024*1024)stop('ANALYSIS_LOG_LIMIT');else stderr.push(b);});
  child.on('error',e=>{clearTimeout(timer);if(!settled){settled=true;reject(e);}});
  child.on('close',code=>{clearTimeout(timer);if(!settled){settled=true;resolve(result(code));}});
 });
}

const ADVICE={
 'imported-wrapper-call':'Review the imported forwarding module and its source-bound IPC evidence; cross-file resolution is unsupported.',
 'factory-created-api':'Review the API factory and its inputs; generated objects are unsupported.',
 'unsupported-or-mutated-object':'Review object construction or mutation; do not infer a stable interface.',
 'unknown-or-shadowed-exposure':'Review Electron binding provenance and scope.',
 'dynamic-channel':'A literal source-bound channel is required; do not guess the resolved channel.',
 'no-exposed-api':'No supported static exposure in this selected file; this does not prove absence in the application.'
};
export async function analyze({asar,reaCli,out}) {
 const root=path.resolve(out),start=performance.now(),timings={},toolFiles=['analyze_electron.mjs','prepare_electron.py','discover_bridge.mjs','discover_modules.mjs'];
 // Caller selects the installed analyzer; never download or execute the app here.
 const reaPath=await fs.realpath(reaCli),reaStat=await fs.stat(reaPath);
 if(!reaStat.isFile()||!['.js','.mjs','.cjs'].includes(path.extname(reaPath)))throw error('INVALID_ANALYZER','Select the installed REA JavaScript CLI file');
 let began=false,phase='prepare';
 try {
  let t=performance.now();
  const p=await runBounded('python3',[path.join(HERE,'prepare_electron.py'),'--asar',path.resolve(asar),'--out',root],{timeoutMs:60000,maxOutput:1024*1024});
  if(p.code!==0){let code='PREPARATION_FAILED';try{code=JSON.parse(p.stdout).error.code;}catch{}throw error(code,'Source preparation failed; no analysis or application execution attempted');}
  began=true;timings.prepareMs=Math.round(performance.now()-t);
  const preparation=await readJson(path.join(root,'preparation.json'),4*1024*1024);
  const tools=Object.fromEntries(await Promise.all(toolFiles.map(async name=>[name,SHA(await readBytes(path.join(HERE,name)))])));
  await fs.writeFile(path.join(root,'run-input.json'),JSON.stringify({schema:'rea-cli-factory.blind-input.v1',startedAt:new Date().toISOString(),tools,analyzer:{path:reaPath,sha256:SHA(await readBytes(reaPath,16*1024*1024))},archive:preparation.archive,scope:'Selected packaged sources only; operator must separately record prior knowledge and manual interventions.'},null,2)+'\n',{flag:'wx',mode:0o600});
  phase='rea';t=performance.now();
  let r;
  try{r=await runBounded(process.execPath,[reaPath,'analyze-javascript-application',path.join(root,'sources'),'--artifact-format','directory','--analysis-timeout-ms','60000','--format','json']);}
  catch(e){if(e.result){await fs.writeFile(path.join(root,'rea-partial.stdout'),e.result.stdout,{flag:'wx',mode:0o600});await fs.writeFile(path.join(root,'rea.stderr'),e.result.stderr,{flag:'wx',mode:0o600});}throw e;}
  await fs.writeFile(path.join(root,'rea-evidence.json'),r.stdout,{flag:'wx',mode:0o600});
  await fs.writeFile(path.join(root,'rea.stderr'),r.stderr,{flag:'wx',mode:0o600});
  if(r.code!==0)throw error('REA_FAILED','REA did not finish successfully; raw output retained');
  const evidence=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(r.stdout));
  timings.reaMs=Math.round(performance.now()-t);phase='discover';t=performance.now();
  const records=[],sources={};await fs.mkdir(path.join(root,'contracts'),{mode:0o700});
  for(const f of preparation.files.filter(f=>f.path!=='package.json')){
   const bytes=await readBytes(path.join(root,f.outputPath),2*1024*1024);
   if(SHA(bytes)!==f.sha256)throw error('PREPARED_SOURCE_CHANGED','Prepared source changed');
   sources[f.path]=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  }
  for(const f of preparation.files.filter(f=>f.path!=='package.json')){
   const index=records.length,record={source:f.path,sourceSha256:f.sha256};
   try {
    const contract=discoverCombined(sources,f.path,evidence);
    const contractPath=`contracts/${String(index).padStart(3,'0')}.json`;
    await fs.writeFile(path.join(root,contractPath),JSON.stringify(contract,null,2)+'\n',{flag:'wx',mode:0o600});
    const reasons={};for(const item of contract.unsupported)reasons[item.reason]=(reasons[item.reason]||0)+1;
    if(!contract.candidates.length&&!contract.unsupported.length)reasons['no-static-exposure']=1;
    Object.assign(record,{status:contract.candidates.length?'candidate':'unsupported',candidates:contract.candidates.length,unsupported:contract.unsupported.length,reasons,contract:contractPath,methods:contract.candidates.map(m=>({name:m.apiPath.join('.'),params:m.params})),nextSteps:[...new Set(contract.unsupported.map(item=>item.nextStep||ADVICE[item.reason]||'Review the recorded source range; this structure is outside the supported subset.'))]});
   }catch(e){Object.assign(record,{status:'error',error:{code:e.code||'INVALID_SOURCE'},nextSteps:['Inspect this source/evidence mismatch before retrying; do not substitute guessed methods.']});}
   records.push(record);
  }
  timings.discoverMs=Math.round(performance.now()-t);timings.totalMs=Math.round(performance.now()-start);
  const count=records.reduce((n,r)=>n+(r.candidates||0),0),failed=records.some(r=>r.status==='error');
  const report={schema:'rea-cli-factory.electron-analysis.v1',ok:count>0&&!failed,status:failed?'incomplete':count?'candidate':'blocked',candidateCount:count,verified:false,runtimeObserved:false,evidenceId:evidence.evidence_id,coverage:evidence.normalized_result?.graph?.coverage,records,timings,limitations:['Candidate-only selected-source analysis, not a generated or verified app CLI.','Zero candidates stops here; no application is launched and no interface is guessed.','Choose task methods, review semantics and lifecycle, then generate a private CLI and verify real readback.','A replay after inspection or tool changes is not a fresh blind test.']};
  await fs.writeFile(path.join(root,'analysis-summary.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});return report;
 }catch(e){if(began)await fs.writeFile(path.join(root,'analysis-failure.json'),JSON.stringify({ok:false,status:'blocked',phase,error:{code:e.code||'INVALID_ANALYSIS'},runtimeObserved:false,verified:false},null,2)+'\n',{flag:'wx',mode:0o600});throw e;}
}
async function main(){const a=process.argv.slice(2);if(a.length===1&&a[0]==='--help'){console.log('--asar APP_ASAR --rea-cli INSTALLED_REA_MJS --out NEW_PRIVATE_DIRECTORY');return;}const o={};for(let i=0;i<a.length;i+=2){if(!['--asar','--rea-cli','--out'].includes(a[i])||!a[i+1]||o[a[i]])throw error('USAGE','See --help');o[a[i]]=a[i+1];}if(Object.keys(o).length!==3)throw error('USAGE','See --help');const r=await analyze({asar:o['--asar'],reaCli:o['--rea-cli'],out:o['--out']});console.log(JSON.stringify({ok:r.ok,status:r.status,candidateCount:r.candidateCount,verified:false,summary:path.join(path.resolve(o['--out']),'analysis-summary.json'),timings:r.timings}));if(!r.ok)process.exitCode=3;}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{console.error(JSON.stringify({ok:false,error:{code:e.code||'ANALYSIS_FAILED',message:e.message}}));process.exitCode=2;});
