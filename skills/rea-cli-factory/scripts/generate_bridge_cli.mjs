#!/usr/bin/env node
/** Generate a private candidate CLI from explicit method selections; never execute the target. */
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {readJson,readBytes,validateMethod,validatePage,error} from './bridge_runtime.mjs';
const ROOT=path.dirname(fileURLToPath(import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex');
export async function generate({contractPath,baselinePath,pageUrl,localScheme,selected,out}){
 const contract=await readJson(contractPath,4*1024*1024),raw=await readBytes(baselinePath);
 if(raw.length>1024*1024)throw error('INPUT_LIMIT','Baseline too large');
 const env=JSON.parse(raw),baseline=env.ok===true?env.result:env;
 if(contract.schema!=='rea-cli-factory.bridge-contract.v1'||!/^ev_[a-f0-9]{64}$/.test(contract.evidenceId)||!baseline||baseline.schema!=='rea-cli-factory.app-inventory.v1'||!baseline.app_path||typeof baseline.identity?.CFBundleExecutable!=='string')throw error('INVALID_CONTRACT','Expected a source-bound contract and application inventory');
 if(!Array.isArray(selected)||selected.length<1||new Set(selected).size!==selected.length)throw error('INVALID_SELECTION','Select at least one unique method explicitly');
 const methods=selected.map(name=>{const m=contract.candidates.filter(m=>m.apiPath.join('.')===name);if(m.length!==1)throw error('INVALID_SELECTION','Selected method is missing or ambiguous');return validateMethod(m[0]);});
 const fixedPage=validatePage(pageUrl,baseline.app_path,localScheme);
 const config={schema:'rea-cli-factory.generated-bridge.v1',status:'candidate',appPath:baseline.app_path,executable:baseline.identity.CFBundleExecutable,pageUrl:fixedPage,...(localScheme?{localScheme}:{}),baselineSha256:sha(raw),evidenceId:contract.evidenceId,source:contract.source,...(contract.sources?{sources:contract.sources}:{}),coverage:contract.coverage,methods,limitations:['Generated mapping does not prove safety, argument semantics or runtime availability.','Requires an explicitly owned runtime session and separate business readback.',...(localScheme?['Custom scheme mapping to this packaged resource requires operator verification; URL shape alone does not establish local content.']:[])]};
 const destination=path.resolve(out);await fs.mkdir(destination,{mode:0o700});
 try{
  for(const name of ['bridge_runtime.mjs','check_compatibility.py','inventory_app.py'])await fs.copyFile(path.join(ROOT,name),path.join(destination,name),1);
  await fs.writeFile(path.join(destination,'baseline.json'),raw,{flag:'wx',mode:0o600});
  await fs.writeFile(path.join(destination,'config.json'),JSON.stringify(config,null,2)+'\n',{flag:'wx',mode:0o600});
  await fs.writeFile(path.join(destination,'cli.mjs'),"#!/usr/bin/env node\nimport {fileURLToPath} from 'node:url';\nimport path from 'node:path';\nimport {runCli} from './bridge_runtime.mjs';\nprocess.exitCode=await runCli(path.dirname(fileURLToPath(import.meta.url)));\n",{flag:'wx',mode:0o700});
 }catch(e){throw error('GENERATION_INCOMPLETE','Generation failed; inspect the newly created output directory before retrying');}
 return {ok:true,status:'candidate',output:destination,selectedMethods:methods.map(m=>m.apiPath.join('.')),verified:false};
}
async function main(){const args=process.argv.slice(2);if(args[0]==='--help'){console.log('--contract JSON --baseline JSON --page-url URL [--local-scheme SCHEME] --select root.method[,root.method] --out NEW_DIRECTORY');return;}const o={};for(let i=0;i<args.length;i+=2){if(!['--contract','--baseline','--page-url','--local-scheme','--select','--out'].includes(args[i])||!args[i+1]||o[args[i]])throw error('USAGE','Invalid arguments');o[args[i]]=args[i+1];}if(!['--contract','--baseline','--page-url','--select','--out'].every(k=>o[k]))throw error('USAGE','See --help');console.log(JSON.stringify(await generate({contractPath:o['--contract'],baselinePath:o['--baseline'],pageUrl:o['--page-url'],localScheme:o['--local-scheme'],selected:o['--select'].split(','),out:o['--out']})));}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{console.error(JSON.stringify({ok:false,error:{code:e.code||'ERROR',message:e.message}}));process.exitCode=1;});
