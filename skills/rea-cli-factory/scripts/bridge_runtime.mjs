/** Generic runner for explicitly selected preload methods. Never asserts business success. */
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
export const error=(code,message)=>Object.assign(new Error(message),{code});
const digest=data=>createHash('sha256').update(data).digest('hex');
const ident=s=>typeof s==='string'&&/^[A-Za-z_$][\w$]*$/.test(s)&&!['__proto__','constructor','prototype'].includes(s);
export async function readBytes(file,max=1024*1024){
 const h=await fs.open(file,'r');try{const stat=await h.stat();if(!stat.isFile()||stat.size>max)throw error('INPUT_LIMIT','Expected a bounded regular JSON file');const b=Buffer.alloc(max+1);let total=0;while(total<b.length){const {bytesRead}=await h.read(b,total,b.length-total,null);if(!bytesRead)break;total+=bytesRead;}if(total>max)throw error('INPUT_LIMIT','Input grew beyond limit');return b.subarray(0,total);}finally{await h.close();}
}
export async function readJson(file,max=1024*1024){return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await readBytes(file,max)));}
export function validateMethod(m){
 if(!m||!Array.isArray(m.apiPath)||m.apiPath.length<2||m.apiPath.length>8||!m.apiPath.every(ident)||!Array.isArray(m.params)||!m.params.every(ident)||new Set(m.params).size!==m.params.length||m.arity!==m.params.length||!Number.isInteger(m.arity)||m.arity>16||!['send','invoke'].includes(m.transport)||m.status!=='candidate')throw error('INVALID_METHOD','Unsupported method contract');
 // Gateway commands carry an immutable channel prefix, never a caller-supplied channel.
 if(m.targetPath!==undefined||m.boundArgs!==undefined){
  if(!Array.isArray(m.targetPath)||m.targetPath.length<2||m.targetPath.length>8||!m.targetPath.every(ident)||!Array.isArray(m.boundArgs)||m.boundArgs.length!==1||typeof m.channel!=='string'||!m.channel||m.channel.length>240||m.boundArgs[0]!==m.channel)throw error('INVALID_METHOD','Gateway commands require one fixed channel and target path');
 }
 return m;
}
export function validatePage(pageUrl,appPath,localScheme){
 let page;try{page=new URL(pageUrl);}catch{throw error('INVALID_PAGE','Fixed local resource URL required');}
 const custom=typeof localScheme==='string'&&/^[a-z][a-z0-9+.-]{1,31}$/.test(localScheme)&&!['file','http','https','ws','wss','data','javascript','ftp','blob'].includes(localScheme)&&page.protocol===localScheme+':'&&page.host;
 if(page.username||page.password||page.port||!(page.protocol==='file:'&&!page.host&&!localScheme||custom))throw error('INVALID_PAGE','Explicit local scheme or file URL required');
 let decoded;try{decoded=decodeURIComponent(page.pathname);}catch{throw error('INVALID_PAGE','Invalid resource encoding');}
 if(/%2f|%5c|%00/i.test(page.pathname)||decoded.includes('\\')||decoded.includes('\0')||path.posix.normalize(decoded)!==decoded)throw error('INVALID_PAGE','Noncanonical resource path');
 if(appPath){const root=path.join(appPath,'Contents/Resources')+path.sep;if(!decoded.startsWith(root))throw error('INVALID_PAGE','Resource path must belong to the selected application');}
 return page.href;
}
export function buildExpression(method,args,pageUrl,localScheme){
 validatePage(pageUrl,undefined,localScheme);
 validateMethod(method);
 if(!Array.isArray(args)||args.length!==method.arity)throw error('INVALID_ARGUMENTS',`Expected ${method.arity} positional JSON arguments`);
 const encoded=JSON.stringify([...(method.boundArgs||[]),...args]);if(encoded.length>1024*1024)throw error('INPUT_LIMIT','Arguments too large');
 return `(async()=>{if(window.location.href!==${JSON.stringify(pageUrl)})throw new Error('PAGE_CHANGED');const keys=${JSON.stringify(method.targetPath||method.apiPath)};let owner=window;for(const key of keys.slice(0,-1)){if(owner==null)throw new Error('BRIDGE_UNAVAILABLE');owner=owner[key];}const fn=owner?.[keys[keys.length-1]];if(typeof fn!=='function')throw new Error('BRIDGE_UNAVAILABLE');const value=await Reflect.apply(fn,owner,JSON.parse(${JSON.stringify(encoded)}));return {hasValue:value!==undefined,value:value===undefined?null:value};})()`;
}
export function validateSession(s,config){
 if(!s||s.schema!=='rea-cli-factory.local-session.v1'||!Number.isInteger(s.pid)||s.pid<1||!Number.isInteger(s.port)||s.port<1||s.port>65535||typeof s.targetId!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(s.targetId)||s.appPath!==config.appPath||typeof s.profile!=='string'||!path.isAbsolute(s.profile)||s.profile.includes('\n')||s.pageUrl!==config.pageUrl)throw error('INVALID_SESSION','Session does not match the fixed target');
 return s;
}
export function selectTarget(list,session){
 if(!Array.isArray(list))throw error('WRONG_TARGET','Invalid target list');
 const matches=list.filter(t=>t.type==='page'&&t.id===session.targetId&&t.url===session.pageUrl);
 if(matches.length!==1)throw error('WRONG_TARGET','Exact target ID and page URL required');
 const target=matches[0],u=new URL(target.webSocketDebuggerUrl);
 if(u.protocol!=='ws:'||u.hostname!=='127.0.0.1'||Number(u.port)!==session.port||u.username||u.password||u.pathname!==`/devtools/page/${session.targetId}`)throw error('WRONG_ENDPOINT','Unexpected local debugger endpoint');
 return target;
}
export async function connect(target){
 const ws=new WebSocket(target.webSocketDebuggerUrl);let id=0;const pending=new Map();
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{ws.close();reject(error('CONNECT_TIMEOUT','Local debugger timeout'));},3000);ws.onopen=()=>{clearTimeout(timer);resolve();};ws.onerror=()=>{clearTimeout(timer);reject(error('CONNECT_FAILED','Local debugger unavailable'));};});
 ws.onmessage=event=>{let m;try{m=JSON.parse(event.data);}catch{return;}const p=pending.get(m.id);if(!p)return;pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(error('CDP_ERROR','Debugger rejected request')):p.resolve(m.result);};
 ws.onclose=()=>{for(const p of pending.values()){clearTimeout(p.timer);p.reject(error('OUTCOME_UNKNOWN','Target closed; read back before retrying a write'));}pending.clear();};
 return {close:()=>ws.close(),async evaluate(expression){const r=await new Promise((resolve,reject)=>{const n=++id;const timer=setTimeout(()=>{pending.delete(n);reject(error('OUTCOME_UNKNOWN','Timed out; read back before retrying a write'));},10000);pending.set(n,{resolve,reject,timer});ws.send(JSON.stringify({id:n,method:'Runtime.evaluate',params:{expression,awaitPromise:true,returnByValue:true}}));});if(r.exceptionDetails)throw error('APP_CALL_FAILED','App method failed; inspect state before retrying');if(r.result?.subtype==='error'||!r.result?.value)throw error('INVALID_RESULT','No structured return value');return r.result.value;}};
}
export async function assertLocalIdentity(session,config,dir){
 if(process.platform!=='darwin')throw error('UNSUPPORTED_HOST','This process-binding implementation requires macOS');
 const baseline=await readBytes(path.join(dir,'baseline.json'));
 if(digest(baseline)!==config.baselineSha256)throw error('BASELINE_CHANGED','Generated baseline changed; regenerate only after verification');
 try{const r=JSON.parse(execFileSync('python3',[path.join(dir,'check_compatibility.py'),'--app',config.appPath,'--baseline',path.join(dir,'baseline.json')],{encoding:'utf8',timeout:30000}));if(r.ok!==true)throw error('APP_CHANGED','Application no longer matches baseline');}
 catch(e){if(e.code==='APP_CHANGED')throw e;let r;try{r=JSON.parse(e.stdout);}catch{}throw error(r?.error?.code||'PREFLIGHT_FAILED','Application compatibility check failed');}
 const ids=execFileSync('/usr/sbin/lsof',['-nP',`-iTCP:${session.port}`,'-sTCP:LISTEN','-Fp'],{encoding:'utf8',timeout:3000}).trim().split('\n').filter(l=>l.startsWith('p'));
 if(ids.length!==1||ids[0]!==`p${session.pid}`)throw error('WRONG_PROCESS','Debug listener is not the selected app PID');
 const exe=path.join(config.appPath,'Contents/MacOS',config.executable);
 const cmd=execFileSync('/bin/ps',['-p',String(session.pid),'-o','command='],{encoding:'utf8',timeout:3000}).trim();
 if(!cmd.startsWith(exe+' ')||!cmd.endsWith(`--rea-cli-owner=${session.owner}`)||typeof session.owner!=='string'||!/^[a-f0-9-]{36}$/.test(session.owner)||!cmd.includes(` --user-data-dir=${session.profile} `))throw error('WRONG_PROCESS','Executable, profile or ownership marker did not match');
 if(await fs.realpath(session.profile)!==session.profile)throw error('WRONG_PROFILE','Profile must be a real absolute directory');
}
export async function callMethod(config,session,method,args,dir,deps={}){
 validateSession(session,config);validateMethod(method);
 const selected=(config.methods||[]).filter(m=>m.apiPath.join('.')===method.apiPath.join('.'));
 if(selected.length!==1||['arity','transport','channel','params','targetPath','boundArgs'].some(k=>JSON.stringify(selected[0][k])!==JSON.stringify(method[k])))throw error('METHOD_NOT_SELECTED','Only the exact selected descriptor may run');
 validatePage(config.pageUrl,config.appPath,config.localScheme);
 const expression=buildExpression(selected[0],args,config.pageUrl,config.localScheme);
 await (deps.identity||assertLocalIdentity)(session,config,dir);
 const list=await (deps.targets|| (async()=>{const r=await fetch(`http://127.0.0.1:${session.port}/json/list`,{signal:AbortSignal.timeout(3000)});if(!r.ok)throw error('TARGET_LIST_FAILED','Cannot inspect selected target');return r.json();}))();
 const target=selectTarget(list,session),client=await (deps.connect||connect)(target);
 try{const result=await client.evaluate(expression);return {ok:true,status:method.transport==='send'?'dispatched':'returned',verified:false,method:method.apiPath.join('.'),result:result.value,limitations:['A return or send dispatch is not a business verification receipt.']};}finally{client.close();}
}
export async function runCli(dir,args=process.argv.slice(2)){
 try{
  const config=await readJson(path.join(dir,'config.json'));if(config.schema!=='rea-cli-factory.generated-bridge.v1'||!Array.isArray(config.methods))throw error('INVALID_CONFIG','Unknown generated configuration');
  if(args.length===0||args[0]==='--help'){console.log('Generated candidate bridge CLI\n  list\n  call --method root.method --args JSON_ARRAY --session SESSION_JSON\nRequires an owned, already-running app session. No automatic launch or business-success claim.');return 0;}
  if(args.length===1&&args[0]==='list'){console.log(JSON.stringify({status:'candidate',methods:config.methods.map(m=>({name:m.apiPath.join('.'),params:m.params,transport:m.transport})),evidenceId:config.evidenceId}));return 0;}
  if(args.length!==7||args[0]!=='call'||args[1]!=='--method'||args[3]!=='--args'||args[5]!=='--session')throw error('USAGE','See --help');
  const m=config.methods.find(m=>m.apiPath.join('.')===args[2]);if(!m)throw error('METHOD_NOT_SELECTED','Only explicitly selected methods can be called');
  const result=await callMethod(config,await readJson(args[6]),m,JSON.parse(args[4]),dir);console.log(JSON.stringify(result));return 0;
 }catch(e){console.error(JSON.stringify({ok:false,error:{code:e.code||'INVALID_INPUT',message:e.message}}));return 1;}
}
