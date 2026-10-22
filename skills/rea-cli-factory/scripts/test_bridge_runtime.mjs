import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {readBytes,buildExpression,validateSession,selectTarget,callMethod} from './bridge_runtime.mjs';
import {generate} from './generate_bridge_cli.mjs';
const method={apiPath:['bridge','save'],params:['data'],arity:1,transport:'send',channel:'save',status:'candidate'};
const config={methods:[method],appPath:'/Applications/Fixture.app',pageUrl:'file:///Applications/Fixture.app/Contents/Resources/app.asar/index.html'};
const session={schema:'rea-cli-factory.local-session.v1',pid:123,port:19000,profile:'/private/test-profile',owner:'00000000-0000-0000-0000-000000000000',targetId:'ABC',...{appPath:config.appPath,pageUrl:config.pageUrl}};
const target={type:'page',id:'ABC',url:session.pageUrl,webSocketDebuggerUrl:'ws://127.0.0.1:19000/devtools/page/ABC'};
test('expression preserves JSON as data and calls the existing method with owner',async()=>{
 const value={text:'");globalThis.injected=true;//',nested:[1,true,null]};let observed;
 const window={location:{href:config.pageUrl},bridge:{save(data){assert.equal(this,window.bridge);observed=data;return data;}}};
 const result=await vm.runInNewContext(buildExpression(method,[value],config.pageUrl),{window});assert.deepEqual(JSON.parse(JSON.stringify(observed)),value);assert.deepEqual(JSON.parse(JSON.stringify(result.value)),value);
});
test('arity and dangerous property names are rejected',()=>{
 assert.throws(()=>buildExpression(method,[],config.pageUrl),{code:'INVALID_ARGUMENTS'});
 assert.throws(()=>buildExpression({...method,apiPath:['bridge','__proto__']},[1],config.pageUrl),{code:'INVALID_METHOD'});
});
test('wrong app, endpoint, target and page fail closed',()=>{
 assert.throws(()=>validateSession({...session,appPath:'/Applications/Other.app'},config),{code:'INVALID_SESSION'});
 for(const t of [{...target,id:'OTHER'},{...target,url:target.url+'?other'}])assert.throws(()=>selectTarget([t],session),{code:'WRONG_TARGET'});
 for(const url of ['ws://example.com:19000/devtools/page/ABC','ws://127.0.0.1:19001/devtools/page/ABC','ws://127.0.0.1:19000/devtools/page/OTHER'])assert.throws(()=>selectTarget([{...target,webSocketDebuggerUrl:url}],session),{code:'WRONG_ENDPOINT'});
});
test('incompatible app never connects or sends',async()=>{
 let connected=false;await assert.rejects(callMethod(config,session,method,[1],'.',{identity:async()=>{throw Object.assign(new Error('changed'),{code:'APP_CHANGED'});},connect:async()=>{connected=true;}}),{code:'APP_CHANGED'});assert.equal(connected,false);
});
test('invalid arguments stop before process inspection',async()=>{
 let inspected=false;await assert.rejects(callMethod(config,session,method,[],'.',{identity:async()=>{inspected=true;}}),{code:'INVALID_ARGUMENTS'});assert.equal(inspected,false);
});
test('send and invoke never label business success; connection always closes',async()=>{
 for(const transport of ['send','invoke']){let closed=false;const r=await callMethod({...config,methods:[{...method,transport}]},session,{...method,transport},[1],'.',{identity:async()=>{},targets:async()=>[target],connect:async()=>({evaluate:async()=>({value:1}),close:()=>{closed=true;}})});assert.equal(r.verified,false);assert.equal(r.status,transport==='send'?'dispatched':'returned');assert.equal(closed,true);}
 let closed=false;await assert.rejects(callMethod(config,session,method,[1],'.',{identity:async()=>{},targets:async()=>[target],connect:async()=>({evaluate:async()=>{throw new Error('failed');},close:()=>{closed=true;}})}));assert.equal(closed,true);
});
test('generator selects explicitly, emits a usable CLI, refuses overwrite and unknown methods',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'rea-generator-'));
 try{
 const cp=path.join(dir,'contract.json'),bp=path.join(dir,'baseline.json'),out=path.join(dir,'generated');
 await fs.writeFile(cp,JSON.stringify({schema:'rea-cli-factory.bridge-contract.v1',evidenceId:'ev_'+'a'.repeat(64),candidates:[method,{...method,apiPath:['bridge','unselected']}],source:{name:'preload.js',sha256:'b'.repeat(64)},coverage:{status:'partial'}}));
 await fs.writeFile(bp,JSON.stringify({schema:'rea-cli-factory.app-inventory.v1',app_path:config.appPath,identity:{CFBundleExecutable:'Fixture'}}));
 const opts={contractPath:cp,baselinePath:bp,pageUrl:config.pageUrl,selected:['bridge.save'],out};
 assert.equal((await generate(opts)).status,'candidate');
 const list=JSON.parse(execFileSync(process.execPath,[path.join(out,'cli.mjs'),'list'],{encoding:'utf8'}));assert.equal(list.methods.length,1);assert.equal(list.methods[0].name,'bridge.save');
 const original=await fs.readFile(path.join(out,'config.json'),'utf8');await assert.rejects(generate(opts),{code:'EEXIST'});assert.equal(await fs.readFile(path.join(out,'config.json'),'utf8'),original);
 await assert.rejects(generate({...opts,out:path.join(dir,'bad'),selected:['absent']}),{code:'INVALID_SELECTION'});
 await assert.rejects(generate({...opts,out:path.join(dir,'remote'),pageUrl:'https://example.com/'}),{code:'INVALID_PAGE'});
 const withQuery=config.pageUrl+'?view=fixture&locale=en';
 await generate({...opts,out:path.join(dir,'query'),pageUrl:withQuery});
 assert.equal(JSON.parse(await fs.readFile(path.join(dir,'query','config.json'))).pageUrl,withQuery);
 const querySession={...session,pageUrl:withQuery};
 assert.equal(selectTarget([{...target,url:withQuery}],querySession).url,withQuery);
 assert.throws(()=>selectTarget([{...target,url:withQuery.replace('view=fixture','view=other')}],querySession),{code:'WRONG_TARGET'});
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('unselected programmatic method cannot reach identity inspection',async()=>{
 let touched=false;await assert.rejects(callMethod(config,session,{...method,apiPath:['bridge','unselected']},[1],'.',{identity:async()=>{touched=true;}}),{code:'METHOD_NOT_SELECTED'});assert.equal(touched,false);
});
test('navigation between target lookup and evaluation is rejected before bridge call',async()=>{
 let called=false;const window={location:{href:config.pageUrl+'#other'},bridge:{save(){called=true;}}};
 await assert.rejects(vm.runInNewContext(buildExpression(method,[1],config.pageUrl),{window}),/PAGE_CHANGED/);assert.equal(called,false);
});

test('baseline byte reader rejects oversized input and directories',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'rea-bounded-'));try{const file=path.join(dir,'data');await fs.writeFile(file,'x'.repeat(33));await assert.rejects(readBytes(file,32),{code:'INPUT_LIMIT'});await assert.rejects(readBytes(dir,32),{code:'INPUT_LIMIT'});}finally{await fs.rm(dir,{recursive:true,force:true});}
});
