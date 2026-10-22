import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {buildExpression,validateMethod,validatePage,callMethod} from './bridge_runtime.mjs';
const pageUrl='file:///Applications/Fixture.app/Contents/Resources/index.html';
const method={apiPath:['settings','read'],targetPath:['bridge','ipc','invoke'],boundArgs:['settings.read'],params:['key'],arity:1,transport:'invoke',channel:'settings.read',status:'candidate'};
test('bound gateway calls original owner with fixed channel before caller data',async()=>{
 let observed;const window={location:{href:pageUrl},bridge:{ipc:{invoke(...args){assert.equal(this,window.bridge.ipc);observed=args;return 'value';}}}};
 const payload={text:'\");globalThis.injected=true;//',channel:'arbitrary.channel'};
 const r=await vm.runInNewContext(buildExpression(method,[payload],pageUrl),{window});
 assert.equal(r.value,'value');assert.deepEqual(JSON.parse(JSON.stringify(observed)),['settings.read',payload]);
 assert.throws(()=>buildExpression(method,['different.channel',payload],pageUrl),{code:'INVALID_ARGUMENTS'});
});
test('unbound and malformed gateway descriptors never execute',()=>{
 for(const m of [{...method,status:'gateway-unbound'},{...method,boundArgs:[]},{...method,boundArgs:['other']},{...method,boundArgs:['settings.read','extra']},{...method,targetPath:['bridge','__proto__']},{...method,targetPath:undefined}])assert.throws(()=>validateMethod(m),{code:'INVALID_METHOD'});
});
test('JSON prototype-named keys remain own data at the original gateway',async()=>{
 const payload=JSON.parse('{"__proto__":{"hidden":true},"x":1}');let observed;
 const window={location:{href:pageUrl},bridge:{ipc:{invoke(channel,value){observed=value;return value;}}}};
 const r=await vm.runInNewContext(buildExpression(method,[payload],pageUrl),{window});
 assert.equal(Object.hasOwn(observed,'__proto__'),true);assert.equal(observed.hidden,undefined);
 assert.deepEqual(JSON.parse(JSON.stringify(r.value)),payload);
});
test('missing conditional exposure is a failure before IPC dispatch',async()=>{
 await assert.rejects(vm.runInNewContext(buildExpression(method,['key'],pageUrl),{window:{location:{href:pageUrl}}}),/BRIDGE_UNAVAILABLE/);
});
test('bound target substitution stops before runtime inspection',async()=>{
 const config={methods:[method],appPath:'/Applications/Fixture.app',pageUrl};
 const session={schema:'rea-cli-factory.local-session.v1',pid:123,port:19000,profile:'/private/profile',targetId:'ABC',...config};let inspected=false;
 for(const altered of [{...method,targetPath:['bridge','other']},{...method,channel:'other',boundArgs:['other']}])await assert.rejects(callMethod(config,session,altered,['key'],'.',{identity:async()=>{inspected=true;}}),{code:'METHOD_NOT_SELECTED'});
 assert.equal(inspected,false);
});
test('custom local protocol requires explicit opt-in and canonical app resource path',async()=>{
 const app='/Applications/Fixture.app',url='localapp://fixture'+app+'/Contents/Resources/index.html#route';
 assert.throws(()=>validatePage(url,app),{code:'INVALID_PAGE'});
 assert.equal(validatePage(url,app,'localapp'),url);
 for(const [bad,scheme]of [['https://fixture'+app+'/Contents/Resources/index.html','https'],['localapp://fixture/Applications/Other.app/Contents/Resources/index.html','localapp'],['localapp://fixture'+app+'/Contents/Resources/%2f..%2fsecret','localapp'],['localapp://user@fixture'+app+'/Contents/Resources/index.html','localapp']])assert.throws(()=>validatePage(bad,app,scheme),{code:'INVALID_PAGE'});
 let observed=false;const window={location:{href:url},bridge:{ipc:{invoke(channel,key){observed=true;assert.equal(channel,'settings.read');return key;}}}};
 assert.equal((await vm.runInNewContext(buildExpression(method,['key'],url,'localapp'),{window})).value,'key');assert.equal(observed,true);
 window.location.href=url+'-changed';await assert.rejects(vm.runInNewContext(buildExpression(method,['key'],url,'localapp'),{window}),/PAGE_CHANGED/);
});
