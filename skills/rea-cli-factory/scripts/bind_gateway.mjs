/** Inert, bounded business-call binding. Raw IPC gateways are never CLI candidates. */
import {parse} from '@babel/parser';
import {createHash} from 'node:crypto';
const sha=text=>createHash('sha256').update(text).digest('hex');
const fail=code=>{const e=new Error(code);e.code=code;throw e;};
const safe=s=>typeof s==='string'&&/^[A-Za-z_$][\w$]{0,119}$/.test(s)&&!['constructor','prototype','__proto__'].includes(s);
const member=n=>['MemberExpression','OptionalMemberExpression'].includes(n?.type);
const call=n=>['CallExpression','OptionalCallExpression'].includes(n?.type);
const key=n=>member(n)?n.computed?(n.property.type==='StringLiteral'?n.property.value:null):n.property.name:null;
const id=(n,name)=>n?.type==='Identifier'&&(name===undefined||n.name===name);
const loc=(n,source)=>({source,start:{line:n.loc.start.line,column:n.loc.start.column},end:{line:n.loc.end.line,column:n.loc.end.column}});
const children=n=>Object.entries(n).flatMap(([k,v])=>['loc','extra','comments','tokens','errors'].includes(k)?[]:Array.isArray(v)?v.filter(x=>x?.type).map(x=>[k,x]):v?.type?[[k,v]]:[]);
const fn=n=>['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression','ObjectMethod','ClassMethod'].includes(n.type);
const returned=n=>n?.type==='BlockStatement'&&n.body.length===1&&n.body[0].type==='ReturnStatement'?n.body[0].argument:null;
function staticPath(n){if(id(n))return [n.name];if(!member(n)||!safe(key(n)))return null;const p=staticPath(n.object);return p?[...p,key(n)]:null;}
function proxyGetter(n){
 if(n?.type!=='NewExpression'||!id(n.callee,'Proxy')||n.arguments.length!==2)return null;
 const [target,handler]=n.arguments;if(target.type!=='ObjectExpression'||target.properties.length||handler.type!=='ObjectExpression'||handler.properties.length!==1)return null;
 const g=handler.properties[0];if(g.type!=='ObjectMethod'||g.computed||g.key.name!=='get'||g.kind!=='method'||g.async||g.generator||g.params.length!==2||!g.params.every(p=>id(p)))return null;
 return g;
}
// This intentionally matches a small pure grammar, rather than interpreting arbitrary Proxy traps.
function factoryShape(n){
 if(!fn(n)||n.async||n.generator||n.params.length!==1||!id(n.params[0]))return null;
 const input=n.params[0].name;let expr=returned(n.body);
 if(expr?.type==='ConditionalExpression'){if(!id(expr.test,input)||expr.alternate.type!=='NullLiteral')return null;expr=expr.consequent;}
 const outer=proxyGetter(expr),inner=outer&&proxyGetter(returned(outer.body));if(!inner)return null;
 const closure=returned(inner.body);
 if(closure?.type!=='ArrowFunctionExpression'||closure.async||closure.params.length!==1||closure.params[0].type!=='RestElement'||!id(closure.params[0].argument))return null;
 const rest=closure.params[0].argument.name,ns=outer.params[1].name,method=inner.params[1].name;
 // Disallow lexical capture collisions, including unused trap target parameters.
 const names=[input,...outer.params.map(p=>p.name),...inner.params.map(p=>p.name),rest];if(new Set(names).size!==names.length)return null;
 let invoke=closure.body,channel;
 if(invoke.type==='BlockStatement'){
  const body=invoke.body;
  if(body.length===2&&body[0].type==='VariableDeclaration'&&body[0].kind==='const'&&body[0].declarations.length===1&&id(body[0].declarations[0].id)&&body[1].type==='ReturnStatement'){
   const d=body[0].declarations[0];if(names.includes(d.id.name))return null;channel=d.init;invoke=body[1].argument;if(!call(invoke)||!id(invoke.arguments[0],d.id.name))return null;
  }else if(body.length===1&&body[0].type==='ReturnStatement'){invoke=body[0].argument;channel=invoke?.arguments?.[0];}else return null;
 }else channel=invoke?.arguments?.[0];
 if(!call(invoke)||invoke.optional||!member(invoke.callee)||invoke.callee.optional||!id(invoke.callee.object,input)||!['invoke','send'].includes(key(invoke.callee))||invoke.arguments.length!==2||invoke.arguments[1].type!=='SpreadElement'||!id(invoke.arguments[1].argument,rest))return null;
 if(channel?.type!=='TemplateLiteral'||channel.expressions.length!==2||!id(channel.expressions[0],ns)||!id(channel.expressions[1],method)||channel.quasis.map(q=>q.value.cooked).join('|')!=='|.|')return null;
 return {transport:key(invoke.callee),invoke,constructors:[expr.callee,returned(outer.body).callee]};
}
function indexAst(ast){
 const scopes=new WeakMap(),parents=new WeakMap(),declared=new WeakSet(),bindings=[],all=[];let steps=0;
 const scope=(parent,isFunction=false)=>({parent,isFunction,bindings:new Map()});
 const declare=(node,s,kind,definition)=>{if(!node)return;if(id(node)){declared.add(node);let b=s.bindings.get(node.name);if(b)b.duplicate=true;else{s.bindings.set(node.name,b={name:node.name,scope:s,kind,definition,refs:[],duplicate:false});bindings.push(b);}return;}
  if(node.type==='RestElement')declare(node.argument,s,kind,definition);else if(node.type==='AssignmentPattern')declare(node.left,s,kind,definition);else if(node.type==='ObjectPattern')for(const p of node.properties)declare(p.type==='RestElement'?p.argument:p.value,s,kind,definition);else if(node.type==='ArrayPattern')for(const item of node.elements)declare(item,s,kind,definition);
 };
 function visit(n,s,parent,k,depth=0){
  if(++steps>2500000||depth>1024)fail('AST_LIMIT_EXCEEDED');
  if(parent)parents.set(n,{node:parent,key:k});all.push(n);
  if(n.type==='Program')s=scope(null,true);
  if(n.type==='FunctionDeclaration'&&n.id)declare(n.id,s,'function',n);
  if(n.type==='ClassDeclaration'&&n.id)declare(n.id,s,'class',n);
  if(fn(n)){s=scope(s,true);if(n.type==='FunctionExpression'&&n.id)declare(n.id,s,'local-function',n);for(const p of n.params)declare(p,s,'parameter',n);}
  else if(['ClassDeclaration','ClassExpression'].includes(n.type)){s=scope(s);if(n.id)declare(n.id,s,'class-self',n);}
  else if(['BlockStatement','CatchClause','ForStatement','ForInStatement','ForOfStatement','SwitchStatement'].includes(n.type))s=scope(s);
  scopes.set(n,s);
  if(n.type==='CatchClause')declare(n.param,s,'catch',n);
  if(n.type==='VariableDeclaration')for(const d of n.declarations){let destination=s;if(n.kind==='var')while(!destination.isFunction)destination=destination.parent;declare(d.id,destination,n.kind,d);}
  if(n.type==='ImportDeclaration')for(const spec of n.specifiers)declare(spec.local,s,'import',spec);
  for(const [field,child]of children(n))visit(child,s,n,field,depth+1);
 }
 visit(ast.program,null);
 const lookup=(s,name)=>{for(;s;s=s.parent)if(s.bindings.has(name))return s.bindings.get(name);return null;};
 for(const n of all){if(!id(n)||declared.has(n))continue;const p=parents.get(n);if(!p)continue;
  if((member(p.node)&&p.key==='property'&&!p.node.computed)||(['ObjectProperty','ObjectMethod','ClassMethod','ClassProperty'].includes(p.node.type)&&p.key==='key'&&!p.node.computed)||(p.node.type==='ExportSpecifier'&&p.key==='exported')||['ImportSpecifier','ImportDefaultSpecifier','ImportNamespaceSpecifier','LabeledStatement','BreakStatement','ContinueStatement'].includes(p.node.type))continue;
  const b=lookup(scopes.get(n),n.name);if(b)b.refs.push(n);
 }
 return {bindings,parents,scopes,lookup,all,steps};
}
function proxyMutation(ix){
 const unbound=(node,name)=>id(node,name)&&!ix.lookup(ix.scopes.get(node),name);
 const aliasCache=new WeakMap();
 const globalObject=(node,seen=new Set())=>{if(unbound(node,'globalThis')||unbound(node,'window'))return true;if(!id(node))return false;const b=ix.lookup(ix.scopes.get(node),node.name);if(!b||b.kind!=='const'||b.duplicate||seen.has(b))return false;if(aliasCache.has(b))return aliasCache.get(b);const result=globalObject(b.definition?.init,new Set(seen).add(b));aliasCache.set(b,result);return result;};
 const knownSymbol=(node,seen=new Set())=>{if(call(node)&&((unbound(node.callee,'Symbol'))||(member(node.callee)&&unbound(node.callee.object,'Symbol')&&key(node.callee)==='for')))return true;if(!id(node))return false;const b=ix.lookup(ix.scopes.get(node),node.name);return !!b&&b.kind==='const'&&!b.duplicate&&!seen.has(b)&&knownSymbol(b.definition?.init,new Set(seen).add(b));};
 const safeGlobalKey=(node,seen=new Set())=>{if(knownSymbol(node))return true;if(node?.type==='TemplateLiteral'){const prefix=node.quasis[0].value.cooked,suffix=node.quasis.at(-1).value.cooked;if(prefix&&!['Proxy','Symbol','for'].some(key=>key.startsWith(prefix))||suffix&&!['Proxy','Symbol','for'].some(key=>key.endsWith(suffix)))return true;}if(['StringLiteral','NumericLiteral'].includes(node?.type))return !['Proxy','Symbol','for'].includes(String(node.value));if(!id(node))return false;const b=ix.lookup(ix.scopes.get(node),node.name);return !!b&&b.kind==='const'&&!b.duplicate&&!seen.has(b)&&safeGlobalKey(b.definition?.init,new Set(seen).add(b));};
 const target=node=>{if(!node)return false;if(unbound(node,'Symbol'))return true;if(member(node)&&unbound(node.object,'Symbol')&&(key(node)==='for'||key(node)===null))return true;if(unbound(node,'Proxy'))return true;if(member(node)&&globalObject(node.object)&&(['Proxy','Symbol'].includes(key(node))||(key(node)===null&&!safeGlobalKey(node.property))))return true;
  if(node.type==='ObjectPattern')return node.properties.some(p=>target(p.type==='RestElement'?p.argument:p.value));if(node.type==='ArrayPattern')return node.elements.some(target);if(node.type==='AssignmentPattern')return target(node.left);if(node.type==='RestElement')return target(node.argument);return false;
 };
 for(const node of ix.all){
  if((node.type==='AssignmentExpression'&&target(node.left))||(node.type==='UpdateExpression'&&target(node.argument))||(node.type==='UnaryExpression'&&node.operator==='delete'&&target(node.argument))||(['ForInStatement','ForOfStatement'].includes(node.type)&&target(node.left)))return node;
  if(call(node)&&member(node.callee)&&(globalObject(node.arguments[0])||unbound(node.arguments[0],'Symbol'))){
   const owner=node.callee.object,method=key(node.callee);
   if((unbound(owner,'Reflect')&&['set','deleteProperty','defineProperty'].includes(method)||unbound(owner,'Object')&&method==='defineProperty')&&((node.arguments[1]?.type!=='StringLiteral'&&!safeGlobalKey(node.arguments[1]))||['Proxy','Symbol','for'].includes(node.arguments[1]?.value)))return node;
   if(unbound(owner,'Object')&&['assign','defineProperties'].includes(method)&&node.arguments.slice(1).some(value=>value.type!=='ObjectExpression'||value.properties.some(p=>p.type!=='ObjectProperty'||p.computed||['Proxy','Symbol','for'].includes(String(p.key.name??p.key.value)))))return node;
  }
 }
 return null;
}
function verifiedSources(sources,evidence){
 const graph=evidence?.normalized_result?.graph;
 if(evidence?.operation!=='analyze_javascript_application'||!/^ev_[a-f0-9]{64}$/.test(evidence?.evidence_id||'')||!Array.isArray(graph?.nodes)||typeof graph?.coverage?.status!=='string'||typeof graph?.coverage?.truncated!=='boolean')fail('INVALID_EVIDENCE');
 const hashes=new Map(Object.entries(sources).map(([name,text])=>[name,sha(text)])),covered=new Set();
 for(const node of graph.nodes){if(!Array.isArray(node.observations))fail('INVALID_EVIDENCE');for(const obs of node.observations){const e=obs.evidence,l=e?.location?.value;if(l?.kind!=='source-range'||!hashes.has(l.source))continue;if(e.location.available!==true||e.artifact?.available!==true)fail('INVALID_EVIDENCE');if(e.artifact.sha256!==hashes.get(l.source))fail('SOURCE_DIGEST_MISMATCH');covered.add(l.source);}}
 for(const name of hashes.keys())if(!covered.has(name))fail('SOURCE_NOT_COVERED');
 return [...hashes].map(([name,sha256])=>({name,sha256}));
}
export function bindGateways(sources,contract,evidence){
 const entries=sources&&typeof sources==='object'&&!Array.isArray(sources)?Object.entries(sources):[];
 if(!entries.length||entries.length>16||entries.some(([n,s])=>typeof s!=='string'||Buffer.byteLength(s)>8*1024*1024||n.length>512||n.startsWith('/')||n.includes('\\')||n.split('/').some(p=>!p||p==='.'||p==='..'))||entries.reduce((a,[,s])=>a+Buffer.byteLength(s),0)>16*1024*1024)fail('SOURCE_LIMIT_EXCEEDED');
 if(contract?.schema!=='rea-cli-factory.bridge-contract.v1'||!Array.isArray(contract.gateways)||!Array.isArray(contract.candidates))fail('INVALID_GATEWAY_CONTRACT');
 const digests=verifiedSources(sources,evidence);for(const d of digests){const prior=(contract.sources||[]).find(p=>p.name===d.name);if(prior&&prior.sha256!==d.sha256)fail('SOURCE_DIGEST_MISMATCH');}const found=[],unsupported=[],stats={sources:entries.length,factories:0,bindings:0,steps:0};
 const gateways=contract.gateways.filter(g=>g.status==='gateway-unbound'&&g.channelParameterIndex===0&&['invoke','send'].includes(g.transport)&&Array.isArray(g.apiPath)&&g.apiPath.length>=2&&g.apiPath.every(safe));
 const reject=(reason,node,name)=>unsupported.push({reason,sourceRange:loc(node,name)});let globalMutation=false;
 for(const [name,text]of entries){
  let ast;try{ast=parse(text,{sourceType:'unambiguous'});}catch{fail('SOURCE_PARSE_FAILED');}
  const ix=indexAst(ast);stats.steps+=ix.steps;
  const mutation=proxyMutation(ix);if(mutation){globalMutation=true;reject('builtin-proxy-mutated',mutation,name);continue;}
  const factories=new Map(),annexNames=new Set();
  if(ast.program.sourceType==='script'&&!ast.program.directives.some(d=>d.value.value==='use strict'))for(const node of ix.all){if(node.type!=='FunctionDeclaration'||!node.id)continue;const parent=ix.parents.get(node)?.node,owner=parent&&ix.parents.get(parent)?.node;if(parent?.type!=='Program'&&!(parent?.type==='BlockStatement'&&owner&&fn(owner)&&owner.body===parent))annexNames.add(node.id.name);}
  for(const b of ix.bindings){if(b.duplicate||b.kind!=='function'||ix.lookup(b.scope,'Proxy')||annexNames.has(b.name)||annexNames.has('Proxy'))continue;const shape=factoryShape(b.definition);if(shape&&shape.constructors.every(callee=>!ix.lookup(ix.scopes.get(callee),callee.name))){factories.set(b,{...shape,binding:b});stats.factories++;}}
  const proxies=[];
  for(const b of ix.bindings){const d=b.definition,init=d?.init;if(b.duplicate||b.kind!=='const'||d?.type!=='VariableDeclarator'||!id(d.id)||!call(init)||!id(init.callee)||init.arguments.length!==1)continue;
   const f=factories.get(ix.lookup(ix.scopes.get(init),init.callee.name));if(!f)continue;
   const p=staticPath(init.arguments[0]);if(!p||p[0]!=='window'||ix.lookup(ix.scopes.get(init),'window'))continue;
   const matches=gateways.filter(g=>g.transport===f.transport&&JSON.stringify(g.apiPath)===JSON.stringify([...p.slice(1),f.transport]));if(matches.length!==1)continue;
   proxies.push({b,f,g:matches[0],init});
  }
  // Index accepted initializer references once; avoid cubic scans for shared factories.
  const accepted=new Map();for(const p of proxies){if(!accepted.has(p.f))accepted.set(p.f,new Set());accepted.get(p.f).add(p.init.callee);}
  const validFactories=new Set();for(const [f,refs]of accepted){if(f.binding.refs.every(r=>refs.has(r)))validFactories.add(f);else reject('factory-escaped-or-mutated',f.binding.definition,name);}
  // Factories must remain private and immutable: every reference must be an accepted initialization.
  for(const proxy of proxies){const {b,f,g}=proxy;
   if(!validFactories.has(f))continue;
   const calls=[],exportRanges=[],escapedNamespaces=new Set();let bad=null;
   const booleanUse=node=>{const parent=ix.parents.get(node)?.node;if(!parent)return false;
    if(parent.type==='UnaryExpression'&&['!','typeof'].includes(parent.operator))return true;
    if(['ConditionalExpression','IfStatement','WhileStatement','DoWhileStatement'].includes(parent.type)&&parent.test===node)return true;
    if(parent.type==='LogicalExpression')return (parent.operator==='&&'&&parent.left===node)||booleanUse(parent);
    return false;
   };
   for(const r of b.refs){let n=r;const parts=[];while(member(ix.parents.get(n)?.node)&&ix.parents.get(n).node.object===n){n=ix.parents.get(n).node;parts.push(key(n));}
    const c=ix.parents.get(n)?.node;
    if(parts.every(safe)&&booleanUse(n))continue;
    // A const ESM export cannot replace its binding. The matched get traps ignore both
    // fresh empty targets, so mutation by an importing consumer cannot alter routing.
    if(parts.length===0&&c?.type==='ExportSpecifier'&&c.local===n){exportRanges.push(loc(c,name));continue;}
    if(parts.length===1&&safe(parts[0])){escapedNamespaces.add(parts[0]);reject('escaped-business-namespace',n,name);continue;}
    if(parts.length!==2||!parts.every(safe)||!call(c)||c.callee!==n){bad=n;break;}
    // Spread calls have no proven arity; leave them unsupported without affecting fixed siblings.
    if(c.arguments.some(a=>a.type==='SpreadElement')){reject('spread-business-call',c,name);continue;}
    if(c.arguments.length>16){reject('business-arity-limit',c,name);continue;}
    calls.push({parts,node:c,arity:c.arguments.length});
   }
   if(bad){reject('proxy-escaped-mutated-or-dynamic',bad,name);continue;}
   stats.bindings++;
   for(const c of calls){if(escapedNamespaces.has(c.parts[0]))continue;const sourceRange=loc(c.node,name),channel=c.parts.join('.');found.push({apiPath:c.parts,targetPath:[...g.apiPath],boundArgs:[channel],params:Array.from({length:c.arity},(_,i)=>`arg${i}`),arity:c.arity,transport:g.transport,channel,status:'candidate',sourceRange,...(g.availability?{availability:g.availability}:{}),provenance:{...g.provenance,gatewayRange:g.sourceRange,factoryRange:loc(f.binding.definition,name),callRanges:[sourceRange],channelResolution:'static-proxy-call',reaResolution:'artifact-only',bindingEvidenceId:evidence.evidence_id,...(exportRanges.length?{exportBoundary:{kind:'immutable-named-esm-export',ranges:exportRanges,consumerCoverage:'not-analyzed',invariant:'fresh-empty-targets-with-target-ignoring-get-traps'}}:{}),sources:[...(g.provenance?.sources||contract.sources||[]),...digests]}});}
  }
 }
 const groups=new Map();for(const c of [...contract.candidates,...(globalMutation?[]:found)]){const key=c.apiPath.join('.');if(!groups.has(key))groups.set(key,[]);groups.get(key).push(c);}
 const candidates=[];
 for(const group of groups.values()){
  const signatures=new Set(group.map(c=>JSON.stringify([c.targetPath||c.apiPath,c.boundArgs||[],c.channel,c.transport,c.arity,c.availability||null])));
  if(signatures.size!==1){unsupported.push({reason:'ambiguous-business-call',apiPath:group[0].apiPath});continue;}
  const c={...group[0]};if(c.provenance?.callRanges)c.provenance={...c.provenance,callRanges:group.flatMap(x=>x.provenance?.callRanges||[])};candidates.push(c);
 }
 return {...contract,sources:[...new Map([...(contract.sources||[]),...digests].map(s=>[s.name,s])).values()],candidates,unsupported:[...(contract.unsupported||[]),...unsupported],bindingAnalysis:stats,bindingCoverage:{status:'partial',scope:'provided-renderer-sources',exportedConsumersAnalyzed:false},limitations:[...(contract.limitations||[]),'Business channels are inferred only from a strict inert Proxy factory and fixed renderer calls; REA artifact coverage does not itself resolve the channel.','A fixed observed call count is not a complete parameter schema. Raw gateway methods remain unbound and cannot be selected.']};
}
