/** Bounded, inert CommonJS/ESM factory and gateway bridge analysis. Never loads analyzed code. */
import {parse} from '@babel/parser';
import {createHash} from 'node:crypto';
import path from 'node:path';

export class ModuleDiscoveryError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new ModuleDiscoveryError(code); };
const hash = text => createHash('sha256').update(text).digest('hex');
const U = Object.freeze({kind:'unknown'});
const atom = value => ({kind:'literal', value});
const data = () => ({kind:'data'});
const object = () => ({kind:'object', props:new Map(), blocked:new Set(), accessors:new Set(), dirty:false});
const safe = name => typeof name === 'string' && /^[A-Za-z_$][\w$]{0,119}$/.test(name) && !['constructor','prototype','__proto__'].includes(name);
const validName = name => typeof name === 'string' && name.length < 512 && !name.startsWith('/') && !name.includes('\\') && name.split('/').every(s => s && s !== '.' && s !== '..');
const position = (node, source) => ({source,start:{line:node.loc.start.line,column:node.loc.start.column},end:{line:node.loc.end.line,column:node.loc.end.column}});
const locKey = loc => `${loc.source}:${loc.start.line}:${loc.start.column}:${loc.end.line}:${loc.end.column}`;
const keyOf = node => node?.computed ? (['StringLiteral','NumericLiteral'].includes(node.property?.type) ? String(node.property.value) : null) : node?.property?.name;
const propertyKey = prop => !prop.computed ? String(prop.key?.name ?? prop.key?.value ?? '') : null;
const FUNCTION = new Set(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression','ObjectMethod']);

export function discoverModules(sources, entryName, evidence) {
  if (!sources || typeof sources !== 'object' || Array.isArray(sources) || !validName(entryName)) fail('INVALID_SOURCES');
  const entries = Object.entries(sources);
  if (!entries.length || entries.length > 32 || entries.some(([name,text]) => !validName(name) || typeof text !== 'string' || Buffer.byteLength(text) > 2*1024*1024) || entries.reduce((sum,[,text])=>sum+Buffer.byteLength(text),0)>8*1024*1024) fail('SOURCE_LIMIT_EXCEEDED');
  const graph = evidence?.normalized_result?.graph;
  if (evidence?.operation !== 'analyze_javascript_application' || !/^ev_[a-f0-9]{64}$/.test(evidence?.evidence_id || '') || !Array.isArray(graph?.nodes) || typeof graph?.coverage?.status !== 'string' || typeof graph?.coverage?.truncated !== 'boolean') fail('INVALID_EVIDENCE');
  let steps=0, depth=0;
  const tick = () => { if (++steps > 200000) fail('ANALYSIS_STEP_LIMIT'); };
  const observations = new Map(), sourceDigests = new Map(), expectedDigests=new Map(entries.map(([name,text])=>[name,hash(text)]));
  for (const n of graph.nodes) {
    tick();
    if (!Array.isArray(n.observations)) fail('INVALID_EVIDENCE');
    for (const obs of n.observations) {
      tick();
      const ev = obs.evidence, loc = ev?.location?.value;
      if (loc?.kind !== 'source-range' || !Object.hasOwn(sources,loc.source)) continue;
      if (ev.location.available !== true || ev.artifact?.available !== true) fail('INVALID_EVIDENCE');
      const expected = expectedDigests.get(loc.source);
      if (expected !== ev.artifact.sha256) fail('SOURCE_DIGEST_MISMATCH');
      sourceDigests.set(loc.source,expected);
      if (n.kind === 'ipc-channel') {
        const k = locKey(loc); if (!observations.has(k)) observations.set(k,[]);
        observations.get(k).push(obs.properties);
      }
    }
  }
  const modules = new Map(), functions = [], exposures = [], unsupported = [], exposureAssignments = new Set();
  const gatewayChannel=Object.freeze({kind:'gateway-channel'}), gatewayTail=Object.freeze({kind:'gateway-tail'});
  let ambiguousExposure=false;
  const windowValue={kind:'window',dirty:false}, processValue={kind:'process',dirty:false};
  const electronValue={kind:'electron',dirty:false}, rendererValue={kind:'ipcRenderer',dirty:false}, bridgeValue={kind:'contextBridge',dirty:false};
  const reject = (node,mod,reason,apiPath) => unsupported.push({reason,...(apiPath?{apiPath}:{}),sourceRange:position(node,mod.name)});
  const env = (parent,mod) => ({parent,mod,cells:new Map()});
  const lookup = (scope,name) => scope?.cells.has(name) ? scope.cells.get(name) : scope?.parent ? lookup(scope.parent,name) : null;
  const bind = (scope,name,value) => scope.cells.set(name,{value,dirty:false});
  function fnValue(node,scope) { const value={kind:'function',node,scope,dirty:false}; functions.push(value); return value; }
  function declare(scope,stmts) {
    for (let stmt of stmts) {
      if (stmt.type==='ExportNamedDeclaration' || stmt.type==='ExportDefaultDeclaration') stmt=stmt.declaration;
      if (!stmt) continue;
      if (stmt.type === 'FunctionDeclaration' && stmt.id) bind(scope,stmt.id.name,fnValue(stmt,scope));
      if (stmt.type === 'ClassDeclaration' && stmt.id) bind(scope,stmt.id.name,{kind:'class',node:stmt,scope,dirty:false});
      if (stmt.type === 'VariableDeclaration') for (const d of stmt.declarations) {
        if (d.id.type === 'Identifier') scope.cells.set(d.id.name,{node:d.init,scope,dirty:stmt.kind !== 'const',resolving:false});
        else if (d.id.type === 'ObjectPattern') for (const p of d.id.properties) {
          if (p.type === 'ObjectProperty' && !p.computed && p.value.type === 'Identifier') scope.cells.set(p.value.name,{node:d.init,scope,select:propertyKey(p),dirty:stmt.kind !== 'const',resolving:false});
        }
      }
    }
  }
  function cellValue(cell,ctx) {
    if (!cell || cell.dirty || cell.resolving) return U;
    if (cell.value) return cell.value;
    cell.resolving=true;
    let v=expression(cell.node,cell.scope,ctx);
    if (cell.select !== undefined) v=get(v,cell.select);
    cell.resolving=false; cell.value=v; return v;
  }
  function get(v,key) {
    if (v.dirty || key === null || ['__proto__','prototype','constructor'].includes(key)) return U;
    if (v.kind === 'window') {const matches=exposures.filter(e=>e.root===key);return matches.length && matches.every(e=>e.value===matches[0].value) ? matches[0].value : U;}
    if (v.kind === 'electron') return key==='contextBridge' ? bridgeValue : key==='ipcRenderer' ? rendererValue : U;
    if (v.kind === 'contextBridge' && key === 'exposeInMainWorld') return {kind:'expose'};
    if (v.kind === 'ipcRenderer') return ['invoke','send'].includes(key) ? {kind:'ipc',transport:key} : ['on','once','off','removeListener','removeAllListeners','sendTo','sendSync','sendToHost','postMessage'].includes(key) ? {kind:'unsupported-ipc'} : U;
    if (v.kind === 'object') {if(v.accessors.has(key))ambiguousExposure=true;return !v.dirty && !v.blocked.has(key) ? v.props.get(key) || U : U;}
    if (v.kind === 'array') return /^\d+$/.test(key) ? v.values[Number(key)] || atom(undefined) : U;
    if (v.kind === 'data') return data();
    if (v.kind === 'result' && v.transport === 'invoke' && key === 'then') return {kind:'then',result:v};
    return U;
  }
  function safeData(value,seen=new Set()) {
    tick();if(value.dirty||seen.has(value))return false;
    if(['literal','data'].includes(value.kind))return true;
    const next=new Set(seen).add(value);
    if(value.kind==='array')return value.values.every(v=>safeData(v,next));
    if(value.kind==='object')return value.blocked.size===0 && [...value.props.values()].every(v=>safeData(v,next));
    return false;
  }
  function relative(mod,request) {
    if (!request.startsWith('./') && !request.startsWith('../')) return null;
    if (request.includes('\\') || request.includes('\0') || request.length > 512) fail('UNSAFE_MODULE_PATH');
    const resolved=path.posix.normalize(path.posix.join(path.posix.dirname(mod.name),request));
    if (!validName(resolved)) fail('UNSAFE_MODULE_PATH');
    const matches=[resolved,...(!path.posix.extname(resolved)?[resolved+'.js',resolved+'.cjs',resolved+'.mjs',resolved+'/index.js',resolved+'/index.cjs',resolved+'/index.mjs']:[])].filter(n=>Object.hasOwn(sources,n));
    if (matches.length !== 1) fail(matches.length ? 'AMBIGUOUS_MODULE' : 'MISSING_MODULE');
    return load(matches[0]).exports;
  }
  function expression(node,scope,ctx) {
    tick(); if (!node) return atom(undefined);
    if (++depth > 64) fail('ANALYSIS_DEPTH_LIMIT');
    try {
      if (['StringLiteral','NumericLiteral','BooleanLiteral'].includes(node.type)) return atom(node.value);
      if (node.type === 'NullLiteral') return atom(null);
      if (node.type === 'Identifier') {
        if(node.name==='window' && !lookup(scope,'window')) return windowValue;
        if(node.name==='process' && !lookup(scope,'process')) return processValue;
        if (node.name === 'undefined' && !lookup(scope,node.name)) return atom(undefined);
        if (node.name === 'exports' && !lookup(scope,node.name)) return scope.mod.exports;
        if (node.name === 'module' && !lookup(scope,node.name)) return scope.mod.moduleValue;
        return cellValue(lookup(scope,node.name),ctx);
      }
      if (FUNCTION.has(node.type)) return fnValue(node,scope);
      if (node.type === 'MemberExpression') return get(expression(node.object,scope,ctx),keyOf(node));
      if (node.type === 'ObjectExpression') {
        const result=object();
        for (const p of node.properties) {
          const key=propertyKey(p);
          if (p.type==='ObjectMethod' && ['get','set'].includes(p.kind) && safe(key) && !result.props.has(key) && !result.blocked.has(key)) { result.blocked.add(key); result.accessors.add(key); continue; }
          if (!['ObjectProperty','ObjectMethod'].includes(p.type) || !safe(key) || result.props.has(key) || result.blocked.has(key)) { result.dirty=true;ctx.bad=true; continue; }
          result.props.set(key,p.type === 'ObjectMethod' ? fnValue(p,scope) : expression(p.value,scope,ctx));
        }
        return result;
      }
      if (node.type === 'ArrayExpression') return {kind:'array',values:node.elements.map(n=>expression(n,scope,ctx))};
      if (node.type === 'UnaryExpression' && node.operator === 'void' && ['NumericLiteral','Identifier'].includes(node.argument.type)) return atom(undefined);
      if (node.type === 'CallExpression') {
        if (node.callee.type === 'Identifier' && node.callee.name === 'require' && !lookup(scope,'require') && node.arguments.length === 1 && node.arguments[0].type === 'StringLiteral') {
          const requested=node.arguments[0].value;
          return requested === 'electron' ? electronValue : relative(scope.mod,requested) || U;
        }
        const callee=expression(node.callee,scope,ctx);
        const args=[];
        for (const a of node.arguments) {
          if (a.type === 'SpreadElement') { const spread=expression(a.argument,scope,ctx); if(spread.kind==='gateway-rest') args.push(gatewayTail); else { if (spread.kind !== 'array') {ctx.bad=true;return U;} args.push(...spread.values); } }
          else args.push(expression(a,scope,ctx));
        }
        if (callee.kind === 'ipc') {
          if (!ctx.trace) {ctx.bad=true; return U;}
          const channel=args[0];
          const gateway=ctx.gateway && channel===gatewayChannel && args.length===2 && args[1]===gatewayTail;
          if (!gateway && (channel?.dirty || channel?.kind !== 'literal' || typeof channel.value !== 'string' || !channel.value || channel.value.length > 240 || args.slice(1).some(a=>!safeData(a)))) {ctx.bad=true;return U;}
          const loc=position(node,scope.mod.name), obs=observations.get(locKey(loc)) || [];
          const matching=obs.find(p=>p?.side==='renderer' && p.operation===callee.transport && (p.resolution==='dynamic' || (!gateway && p.resolution==='literal' && p.channel===channel.value)));
          if (!matching) {ctx.bad=true;ctx.reason='ipc-source-range-not-supported-by-evidence';return U;}
          ctx.trace.push({transport:callee.transport,...(gateway?{gateway:true}:{channel:channel.value}),sourceRange:loc,reaResolution:matching.resolution});
          return {kind:'result',transport:callee.transport};
        }
        if (callee.kind === 'function' && !callee.dirty) return invoke(callee,args,ctx);
        if (callee.kind === 'then' && args.length === 1 && args[0].kind === 'function' && pureResponse(args[0])) return callee.result;
        ctx.bad=true; return U;
      }
      ctx.bad=true; return U;
    } finally { depth--; }
  }
  function inertValue(value,seen=new Set()) {
    tick();if(value.kind==='unknown'||value.dirty||seen.has(value))return false;
    const next=new Set(seen).add(value);
    if(value.kind==='object')return [...value.blocked].every(k=>value.accessors.has(k)) && [...value.props.values()].every(v=>inertValue(v,next));
    if(value.kind==='array')return value.values.every(v=>inertValue(v,next));
    return true;
  }
  function invoke(fn,args,ctx) {
    tick(); const node=fn.node;
    if (ctx.stack?.has(node) || node.async || node.generator) {ctx.bad=true;return U;}
    const scope=env(fn.scope,fn.scope.mod), next={...ctx,stack:new Set(ctx.stack || []).add(node)};
    for (let i=0;i<node.params.length;i++) {
      const p=node.params[i];
      if (p.type === 'Identifier') bind(scope,p.name,args[i] || atom(undefined));
      else if (p.type === 'RestElement' && p.argument.type === 'Identifier' && i === node.params.length-1) bind(scope,p.argument.name,args.length===i+1 && args[i]===gatewayTail ? {kind:'gateway-rest'} : {kind:'array',values:args.slice(i)});
      else {ctx.bad=true;return U;}
    }
    let result=atom(undefined);
    if (node.body.type !== 'BlockStatement') result=expression(node.body,scope,next);
    else {
      declare(scope,node.body.body);
      for (const stmt of node.body.body) {
        if (stmt.type === 'VariableDeclaration' && stmt.kind === 'const') {
          for (const d of stmt.declarations) { if (d.id.type !== 'Identifier' && d.id.type !== 'ObjectPattern') {next.bad=true;break;} const initialized=expression(d.init,scope,next);if(!inertValue(initialized))next.bad=true; }
        } else if (stmt.type === 'ReturnStatement') {result=expression(stmt.argument,scope,next);break;}
        else if (stmt.type === 'ExpressionStatement') {const evaluated=expression(stmt.expression,scope,next);if(!inertValue(evaluated))next.bad=true;}
        else if (stmt.type !== 'FunctionDeclaration' && stmt.type !== 'EmptyStatement') {next.bad=true;break;}
      }
    }
    if(!inertValue(result))next.bad=true;
    if (next.bad) ctx.bad=true;
    if (next.reason) ctx.reason=next.reason;
    if (next.bad) return U;
    return result;
  }
  // Only pure response projection/branching and simple Error construction are allowed.
  // The wrapper is retained at runtime; this pass merely rules out extra operations.
  function pureResponse(fn) {
    if (fn.dirty || fn.node.async || fn.node.generator || fn.node.params.some(p=>p.type !== 'Identifier')) return false;
    const scope=env(fn.scope,fn.scope.mod); fn.node.params.forEach(p=>bind(scope,p.name,data()));
    if (fn.node.body.type === 'BlockStatement') declare(scope,fn.node.body.body);
    function pure(node) {
      tick(); if (!node) return true;
      if (['StringLiteral','NumericLiteral','BooleanLiteral','NullLiteral'].includes(node.type)) return true;
      if (node.type === 'Identifier') {const v=cellValue(lookup(scope,node.name),{});return ['data','literal'].includes(v.kind);}
      if (node.type === 'MemberExpression') return pure(node.object) && keyOf(node)!==null;
      if (node.type === 'BlockStatement') return node.body.every(pure);
      if (node.type === 'ReturnStatement' || node.type === 'ThrowStatement') return pure(node.argument);
      if (node.type === 'IfStatement') return pure(node.test)&&pure(node.consequent)&&pure(node.alternate);
      if (node.type === 'VariableDeclaration') return node.kind==='const' && node.declarations.every(d=>d.id.type==='Identifier' && pure(d.init));
      if (['UnaryExpression','BinaryExpression','LogicalExpression','ConditionalExpression'].includes(node.type)) return [node.argument,node.left,node.right,node.test,node.consequent,node.alternate].filter(Boolean).every(pure);
      if (node.type === 'NewExpression' && node.callee.type==='Identifier' && node.arguments.every(pure)) {
        if (node.callee.name === 'Error' && !lookup(scope,'Error')) return true;
        const klass=cellValue(lookup(scope,node.callee.name),{});
        return pureErrorClass(klass);
      }
      return false;
    }
    return pure(fn.node.body);
  }
  function pureErrorClass(value) {
    if (value.kind!=='class' || value.dirty || value.node.superClass?.type!=='Identifier' || value.node.superClass.name!=='Error' || lookup(value.scope,'Error')) return false;
    const members=value.node.body.body, ctor=members.find(n=>n.kind==='constructor');
    if (!ctor || ctor.params.some(p=>p.type!=='Identifier') || members.some(n=>n!==ctor && (n.type!=='ClassProperty' || n.value || n.static || n.computed))) return false;
    const parameters=new Set(ctor.params.map(p=>p.name));
    const expr=n=>['StringLiteral','NumericLiteral','BooleanLiteral','NullLiteral'].includes(n?.type) || (n?.type==='Identifier'&&parameters.has(n.name)) || (n?.type==='MemberExpression'&&keyOf(n)!==null&&expr(n.object));
    return ctor.body.body.every(s=>s.type==='ExpressionStatement' && ((s.expression.type==='CallExpression'&&s.expression.callee.type==='Super'&&s.expression.arguments.every(expr)) || (s.expression.type==='AssignmentExpression'&&s.expression.operator==='='&&s.expression.left.type==='MemberExpression'&&s.expression.left.object.type==='ThisExpression'&&safe(keyOf(s.expression.left))&&expr(s.expression.right))));
  }
  function load(name) {
    if (modules.has(name)) {const m=modules.get(name);if(m.loading)fail('CYCLIC_MODULE');return m;}
    if (!Object.hasOwn(sources,name)) fail('MISSING_MODULE');
    if (!sourceDigests.has(name)) fail('SOURCE_NOT_IN_EVIDENCE');
    let ast; try {ast=parse(sources[name],{sourceType:'unambiguous'});} catch {fail('SOURCE_PARSE_FAILED');}
    const mod={name,ast,exports:object(),exportNodes:new Set(),loading:true}; modules.set(name,mod); mod.moduleValue=object();mod.moduleValue.props.set('exports',mod.exports); mod.scope=env(null,mod); declare(mod.scope,ast.program.body);
    // ESM bindings resolve only against supplied source and trusted Electron symbols.
    for(const stmt of ast.program.body) if(stmt.type==='ImportDeclaration') {
      const imported=stmt.source.value==='electron' ? electronValue : relative(mod,stmt.source.value) || U;
      for(const spec of stmt.specifiers) bind(mod.scope,spec.local.name,spec.type==='ImportNamespaceSpecifier'?imported:spec.type==='ImportSpecifier'?get(imported,spec.imported.name ?? spec.imported.value):get(imported,'default'));
    }
    for(const stmt of ast.program.body) {
      if(stmt.type==='ExportAllDeclaration') fail('UNSUPPORTED_ESM_EXPORT');
      if(stmt.type==='ExportNamedDeclaration') {
        const from=stmt.source ? relative(mod,stmt.source.value) || U : null;
        const names=[];
        if(stmt.declaration?.type==='VariableDeclaration') for(const d of stmt.declaration.declarations) {
          if(d.id.type!=='Identifier') fail('UNSUPPORTED_ESM_EXPORT'); names.push([d.id.name,d.id.name]);
        }
        else if(stmt.declaration?.id) names.push([stmt.declaration.id.name,stmt.declaration.id.name]);
        for(const spec of stmt.specifiers || []) {
          if(spec.type!=='ExportSpecifier') fail('UNSUPPORTED_ESM_EXPORT'); names.push([spec.exported.name ?? spec.exported.value,spec.local.name ?? spec.local.value]);
        }
        for(const [exported,local] of names) {
          if(!safe(exported)||mod.exports.props.has(exported)) fail('AMBIGUOUS_ESM_EXPORT');
          mod.exports.props.set(exported,from?get(from,local):cellValue(lookup(mod.scope,local),{}));
        }
      } else if(stmt.type==='ExportDefaultDeclaration') {
        const n=stmt.declaration;
        mod.exports.props.set('default',n.id?cellValue(lookup(mod.scope,n.id.name),{}):expression(n,mod.scope,{}));
      }
    }
    // Resolve literal imports before CommonJS exports; target modules are never executed.
    for (const stmt of ast.program.body) if (stmt.type==='ExpressionStatement' && stmt.expression.type==='CallExpression' && stmt.expression.callee.type==='Identifier' && stmt.expression.callee.name==='require') expression(stmt.expression,mod.scope,{});
    for (const stmt of ast.program.body) if (stmt.type==='VariableDeclaration') for (const d of stmt.declarations) if (d.init?.type==='CallExpression' && d.init.callee.type==='Identifier'&&d.init.callee.name==='require') expression(d.init,mod.scope,{});
    for (const stmt of ast.program.body) {
      const a=stmt.type==='ExpressionStatement' ? stmt.expression : null;
      if (a?.type==='AssignmentExpression'&&a.operator==='='&&a.left.type==='MemberExpression') {
        const l=a.left, key=keyOf(l);
        if (l.object.type==='Identifier' && l.object.name==='exports' && !lookup(mod.scope,'exports') && safe(key)) {
          mod.exportNodes.add(a);
          if (mod.exports.props.has(key)) mod.exports.blocked.add(key);
          else mod.exports.props.set(key,expression(a.right,mod.scope,{}));
        } else if (l.object.type==='Identifier'&&l.object.name==='module'&&!lookup(mod.scope,'module')&&key==='exports') {
          mod.exportNodes.add(a);
          if (mod.exportAssigned || mod.exports.props.size) mod.exports.dirty=true;
          else {mod.exports=expression(a.right,mod.scope,{});mod.moduleValue.props.set('exports',mod.exports);mod.exportAssigned=true;}
        }
      }
    }
    mod.loading=false; return mod;
  }
  load(entryName);
  // Only an unshadowed context-isolation branch is a recognized conditional exposure.
  // Branches are retained as runtime availability requirements, never evaluated here.
  function collect(stmts,mod,branch=null) {
    if(branch && stmts.some(s=>['VariableDeclaration','FunctionDeclaration','ClassDeclaration'].includes(s.type))) return;
    for(const stmt of stmts) {
      if(stmt.type==='IfStatement' && !branch && stmt.test.type==='MemberExpression' && keyOf(stmt.test)==='contextIsolated' && stmt.test.object.type==='Identifier' && stmt.test.object.name==='process' && !lookup(mod.scope,'process')) {
        const list=n=>n?.type==='BlockStatement'?n.body:n?[n]:[];
        collect(list(stmt.consequent),mod,{group:stmt,value:true});
        collect(list(stmt.alternate),mod,{group:stmt,value:false});continue;
      }
      if(stmt.type==='TryStatement' && branch && !stmt.finalizer && (!stmt.handler || !containsExposure(stmt.handler.body))) {collect(stmt.block.body,mod,branch);continue;}
      const node=stmt.type==='ExpressionStatement'?stmt.expression:null;
      if(node?.type==='CallExpression' && expression(node.callee,mod.scope,{}).kind==='expose') {
        const root=expression(node.arguments[0],mod.scope,{});
        if(root.kind!=='literal'||!safe(root.value)||node.arguments.length!==2) {reject(node,mod,'dynamic-exposure');continue;}
        exposures.push({root:root.value,value:expression(node.arguments[1],mod.scope,{}),node,mod,branch,mechanism:'contextBridge'});
      } else if(branch && node?.type==='AssignmentExpression' && node.operator==='=' && node.left.type==='MemberExpression' && node.left.object.type==='Identifier' && node.left.object.name==='window' && !lookup(mod.scope,'window') && safe(keyOf(node.left))) {
        exposureAssignments.add(node);
        exposures.push({root:keyOf(node.left),value:expression(node.right,mod.scope,{}),node,mod,branch,mechanism:'window'});
      }
    }
  }
  function containsExposure(node,walkDepth=0) {
    tick();if(walkDepth>128)fail('ANALYSIS_DEPTH_LIMIT');if(!node||typeof node!=='object')return false;
    if(node.type==='CallExpression' && node.callee.type==='MemberExpression' && keyOf(node.callee)==='exposeInMainWorld')return true;
    return Object.entries(node).some(([k,v])=>k!=='loc' && (Array.isArray(v)?v.some(n=>containsExposure(n,walkDepth+1)):v&&typeof v==='object'&&containsExposure(v,walkDepth+1)));
  }
  for(const mod of modules.values())collect(mod.ast.program.body,mod);
  function mark(value,seen=new Set(),invalidatePrimitive=false,markDepth=0) {
    tick();if(markDepth>64)fail('ANALYSIS_DEPTH_LIMIT');if(seen.has(value))return;seen.add(value);
    if(value.kind==='window'||value.kind==='process') {value.dirty=true;ambiguousExposure=true;}
    else if(value.kind==='object') {value.dirty=true;for(const child of value.props.values())mark(child,seen,true,markDepth+1);}
    else if(value.kind==='array') {for(const child of value.values)mark(child,seen,true,markDepth+1);}
    else if(value.kind==='function') {const returned=invoke(value,value.node.params.map(()=>data()),{});value.dirty=true;mark(returned,seen,false,markDepth+1);}
    else if(['class','electron','contextBridge','ipcRenderer'].includes(value.kind) || (invalidatePrimitive && ['literal','data'].includes(value.kind)))value.dirty=true;
  }
  function mutation(target,scope) {
    if(target?.type==='ObjectPattern') {for(const p of target.properties)mutation(p.value||p.argument,scope);return;}
    if(target?.type==='ArrayPattern') {for(const p of target.elements)mutation(p,scope);return;}
    if(target?.type==='AssignmentPattern'||target?.type==='RestElement') {mutation(target.left||target.argument,scope);return;}
    if (target?.type==='Identifier') {if(['require','exports','module','Error','undefined','window','process'].includes(target.name)&&!lookup(scope,target.name))fail('OPAQUE_MODULE_BINDING');const c=lookup(scope,target.name);if(c) {mark(cellValue(c,{}),new Set(),true);c.dirty=true;} return;}
    if (target?.type==='MemberExpression') {
      let globalRoot=target;const globalKeys=[];
      while(globalRoot?.type==='MemberExpression') {globalKeys.unshift(keyOf(globalRoot));globalRoot=globalRoot.object;}
      if(globalRoot?.type==='Identifier' && globalRoot.name==='window' && !lookup(scope,'window')) {
        for(const e of exposures) if(globalKeys[0]===null || globalKeys[0]===e.root) mark(e.value);
      }
      if(globalRoot?.type==='Identifier' && globalRoot.name==='process' && !lookup(scope,'process') && (globalKeys[0]===null || globalKeys[0]==='contextIsolated')) ambiguousExposure=true;
      const v=expression(target.object,scope,{}), key=keyOf(target);
      if(v.kind==='window') {for(const e of exposures) if(key===null||key===e.root)mark(e.value);}
      else if(v.kind==='process' && (key===null||key==='contextIsolated'))ambiguousExposure=true;
      else if (v.kind==='object') {if(v.accessors.has(key))ambiguousExposure=true;if(v===scope.mod.moduleValue && (key===null||key==='exports'))mark(scope.mod.exports);if(key===null)mark(v);else {const previous=v.props.get(key);if(previous)mark(previous,new Set(),true);v.blocked.add(key);}}
      else {mark(v);let root=target;while(root?.type==='MemberExpression')root=root.object;if(root?.type==='Identifier')mark(expression(root,scope,{}));}
    }
  }
  const scanned=new Set();
  function scan(node,scope,scanDepth=0) {
    tick();if(scanDepth>128)fail('ANALYSIS_DEPTH_LIMIT'); if (!node || typeof node!=='object') return;
    if (FUNCTION.has(node.type)) return; // instantiated closures get their own lexical scope below
    if (node.type==='ClassDeclaration' || node.type==='ClassExpression') return;
    if(node.type==='MemberExpression') {const receiver=expression(node.object,scope,{});if(receiver.kind==='object' && (receiver.accessors.has(keyOf(node)) || (keyOf(node)===null && receiver.accessors.size)))ambiguousExposure=true;}
    if (node.type==='WithStatement' || (node.type==='CallExpression'&&node.callee.type==='Identifier'&&node.callee.name==='eval')) fail('OPAQUE_SCOPE');
    if (node.type==='BlockStatement') {const child=env(scope,scope.mod);declare(child,node.body);for(const stmt of node.body)scan(stmt,child,scanDepth+1);return;}
    if (node.type==='AssignmentExpression' || node.type==='UpdateExpression' || (node.type==='UnaryExpression'&&node.operator==='delete')) {
      // Only declarative, single top-level CommonJS exports are interpreted above.
      const t=node.left||node.argument;
      const declarative=scope.mod.exportNodes.has(node) || exposureAssignments.has(node);
      if (!declarative) {mutation(t,scope);if(node.right)mark(expression(node.right,scope,{}));}
    }
    if(['ForOfStatement','ForInStatement'].includes(node.type)) {mutation(node.left,scope);mark(expression(node.right,scope,{}));}
    if (node.type==='CallExpression') {
      const c=expression(node.callee,scope,{});
      if(c.kind==='expose' && !exposures.some(e=>e.node===node)) ambiguousExposure=true;
      const ctx={};
      if (c.kind==='function') expression(node,scope,ctx);
      if (!['function','expose','ipc'].includes(c.kind) || ctx.bad) for (const arg of node.arguments) mark(expression(arg,scope,{}));
      if (c.kind==='unknown' && node.callee.type==='MemberExpression') mark(expression(node.callee.object,scope,{}));
    }
    for (const [key,value] of Object.entries(node)) {
      if (['loc','comments','tokens','errors'].includes(key)) continue;
      if (Array.isArray(value)) for (const child of value) scan(child,scope,scanDepth+1);
      else if (value && typeof value==='object' && value.type) scan(value,scope,scanDepth+1);
    }
  }
  for (const mod of modules.values()) for(const stmt of mod.ast.program.body) scan(stmt,mod.scope);
  for (let i=0;i<functions.length;i++) {
    if (i>20000) fail('FUNCTION_LIMIT_EXCEEDED');
    const fn=functions[i];
    // Same AST may close over different factory arguments, so deduplicate scope + AST pairs only.
    const identity=fn.scope; if (!identity.scannedFunctions)identity.scannedFunctions=new Set();
    if(identity.scannedFunctions.has(fn.node))continue;identity.scannedFunctions.add(fn.node);scanned.add(fn);
    const scope=env(fn.scope,fn.scope.mod);
    for (const p of fn.node.params) {if(p.type==='Identifier')bind(scope,p.name,data());else if(p.type==='RestElement'&&p.argument.type==='Identifier')bind(scope,p.argument.name,{kind:'array',values:[]});}
    if(fn.node.body.type==='BlockStatement')declare(scope,fn.node.body.body);
    scan(fn.node.body,scope);
  }
  const candidates=[], gateways=[], roots=new Set();
  function visit(value,apiPath,at,mod,availability,seen=new Set()) {
    tick(); if(apiPath.length>16 || seen.has(value)) {reject(at,mod,'object-depth-or-cycle',apiPath);return;}
    if (value.kind==='object'&&!value.dirty) {
      for(const key of value.blocked) if(!value.props.has(key))reject(at,mod,'unsupported-accessor',[...apiPath,key]);
      for(const [key,item] of value.props) {
        if(value.blocked.has(key)) {reject(at,mod,'mutated-property',[...apiPath,key]);continue;}
        visit(item,[...apiPath,key],at,mod,availability,new Set(seen).add(value));
      }
      return;
    }
    if(value.kind!=='function'||value.dirty) {reject(at,mod,'unsupported-or-mutated-value',apiPath);return;}
    const fn=value.node;
    const isGateway=fn.params.length===2 && fn.params[0].type==='Identifier' && safe(fn.params[0].name) && fn.params[1].type==='RestElement' && fn.params[1].argument.type==='Identifier' && safe(fn.params[1].argument.name);
    if(!isGateway && fn.params.some(p=>p.type!=='Identifier'||!safe(p.name))) {reject(fn,value.scope.mod,'complex-parameters',apiPath);return;}
    const ctx={trace:[],stack:new Set(),gateway:isGateway}, params=isGateway?[fn.params[0].name]:fn.params.map(p=>p.name);
    invoke(value,isGateway?[gatewayChannel,gatewayTail]:params.map(()=>data()),ctx);
    if(ctx.bad||ctx.trace.length!==1) {reject(fn,value.scope.mod,ctx.reason||'not-a-single-supported-ipc-operation',apiPath);return;}
    const leaf=ctx.trace[0];
    const descriptor={apiPath,params,arity:params.length,transport:leaf.transport,...(leaf.gateway?{status:'gateway-unbound',channelParameterIndex:0,restParameter:fn.params[1].argument.name}:{channel:leaf.channel,status:'candidate'}),sourceRange:leaf.sourceRange,
      ...(availability?{availability}:{}),provenance:{methodRange:position(fn,value.scope.mod.name),ipcRange:leaf.sourceRange,channelResolution:leaf.gateway?'unbound-parameter':'scoped-static-inference',reaResolution:leaf.reaResolution,sources:[...modules.keys()].map(name=>({name,sha256:sourceDigests.get(name)}))}};
    (leaf.gateway?gateways:candidates).push(descriptor);
  }
  for(const e of exposures) {
    if(ambiguousExposure || bridgeValue.dirty || electronValue.dirty) {reject(e.node,e.mod,'ambiguous-exposure');continue;}
    if(roots.has(e.root))continue;
    const matches=exposures.filter(x=>x.root===e.root);
    const paired=matches.length===2 && matches.every(x=>x.branch && x.value===e.value && x.branch.group===e.branch?.group) && matches[0].branch.value!==matches[1].branch.value;
    if(matches.length!==1 && !paired) {reject(e.node,e.mod,'duplicate-exposure-root');continue;}
    const availability=e.branch?{kind:'conditional',condition:'process.contextIsolated',branches:matches.map(x=>({value:x.branch.value,exposure:x.mechanism})),runtimeCheck:'api-path-exists'}:null;
    roots.add(e.root);visit(e.value,[e.root],e.node,e.mod,availability);
  }
  if(!exposures.length) reject(modules.get(entryName).ast.program,modules.get(entryName),'no-supported-top-level-exposure');
  return {schema:'rea-cli-factory.bridge-contract.v1',evidenceId:evidence.evidence_id,source:{name:entryName,sha256:sourceDigests.get(entryName)},sources:[...modules.keys()].map(name=>({name,sha256:sourceDigests.get(name)})),coverage:{...graph.coverage},candidates,gateways,unsupported,
    limitations:['Inert static candidates only; original exposed methods and response wrappers must be called at runtime.','Channel values are inferred from scoped source expressions; REA may only observe a dynamic channel at the IPC leaf.','Only bounded CommonJS/ESM imports, literal object factories, narrow context-isolation exposure branches and single IPC chains are supported. Raw gateways require separate source-supported binding and are never callable candidates.','Candidates do not establish application behavior, parameter schemas, authorization or runtime compatibility.'],analysis:{modules:modules.size,steps}};
}
