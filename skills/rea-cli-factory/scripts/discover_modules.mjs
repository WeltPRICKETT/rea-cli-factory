/** Bounded, inert CommonJS/factory bridge analysis. Never loads analyzed code. */
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
const object = () => ({kind:'object', props:new Map(), blocked:new Set(), dirty:false});
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
  const modules = new Map(), functions = [], exposures = [], unsupported = [];
  let ambiguousExposure=false;
  const electronValue={kind:'electron',dirty:false}, rendererValue={kind:'ipcRenderer',dirty:false}, bridgeValue={kind:'contextBridge',dirty:false};
  const reject = (node,mod,reason,apiPath) => unsupported.push({reason,...(apiPath?{apiPath}:{}),sourceRange:position(node,mod.name)});
  const env = (parent,mod) => ({parent,mod,cells:new Map()});
  const lookup = (scope,name) => scope?.cells.has(name) ? scope.cells.get(name) : scope?.parent ? lookup(scope.parent,name) : null;
  const bind = (scope,name,value) => scope.cells.set(name,{value,dirty:false});
  function fnValue(node,scope) { const value={kind:'function',node,scope,dirty:false}; functions.push(value); return value; }
  function declare(scope,stmts) {
    for (const stmt of stmts) {
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
    if (v.kind === 'electron') return key==='contextBridge' ? bridgeValue : key==='ipcRenderer' ? rendererValue : U;
    if (v.kind === 'contextBridge' && key === 'exposeInMainWorld') return {kind:'expose'};
    if (v.kind === 'ipcRenderer') return ['invoke','send'].includes(key) ? {kind:'ipc',transport:key} : ['on','once','off','removeListener','removeAllListeners'].includes(key) ? {kind:'event'} : U;
    if (v.kind === 'object') return !v.dirty && !v.blocked.has(key) ? v.props.get(key) || U : U;
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
    const matches=[resolved,...(!path.posix.extname(resolved)?[resolved+'.js',resolved+'.cjs',resolved+'/index.js',resolved+'/index.cjs']:[])].filter(n=>Object.hasOwn(sources,n));
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
          if (!['ObjectProperty','ObjectMethod'].includes(p.type) || !safe(key) || p.kind === 'get' || p.kind === 'set' || result.props.has(key)) { result.dirty=true;ctx.bad=true; continue; }
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
          if (a.type === 'SpreadElement') { const spread=expression(a.argument,scope,ctx); if (spread.kind !== 'array') {ctx.bad=true;return U;} args.push(...spread.values); }
          else args.push(expression(a,scope,ctx));
        }
        if (callee.kind === 'ipc') {
          if (!ctx.trace) {ctx.bad=true; return U;}
          const channel=args[0];
          if (channel?.dirty || channel?.kind !== 'literal' || typeof channel.value !== 'string' || !channel.value || channel.value.length > 240 || args.slice(1).some(a=>!safeData(a))) {ctx.bad=true;return U;}
          const loc=position(node,scope.mod.name), obs=observations.get(locKey(loc)) || [];
          const matching=obs.find(p=>p?.side==='renderer' && p.operation===callee.transport && (p.resolution==='dynamic' || (p.resolution==='literal' && p.channel===channel.value)));
          if (!matching) {ctx.bad=true;ctx.reason='ipc-source-range-not-supported-by-evidence';return U;}
          ctx.trace.push({transport:callee.transport,channel:channel.value,sourceRange:loc,reaResolution:matching.resolution});
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
    if(value.kind==='object')return value.blocked.size===0 && [...value.props.values()].every(v=>inertValue(v,next));
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
      else if (p.type === 'RestElement' && p.argument.type === 'Identifier' && i === node.params.length-1) bind(scope,p.argument.name,{kind:'array',values:args.slice(i)});
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
    let ast; try {ast=parse(sources[name],{sourceType:'script'});} catch {fail('SOURCE_PARSE_FAILED');}
    const mod={name,ast,exports:object(),exportNodes:new Set(),loading:true}; modules.set(name,mod); mod.moduleValue=object();mod.moduleValue.props.set('exports',mod.exports); mod.scope=env(null,mod); declare(mod.scope,ast.program.body);
    // Resolve literal imports before exports; target modules are never executed.
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
  // Materialize exposed values first, then invalidate aliases/properties via lexical mutation scans.
  for (const mod of modules.values()) for (const stmt of mod.ast.program.body) {
    const call=stmt.type==='ExpressionStatement' ? stmt.expression : null;
    if (call?.type!=='CallExpression' || expression(call.callee,mod.scope,{}).kind!=='expose') continue;
    const root=expression(call.arguments[0],mod.scope,{});
    if (root.kind!=='literal'||!safe(root.value)||call.arguments.length!==2) {reject(call,mod,'dynamic-exposure');continue;}
    exposures.push({root:root.value,value:expression(call.arguments[1],mod.scope,{}),node:call,mod});
  }
  function mark(value,seen=new Set(),invalidatePrimitive=false,markDepth=0) {
    tick();if(markDepth>64)fail('ANALYSIS_DEPTH_LIMIT');if(seen.has(value))return;seen.add(value);
    if(value.kind==='object') {value.dirty=true;for(const child of value.props.values())mark(child,seen,true,markDepth+1);}
    else if(value.kind==='array') {for(const child of value.values)mark(child,seen,true,markDepth+1);}
    else if(value.kind==='function') {const returned=invoke(value,value.node.params.map(()=>data()),{});value.dirty=true;mark(returned,seen,false,markDepth+1);}
    else if(['class','electron','contextBridge','ipcRenderer'].includes(value.kind) || (invalidatePrimitive && ['literal','data'].includes(value.kind)))value.dirty=true;
  }
  function mutation(target,scope) {
    if(target?.type==='ObjectPattern') {for(const p of target.properties)mutation(p.value||p.argument,scope);return;}
    if(target?.type==='ArrayPattern') {for(const p of target.elements)mutation(p,scope);return;}
    if(target?.type==='AssignmentPattern'||target?.type==='RestElement') {mutation(target.left||target.argument,scope);return;}
    if (target?.type==='Identifier') {if(['require','exports','module','Error','undefined'].includes(target.name)&&!lookup(scope,target.name))fail('OPAQUE_MODULE_BINDING');const c=lookup(scope,target.name);if(c) {mark(cellValue(c,{}),new Set(),true);c.dirty=true;} return;}
    if (target?.type==='MemberExpression') {
      const v=expression(target.object,scope,{}), key=keyOf(target);
      if (v.kind==='object') {if(v===scope.mod.moduleValue && (key===null||key==='exports'))mark(scope.mod.exports);if(key===null)mark(v);else {const previous=v.props.get(key);if(previous)mark(previous,new Set(),true);v.blocked.add(key);}}
      else {mark(v);let root=target;while(root?.type==='MemberExpression')root=root.object;if(root?.type==='Identifier')mark(expression(root,scope,{}));}
    }
  }
  const scanned=new Set();
  function scan(node,scope,scanDepth=0) {
    tick();if(scanDepth>128)fail('ANALYSIS_DEPTH_LIMIT'); if (!node || typeof node!=='object') return;
    if (FUNCTION.has(node.type)) return; // instantiated closures get their own lexical scope below
    if (node.type==='ClassDeclaration' || node.type==='ClassExpression') return;
    if (node.type==='WithStatement' || (node.type==='CallExpression'&&node.callee.type==='Identifier'&&node.callee.name==='eval')) fail('OPAQUE_SCOPE');
    if (node.type==='BlockStatement') {const child=env(scope,scope.mod);declare(child,node.body);for(const stmt of node.body)scan(stmt,child,scanDepth+1);return;}
    if (node.type==='AssignmentExpression' || node.type==='UpdateExpression' || (node.type==='UnaryExpression'&&node.operator==='delete')) {
      // Only declarative, single top-level CommonJS exports are interpreted above.
      const t=node.left||node.argument;
      const declarative=scope.mod.exportNodes.has(node);
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
  const candidates=[], roots=new Set();
  function visit(value,apiPath,at,mod,chain,seen=new Set()) {
    tick(); if(apiPath.length>16 || seen.has(value)) {reject(at,mod,'object-depth-or-cycle',apiPath);return;}
    if (value.kind==='object'&&!value.dirty) {
      for(const [key,item] of value.props) {
        if(value.blocked.has(key)) {reject(at,mod,'mutated-property',[...apiPath,key]);continue;}
        visit(item,[...apiPath,key],at,mod,chain,new Set(seen).add(value));
      }
      return;
    }
    if(value.kind!=='function'||value.dirty) {reject(at,mod,'unsupported-or-mutated-value',apiPath);return;}
    const fn=value.node;
    if(fn.params.some(p=>p.type!=='Identifier'||!safe(p.name))) {reject(fn,value.scope.mod,'complex-parameters',apiPath);return;}
    const ctx={trace:[],stack:new Set()}, params=fn.params.map(p=>p.name);
    invoke(value,params.map(()=>data()),ctx);
    if(ctx.bad||ctx.trace.length!==1) {reject(fn,value.scope.mod,ctx.reason||'not-a-single-supported-ipc-operation',apiPath);return;}
    const leaf=ctx.trace[0];
    candidates.push({apiPath,params,arity:params.length,transport:leaf.transport,channel:leaf.channel,status:'candidate',sourceRange:leaf.sourceRange,
      provenance:{methodRange:position(fn,value.scope.mod.name),ipcRange:leaf.sourceRange,channelResolution:'scoped-static-inference',reaResolution:leaf.reaResolution,sources:[...modules.keys()].map(name=>({name,sha256:sourceDigests.get(name)}))}});
  }
  for(const e of exposures) {
    if(ambiguousExposure || bridgeValue.dirty || electronValue.dirty) {reject(e.node,e.mod,'ambiguous-exposure');continue;}
    if(roots.has(e.root)||exposures.filter(x=>x.root===e.root).length!==1) {reject(e.node,e.mod,'duplicate-exposure-root');continue;}
    roots.add(e.root);visit(e.value,[e.root],e.node,e.mod,[]);
  }
  if(!exposures.length) reject(modules.get(entryName).ast.program,modules.get(entryName),'no-supported-top-level-exposure');
  return {schema:'rea-cli-factory.bridge-contract.v1',evidenceId:evidence.evidence_id,source:{name:entryName,sha256:sourceDigests.get(entryName)},sources:[...modules.keys()].map(name=>({name,sha256:sourceDigests.get(name)})),coverage:{...graph.coverage},candidates,unsupported,
    limitations:['Inert static candidates only; original exposed methods and response wrappers must be called at runtime.','Channel values are inferred from scoped source expressions; REA may only observe a dynamic channel at the IPC leaf.','Only bounded CommonJS imports, literal object factories, simple parameters and single IPC chains are supported.','Candidates do not establish application behavior, parameter schemas, authorization or runtime compatibility.'],analysis:{modules:modules.size,steps}};
}
