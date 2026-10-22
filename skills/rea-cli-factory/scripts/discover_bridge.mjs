#!/usr/bin/env node
/** Inert, deliberately narrow Electron preload bridge extraction. */
import {parse} from '@babel/parser';
import {createHash} from 'node:crypto';
import {open} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';

export class DiscoveryError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new DiscoveryError(code); };
const sha = text => createHash('sha256').update(text).digest('hex');
const simple = text => typeof text === 'string' && /^[A-Za-z_$][\w$-]{0,119}$/.test(text) && !['__proto__','prototype','constructor'].includes(text);
function walk(node, fn, parent = null) {
  if (!node || typeof node !== 'object') return;
  if (node.type) fn(node, parent);
  for (const [key, value] of Object.entries(node)) {
    if (['loc','comments','tokens','errors'].includes(key)) continue;
    if (Array.isArray(value)) for (const child of value) walk(child, fn, node);
    else if (value && typeof value === 'object') walk(value, fn, node);
  }
}
function boundNames(pattern) {
  if (!pattern) return [];
  if (pattern.type === 'Identifier') return [pattern.name];
  if (pattern.type === 'ObjectPattern') return pattern.properties.flatMap(p => boundNames(p.value || p.argument));
  if (pattern.type === 'ArrayPattern') return pattern.elements.flatMap(boundNames);
  if (pattern.type === 'AssignmentPattern') return boundNames(pattern.left);
  if (pattern.type === 'RestElement') return boundNames(pattern.argument);
  return [];
}
function rootName(node) {
  while (node?.type === 'MemberExpression') node = node.object;
  return node?.type === 'Identifier' ? node.name : null;
}
function member(node, key) {
  return node?.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier' && node.property.name === key;
}
function range(node, source) {
  return {source, start: {line: node.loc.start.line, column: node.loc.start.column},
    end: {line: node.loc.end.line, column: node.loc.end.column}};
}
const rangeKey = loc => `${loc?.start?.line}:${loc?.start?.column}:${loc?.end?.line}:${loc?.end?.column}`;
function sourceName(name) {
  return typeof name === 'string' && name.length <= 240 && /^[\w@+./ -]+$/.test(name) &&
    !name.startsWith('/') && name.split('/').every(p => p && p !== '.' && p !== '..');
}

export function discover(source, name, evidence) {
  if (typeof source !== 'string' || Buffer.byteLength(source) > 2 * 1024 * 1024 || !sourceName(name)) fail('INVALID_SOURCE');
  if (evidence?.operation !== 'analyze_javascript_application' || !/^ev_[a-f0-9]{64}$/.test(evidence.evidence_id || '')) fail('INVALID_EVIDENCE');
  const graph = evidence.normalized_result?.graph;
  if (!Array.isArray(graph?.nodes) || !graph.coverage || typeof graph.coverage.status !== 'string' || typeof graph.coverage.truncated !== 'boolean') fail('INVALID_EVIDENCE');
  const digest = sha(source), locations = new Map();
  let matchedSource = false;
  for (const node of graph.nodes) {
    if (!Array.isArray(node.observations)) fail('INVALID_EVIDENCE');
    for (const obs of node.observations) {
      const ev = obs.evidence, loc = ev?.location?.value;
      if (loc?.kind !== 'source-range' || loc.source !== name) continue;
      if (ev.location.available !== true) fail('INVALID_EVIDENCE');
      if (ev.artifact?.available !== true || ev.artifact.sha256 !== digest) fail('SOURCE_DIGEST_MISMATCH');
      matchedSource = true;
      if (node.kind === 'ipc-channel' && obs.properties?.resolution === 'literal') {
        const key = rangeKey(loc);
        const items = locations.get(key) || []; items.push(obs.properties); locations.set(key, items);
      }
    }
  }
  if (!matchedSource) fail('SOURCE_NOT_IN_EVIDENCE');
  let ast;
  try { ast = parse(source, {sourceType:'unambiguous'}); } catch { fail('SOURCE_PARSE_FAILED'); }
  const declarations = new Map(), bindings = new Map(), dirty = new Set();
  let opaqueScope = false;
  const addName = n => declarations.set(n, (declarations.get(n) || 0) + 1);
  walk(ast, node => {
    if (node.type === 'WithStatement' || (node.type === 'Identifier' && node.name === 'eval')) opaqueScope = true;
    if (node.type === 'ReturnStatement') { const root = rootName(node.argument); if (root) dirty.add(root); }
    if (['ForInStatement','ForOfStatement'].includes(node.type)) {
      const root = rootName(node.left); if (root) dirty.add(root);
      boundNames(node.left).forEach(n => dirty.add(n));
    }
    if (node.type === 'VariableDeclarator') boundNames(node.id).forEach(addName);
    if (['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression','ObjectMethod','ClassMethod'].includes(node.type)) {
      if (node.id) addName(node.id.name);
      node.params.flatMap(boundNames).forEach(addName);
    }
    if (node.type === 'CatchClause') boundNames(node.param).forEach(addName);
    if (node.type === 'ClassDeclaration' && node.id) addName(node.id.name);
    if (node.type.startsWith('Import') && node.local) addName(node.local.name);
    if (['AssignmentExpression','UpdateExpression'].includes(node.type) || (node.type === 'UnaryExpression' && node.operator === 'delete')) {
      const target = node.left || node.argument;
      const root = rootName(target); if (root) dirty.add(root);
      boundNames(target).forEach(n => dirty.add(n));
      walk(target, part => { if (part.type === 'MemberExpression') { const root = rootName(part); if (root) dirty.add(root); } });
    }
    // Any alias or escape into an unknown call could enable later mutation.
    if (node.type === 'VariableDeclarator') { const root = rootName(node.init); if (root) dirty.add(root); }
    if (node.type === 'AssignmentExpression') { const root = rootName(node.right); if (root) dirty.add(root); }
    if (node.type === 'CallExpression' && !member(node.callee,'exposeInMainWorld')) {
      for (const arg of node.arguments) { const root = rootName(arg); if (root) dirty.add(root); }
    }
  });
  for (const stmt of ast.program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id) bindings.set(stmt.id.name, stmt);
    if (stmt.type === 'VariableDeclaration' && stmt.kind === 'const') {
      for (const decl of stmt.declarations) if (decl.id.type === 'Identifier') bindings.set(decl.id.name, decl.init);
    }
  }
  walk(ast, node => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const root = rootName(node.callee), bound = bindings.get(root);
      if (bound && ['ObjectExpression','FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(bound.type)) dirty.add(root);
    }
  });
  // Propagate mutation through locally stored object aliases.
  let changed = true;
  while (changed) {
    changed = false;
    for (const name of [...dirty]) {
      const init = bindings.get(name);
      if (init?.type !== 'ObjectExpression') continue;
      for (const p of init.properties) {
        const root = rootName(p.value || p.argument);
        if (root && !dirty.has(root)) { dirty.add(root); changed = true; }
      }
    }
  }
  const safeBinding = name => !opaqueScope && declarations.get(name) === 1 && !dirty.has(name);
  const namespaces = new Set(), bridges = new Set(), renderers = new Set();
  const electronRequire = node => node?.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require' && node.arguments.length === 1 && node.arguments[0].type === 'StringLiteral' && node.arguments[0].value === 'electron';
  if (!declarations.has('require') && !dirty.has('require')) {
    for (const stmt of ast.program.body) if (stmt.type === 'VariableDeclaration' && stmt.kind === 'const') {
      for (const decl of stmt.declarations) if (electronRequire(decl.init)) {
        if (decl.id.type === 'Identifier' && safeBinding(decl.id.name)) namespaces.add(decl.id.name);
        if (decl.id.type === 'ObjectPattern') for (const prop of decl.id.properties) {
          if (prop.type !== 'ObjectProperty' || prop.computed || prop.value.type !== 'Identifier' || !safeBinding(prop.value.name)) continue;
          if (prop.key.name === 'contextBridge') bridges.add(prop.value.name);
          if (prop.key.name === 'ipcRenderer') renderers.add(prop.value.name);
        }
      }
    }
  }
  const isElectron = (node, key, set) => (node?.type === 'Identifier' && set.has(node.name)) || (member(node,key) && node.object.type === 'Identifier' && namespaces.has(node.object.name));
  const candidates = [], unsupported = [], exposures = [];
  let ambiguousExposure = false;
  const reject = (node, reason) => unsupported.push({reason, sourceRange: range(node,name)});
  const topCalls = new Set(ast.program.body.filter(s => s.type === 'ExpressionStatement').map(s => s.expression));
  walk(ast, node => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression' || (node.callee.property.name || node.callee.property.value) !== 'exposeInMainWorld') return;
    if (node.callee.computed) { ambiguousExposure = true; reject(node,'dynamic-exposure'); return; }
    if (!topCalls.has(node) || !isElectron(node.callee.object,'contextBridge',bridges)) { ambiguousExposure = true; reject(node,'unknown-or-shadowed-exposure'); return; }
    if (node.arguments.length !== 2 || node.arguments[0].type !== 'StringLiteral' || !simple(node.arguments[0].value)) { ambiguousExposure = true; reject(node,'dynamic-exposure'); return; }
    exposures.push({node, root:node.arguments[0].value, object:node.arguments[1]});
  });
  const rootCounts = new Map(); for (const e of exposures) rootCounts.set(e.root,(rootCounts.get(e.root)||0)+1);
  function resolve(node, seen = new Set()) {
    if (node?.type !== 'Identifier') return node;
    if (!safeBinding(node.name) || seen.has(node.name) || !bindings.has(node.name)) return null;
    seen.add(node.name); return resolve(bindings.get(node.name),seen);
  }
  function safeValue(node, params) {
    if (node?.type === 'Identifier') return params.includes(node.name);
    if (['StringLiteral','NumericLiteral','BooleanLiteral','NullLiteral'].includes(node?.type)) return true;
    if (node?.type === 'ObjectExpression') return node.properties.every(p => p.type === 'ObjectProperty' && !p.computed && simple(p.key.name || p.key.value) && safeValue(p.value,params));
    if (node?.type === 'ArrayExpression') return node.elements.every(p => safeValue(p,params));
    return false;
  }
  function method(value, path, at) {
    const fn = resolve(value);
    if (!fn || !['ArrowFunctionExpression','FunctionExpression','FunctionDeclaration'].includes(fn.type) || fn.async || fn.generator) return reject(at,'unsupported-method-or-mutated-binding');
    if (fn.params.some(p => p.type !== 'Identifier' || !simple(p.name))) return reject(at,'complex-parameters');
    const params = fn.params.map(p=>p.name);
    let call = fn.body;
    if (call.type === 'BlockStatement') {
      if (call.directives?.length || call.body.length !== 1 || !['ReturnStatement','ExpressionStatement'].includes(call.body[0].type)) return reject(at,'complex-body-or-event-subscription');
      call = call.body[0].argument || call.body[0].expression;
    }
    if (call?.type !== 'CallExpression' || !['invoke','send'].some(k => member(call.callee,k)) || !isElectron(call.callee.object,'ipcRenderer',renderers)) return reject(at,'unsupported-transport-or-shadowed-ipc');
    if (call.arguments[0]?.type !== 'StringLiteral' || !call.arguments[0].value || call.arguments[0].value.length > 240) return reject(at,'dynamic-channel');
    if (!call.arguments.slice(1).every(a=>safeValue(a,params))) return reject(at,'complex-ipc-arguments');
    const transport = call.callee.property.name, channel = call.arguments[0].value, loc = range(call,name);
    const observations = locations.get(rangeKey(loc)) || [];
    if (!observations.some(p=>p.side==='renderer' && p.operation===transport && p.channel===channel)) return reject(at,'ipc-source-range-not-supported-by-evidence');
    candidates.push({apiPath:path,params,arity:params.length,transport,channel,status:'candidate',sourceRange:loc});
  }
  function object(value,path,seen = new Set()) {
    const obj = resolve(value);
    if (!obj || obj.type !== 'ObjectExpression' || seen.has(obj)) return reject(value,'unsupported-or-mutated-object');
    const nextSeen = new Set(seen); nextSeen.add(obj);
    const keys = new Set();
    // A spread/getter or duplicate key can replace previously observed methods.
    for (const p of obj.properties) {
      const key = p.key?.name || p.key?.value;
      if (p.type !== 'ObjectProperty' || p.computed || !simple(key) || keys.has(key)) return reject(obj,'complex-object-or-duplicate-key');
      keys.add(key);
    }
    for (const p of obj.properties) {
      const key = p.key.name || p.key.value, target = resolve(p.value);
      if (target?.type === 'ObjectExpression') object(p.value,[...path,key],nextSeen);
      else method(p.value,[...path,key],p);
    }
  }
  for (const exposure of exposures) {
    if (ambiguousExposure) reject(exposure.node,'ambiguous-exposure-in-source');
    else if (rootCounts.get(exposure.root) !== 1) reject(exposure.node,'duplicate-exposure-root');
    else object(exposure.object,[exposure.root]);
  }
  return {schema:'rea-cli-factory.bridge-contract.v1',evidenceId:evidence.evidence_id,
    source:{name,sha256:digest},coverage:{status:graph.coverage.status,truncated:graph.coverage.truncated,
      omitted_count:graph.coverage.omitted_count ?? null,limits:graph.coverage.limits ?? []},candidates,unsupported,
    limitations:['Static candidates only; no analyzed code was executed and no runtime behavior is verified.',
      'Source hash and IPC source ranges match supplied REA observations; REA cryptographic integrity is not verified.',
      'Only a narrow top-level CommonJS subset is supported; shadowing, mutations and complex methods are rejected conservatively.',
      'Runtime must call the original exposed bridge method, not construct direct IPC calls.',
      'Partial REA coverage and unsupported entries do not establish absence of other interfaces.']};
}

async function bounded(path, max) {
  const handle = await open(path,'r');
  try {
    const bytes = Buffer.alloc(max + 1); let total = 0;
    while (total < bytes.length) { const {bytesRead} = await handle.read(bytes,total,bytes.length-total,null); if (!bytesRead) break; total += bytesRead; }
    if (total > max) fail('INPUT_TOO_LARGE');
    return new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,total));
  } finally { await handle.close(); }
}
export async function main(argv=process.argv.slice(2)) {
  try {
    const args = {};
    for (let i=0;i<argv.length;i+=2) {
      if (!['--source','--source-name','--evidence','--out'].includes(argv[i]) || !argv[i+1] || args[argv[i]]) fail('INVALID_ARGUMENTS');
      args[argv[i]]=argv[i+1];
    }
    if (Object.keys(args).length !== 4) fail('INVALID_ARGUMENTS');
    const result=discover(await bounded(args['--source'],2*1024*1024),args['--source-name'],JSON.parse(await bounded(args['--evidence'],64*1024*1024)));
    const out = await open(args['--out'],'wx');
    try { await out.writeFile(JSON.stringify(result,null,2)+'\n'); } finally { await out.close(); }
    return 0;
  } catch (e) { process.stderr.write(JSON.stringify({ok:false,error:{code:e.code || 'INVALID_INPUT'}})+'\n'); return 2; }
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) process.exitCode=await main();
