import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {evaluateToolCall,validatePolicy} from '../src/policy.mjs';
import plugin from '../index.mjs';
const tool=(toolName,params={},toolKind)=>({toolName,params,...(toolKind?{toolKind}:{})});
const evaluate=(call,rules)=>evaluateToolCall(call,{rules});
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'action-guardrails-'));
const allowed=path.join(temp,'allowed');const outside=path.join(temp,'outside');
fs.mkdirSync(allowed);fs.mkdirSync(outside);
const allowedFile=path.join(allowed,'note.txt');const outsideFile=path.join(outside,'secrets.txt');
fs.writeFileSync(allowedFile,'safe');fs.writeFileSync(outsideFile,'SECRET-NOT-FOR-LOGS');
const rRead=[{tool:'read',effect:'allow',pathRoots:[allowed]}];

test('default deny blocks every unconfigured tool',()=>{
  assert.equal(evaluateToolCall(tool('exec',{command:'echo ok'}),{}).effect,'deny');
  assert.equal(evaluateToolCall(tool('read',{path:allowedFile}),{}).code,'DEFAULT_DENY');
});
test('exact allowlisted normal tool passes',()=>assert.equal(evaluate(tool('read_inbox',{folder:'inbox'}),[{tool:'read_inbox',effect:'allow'}]).effect,'allow'));
test('explicit deny wins',()=>assert.equal(evaluate(tool('send_email',{to:'bad.invalid'}),[{tool:'send_email',effect:'deny'}]).code,'POLICY_DENY'));
test('filesystem read under configured real root allowed',()=>assert.equal(evaluate(tool('read',{path:allowedFile}),rRead).effect,'allow'));
test('filesystem read outside root blocked',()=>assert.equal(evaluate(tool('read',{path:outsideFile}),rRead).code,'OUTSIDE_ALLOWED_ROOT'));
test('filesystem traversal blocked',()=>assert.equal(evaluate(tool('read',{path:path.join(allowed,'..','outside','secrets.txt')}),rRead).effect,'deny'));
test('relative paths blocked',()=>assert.equal(evaluate(tool('read',{path:'notes.txt'}),rRead).code,'INVALID_PATH'));
test('missing roots block path-tools even with allow',()=>assert.equal(evaluate(tool('read',{path:allowedFile}),[{tool:'read',effect:'allow'}]).code,'PATH_SCOPE_MISSING'));
test('ambiguous path aliases block',()=>assert.equal(evaluate(tool('read',{path:allowedFile,file_path:outsideFile}),rRead).code,'INVALID_PATH'));
test('symlink out of approved directory denied',t=>{ const link=path.join(allowed,'linked.txt');try{fs.symlinkSync(outsideFile,link);}catch {t.skip('no symlink privilege');return;} assert.equal(evaluate(tool('read',{path:link}),rRead).code,'OUTSIDE_ALLOWED_ROOT'); });
test('write inside approved root permitted and traversal denied',()=>{let rules=[{tool:'write',effect:'allow',pathRoots:[allowed]}];assert.equal(evaluate(tool('write',{path:path.join(allowed,'newfile.txt')}),rules).effect,'allow');assert.equal(evaluate(tool('write',{path:outsideFile}),rules).effect,'deny')});
test('message sending needs recipient allowlist',()=>assert.equal(evaluate(tool('message',{action:'send',target:'alice@example.invalid'}),[{tool:'message',effect:'allow'}]).code,'RECIPIENT_SCOPE_MISSING'));
test('message to approved recipient permitted',()=>assert.equal(evaluate(tool('message',{action:'send',target:'ALICE@example.invalid'}),[{tool:'message',effect:'allow',recipients:['alice@example.invalid']}]).effect,'allow'));
test('message to unapproved recipient blocked',()=>assert.equal(evaluate(tool('message',{action:'send',target:'attacker@example.invalid'}),[{tool:'message',effect:'allow',recipients:['alice@example.invalid']}]).code,'UNAUTHORIZED_RECIPIENT'));
test('unsupported message action blocked',()=>assert.equal(evaluate(tool('message',{action:'react',target:'alice@example.invalid'}),[{tool:'message',effect:'allow',recipients:['alice@example.invalid']}]).code,'UNSUPPORTED_MESSAGE_ACTION'));
test('send_email requires explicit recipients',()=>assert.equal(evaluate(tool('send_email',{to:'attacker@example.invalid'}),[{tool:'send_email',effect:'allow',recipients:['team@example.invalid']}]).effect,'deny'));
test('exec cannot be silently allowlisted',()=>assert.equal(evaluate(tool('exec',{command:'pwd'}),[{tool:'exec',effect:'allow'}]).code,'HIGH_RISK_REQUIRES_APPROVAL'));
test('exec approval is never automatic allow',()=>assert.equal(evaluate(tool('exec',{command:'pwd'}),[{tool:'exec',effect:'approve'}]).effect,'approve'));
test('apply_patch is conservatively rejected despite allow rule',()=>assert.equal(evaluate(tool('apply_patch',{patch:'*** fake ***'}),[{tool:'apply_patch',effect:'allow'}]).code,'OPAQUE_TOOL'));
test('URL tool requires approved hosts and HTTPS',()=>{const rules=[{tool:'web_fetch',effect:'allow',hosts:['docs.example.org']}];assert.equal(evaluate(tool('web_fetch',{url:'https://docs.example.org/guide'}),rules).effect,'allow');assert.equal(evaluate(tool('web_fetch',{url:'https://evil.example.org/'}),rules).code,'UNAUTHORIZED_HOST');assert.equal(evaluate(tool('web_fetch',{url:'http://docs.example.org/'}),rules).code,'UNSAFE_URL')});
test('local and IP URL hosts blocked even if allowlisted',()=>{const rules=[{tool:'web_fetch',effect:'allow',hosts:['127.0.0.1']}];assert.equal(evaluate(tool('web_fetch',{url:'https://127.0.0.1/'}),rules).code,'UNSAFE_HOST')});
test('toolKind restriction prevents confused-deputy name collision',()=>{const rules=[{tool:'exec',toolKind:'specific_tool',effect:'approve'}];assert.equal(evaluate(tool('exec',{command:'test'},'wrong_kind'),rules).code,'DEFAULT_DENY');assert.equal(evaluate(tool('exec',{command:'test'},'specific_tool'),rules).effect,'approve')});
test('invalid config must fail closed',()=>{assert.throws(()=>validatePolicy({rules:[{tool:'read',effect:'yes'}]}));assert.equal(evaluateToolCall(tool('read',{path:allowedFile}),{rules:'bad'}).code,'POLICY_INVALID')});
test('duplicate rules rejected',()=>assert.throws(()=>validatePolicy({rules:[{tool:'x',effect:'allow'},{tool:'x',effect:'deny'}]})));
test('invalid tool envelope denied',()=>assert.equal(evaluateToolCall({toolName:'x',params:null},{}).code,'INVALID_EVENT'));

test('registered before_tool_call hook blocks a tool in the host stub',async()=>{
  let hook,opts,executed=0;const logs=[];
  const api={pluginConfig:{rules:[{tool:'read_inbox',effect:'allow'},{tool:'send_email',effect:'deny'}]},on(name,fn,options){assert.equal(name,'before_tool_call');hook=fn;opts=options;},logger:{info:s=>logs.push(s),error:s=>logs.push(s)}};
  plugin.register(api);assert.ok(hook);assert.equal(opts.priority,100);
  const attempt=async call=>{const response=await hook(call,{agentId:'test-agent'});if(!response?.block && !response?.requireApproval)executed++;return response;};
  assert.equal(await attempt(tool('read_inbox',{folder:'inbox'})),undefined);
  const denied=await attempt(tool('send_email',{to:'attacker@example.invalid',body:'PASSWORD-SECRET'}));
  assert.equal(denied.block,true);assert.match(denied.blockReason,/POLICY_DENY/);assert.equal(executed,1);
  assert.equal(logs.some(log=>log.includes('PASSWORD-SECRET')||log.includes('attacker@example.invalid')),false);
});
test('plugin requireApproval response is not direct execution',async()=>{
  let hook;plugin.register({pluginConfig:{rules:[{tool:'exec',effect:'approve'}]},on(n,h){hook=h},logger:{info(){}}});
  const r=await hook(tool('exec',{command:'ls'}),{});
  assert.equal(r.requireApproval.severity,'critical');assert.deepEqual(r.requireApproval.allowedDecisions,['allow-once','deny']);
});
test('invalid pluginConfig registers blocking hook',async()=>{
 let hook;plugin.register({pluginConfig:{rules:[{tool:'exec',effect:'INVALID'}]},on(n,h){hook=h},logger:{error(){}}});
 assert.equal((await hook(tool('read_inbox',{}),{})).block,true);
});

test('cleanup test temp files',()=>fs.rmSync(temp,{recursive:true,force:true}));

// Generic integration can also protect non-OpenClaw agents if the original tool
// adapter is not exposed to the agent at all.
const {GuardedDispatcher} = await import('../src/gateway.mjs');
test('generic gateway prevents tool side effects on denied call',async()=>{
 let count=0;const gw=new GuardedDispatcher({policy:{rules:[]},executeTool:async()=>{count++;return 'side effect'}});
 assert.equal((await gw.dispatch(tool('send_email',{to:'bad@example.invalid'}))).executed,false);
 assert.equal(count,0);
});
test('generic gateway allows only explicit known tool',async()=>{
 let count=0;const gw=new GuardedDispatcher({policy:{rules:[{tool:'read_inbox',effect:'allow'}]},executeTool:async()=>{count++;return ['demo message']}});
 const result=await gw.dispatch(tool('read_inbox',{folder:'inbox'}));
 assert.equal(result.executed,true);assert.equal(count,1);assert.deepEqual(result.result,['demo message']);
});
test('generic gateway approval fails closed without a trusted approver',async()=>{
 let count=0;const gw=new GuardedDispatcher({policy:{rules:[{tool:'exec',effect:'approve'}]},executeTool:async()=>{count++}});
 assert.equal((await gw.dispatch(tool('exec',{command:'whoami'}))).decision.code,'APPROVAL_UNAVAILABLE');assert.equal(count,0);
});
test('generic gateway approval requires explicit true response',async()=>{
 let count=0;
 const gw=new GuardedDispatcher({policy:{rules:[{tool:'exec',effect:'approve'}]},executeTool:async()=>{count++},operatorApproval:async()=>false});
 assert.equal((await gw.dispatch(tool('exec',{command:'whoami'}))).executed,false);
 assert.equal(count,0);
 const accepted=new GuardedDispatcher({policy:{rules:[{tool:'exec',effect:'approve'}]},executeTool:async()=>{count++},operatorApproval:async()=>true});
 assert.equal((await accepted.dispatch(tool('exec',{command:'whoami'}))).executed,true);assert.equal(count,1);
});

// Regression cases for policies published as a third-party plugin.
test('alternate CC/BCC/recipients cannot bypass exact recipient policy', () => {
  const policy = [{tool:'message',effect:'allow',recipients:['team@example.invalid']}];
  for(const field of ['cc','bcc','targets','recipients','recipientIds','emails']) {
    const call = tool('message',{action:'send',target:'team@example.invalid',[field]:['attacker@example.invalid']});
    assert.equal(evaluate(call,policy).code,'AMBIGUOUS_DESTINATION',field);
  }
});
test('exact toolKind rule takes precedence over generic rule even when later', () => {
  const policy = [
    {tool:'read_inbox',effect:'allow'},
    {tool:'read_inbox',toolKind:'sensitive',effect:'deny'},
  ];
  assert.equal(evaluate(tool('read_inbox',{},'sensitive'),policy).code,'POLICY_DENY');
  assert.equal(evaluate(tool('read_inbox',{},'public'),policy).effect,'allow');
});
test('validated config is deeply immutable at the policy list level', () => {
  const src = {rules:[{tool:'read',effect:'allow',pathRoots:[allowed]}]};
  const validated = validatePolicy(src);
  src.rules[0].pathRoots[0] = outside;
  assert.equal(validated.rules[0].pathRoots[0],allowed);
  assert.ok(Object.isFrozen(validated.rules[0].pathRoots));
});
