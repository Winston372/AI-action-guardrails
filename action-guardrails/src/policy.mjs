/**
 * Action Guardrails: operator-authored exact-match policy for OpenClaw tool calls.
 * All decisions are made on host-side metadata, never instructions in external content.
 * No user/model content is written to the audit log.
 * WARNING: in-process hooks cannot replace OS sandboxing or kernel-enforced controls.
 */
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';

const FILE_TOOLS = new Set(['read', 'write', 'edit']);
const SEND_TOOLS = new Set(['message', 'send_email']);
// Multi-destination or alternate route fields cannot be validated from a single target.
const MULTI_DESTINATION_KEYS = ['cc', 'bcc', 'targets', 'recipients', 'recipientIds', 'emails'];
const URL_TOOLS = new Set(['web_fetch']);
const SHELL_TOOLS = new Set(['exec', 'process', 'browser', 'nodes']);
const ALWAYS_DENY_TOOLS = new Set(['apply_patch']); // opaque patch text; derivedPaths are not authoritative
const EFFECTS = new Set(['allow', 'deny', 'approve']);
const RESULT = (effect, code, reason) => Object.freeze({ effect, code, reason });
const deny = (code, reason) => RESULT('deny', code, reason);
const approve = (code, reason) => RESULT('approve', code, reason);
const allow = (code, reason) => RESULT('allow', code, reason);

const isPlainRecord = x => x !== null && typeof x === 'object' && !Array.isArray(x) && Object.getPrototypeOf(x) === Object.prototype;
const validStrings = x => x === undefined || (Array.isArray(x) && x.every(s => typeof s === 'string' && s.length > 0));
const dangerousProtoKeys = new Set(['__proto__', 'constructor', 'prototype']);

export function validatePolicy(input) {
  // Fail closed: even a configuration typo must never produce implicit permission.
  if (!isPlainRecord(input)) throw new Error('policy config must be an object');
  if (Object.keys(input).some(k => !['rules', 'auditDecisions'].includes(k))) throw new Error('unknown policy config key');
  if (input.auditDecisions !== undefined && typeof input.auditDecisions !== 'boolean') throw new Error('auditDecisions must be boolean');
  if (input.rules !== undefined && !Array.isArray(input.rules)) throw new Error('rules must be an array');
  const rules = input.rules ?? [];
  const keys = new Set();
  for (const r of rules) {
    if (!isPlainRecord(r)) throw new Error('rule must be an object');
    if (Object.keys(r).some(k => !['tool', 'toolKind', 'effect', 'pathRoots', 'recipients', 'hosts'].includes(k))) throw new Error('unknown rule key');
    if (typeof r.tool !== 'string' || !r.tool || dangerousProtoKeys.has(r.tool)) throw new Error('invalid tool name');
    if (r.toolKind !== undefined && (typeof r.toolKind !== 'string' || !r.toolKind)) throw new Error('invalid toolKind');
    if (!EFFECTS.has(r.effect)) throw new Error('effect must be allow, deny, approve');
    if (![r.pathRoots, r.recipients, r.hosts].every(validStrings)) throw new Error('scope lists must contain strings');
    const key = `${r.tool}\u0000${r.toolKind ?? ''}`;
    if (keys.has(key)) throw new Error(`duplicate rule: ${r.tool}`);
    keys.add(key);
  }
  // Copy arrays so a caller cannot change a validated policy through shared references.
  return Object.freeze({
    rules: Object.freeze(rules.map(r => Object.freeze({
      ...r,
      ...(r.pathRoots ? {pathRoots: Object.freeze([...r.pathRoots])} : {}),
      ...(r.recipients ? {recipients: Object.freeze([...r.recipients])} : {}),
      ...(r.hosts ? {hosts: Object.freeze([...r.hosts])} : {}),
    }))),
    auditDecisions: input.auditDecisions ?? true
  });
}

function scopedValue(params, keys) {
  const seen = keys.filter(k => Object.hasOwn(params, k));
  if (seen.length !== 1 || typeof params[seen[0]] !== 'string' || params[seen[0]].length === 0) return null;
  return params[seen[0]];
}

function nearestExistingPath(p) {
  // realpath existing ancestor so symlinks cannot trivially escape configured roots.
  let cursor = path.resolve(p);
  const suffix = [];
  while (!fs.existsSync(cursor)) {
    const parent = path.dirname(cursor);
    if (parent === cursor) return null;
    suffix.unshift(path.basename(cursor));
    cursor = parent;
  }
  return path.resolve(fs.realpathSync(cursor), ...suffix);
}

function withinRoot(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function validatePath(params, roots) {
  if (!Array.isArray(roots) || roots.length === 0) return deny('PATH_SCOPE_MISSING', 'Operator has not configured any path roots');
  const p = scopedValue(params, ['path', 'file_path', 'filePath']);
  if (!p || !path.isAbsolute(p) || p.includes('\u0000')) return deny('INVALID_PATH', 'A single absolute file path is required');
  try {
    const candidate = nearestExistingPath(p);
    if (!candidate) return deny('UNRESOLVED_PATH', 'Cannot resolve requested path');
    for (const root of roots) {
      if (!path.isAbsolute(root)) return deny('INVALID_ROOT', 'Configured path roots must be absolute');
      // If a configured root does not exist, deny instead of guessing its future target.
      const canonicalRoot = fs.realpathSync(root);
      if (withinRoot(candidate, canonicalRoot)) return null;
    }
  } catch {
    return deny('PATH_CHECK_ERROR', 'Unable to verify path containment');
  }
  return deny('OUTSIDE_ALLOWED_ROOT', 'Requested path is outside approved filesystem roots');
}

function validateRecipient(params, recipients) {
  // A second recipient list must never escape a single-recipient allowlist.
  if (MULTI_DESTINATION_KEYS.some(k => Object.hasOwn(params, k))) {
    return deny('AMBIGUOUS_DESTINATION', 'Additional destination fields are not supported');
  }
  if (!Array.isArray(recipients) || recipients.length === 0) return deny('RECIPIENT_SCOPE_MISSING', 'No authorized recipients configured');
  const dest = scopedValue(params, ['to', 'target', 'recipient']);
  if (!dest) return deny('INVALID_RECIPIENT', 'Exactly one recipient field is required');
  const d = dest.trim().toLowerCase();
  return recipients.some(x => x.trim().toLowerCase() === d) ? null : deny('UNAUTHORIZED_RECIPIENT', 'Destination is not on the operator allowlist');
}

function validateUrl(params, hosts) {
  if (!Array.isArray(hosts) || hosts.length === 0) return deny('HOST_SCOPE_MISSING', 'No approved URL hosts configured');
  const value = scopedValue(params, ['url']);
  if (!value) return deny('INVALID_URL', 'A URL is required');
  try {
    const u = new URL(value);
    if (u.protocol !== 'https:' || u.username || u.password || (u.port && u.port !== '443')) return deny('UNSAFE_URL', 'Only standard HTTPS without URL credentials is supported');
    const host = u.hostname.toLowerCase();
    if (!hosts.some(h => h.toLowerCase() === host)) return deny('UNAUTHORIZED_HOST', 'Host not on operator allowlist');
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || net.isIP(host)) return deny('UNSAFE_HOST', 'Local domains and literal IP targets are disallowed');
    return null;
  } catch {
    return deny('INVALID_URL', 'Invalid URL');
  }
}

export function evaluateToolCall(event, policyInput = {}) {
  let policy;
  try { policy = validatePolicy(policyInput); }
  catch { return deny('POLICY_INVALID', 'Operator policy is invalid'); }
  if (!event || typeof event.toolName !== 'string' || !isPlainRecord(event.params)) return deny('INVALID_EVENT', 'Tool metadata is incomplete');
  const name = event.toolName;
  // A toolKind-specific rule wins over a generic rule, regardless of order.
  const rule = policy.rules.find(r => r.tool === name && r.toolKind !== undefined && r.toolKind === event.toolKind)
    ?? policy.rules.find(r => r.tool === name && r.toolKind === undefined);
  if (!rule) return deny('DEFAULT_DENY', 'No exact operator rule for this tool and kind');
  if (rule.effect === 'deny') return deny('POLICY_DENY', 'Tool explicitly denied by operator');

  if (ALWAYS_DENY_TOOLS.has(name)) return deny('OPAQUE_TOOL', 'Opaque multi-file patch cannot be safely scoped at this hook');
  if (FILE_TOOLS.has(name)) {
    const d = validatePath(event.params, rule.pathRoots);
    if (d) return d;
  }
  if (SEND_TOOLS.has(name)) {
    const d = validateRecipient(event.params, rule.recipients);
    if (d) return d;
    if (name === 'message' && event.params.action !== 'send') return deny('UNSUPPORTED_MESSAGE_ACTION', 'Only explicit message.send supported');
  }
  if (URL_TOOLS.has(name)) {
    const d = validateUrl(event.params, rule.hosts);
    if (d) return d;
  }
  // Shell, browser, and remote node operations cannot be statically proven safe.
  // Host approval can be requested, but an agent must never auto-approve them.
  if (SHELL_TOOLS.has(name) && rule.effect !== 'approve') return deny('HIGH_RISK_REQUIRES_APPROVAL', 'High-impact tools must require operator approval');
  if (rule.effect === 'approve') return approve('OPERATOR_APPROVAL_REQUIRED', `Operator approval required for ${name}`);
  return allow('EXPLICIT_ALLOW', `Rule allows ${name}`);
}
