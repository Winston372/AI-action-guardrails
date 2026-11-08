import { evaluateToolCall, validatePolicy } from './src/policy.mjs';

/** Native OpenClaw plugin. No model-controlled data can edit the policy in this hook. */
export default {
  id: 'action-guardrails',
  name: 'Action Guardrails',
  description: 'Execution-time allow/deny/approval policy for tool calls',
  register(api) {
    const rawPolicy = api.pluginConfig ?? {};
    let policy;
    try {
      policy = validatePolicy(rawPolicy);
    } catch (err) {
      api.logger?.error?.('[action-guardrails] Invalid policy; every tool call will be blocked');
      policy = null;
    }
    api.on('before_tool_call', async (event, ctx) => {
      let decision;
      try {
        decision = policy ? evaluateToolCall(event, policy) : { effect:'deny', code:'POLICY_INVALID', reason:'Operator policy invalid' };
      } catch {
        decision = { effect:'deny', code:'EVALUATION_ERROR', reason:'Policy evaluation failed' };
      }
      // Only metadata in logs. Never log prompt content, tool arguments, file bytes or messages.
      if (policy?.auditDecisions !== false) {
        api.logger?.info?.(`[action-guardrails] ${decision.effect.toUpperCase()} code=${decision.code} tool=${String(event?.toolName ?? 'unknown').replace(/[^\x20-\x7e]/g, '?').slice(0,80)} agent=${String(ctx?.agentId ?? 'unknown').replace(/[^\x20-\x7e]/g, '?').slice(0,80)}`);
      }
      if (decision.effect === 'deny') return { block:true, blockReason:`Action Guardrails [${decision.code}]: ${decision.reason}` };
      if (decision.effect === 'approve') return {
        requireApproval: {
          title: `Approve tool: ${event.toolName}`,
          description: `Operator-approved action requested. Policy: ${decision.code}. Review the exact tool arguments in OpenClaw before allowing.`,
          severity:'critical',
          timeoutMs:60_000,
          allowedDecisions:['allow-once','deny']
        }
      };
      return undefined; // permitted; do not mutate tool args
    }, { priority:100 });
  }
};
