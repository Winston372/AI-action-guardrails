# Action Guardrails

**Execution-time tool authorization for autonomous agents.** A native OpenClaw plugin and a small framework-independent JavaScript dispatcher.

> **Status: 0.2.0 preview.** The OpenClaw `before_tool_call` registration and policy engine are unit-tested using a host stub. **Live OpenClaw Gateway end-to-end integration has not yet been validated**, so do not label this as audited or production-ready.

## What it enforces

The plugin registers an OpenClaw **`before_tool_call`** hook. It checks each tool name and its arguments against an **operator-owned** policy before execution. It returns **block**, **approval required**, or **allow**. The LLM does not choose or modify the policy.

- **Default deny:** tools without an exact rule are blocked.
- **Filesystem boundaries:** `read`, `write`, `edit` require an absolute path under a configured existing directory, with realpath/symlink checks at evaluation time.
- **Outbound destinations:** `message` and `send_email` require a configured recipient; extra multi-recipient fields are refused.
- **Network destinations:** `web_fetch` requires HTTPS and an exact approved hostname (not a network firewall or complete SSRF defense).
- **High-risk tools:** `exec`, `process`, `browser`, `nodes` cannot be silently allowed; request explicit operator approval or deny them.
- **Audit:** logs decision codes and tool identifiers, not message text, paths, secrets or tool arguments.

An optional **`GuardedDispatcher`** exports the same policy engine for other JavaScript agents. Applications must wire **all** actual tool invocations through it.

## Install in OpenClaw

Requirements: Node.js 20+ and an OpenClaw instance that supports native plugin `before_tool_call` hooks. **Review the plugin source before installing:** plugins run with host privileges.

```bash
# From the cloned repository root
npm test
npm run check
openclaw plugins install ./
```

Edit your existing `~/.openclaw/openclaw.json` and **merge** this `plugins.entries` fragment (do **not** overwrite your whole file). Replace the placeholder path with an **existing trusted directory**. The `.invalid` destination is deliberately non-deliverable; replace it only if you really intend to permit a real recipient.

```json
{
  "plugins": {
    "entries": {
      "action-guardrails": {
        "enabled": true,
        "config": {
          "auditDecisions": true,
          "rules": [
            {"tool":"read", "effect":"allow", "pathRoots":["/home/YOU/safe-agent-workspace"]},
            {"tool":"exec", "effect":"deny"},
            {"tool":"process", "effect":"deny"},
            {"tool":"browser", "effect":"deny"},
            {"tool":"nodes", "effect":"deny"},
            {"tool":"message", "effect":"approve", "recipients":["team@example.invalid"]}
          ]
        }
      }
    }
  }
}
```

Windows JSON path format: `"C:\\Users\\YOU\\safe-agent-workspace"`. No rules means **all tools denied**; configure allowed workflows carefully before enabling it.

```bash
openclaw plugins enable action-guardrails
openclaw plugins inspect action-guardrails --runtime --json
openclaw plugins reload action-guardrails
```

On your **test instance**, confirm the hook loaded and compare a harmless `read` inside and outside the allowed root. The outside read must be blocked. Also check a disallowed `exec` request. If your specific runner does not emit `before_tool_call`, this plugin cannot guard those calls.

After you publish this repository on GitHub, users can install its reviewed, pinned ref via:

```bash
openclaw plugins install git:github.com/OWNER/action-guardrails@YOUR_TAG
```

The `OWNER` and `YOUR_TAG` values are placeholders; there is no claim that this GitHub repository already exists.

## Policy reference

| Tool rule | Effect | Behavior |
|---|---|---|
| no matching rule | — | deny |
| `read`, `write`, `edit` + `pathRoots` | allow / approve / deny | check canonical path against root |
| `message`, `send_email` + `recipients` | allow / approve / deny | match exactly one destination; reject CC/BCC/multiple destinations |
| `web_fetch` + `hosts` | allow / approve / deny | HTTPS exact hostname |
| `exec`, `process`, `browser`, `nodes` | approve / deny | never silent allow |
| `apply_patch` | — | always deny (cannot reliably scope opaque patch) |
| other tool names | explicit allow / approve / deny | **no parameter inspection**; only allow after auditing its adapter |

Rules are matched by exact `tool`. Optional `toolKind` restricts a rule to the host tool kind and takes priority over generic rules. `approve` uses OpenClaw's own approval flow. The plugin **does not automatically grant operator consent**.

## Use the dispatcher in another JavaScript Agent

```js
import { GuardedDispatcher } from 'openclaw-action-guardrails';

const gateway = new GuardedDispatcher({
  policy: { rules: [{ tool: 'read_inbox', effect: 'allow' }] },
  executeTool: async (call) => trustedToolAdapter(call),
});

const result = await gateway.dispatch({toolName: 'read_inbox', params: {folder: 'inbox'}});
if (!result.executed) console.log(result.decision.code);
```

The host must keep its real `trustedToolAdapter` private and route **every** model-controlled tool call through the dispatcher. Without a separately authenticated `operatorApproval`, an `approve` decision fails closed.

## Development / tests

```bash
npm test
npm run check
```

Tests cover default deny, path containment, traversal, symlinks, destinations, ambiguous recipients, tool kind matching, invalid policies, approvals, and registration of the native `before_tool_call` hook. CI runs them on every push / pull request.

## Security boundaries

This is **policy enforcement at the tool-call hook**, not a complete defense against prompt injection or data exfiltration. It cannot protect execution paths that bypass the hook, other privileged agents, or direct OS / network calls. In-process path checks have a time-of-check/time-of-use race. Allowed URLs can still redirect or leak data; apply firewall/egress rules and OS sandboxing. Other host plugins may rewrite tool arguments through hook mechanisms; validate final execution behavior in the actual host before relying on the policy. Do not permit agents to alter plugin configuration.

See [SECURITY.md](SECURITY.md) and [繁體中文說明](README.zh-TW.md).

## License

MIT.
