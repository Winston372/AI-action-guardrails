# Action Guardrails

**Execution-Time Security for Autonomous AI Agents**

Action Guardrails is an open-source security plugin designed to prevent AI agents from executing unauthorized or potentially dangerous tool operations.

Instead of relying solely on system prompts, Action Guardrails enforces security policies at the tool-execution boundary.

**An AI agent can make a wrong decision. That doesn't mean the action should be executed.**

## Key Features

- **Default Deny** — Block tool operations unless explicitly authorized.
- **File Access Control** — Restrict file operations to approved directories.
- **Outbound Protection** — Prevent unauthorized messages and data transfers.
- **Network Restrictions** — Limit supported web requests to approved HTTPS destinations.
- **Human Approval** — Require authorization for high-risk operations.
- **Audit Logging** — Record security decisions for review and debugging.

## How It Works

User Request → AI Agent → Tool Call → **Action Guardrails** → Tool Execution

Before executing a tool call, Action Guardrails evaluates it against security policies configured by the operator.

The result is one of three decisions:

- **ALLOW** — Execute an authorized action.
- **BLOCK** — Reject an unauthorized action.
- **REQUEST APPROVAL** — Require human confirmation before execution.

## Quick Start

**Requirements:** Node.js 20+ and a compatible OpenClaw installation.

Clone the repository:

`git clone https://github.com/Winston372/AI-action-guardrails.git`

`cd AI-action-guardrails`

Run automated tests:

`npm test`

`npm run check`

Install the OpenClaw plugin:

`openclaw plugins install ./`

Configure the plugin in your OpenClaw settings before using it. See the configuration examples included in this repository.

## Integration

Action Guardrails provides:

1. **OpenClaw Plugin** — Integrates through the `before_tool_call` hook to enforce security policies before tool execution.
2. **JavaScript Policy Engine** — Provides a reusable guarded dispatcher for other JavaScript-based agents.

## Development Status

**Version 0.2.0 — Preview**

The policy engine and simulated OpenClaw hook have been tested. Live OpenClaw Gateway end-to-end integration has not yet been verified.

This project is experimental and has not undergone an independent security audit. It is not production-ready.

Action Guardrails provides an additional execution-time authorization layer, not complete protection against prompt injection or data exfiltration.

## Documentation

- [Traditional Chinese Guide](README.zh-TW.md)
- [Security Information](SECURITY.md)
- [Configuration Example](examples/openclaw-config-example.json)

## License

MIT License.

---

**Security should not depend solely on whether an AI agent makes the right decision. It should also depend on what the agent is actually allowed to execute.**
