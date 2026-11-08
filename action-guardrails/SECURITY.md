# Security policy and limitations

Action Guardrails enforces operator-defined decisions only at OpenClaw's `before_tool_call` hook (and through `GuardedDispatcher` where explicitly wired). It is not antivirus, a data-loss-prevention product, or a network firewall.

## Operational rules

1. Keep policy configuration and plugin files outside agent-writable paths. Review sources before installation.
2. Grant the least tools necessary; unconfigured tools are blocked by default.
3. Require human review for `exec`, `process`, `browser`, `nodes`, and sensitive outbound operations.
4. Combine this hook with OS sandboxing, filesystem permissions, network egress controls, and secret segregation.
5. Verify actual host coverage, including other plugin hooks and tool parameter rewrites, on the OpenClaw version you deploy.

## Known limitations

- In-process path containment can be raced by symlink/path changes between check and filesystem use (TOCTOU).
- URL hostname checks do not stop redirects, DNS rebinding or exfiltration to an approved host.
- Additional nonstandard/third-party tools may have parameter envelopes not inspected by this policy; even an explicit `allow` may be unsafe for those tools.
- Not all OpenClaw runtimes or tool relays necessarily emit the same hook; direct calls bypassing the tool router are not covered.
- A more privileged plugin or runtime may rewrite parameters after a policy decision; do not treat this as an immutable execution boundary without host-level verification.
- Approvals are delegated to the host, not cryptographically verified by this package.
- Policy engine / host stub tests have passed. A real OpenClaw Gateway integration test and an independent security audit are still outstanding.

If reporting vulnerabilities, use synthetic/test data and redact credentials. No production deployment should rely solely on this plugin.
