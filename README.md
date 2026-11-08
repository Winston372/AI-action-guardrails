# Action Guardrails

### Execution-Time Security for Autonomous AI Agents

**AI agents make decisions. Action Guardrails enforce permissions.**

**讓 AI Agent 可以犯錯，但不能越權執行。**

Action Guardrails is an open-source security plugin that helps prevent autonomous AI agents from performing unauthorized or potentially dangerous tool operations.

Instead of relying solely on system prompts or the AI model's judgment, Action Guardrails introduces an independent security policy layer **between the AI agent and tool execution**.

The project provides an OpenClaw plugin and a reusable JavaScript policy engine for other agent-based applications.

**Languages:** English | [繁體中文](#繁體中文說明)

---

## 1. Why Action Guardrails?

Autonomous AI agents can do more than generate text. They can read files, execute commands, access external services, send messages, and interact with other applications.

These capabilities create new security risks.

For example, an AI agent may encounter malicious instructions embedded in an email, document, or webpage. Through *prompt injection*, an attacker may attempt to influence the agent into performing actions that the legitimate user never authorized.

Traditional prompt-based safeguards are useful but cannot guarantee that every malicious instruction will be rejected.

**Action Guardrails addresses a different question:**

> Even if an AI agent makes a wrong decision, can we prevent that decision from becoming an unauthorized action?

The objective is to enforce permissions at the tool-execution boundary.

## 2. How It Works

**User Request → AI Agent → Action Guardrails → Tools**

When an AI agent attempts to invoke a tool, Action Guardrails evaluates the requested operation against security policies defined by the system operator.

The policy engine determines whether the requested action should be allowed, denied, or submitted for additional authorization.

| Decision | Behavior |
|---|---|
| **ALLOW** | Permit an operation that satisfies the configured security policy |
| **DENY** | Block an operation that violates the security policy |
| **REQUIRE APPROVAL** | Request operator authorization before execution, where supported by the host |

For example, an agent may attempt to read a private file outside its authorized workspace. Even if the model has already decided to perform that action, the policy engine can reject the tool call before the file is accessed.

The security policy is controlled by the operator, not by the agent or the external content it processes.

## 3. Key Features

| Feature | Description |
|---|---|
| **Default Deny** | Block tool operations unless explicitly authorized |
| **File Access Control** | Restrict file operations to designated directories |
| **Outbound Protection** | Limit supported messaging operations to approved recipients |
| **Network Restrictions** | Restrict supported web requests to approved HTTPS hosts |
| **High-Risk Action Control** | Deny or require authorization for high-risk tools |
| **Audit Logging** | Record policy decisions and relevant tool identifiers |

### Security Policy Enforcement

Action Guardrails supports configurable rules based on tool names and supported parameters.

Policies can define which operations are permitted and restrict access to sensitive resources.

For supported file operations, the policy engine checks absolute paths, configured directory boundaries, and symbolic links during evaluation.

For supported outbound operations, it checks the destination against an operator-defined allowlist.

### Human-in-the-Loop Security

Some operations may require an additional authorization decision.

The policy engine can classify selected actions as requiring operator approval.

Approval must be handled by a trusted mechanism outside the model. The plugin must not treat the agent's own statements as operator consent.

### Security Auditability

Action Guardrails supports policy-decision logging.

Logs contain decision codes and tool identifiers, rather than storing full prompts, message contents, file contents, or tool arguments.

This helps developers review rejected operations while reducing unnecessary exposure of sensitive information.

## 4. Architecture

The project contains three main components.

### Policy Engine

The central security component evaluates tool requests against configured authorization rules.

It implements default-deny behavior and supported resource-level restrictions.

### OpenClaw Plugin

The OpenClaw integration registers a `before_tool_call` hook.

When the compatible OpenClaw host invokes this hook, the plugin evaluates the tool request before execution and returns the corresponding enforcement decision.

### JavaScript SDK

The reusable `GuardedDispatcher` enables developers of other JavaScript-based AI agents to route tool operations through the same policy engine.

Applications must ensure that all relevant tool execution paths go through the guarded dispatcher.

## 5. Installation

### Requirements

- Node.js 20 or later
- A compatible OpenClaw installation for plugin integration
- Access to the complete project source code

### Step 1 — Clone the repository

```bash
git clone https://github.com/Winston372/AI-action-guardrails.git
cd AI-action-guardrails
```

### Step 2 — Run automated tests

```bash
npm test
npm run check
```

These commands run the included tests and JavaScript syntax checks.

### Step 3 — Install the OpenClaw plugin

```bash
openclaw plugins install ./
```

### Step 4 — Configure security policies

Configure the plugin in your existing OpenClaw configuration.

Merge the settings into your existing configuration rather than replacing the entire file.

Example:

```json
{
  "plugins": {
    "entries": {
      "action-guardrails": {
        "enabled": true,
        "config": {
          "auditDecisions": true,
          "rules": [
            {
              "tool": "read",
              "effect": "allow",
              "pathRoots": [
                "/home/user/safe-workspace"
              ]
            },
            {
              "tool": "exec",
              "effect": "deny"
            },
            {
              "tool": "message",
              "effect": "approve",
              "recipients": [
                "team@example.invalid"
              ]
            }
          ]
        }
      }
    }
  }
}
```

Replace the workspace path with an existing, trusted directory.

The `.invalid` email address is a non-deliverable placeholder, not a real recipient.

**Important:** Rules use exact tool names. Unmatched tools are denied by default. Configure trusted workflows carefully before enabling the plugin.

### Step 5 — Verify enforcement

After installation, test the plugin in an isolated OpenClaw environment.

Confirm that:

1. An authorized file read can proceed.
2. A file read outside the approved directory is blocked.
3. An explicitly denied tool cannot execute.
4. Tool calls actually pass through the registered security hook.

The plugin cannot protect tool execution paths that bypass its hook.

## 6. Example: Preventing Unauthorized File Access

Consider an AI agent instructed to summarize documents within an approved workspace.

An attacker embeds an instruction in an external document asking the agent to access a private file outside that workspace.

Without execution-time authorization, an unsafe agent integration might attempt to carry out that request.

With the following Action Guardrails policy:

```json
{
  "tool": "read",
  "effect": "allow",
  "pathRoots": [
    "/home/user/safe-workspace"
  ]
}
```

The supported file-reading tool is allowed to access files within the configured workspace, subject to the policy engine's path checks.

Attempts to read files outside the approved directory are rejected.

**The key principle is that an agent's decision does not constitute authorization.**

## 7. Integration with Other Agents

Developers can use `GuardedDispatcher` to apply security policies in JavaScript-based agent systems.

```javascript
import { GuardedDispatcher } from './src/gateway.mjs';

const gateway = new GuardedDispatcher({
  policy: {
    rules: [
      {
        tool: 'read_inbox',
        effect: 'allow'
      }
    ]
  },
  executeTool: async (call) => trustedToolAdapter(call)
});

const result = await gateway.dispatch({
  toolName: 'read_inbox',
  params: { folder: 'inbox' }
});
```

The application must define a trusted tool adapter and ensure the agent cannot bypass the dispatcher to invoke the underlying tools directly.

## 8. Current Limitations

Action Guardrails provides an additional execution-time authorization layer, not complete protection against prompt injection or data exfiltration.

Current limitations include:

- Operations that bypass the configured tool hook are not protected.
- Filesystem checks do not eliminate all time-of-check/time-of-use risks.
- Approved network destinations may still introduce security risks.
- Human approval requires trustworthy host-side implementation.
- Compatibility with specific OpenClaw versions must be verified.

For sensitive or production workloads, use additional controls such as operating-system sandboxing, network restrictions, least-privilege credentials, monitoring, and independent security review.

## 9. Development Status

**Version: 0.2.0 — Experimental Preview**

The policy engine, guarded dispatcher, and simulated OpenClaw hook have undergone automated testing.

Live end-to-end verification against an actual OpenClaw Gateway has not yet been completed.

This project has not undergone an independent security audit and is not currently considered production-ready.

Contributions, testing, issue reports, and security feedback are welcome.

## 10. License

Distributed under the MIT License.

See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md) for additional information.

---

# 繁體中文說明

## 一、什麼是 Action Guardrails？

**Action Guardrails — 自主 AI Agent 的執行層安全防護**

Action Guardrails 是一個開源的第三方安全元件，主要目的在於防止自主 AI Agent 執行未經授權的工具操作。

隨著 AI Agent 逐漸具備讀取檔案、執行指令、存取網路及操作外部服務的能力，AI 系統的安全問題已經不只是模型會不會產生錯誤答案，而是**錯誤決策是否可能直接轉變成實際操作**。

本專案透過獨立的安全政策引擎，在工具執行之前檢查權限，降低 Agent 越權操作的風險。

**核心理念：讓 Agent 可以犯錯，但不能越權執行。**

## 二、為什麼需要 Guardrails？

傳統的 AI 安全防護經常透過 System Prompt，要求模型遵守特定規則。

例如：

「不要讀取私人檔案。」

「不要將敏感資訊傳送給第三方。」

這些提示可以降低風險，但不能保證模型永遠不會受到外部惡意指示影響。

假設 AI Agent 正在整理電子郵件，其中一封郵件夾帶 Prompt Injection，要求 Agent 讀取私人檔案，再把資料寄送到外部地址。

即使使用者沒有授權，Agent 仍可能受到誘導而提出危險的工具呼叫。

Action Guardrails 的設計目的，就是在 Agent 已經提出操作請求之後，增加一道**獨立於模型判斷的執行權限檢查**。

## 三、運作原理

**使用者 → AI Agent → Action Guardrails → 工具執行**

當 Agent 要呼叫工具時，Guardrails 先檢查該操作是否符合預先設定的安全政策。

可能產生三種判斷：

| 判斷 | 實際意義 |
|---|---|
| **ALLOW（允許）** | 操作符合授權範圍，可繼續執行 |
| **DENY（拒絕）** | 操作違反安全規則，阻止執行 |
| **REQUIRE APPROVAL（要求核准）** | 需要透過可信任的核准機制取得授權 |

安全政策由系統管理者設定，不應由 Agent 自行修改。

因此，外部文件或郵件中的惡意指示，不能直接取得工具執行權限。

## 四、主要安全功能

### 1. Default Deny — 預設拒絕

沒有明確授權的工具操作，預設不允許執行。

這能避免 Agent 自動使用尚未經過安全評估的工具。

### 2. File Access Control — 檔案存取控制

限制 Agent 可以讀取或操作的檔案範圍。

例如只允許存取指定的工作資料夾，而非整台電腦。

### 3. Outbound Protection — 對外傳輸控制

針對支援的寄信與訊息工具，檢查收件者是否符合允許清單。

可降低 Agent 將資訊傳送到未授權目的地的風險。

### 4. Network Restrictions — 網路目的地限制

針對支援的網頁擷取工具，限制可存取的 HTTPS 網域。

這是工具層的目的地檢查，不能取代網路防火牆。

### 5. Human Approval — 人工核准

部分高風險工具操作可以設定為需要額外核准。

真正的核准必須由可信任的系統或使用者介面處理，而不是由 AI 自行宣稱已取得同意。

### 6. Audit Logging — 安全稽核紀錄

記錄工具呼叫的政策判斷及阻擋原因，協助開發者分析安全事件。

目前的紀錄設計避免直接儲存完整 Prompt、檔案內容及工具參數。

## 五、系統架構

Action Guardrails 包含三個核心部分。

| 元件 | 功能 |
|---|---|
| **Policy Engine** | 依安全政策判斷允許、拒絕或要求核准 |
| **OpenClaw Plugin** | 使用 `before_tool_call` 在工具執行前攔截 |
| **JavaScript SDK** | 讓其他 JavaScript Agent 接入相同的政策檢查機制 |

這樣的架構讓安全規則與 AI 模型本身分離。

即使模型更換，仍可依整合方式使用相同的安全政策。

## 六、安裝與使用

### 系統需求

- Node.js 20 或更新版本
- 相容的 OpenClaw 執行環境
- 完整的 Action Guardrails 專案原始碼

### 下載專案

```bash
git clone https://github.com/Winston372/AI-action-guardrails.git
cd AI-action-guardrails
```

### 執行測試

```bash
npm test
npm run check
```

### 安裝 Plugin

```bash
openclaw plugins install ./
```

接著依照自己的使用需求，在 OpenClaw 設定檔中啟用 Plugin 並配置安全政策。

建議先在測試環境確認權限檢查正常，再考慮導入實際工作流程。

## 七、實際安全政策範例

假設希望 AI Agent 只能讀取指定的工作資料夾：

```json
{
  "tool": "read",
  "effect": "allow",
  "pathRoots": [
    "/home/user/safe-workspace"
  ]
}
```

這段設定代表：

- `tool`：指定套用安全規則的工具。
- `effect`：符合條件時允許執行。
- `pathRoots`：指定允許存取的資料夾範圍。

當 Agent 嘗試讀取其他位置的私人檔案時，政策引擎會檢查路徑是否超出授權範圍。

如果不符合規則，操作將被拒絕。

**即使 Agent 已經決定讀取檔案，也不代表它具有讀取權限。**

## 八、其他 AI Agent 如何整合？

除了 OpenClaw，本專案也提供可重複使用的 JavaScript `GuardedDispatcher`。

開發者可以將 Agent 的工具執行流程接入統一的安全檢查層。

基本概念是：

**Agent 提出工具呼叫 → GuardedDispatcher 檢查政策 → 決定是否執行工具**

需要注意，開發者必須確保模型無法繞過這個檢查層直接操作底層工具。

## 九、安全限制與注意事項

Action Guardrails 並不是能夠阻止所有 Prompt Injection 的完整安全產品。

它主要負責的是**工具執行前的政策檢查**。

以下情況仍需要其他安全措施：

- Agent 可以透過未受保護的路徑直接執行操作。
- 工具本身具有過高的系統權限。
- 外部網路連線未受到適當限制。
- 執行環境缺乏隔離措施。
- 管理者設定了過於寬鬆的授權規則。

建議與最小權限原則、沙盒隔離、網路存取限制、人工審核及安全監控搭配使用。

## 十、專案目前狀態

**目前版本：v0.2.0 — 實驗性預覽版**

已完成政策引擎、OpenClaw Plugin 介面及 JavaScript GuardedDispatcher 的初步實作。

目前已進行自動化測試，包括預設拒絕、路徑範圍、收件者檢查、政策判斷及模擬 Hook 測試。

但尚未完成真實 OpenClaw Gateway 環境的端到端驗證，也未經獨立資安稽核。

因此，現階段適合開發者研究、測試與參與改善，不應直接視為已完成正式安全驗證的產品。

## 十一、開源授權

本專案採用 MIT License。

歡迎開發者檢視原始碼、提出 Issue、協助測試及改善政策執行機制。

---

### Our Principle｜核心理念

**AI Agents make decisions. Guardrails enforce permissions.**

**AI Agent 負責決策，Guardrails 負責執行權限。**
