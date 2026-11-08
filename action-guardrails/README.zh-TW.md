# Action Guardrails｜實際可運作的工具執行前防護

這是**可安裝到 OpenClaw 的第三方 Plugin**，而非僅依賴 Prompt 的行為提示。它使用 `before_tool_call` 在 Agent 呼叫工具之前檢查可信管理者設定的政策，結果為：**允許 / 阻擋 / 要求人工核准**。

**驗證狀態：** 已完成 Node.js 政策引擎及模擬 Host Hook 的自動化測試；**尚未在真正的 OpenClaw Gateway 做端到端驗證**。公開程式碼不代表經過資安稽核或可直接用於生產環境。

## 安裝

需安裝 Node.js 20+、相容版本的 OpenClaw CLI。在解壓或 clone 的專案根目錄執行：

```bash
npm test
npm run check
openclaw plugins install ./
```

在 `~/.openclaw/openclaw.json` 裡**合併**以下設定（不要整份覆蓋；先把路徑換成實際存在且允許 Agent 讀取的目錄）：

```json
{
  "plugins": {
    "entries": {
      "action-guardrails": {
        "enabled": true,
        "config": {
          "auditDecisions": true,
          "rules": [
            { "tool": "read", "effect": "allow", "pathRoots": ["/home/YOU/safe-agent-workspace"] },
            { "tool": "exec", "effect": "deny" },
            { "tool": "message", "effect": "approve", "recipients": ["team@example.invalid"] }
          ]
        }
      }
    }
  }
}
```

Windows 路徑需要反斜線跳脫，例如 `"C:\\Users\\YOU\\safe-agent-workspace"`。設定檔請放在 Agent 無權更改的位置；**沒有規則等於拒絕所有工具**。

```bash
openclaw plugins enable action-guardrails
openclaw plugins inspect action-guardrails --runtime --json
openclaw plugins reload action-guardrails
```

在測試環境確認 `before_tool_call` 已載入，並測試允許範圍內的安全讀檔，以及**範圍外必須拒絕**的讀檔。確認這條路徑真的會經過 Hook 才能聲稱被這個 Plugin 保護。

## 主要功能

- **預設拒絕：** 不在政策清單的工具無法執行。
- **限制檔案路徑：** `read` / `write` / `edit` 僅可操作指定目錄，並於檢查時處理符號連結。
- **限制收件者：** `message` / `send_email` 需符合允許收件者；多收件者欄位會拒絕。
- **網址限制：** `web_fetch` 僅允許指定 HTTPS 主機，**不能取代網路防火牆**。
- **高風險操作：** `exec` / `process` / `browser` / `nodes` 不允許靜默放行，必須拒絕或要求人工核准。
- **稽核：** 記錄允許／拒絕原因，不記錄機密資料內容。

此套件另提供 `GuardedDispatcher`，讓 JavaScript Agent 開發者透過相同政策引擎包裝自己的 Tool Adapter；**不是所有 Agent 都能單靠安裝外掛自動受到保護**。

## 限制

這不是完整的 Prompt Injection 檢測、防資料外洩或防惡意程式產品。無法覆蓋不經 OpenClaw Hook 的工具、直接執行的程式、已授權的危險行為、其他外掛改寫參數造成的風險。檔案路徑檢查無法排除所有競態條件，網址白名單也無法阻擋重新導向／DNS 風險。正式部署仍須搭配作業系統隔離、最低權限及對外連線控管。

完整英文技術規格與 SDK 範例見 [README.md](README.md)，安全界限見 [SECURITY.md](SECURITY.md)。
