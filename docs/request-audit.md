# HTTP 请求包审计（LLM）

> 阶段 19 产物。接口：`POST /api/v1/audit/request`。
>
> **这不是 DAST。** 服务端只读取报文文本，不重放请求、不访问目标、不执行任何内容。
> 它发现的是报文本身可见的风险信号，不能确认服务端是否存在 SQL 注入、XSS、越权等漏洞。
>
> 请求包审计**只保留 LLM 这一路分析**，没有本地规则检测。解析与脱敏是本地确定性步骤，
> 但它们不产生审计发现。

## 1. 定位与能力边界

### 能做什么

- 解析一段原始 HTTP/1.x 请求报文，展示方法、路径、协议、头部、参数与 body 摘要；
- 对报文中的凭证与个人信息做**发送前脱敏**，并给出脱敏预览；
- 脱敏预览**可手动编辑**；确认后把编辑后的文本原样发送给 LLM 做语义审计；
- 所有发现都带真实报文行号、脱敏证据、来源与置信度。

### 不能做什么

| 做不到 | 原因 |
|---|---|
| 确认 SQL 注入 / XSS / 命令注入 | 需要服务端如何处理参数的代码或响应 |
| 判断越权 / IDOR | 需要多用户、多请求对比 |
| 检查响应头、Cookie 属性、TLS 配置 | 请求报文里没有响应信息 |
| 判断 origin-form 请求是 http 还是 https | 报文本身不携带协议；只有 absolute-form 才能确定 |
| 重放或验证攻击 | 本项目明确禁止向目标发起请求 |

因此结果统一使用“候选发现 / 风险信号”的措辞，严重等级最高只到 `high`：
`critical` 会被降为 `high`；`missing_csrf_token` 最高 `low`；
`content_type_mismatch` 与 `suspicious_payload_pattern` 最高 `medium`。

## 2. 输入与解析

- 支持 CRLF 与 LF；孤立 CR、NUL、缺少头部空行、折叠头、畸形请求行会直接报错。
- 支持 origin-form（`/path?query`）、absolute-form（`http(s)://host/path?query`）与 `OPTIONS *`。
- 不支持的 `CONNECT host:port` 会明确报错，不做猜测。
- 请求头最多 200 条、报文最多 20,000 行、字符上限由 `MAX_HTTP_REQUEST_CHARS` 控制（默认 64,000）。
- body 形态：`none` / `urlencoded` / `json` / `multipart` / `text`。multipart 不拆分字段，只做文本脱敏。
- 行号从请求行（第 1 行）开始；body 行号按空行之后的位置计算。

解析只把报文变成结构化数据，**不判断安全性**。

## 3. 脱敏

默认替换以下内容，只保留名称与结构，便于模型继续判断：

| 位置 | 规则 |
|---|---|
| 请求头 | `Authorization`、`Proxy-Authorization`、`Cookie`、`Set-Cookie`、`X-API-Key`、`X-Auth-Token`、`X-CSRF-Token` 等 |
| Cookie | 请求中的 Cookie 值全部替换，只保留名称；Set-Cookie 保留 `Path`/`HttpOnly`/`SameSite` 等属性 |
| URL 查询参数 | 参数名命中 `password`、`token`、`secret`、`session`、`api_key`、`csrf` 等，或值呈已知令牌形态 |
| URL 用户信息 | `http://user:pass@host` → `http://<REDACTED>@host` |
| JSON / 表单 body | 敏感字段名的值替换；已知令牌形态即使出现在普通字段也替换 |
| 普通文本 | JWT、`sk-`、`AKIA`、GitHub token、`Bearer`/`Basic` 凭证 |

已知令牌形态只收高置信度模式，避免把普通 base64 或代码片段误删；
但**脱敏规则不是穷尽的**，用户仍必须在预览中人工检查。

## 4. 两阶段确认

```
POST /audit/request {raw_request, preview_only: true}
        ↓ 返回 redacted_request + preview_fingerprint（不产生发现）
用户查看并编辑脱敏预览
        ↓
POST /audit/request {raw_request, redacted_request: <编辑后的文本>,
                     confirm_send: true, preview_fingerprint: <编辑文本的 SHA-256>}
        ↓ 服务端核对指纹后，以 redacted_request 为准调用 LLM
```

- 预览文本可编辑。编辑后前端重新计算 SHA-256，作为新的 `preview_fingerprint`；
- 正式审计时如果提供 `redacted_request`，服务端**以它为准**，不会再对原始报文重新脱敏；
- 正式审计时 `confirm_send` 不为 `true` → `422 request_confirmation_required`；
- 指纹与提交的文本不一致 → `409 request_preview_outdated`；
- 预览模式不会发起模型请求，也不会产生审计发现；正式审计必须确认预览。

## 5. 分析能力：只有 LLM

请求包审计**没有本地规则检测**。本地只做两件确定性、但不产出发现的事：

1. 解析报文结构（方法、目标、头部、参数、body）；
2. 脱敏并生成预览指纹。

原因：

- 请求包是结构化数据，适合先解析再判断；但本项目按课程要求不再为请求包维护一套本地规则；
- 仅凭一段请求报文无法确认 SQL 注入、XSS、越权等服务端漏洞，本地规则能提供的也只是
  “参数名敏感”“Content-Type 不一致”这类信号，容易让结果看起来比实际更确定；
- 把判断集中到 LLM，能力边界更清晰：**没有 LLM 就没有审计发现**，
  不会出现“本地规则说没问题”的误导。

因此：

- 预览阶段的 `findings` 恒为空；
- 服务端未启用 LLM、未配置 LLM 或 LLM 失败时，`findings` 为空，整体 `status=partial`；
- 前端必须展示原因，不能把空结果读成“请求安全”。

## 6. LLM 审计

- 只接收脱敏后的报文，不接收原始报文、历史记录或响应。
- 系统提示词声明报文是不可信数据，报文放在带随机后缀的 `<request-…>` 标签中。
- 允许类别：`sensitive_data_in_url`、`credentials_in_plaintext`、`missing_csrf_token`、
  `content_type_mismatch`、`suspicious_payload_pattern`。
- 输出校验：
  - `RequestLlmFinding` 使用 `extra="forbid"`，字段缺失或多出未约定键即丢弃该条；
  - `evidence` 必须是实际发送的脱敏文本的逐字子串；
  - 行号必须落在实际发送的行范围内；证据必须能在该行范围内找到；
  - 模型没给行号时，只有证据能唯一匹配一行才推导，否则丢弃；
  - 模型声称有发现但全部不合格 → 整次 LLM 审计报 `failed`，不会显示成“没发现问题”；
  - 等级按类别收紧：`critical` → `high`，CSRF 信号最高 `low`，
    Content-Type / 攻击载荷特征最高 `medium`。
- 置信度仍是模型自评，不是漏洞概率。
- 请求报文里的文本可能尝试提示词注入；上述证据与行号校验用于限制编造结果。

## 7. 状态与结果

- 分析器状态只有两部分：
  - `http_request_parse`：解析与脱敏，总是成功（失败时接口直接返回 422）；
  - `http_request_llm`：`success` / `skipped` / `unavailable` / `failed`，非成功必须带原因。
- 只有 LLM `success` 时整体 `status=completed`；预览、未启用、未配置或失败时均为 `partial`。
- `findings` 全部来自 LLM，按严重程度、行号与类别排序；同一类别同一行在 LLM 解析阶段去重。
- `edited=true` 表示用户手动编辑过预览：`redacted_request` 是编辑后的文本，
  `redaction.redacted_count` 为 0（服务端没有再次脱敏）。
- 没有本地结果可以兜底；LLM 失败时返回空发现 + 失败原因，而不是旧结果或猜测结果。

## 8. 隐私与安全

- 原始报文**不写入**扫描历史、SQLite、日志、报告或 Git。
- 不重放请求、不向目标发起网络请求、不执行 body 中的任何内容。
- LLM 只收到确认后的文本；调用前必须确认预览，指纹绑定防止确认后替换内容。
- 预览允许手动编辑，**编辑后的内容会原样发送**。用户需要自行确认没有把真实凭证
  重新写回预览；服务端不会对 `redacted_request` 再次脱敏。
- 错误响应只含固定中文说明，不回显原始报文、密钥或内部路径。
- 该接口与扫描/修复/删除历史一样校验浏览器 `Origin`，阻止跨站触发。
- `LLM_ENABLED=false` 依然是完全的熔断开关；此时请求审计不会产生任何发现。

## 9. 真实响应示例

以下为一次 `preview_only=true` 的实际响应（部分字段省略）：

```json
{
  "audit_id": "dededc4ac8d15846",
  "status": "partial",
  "preview_only": true,
  "parsed": {
    "method": "POST",
    "target": "/login?next=/home&token=<REDACTED>",
    "path": "/login",
    "http_version": "HTTP/1.1",
    "scheme": null,
    "header_count": 4,
    "parameter_count": 4,
    "cookie_count": 2,
    "body": {
      "kind": "json",
      "content_type": "application/json",
      "length": 41,
      "line_start": 7
    },
    "line_count": 7
  },
  "redacted_request": "POST /login?next=/home&token=<REDACTED> HTTP/1.1\nHost: example.com\nAuthorization: Bearer <REDACTED>\nCookie: session=<REDACTED>; theme=<REDACTED>\nContent-Type: application/json\n\n{\"username\":\"alice\",\"password\":\"<REDACTED>\"}",
  "preview_fingerprint": "b0bbee7ba9c333e1158db7e3f3312cbee377a592361a7c7b483c02f36b73b6d1",
  "redaction": {
    "redacted_count": 5,
    "categories": ["body:password", "header:authorization", "header:cookie", "query:token"]
  },
  "findings": [],
  "summary": {
    "total_findings": 0,
    "severity_counts": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "source_counts": {}
  },
  "analyzer_status": [
    {"name": "http_request_parse", "state": "success", "findings_count": 0},
    {
      "name": "http_request_llm",
      "state": "skipped",
      "reason": "预览模式：未调用 LLM。预览阶段只解析与脱敏，不产生审计发现。",
      "findings_count": 0
    }
  ],
  "llm_invoked": false
}
```

## 10. 已知限制

- **没有 LLM 就没有审计结果**：预览、未配置或调用失败时 `findings` 为空，
  这不代表请求安全。
- 只支持单段 HTTP/1.x 文本报文；HTTP/2 伪头部、chunked 编码细节、multipart 字段不展开。
  因此 multipart 中按字段名承载的敏感值可能漏脱敏，**必须在预览中人工检查**。
- 只看请求，不看响应；Cookie 属性、响应安全头等无法检查。
- origin-form 无法判断实际协议，“明文传输”只在 absolute-form 的 `http://` 上报告。
- 脱敏依赖名称与令牌模式，可能漏掉自定义格式的凭证；**必须以预览为准**。
- 预览允许手动编辑，编辑后以编辑文本为准发送；把真实凭证重新写回预览属于用户操作，
  服务端不会再次脱敏。
- LLM 判断不可复现，且会受报文表述影响；所有结果都需要人工复核。
- 没有历史与报告：请求包审计结果不进入扫描历史，也不会生成报告。
