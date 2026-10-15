# ARGUS API 契约

> 本文档中的请求/响应示例**均由实际运行的代码产出**，不是手写示意。
> 文档与实现不一致时以代码为准（`backend/app/schemas/`），并应同步修正本文档。

## 目录

- [实现状态](#实现状态)
- [通用约定](#通用约定)
- [接口列表](#接口列表)
- [数据结构](#数据结构)
- [错误响应](#错误响应)
- [关键字段语义](#关键字段语义)

---

## 实现状态

ARGUS 采用分阶段开发，本文档同时承载「已实现的接口」与「已确定但尚未实现的契约」。
**下表必须与实际代码保持一致**：

| 接口 | 状态 | 说明 |
|---|---|---|
| `GET /` | ✅ 已实现 | 服务说明 |
| `GET /api/v1/health` | ✅ 已实现 | 健康检查 |
| `POST /api/v1/scan` | 📝 契约已定，阶段 5 实现 | 提交代码文本扫描 |
| `POST /api/v1/scan/upload` | 📝 契约已定，阶段 5 实现 | 上传单个文件扫描 |

请求/响应**模型**（`ScanRequest`、`Finding`、`ScanResponse`、错误结构）已在阶段 4 完成并通过测试，
因此前端可以在后端接口落地之前先按本契约编写类型定义。

---

## 通用约定

| 项目 | 约定 |
|---|---|
| Base URL | `http://127.0.0.1:8000` |
| 版本前缀 | `/api/v1` |
| 请求/响应体 | `application/json`（上传接口为 `multipart/form-data`） |
| 字符编码 | UTF-8 |
| 交互式文档 | `/docs`（Swagger UI）、`/redoc` |

### 枚举取值

所有枚举取值统一为**小写英文**。输入时**不区分大小写**（`"HIGH"`、`"High"`、`" high "` 都会归一化为 `"high"`）。

| 枚举 | 取值 |
|---|---|
| `severity` | `critical` / `high` / `medium` / `low` / `info` |
| `source` | `static_rule` / `heuristic` / `semgrep` / `llm` |
| `status`（ScanResponse） | `completed` / `partial` / `failed` |
| `analyzer_status[].state` | `success` / `skipped` / `unavailable` / `failed` |
| `analyzer_status[].name` | `language_detection` / `feature_extraction` / `rules` / `semgrep` / `llm` |

### 未知值的表示

**行号无法可靠定位时返回 `null`，不使用 `0` 或 `-1` 作为哨兵值。**

原因：哨兵值在类型上与真实行号无法区分，前端一旦漏判就会把 `-1` 渲染成行号，
这与「不得编造行号」的要求直接冲突。前端应根据 `null` 显示「未能可靠定位」。

同理，`detected_language` 无法识别时为 `null`（显示「未知语言」），而不是字符串 `"unknown"` 之外的花招
（`"unknown"` 本身也是合法取值，由阶段 6 的语言识别模块决定使用哪种表示，届时同步更新本文档）。

### 请求体严格校验

请求模型设置了 `extra="forbid"`：提交未定义的字段会返回 422。
这是有意为之——字段名拼错时应当立刻报错，而不是静默忽略导致「以为启用了某项分析，其实没有」。

---

## 接口列表

### `GET /`

返回服务说明与常用入口。

```json
{
  "service": "ARGUS API",
  "version": "0.1.0",
  "description": "ARGUS 智能代码安全分析平台后端服务",
  "docs": "/docs",
  "health": "/api/v1/health"
}
```

### `GET /api/v1/health`

返回服务状态、版本与运行环境。无需认证，不读写用户数据。

```json
{
  "status": "ok",
  "service": "ARGUS API",
  "version": "0.1.0",
  "environment": "development"
}
```

> ⚠️ `status` 为 `ok` **只代表 Web 服务本身可用**，不代表规则、Semgrep 或 LLM 分析器已就绪。
> 各分析器的实际状态由扫描响应中的 `analyzer_status` 报告。

### `POST /api/v1/scan` （阶段 5 实现）

提交代码文本进行扫描。

**请求体：**

```json
{
  "source_code": "def get_user(user_id):\n    query = \"SELECT * FROM users WHERE id = \" + user_id\n    return db.execute(query)\n",
  "language": "python",
  "filename": "views.py",
  "analysis_options": {
    "enable_llm": false,
    "enable_semgrep": false
  }
}
```

| 字段 | 类型 | 必填 | 约束 |
|---|---|---|---|
| `source_code` | string | 是 | 不能为空或仅含空白字符；长度上限由配置 `MAX_SOURCE_CODE_CHARS` 决定（默认 200000 字符） |
| `language` | string \| null | 否 | 小写标识，匹配 `^[a-z0-9+#._-]+$`，最长 32；省略时由后端自动识别 |
| `filename` | string \| null | 否 | **仅作展示**，不参与任何文件系统操作；不能含路径分隔符、`..`、空字符，不能是 Windows 保留名，最长 255 |
| `analysis_options.enable_llm` | boolean | 否 | 默认 `false`。与配置 `LLM_ENABLED` 的关系在阶段 10 明确 |
| `analysis_options.enable_semgrep` | boolean | 否 | 默认 `false`。Semgrep 未安装时会降级为 `unavailable`，不会导致扫描失败 |

**响应：** `ScanResponse`，见[数据结构](#数据结构)。

### `POST /api/v1/scan/upload` （阶段 5 实现）

上传单个代码文件进行扫描，`multipart/form-data`，文件字段名为 `file`。

- 允许的扩展名在一处集中配置，阶段 5 补充完整清单（预期包含 `.py` `.js` `.jsx` `.ts` `.tsx` `.php` `.java` `.go` `.rb` `.html` `.vue`）。
- 文件大小上限由配置 `MAX_UPLOAD_SIZE_BYTES` 决定（默认 1 MB）。
- 不依据客户端提交的 MIME 类型判断安全性；文件在内存中处理，不落盘。
- 响应与 `POST /api/v1/scan` 完全一致（同样是 `ScanResponse`），两条入口共用同一分析流程。

---

## 数据结构

### `Finding`

一条**候选发现**。请注意：它表示「值得人工复核的线索」，不等于已确认的漏洞。

```json
{
  "id": "c0018ebefa2292bb",
  "title": "疑似 SQL 注入：查询语句由字符串拼接构造",
  "vulnerability_type": "sql_injection",
  "severity": "high",
  "description": "SQL 查询通过字符串拼接构造，若 user_id 来自用户输入，攻击者可改变查询语义。",
  "evidence": "query = \"SELECT * FROM users WHERE id = \" + user_id",
  "line_start": 2,
  "line_end": 2,
  "recommendation": "改用参数化查询，例如 db.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))。",
  "confidence": 0.7,
  "source": "static_rule",
  "cwe_id": "CWE-89"
}
```

| 字段 | 类型 | 约束与说明 |
|---|---|---|
| `id` | string | 1–64 字符。稳定标识符：同一问题在多次扫描中保持相同，便于去重与前端列表 key 稳定。由 `make_finding_id()` 生成 |
| `title` | string | 1–200 字符 |
| `vulnerability_type` | string | 1–100 字符。使用受控词表（如 `sql_injection`），不要填自由描述 |
| `severity` | enum | 见[枚举取值](#枚举取值) |
| `description` | string | 1–4000 字符。面向用户的风险说明 |
| `evidence` | string | 0–2000 字符。**允许为空**——没有可展示的片段时宁可留空，也不编造 |
| `line_start` | integer \| null | ≥ 1。无法可靠定位时为 `null` |
| `line_end` | integer \| null | ≥ 1。必须 ≥ `line_start`；只给 `line_start` 表示单行发现；给了 `line_end` 就必须给 `line_start` |
| `recommendation` | string | 1–4000 字符。可以是「建议人工复核」这类保守表述 |
| `confidence` | number | 0.0–1.0（闭区间）。语义见[关键字段语义](#关键字段语义) |
| `source` | enum | 见[枚举取值](#枚举取值) |
| `cwe_id` | string \| null | 形如 `CWE-89`。没有明确对应关系时留空，不要硬套 |

> 未知字段会被**忽略**而不是报错。这一行为是有意的：同一个模型既要承接我们自己分析器的输出，
> 也要承接 LLM 的返回，后者常带额外字段；若设成 `extra="forbid"`，一条多余的说明字段就会让整条发现有价值信息被丢弃。
> 需要严格校验 LLM 返回时，应在阶段 9 用单独的传输对象承接后再转换成本模型。

### `ScanResponse`

```json
{
  "scan_id": "7f3a9c21b4e8d056",
  "status": "partial",
  "detected_language": "python",
  "findings": [ "...见上方 Finding..." ],
  "summary": {
    "total_findings": 2,
    "severity_counts": {
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    },
    "source_counts": {
      "static_rule": 1,
      "llm": 1
    }
  },
  "duration_ms": 184,
  "analyzer_status": [
    {
      "name": "language_detection",
      "state": "success",
      "reason": null,
      "duration_ms": 1,
      "findings_count": 0
    },
    {
      "name": "feature_extraction",
      "state": "success",
      "reason": null,
      "duration_ms": 3,
      "findings_count": 2
    },
    {
      "name": "rules",
      "state": "success",
      "reason": null,
      "duration_ms": 5,
      "findings_count": 1
    },
    {
      "name": "semgrep",
      "state": "unavailable",
      "reason": "未检测到 semgrep 可执行文件，已跳过该分析器",
      "duration_ms": null,
      "findings_count": 0
    },
    {
      "name": "llm",
      "state": "success",
      "reason": null,
      "duration_ms": 175,
      "findings_count": 1
    }
  ],
  "disclaimer": "ARGUS 是代码安全分析的辅助工具，不是安全证明工具。结果来自规则匹配、特征启发式与（可选的）模型判断，均可能误报或漏报。confidence 表示分析器对自身判断的估计，不是漏洞真实发生的概率。未发现漏洞不代表代码绝对安全，请结合人工复核。"
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `scan_id` | string | 8–64 字符。用于关联历史记录（阶段 15）与修复建议（阶段 16） |
| `status` | enum | `completed` / `partial` / `failed` |
| `detected_language` | string \| null | 识别出的语言；无法识别时为 `null` |
| `findings` | array | 候选发现列表 |
| `summary` | object | **必须由真实结果计算**，见下方说明 |
| `duration_ms` | integer | ≥ 0。实际耗时 |
| `analyzer_status` | array | 各分析器状态 |
| `disclaimer` | string | 定位声明，默认固定文案 |

#### `summary`

| 字段 | 说明 |
|---|---|
| `total_findings` | 发现总数，必须等于 `findings` 的长度 |
| `severity_counts` | 按严重等级计数。固定包含全部 5 个等级，前端无需处理「某等级缺失」 |
| `source_counts` | 按来源计数，只包含实际出现过的来源 |

`ScanSummary` 通过 `ScanSummary.from_findings(findings)` 构造，把统计与结果绑定，
避免出现摘要数字与 `findings` 对不上的情况。**实现中不允许手工填写这些数字。**

#### `analyzer_status[]`

| 字段 | 类型 | 说明 |
|---|---|---|
| `name` | enum | 分析器标识 |
| `state` | enum | `success` / `skipped` / `unavailable` / `failed` |
| `reason` | string \| null | **非 `success` 状态时必须提供**，否则模型校验失败 |
| `duration_ms` | integer \| null | 未执行时为 `null` |
| `findings_count` | integer | ≥ 0。`0` 表示未发现问题，与「分析失败」是两回事 |

---

## 错误响应

所有错误路径返回**同一结构**：

```json
{
  "error": {
    "code": "validation_error",
    "message": "请求参数校验未通过，请检查提交的内容。",
    "details": []
  }
}
```

| 字段 | 说明 |
|---|---|
| `code` | 机器可读错误码，供前端分支处理 |
| `message` | 面向用户的中文说明 |
| `details` | 字段级明细；没有明细时为空数组，不是 `null` |

### 错误码

| `code` | 典型状态码 | 含义 |
|---|---|---|
| `invalid_request` | 400 / 429 | 请求无法处理 |
| `validation_error` | 422 | 参数校验未通过 |
| `empty_input` | 422 | 输入为空 |
| `input_too_large` | 413 / 422 | 输入超过大小限制 |
| `unsupported_file_type` | 415 | 文件类型不支持 |
| `unsupported_language` | 422 | 语言不受支持 |
| `not_found` | 404 | 资源不存在 |
| `method_not_allowed` | 405 | 请求方法不允许 |
| `analyzer_failed` | 200（体现在 `analyzer_status`） | 某个分析器执行失败 |
| `llm_unavailable` | — | LLM 未配置或不可用 |
| `llm_output_invalid` | — | LLM 返回内容不合法 |
| `internal_error` | 500 | 服务器内部错误 |

### 真实示例

以下响应均由实际运行产出。

**空代码 → 422**

```json
{
  "error": {
    "code": "validation_error",
    "message": "请求参数校验未通过，请检查提交的内容。",
    "details": [
      {
        "field": "source_code",
        "message": "source_code 不能为空或仅包含空白字符"
      }
    ]
  }
}
```

**超长代码 → 422**（响应体仅 155 字节，**不回显**那 200 KB 的源代码）

```json
{
  "error": {
    "code": "validation_error",
    "message": "请求参数校验未通过，请检查提交的内容。",
    "details": [
      {
        "field": "source_code",
        "message": "source_code 长度 200001 超过上限 200000 个字符"
      }
    ]
  }
}
```

**未知字段 → 422**

```json
{
  "error": {
    "code": "validation_error",
    "message": "请求参数校验未通过，请检查提交的内容。",
    "details": [
      {
        "field": "analysis_options.enable_llmm",
        "message": "不支持的字段，请检查字段名是否拼写正确。"
      }
    ]
  }
}
```

**非法语言 → 422**

```json
{
  "error": {
    "code": "validation_error",
    "message": "请求参数校验未通过，请检查提交的内容。",
    "details": [
      {
        "field": "language",
        "message": "格式不合法，需匹配模式 ^[a-z0-9+#._-]+$。"
      }
    ]
  }
}
```

**路径穿越文件名 → 422**

```json
{
  "error": {
    "code": "validation_error",
    "message": "请求参数校验未通过，请检查提交的内容。",
    "details": [
      {
        "field": "filename",
        "message": "filename 只能是文件名，不能包含路径分隔符"
      }
    ]
  }
}
```

**不存在的路由 → 404**

```json
{
  "error": {
    "code": "not_found",
    "message": "请求的资源不存在。",
    "details": []
  }
}
```

**未捕获异常 → 500**

```json
{
  "error": {
    "code": "internal_error",
    "message": "服务器内部错误，请稍后重试。",
    "details": []
  }
}
```

### 错误响应的安全约定

1. **不返回 Python traceback、服务器文件路径、API key 或环境变量。**
   500 响应只包含固定文案，完整堆栈仅写入服务端日志。
2. **不回显用户提交的源代码。** Pydantic 原始错误项中的 `input` 字段在校验失败时
   会携带出错字段的完整取值——当 `source_code` 本身校验失败时，那就是整段代码。
   实现中刻意丢弃了 `input` 与 `ctx`，只保留字段路径与说明文本。
3. **错误提示已本地化为中文。** Pydantic 内置的英文消息会被替换；
   未覆盖的错误类型保留原文，以便排错。

---

## 关键字段语义

### `confidence` 不是漏洞概率

`confidence` 表示**分析器对自身判断的估计**：

- 规则命中给出的是「这条模式匹配得有多典型」；
- LLM 给出的是模型自评的把握程度。

因此：

- **不同来源的 `confidence` 不可直接比较，更不可相加。**
- **不得用它推算「总体安全分数」。**
- 它是给人工复核排序用的参考值，不能解读为「这个漏洞有 70% 概率真实存在」。

### `source` 的作用

每条发现都必须如实标注来源，让用户能区分：

- `static_rule`：可解释的规则证据，可复现、可追查；
- `heuristic`：基于语言特征的候选线索，置信度最低，仅作提示；
- `semgrep`：外部静态分析工具的结论；
- `llm`：模型的语义判断，可能受提示与上下文影响。

多个分析器报告同一问题时，结果会合并或标注为关联发现，但**原始证据不会被丢弃**。

### 空 `findings` 不等于代码安全

`findings: []` 的含义取决于 `analyzer_status`：

- 所有分析器 `success` 且 `findings` 为空 → 本次分析未发现问题；
- 存在 `failed` / `unavailable` 的分析器 → 只是这些分析没有执行，**不能读作「代码安全」**。

前端必须结合 `analyzer_status` 与 `disclaimer` 展示，不能只显示「未发现漏洞」。
