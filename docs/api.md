# ARGUS API 契约

> 本文档中的请求/响应示例**均由实际运行的代码产出**，不是手写示意。
> 文档与实现不一致时以代码为准（`backend/app/schemas/`），并应同步修正本文档。

## 目录

- [实现状态](#实现状态)
- [通用约定](#通用约定)
- [接口列表](#接口列表)
- [数据结构](#数据结构)
- [语言识别](#语言识别)
- [特征提取与候选线索](#特征提取与候选线索)
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
| `POST /api/v1/scan` | ✅ 已实现（阶段 6） | 提交代码文本；已接入语言识别、特征提取与候选线索提取 |
| `POST /api/v1/scan/upload` | ✅ 已实现（阶段 6） | 上传单个文件；分析能力与 `/scan` 完全一致 |

> ⚠️ **当前只有「启发式」这一路分析。** 本地规则（阶段 7）、Semgrep（阶段 8）与
> LLM（阶段 9）尚未接入，它们会在 `analyzer_status` 中标记为 `skipped` / `unavailable`
> **并给出原因**。因此：
>
> - `findings` 中的每一条来源都是 `heuristic`，**是候选线索，不是已确认的漏洞**；
> - `findings` 为空不代表代码安全，前端必须结合 `analyzer_status` 展示；
> - 只要还有分析器没执行，`status` 就是 `partial` 而不是 `completed`。

请求/响应**模型**（`ScanRequest`、`Finding`、`ScanResponse`、错误结构）在阶段 4 完成，
输入校验在阶段 5 落地，分析能力自阶段 6 起接入，均已通过测试。

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
| `analyzer_status[].name` | `language_detection` / `feature_extraction` / `clue_extraction` / `rules` / `semgrep` / `llm` |
| `features.language_source` | `explicit` / `extension` / `heuristic` / `none` |

### 未知值的表示

**行号无法可靠定位时返回 `null`，不使用 `0` 或 `-1` 作为哨兵值。**

原因：哨兵值在类型上与真实行号无法区分，前端一旦漏判就会把 `-1` 渲染成行号，
这与「不得编造行号」的要求直接冲突。前端应根据 `null` 显示「未能可靠定位」。

同理，**语言无法识别时 `detected_language` 为 `null`，不使用 `"unknown"` 这类哨兵字符串**。
虽然在类型上 `"unknown"` 也能通过 `LanguageId` 的格式校验，但它与真实语言取值混在同一取值域里，
前端一旦漏判就会把「未知语言」当成一种真实语言渲染出来。
前端应依据 `null` 显示「未知语言」。

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

### `POST /api/v1/scan`

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
| `language` | string \| null | 否 | 小写标识，匹配 `^[a-z0-9+#._-]+$`，最长 32；省略时由后端自动识别，见[语言识别](#语言识别) |
| `filename` | string \| null | 否 | **仅作展示**，不参与任何文件系统操作；完整规则见[文件名校验](#文件名校验) |
| `analysis_options.enable_llm` | boolean | 否 | 默认 `false`。与配置 `LLM_ENABLED` 的关系在阶段 10 明确 |
| `analysis_options.enable_semgrep` | boolean | 否 | 默认 `false`。Semgrep 未安装时会降级为 `unavailable`，不会导致扫描失败 |

JSON 请求体按规范即为 UTF-8，因此响应中的 `source_encoding` 固定为 `null`。

**响应：** `ScanResponse`，见[数据结构](#数据结构)。

### `POST /api/v1/scan/upload`

上传单个代码文件进行扫描，`multipart/form-data`。

**表单字段：**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `file` | file | 是 | 待扫描的文件。**必须带扩展名**，扩展名决定文件类型 |
| `language` | string | 否 | 显式指定语言，**优先级高于扩展名与内容推断** |
| `enable_llm` | boolean | 否 | 默认 `false` |
| `enable_semgrep` | boolean | 否 | 默认 `false` |

**处理流程与安全边界：**

| 步骤 | 行为 |
|---|---|
| 1. 文件名 | 校验见[文件名校验](#文件名校验)。文件名**只用于展示与推断语言**，不会被拼接成任何路径 |
| 2. 扩展名 | 与配置 `ALLOWED_FILE_EXTENSIONS` 比对。**只看扩展名，完全不读取客户端提交的 `Content-Type`** |
| 3. 大小 | 分块读取（每块 64 KB），累计超过 `MAX_UPLOAD_SIZE_BYTES`（默认 1 MB）**立即停止读取**并返回 413 |
| 4. 编码 | BOM 感知解码；无 BOM 时依次严格尝试 UTF-8、GBK，失败则返回 422 |
| 5. 字符数 | 解码后字符数超过 `MAX_SOURCE_CODE_CHARS` 返回 413 |
| 6. 分析 | 构造与 `/scan` 相同的 `ScanRequest`，进入同一流程 |

**允许的文件类型**（由 `ALLOWED_FILE_EXTENSIONS` 配置，默认值）：

`.py` `.js` `.jsx` `.ts` `.tsx` `.php` `.java` `.go` `.rb` `.html` `.vue`

**编码处理：**

- UTF-8 / UTF-16 带 BOM 的文件按 BOM 指定的编码解码。
- 无 BOM 时依次严格尝试 **UTF-8**、**GBK**。GBK 兜底是为了兼容中文 Windows 上
  "记事本另存为"产生的源码文件。
- 全部使用 `errors="strict"`：**解不开就报错，绝不用替换字符悄悄"修好"**。
  静默替换会把"这个文件解不开"变成"这个文件解开了但内容是乱码"，
  后者会一路流到分析器和界面，产生无法解释的结论。
- 含 NUL 字节、或解码后控制字符占比超过 2% 的内容判定为非文本，返回 422。
- **实际使用的编码会在响应的 `source_encoding` 字段中返回**——
  落到 GBK 兜底时必须让用户知道，否则就是一次静默的字符集转换。

**不落盘：** 全程只在内存中处理，不写入任何文件，也不产生由文件名派生的路径。
（Starlette 对超过 1 MB 的请求体会使用自动清理的临时缓冲；在 1 MB 上限内不会触发。）

**响应：** 与 `POST /api/v1/scan` 完全一致（同样是 `ScanResponse`）。

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
  "scan_id": "7c929a39e4604047a3582ec099b7dc58",
  "status": "partial",
  "detected_language": "python",
  "source_encoding": null,
  "findings": [
    {
      "id": "281259ed3c9bbefb",
      "title": "检测到可能的用户输入来源",
      "vulnerability_type": "untrusted_input_source",
      "severity": "info",
      "description": "启发式线索（尚未确认为漏洞）：检测到可能的用户输入来源。这是数据来源标记，本身不是缺陷；用于与危险调用位置对照判断流向。",
      "evidence": "uid = request.args.get(\"id\")",
      "line_start": 5,
      "line_end": 5,
      "recommendation": "这是一处数据来源标记，本身不是缺陷。请沿该值的流向检查是否进入了命令执行、SQL 拼接、动态执行或 HTML 输出等危险位置；若确实如此，在进入危险位置之前做校验与转义。",
      "confidence": 0.25,
      "source": "heuristic",
      "cwe_id": null
    },
    {
      "id": "a9dd01b4c456b580",
      "title": "疑似 SQL 语句由字符串拼接或格式化构造",
      "vulnerability_type": "sql_injection",
      "severity": "low",
      "description": "启发式线索（尚未确认为漏洞）：疑似 SQL 语句由字符串拼接或格式化构造。需人工确认拼接部分是否来自不可信输入；若使用参数化占位符则不构成风险。",
      "evidence": "q = \"SELECT * FROM users WHERE id = \" + uid",
      "line_start": 6,
      "line_end": 6,
      "recommendation": "请确认该语句是否受用户输入影响。若受影响的只是参数值，改用参数化查询（占位符 + 参数绑定）即可；若表名、列名、排序字段也来自输入，则需改用白名单映射，占位符无法覆盖这类位置。",
      "confidence": 0.45,
      "source": "heuristic",
      "cwe_id": "CWE-89"
    },
    {
      "id": "ba5dfad57c1622fe",
      "title": "检测到系统命令调用",
      "vulnerability_type": "command_injection",
      "severity": "low",
      "description": "启发式线索（尚未确认为漏洞）：检测到系统命令调用。命令行由拼接或变量构造时需确认参数是否来自不可信输入；固定字面量参数风险较低。",
      "evidence": "os.system(\"ping -c 1 \" + host)",
      "line_start": 10,
      "line_end": 10,
      "recommendation": "请确认命令参数是否来自不可信输入。若来自，优先改为参数数组调用并避免经过 shell；无法避免时对参数做白名单校验，不要依赖对特殊字符的转义。",
      "confidence": 0.45,
      "source": "heuristic",
      "cwe_id": "CWE-78"
    }
  ],
  "summary": {
    "total_findings": 3,
    "severity_counts": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 2,
      "info": 1
    },
    "source_counts": {
      "heuristic": 3
    }
  },
  "duration_ms": 0,
  "analyzer_status": [
    {
      "name": "language_detection",
      "state": "success",
      "reason": null,
      "duration_ms": 0,
      "findings_count": 0
    },
    {
      "name": "feature_extraction",
      "state": "success",
      "reason": null,
      "duration_ms": null,
      "findings_count": 0
    },
    {
      "name": "clue_extraction",
      "state": "success",
      "reason": null,
      "duration_ms": null,
      "findings_count": 3
    },
    {
      "name": "rules",
      "state": "skipped",
      "reason": "本地规则检测将在阶段 7 接入，本次扫描未执行该分析器。",
      "duration_ms": null,
      "findings_count": 0
    },
    {
      "name": "semgrep",
      "state": "skipped",
      "reason": "本次请求未启用该分析器（对应的 analysis_options 开关为 false）。",
      "duration_ms": null,
      "findings_count": 0
    },
    {
      "name": "llm",
      "state": "skipped",
      "reason": "本次请求未启用该分析器（对应的 analysis_options 开关为 false）。",
      "duration_ms": null,
      "findings_count": 0
    }
  ],
  "features": {
    "language": "python",
    "language_source": "extension",
    "language_evidence": "由文件名扩展名 .py 确定",
    "stats": {
      "total_lines": 10,
      "non_blank_lines": 8,
      "total_chars": 211,
      "max_line_length": 47
    },
    "structure": {
      "function_count": 2,
      "class_count": 0,
      "import_count": 2,
      "imports": [
        "os",
        "flask"
      ]
    },
    "notes": [
      "候选线索按 python 的语法特征逐行匹配得到，跨行书写的语句不会被识别，因此必然存在漏报。",
      "函数数与类数按语言声明模式匹配得到，属近似值：不解析语法树，无法识别匿名函数等形式。"
    ]
  },
  "disclaimer": "ARGUS 是代码安全分析的辅助工具，不是安全证明工具。结果来自规则匹配、特征启发式与（可选的）模型判断，均可能误报或漏报。confidence 表示分析器对自身判断的估计，不是漏洞真实发生的概率。未发现漏洞不代表代码绝对安全，请结合人工复核。"
}
```

> 上面是**实际运行产出**：`POST /api/v1/scan` 提交一个 10 行的 `views.py`
> （含 `request.args.get`、字符串拼接的 SQL、以及 `os.system` 拼接调用）。
>
> 三条发现全部为 `source: "heuristic"`，严重等级最高只有 `low`，最高置信度 0.45——
> 这正是「候选线索」应有的样子：**它们标出值得人工复核的位置，而不是断言存在漏洞**。
> 标题与描述都刻意使用"疑似""检测到"而非"存在漏洞"。
>
> `status` 为 `partial` 是如实的：规则、Semgrep 与 LLM 都没有执行。

| 字段 | 类型 | 说明 |
|---|---|---|
| `scan_id` | string | 8–64 字符。用于关联历史记录（阶段 15）与修复建议（阶段 16） |
| `status` | enum | `completed` / `partial` / `failed` |
| `detected_language` | string \| null | 识别出的语言；无法识别时为 `null` |
| `source_encoding` | string \| null | 上传文件实际使用的解码方式；JSON 提交为 `null`。见[编码处理](#post-apiv1scanupload) |
| `findings` | array | 候选发现列表 |
| `summary` | object | **必须由真实结果计算**，见下方说明 |
| `duration_ms` | integer | ≥ 0。实际耗时 |
| `analyzer_status` | array | 各分析器状态 |
| `features` | object \| null | 特征提取结果，见 [`features`](#features)。为 `null` 表示该步骤未执行 |
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
| `duration_ms` | integer \| null | 未执行时为 `null`。语言识别、特征提取与候选线索提取共用一次调用，**耗时只计在 `language_detection` 上**，另两项为 `null`，以免同一个数字被重复计数 |
| `findings_count` | integer | ≥ 0。`0` 表示未发现问题，与「分析失败」是两回事 |

`clue_extraction` 与 `feature_extraction` 分开报告，是因为「统计做了、线索没做」是一种真实状态：
语言未识别时统计仍可完成，线索提取则会跳过。合在一起会导致要么误报成功、要么误报失败。

### `features`

特征提取的产出。它描述**看到了什么**，不含任何"这是不是漏洞"的判断。

```json
{
  "language": "python",
  "language_source": "extension",
  "language_evidence": "由文件名扩展名 .py 确定",
  "stats": { "total_lines": 10, "non_blank_lines": 8, "total_chars": 211, "max_line_length": 47 },
  "structure": { "function_count": 2, "class_count": 0, "import_count": 2, "imports": ["os", "flask"] },
  "notes": ["..."]
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `language` | string \| null | 与 `detected_language` 一致。`null` 表示未识别 |
| `language_source` | enum | `explicit` / `extension` / `heuristic` / `none`，见[语言识别](#语言识别) |
| `language_evidence` | string | 1–200 字符。得出该结论的依据，例如 `"由文件名扩展名 .py 确定"`。**未识别时也必须说明尝试过什么**，不能只给一个空洞的 `null` |
| `stats` | object | 客观计数，见下 |
| `structure` | object | 结构信息，见下 |
| `notes` | array | 处理说明，每项 1–300 字符。用于交代"哪些信息没取到、为什么" |

#### `features.stats`

| 字段 | 说明 |
|---|---|
| `total_lines` | 总行数。末行的换行符不额外算作一行（`"a\n"` 是 1 行） |
| `non_blank_lines` | 非空行数（仅含空白字符的行不计入） |
| `total_chars` | 字符总数，与输入**逐字符一致**（含换行符） |
| `max_line_length` | 最长一行的字符数（不含换行符） |

#### `features.structure`

| 字段 | 说明 |
|---|---|
| `function_count` | 函数/方法的**大致**数量 |
| `class_count` | 类/结构体的**大致**数量 |
| `import_count` | 匹配到的导入语句条数，可能大于 `imports` 的长度（超出上限的部分被丢弃） |
| `imports` | 导入的**模块名**列表，已去重、按出现顺序、最多 200 条 |

> ⚠️ **`function_count` 与 `class_count` 是近似值。** 它们通过按语言匹配声明模式得到，
> 不解析语法树、不编译、不导入代码，因此**无法识别匿名函数**等形式。
> 未登记模式的语言（如 `vue`）或未识别的语言，两者均为 `0`，
> 且 `notes` 中会明确写出"未统计"，避免把 `0` 误读成"这个文件没有函数"。

---

### 文件名校验

`filename` 与上传的 `file` 文件名共用同一套规则（实现见 `validate_display_filename()`）。
**该字段只用于展示来源与推断语言，永远不会被拼接成文件系统路径。**

| 拒绝的情况 | 示例 | 原因 |
|---|---|---|
| 空字符串 / 全空白 | `""`、`"   "` | 无意义 |
| 路径分隔符 | `dir/views.py`、`dir\views.py` | 调用方在传路径 |
| `..`（含中间出现） | `../../etc/passwd`、`archive..tar.py` | 路径跳转，中间出现也保守拒绝 |
| 冒号 | `C:views.py`、`views.py:evil` | Windows 盘符前缀 / NTFS 数据流 |
| Windows 保留名 | `CON`、`con.py`、`NUL.txt`、`LPT1.py` | 保留设备名 |
| 尾随点 | `views.py.` | Windows 静默丢弃，`views.py.` 与 `views.py` 会指向同一文件 |
| NUL 字符 | `views.py\x00.txt` | C 层字符串截断，可绕过扩展名检查 |
| 超长 | > 255 字符 | 与常见文件系统上限一致 |

首尾**空白会被去除而不是报错**：该字段仅作展示，去空白不影响任何判定，
且 Windows 本身也会丢弃文件名末尾的空格。

**关于百分号编码**：`%2e%2e%2f` 这类百分号编码的穿越串到达服务端时已是字面量文本，
既不含分隔符也不含 `..`，因此不会被路径规则拦截。之所以不额外拒绝含 `%` 的文件名：
该字段从不参与路径拼接，字面量是惰性的，而拒绝所有含 `%` 的名字会误伤
`100%_done.py` 这类正常文件。此行为由测试 `test_upload_rejects_percent_encoded_traversal_only_as_a_type_error` 固定。

---

## 语言识别

### 优先级

从高到低，**前一级拿到结论就不再往下走**：

| 优先级 | 来源（`language_source`） | 判定方式 | 可信度 |
|---|---|---|---|
| 1 | `explicit` | 请求中显式指定的 `language`（JSON 字段或上传表单字段） | 调用方说了算 |
| 2 | `extension` | 文件扩展名查表，**确定性**，不是猜测 | 高 |
| 3 | `heuristic` | 代码内容特征推断（shebang、语法标记） | 可能出错 |
| 4 | `none` | 以上都不成立，`language` 返回 `null` | — |

> 扩展名优先于内容特征：扩展名是查表，内容是启发式。
> 因此一个内容像 PHP 但名为 `views.py` 的文件会被判定为 `python`——
> 这是有意的，调用方给出的信息比猜测更可靠。

### 内容特征

第三级只使用**明确的语法标记**，并按登记顺序取第一条命中。刻意不收录模糊信号：

- `<?php`、`<!DOCTYPE html>`、`<template>…<script>`（Vue 单文件组件）
- 无分号的 `package main`（Go）／有分号的 `package com.example;`（Java）
- `import java.*`、`from ... import ...`、以冒号结尾的 `def`
- `function 名(`、`console.log(`、箭头函数赋值
- shebang：`#!/usr/bin/env python3`、`#!/usr/bin/node` 等（会剥掉版本号与 `env` 前缀）

**单独一个 `class Foo` 不足以判定语言**——Java、JS、Python 里都合法。
这类情况下返回 `null` 而不是猜一个：猜错语言会让候选线索按错误的规则去匹配，
产出一批看似合理、实则无关的结果，**比不产出更糟**。

### 未识别时会发生什么

`language` 为 `null`、`language_source` 为 `none`，并且：

- `feature_extraction` 仍然 `success`（统计与结构不依赖语言）；
- `clue_extraction` 变为 `skipped` **并说明原因**；
- `features.notes` 中记录「未识别出语言，已跳过候选线索提取」。

---

## 特征提取与候选线索

### 候选线索不是漏洞

`clue_extraction` 产出的是**值得人工复核的位置**，不是漏洞判定。为让这一点无法被误读，
实现中做了硬性约束（均有测试固定）：

| 约束 | 取值 | 理由 |
|---|---|---|
| `source` | 恒为 `heuristic` | 便于与规则证据区分 |
| `severity` | **最高只到 `low`** | 判定严重程度是规则检测器的职责 |
| `confidence` | **0.25–0.45** | 只是"值得看一眼"的强度，不是漏洞概率 |
| 措辞 | "疑似""检测到" | 绝不写"存在漏洞" |

### 按行匹配

逐行扫描。这带来几个确定的性质：

- **行号一定准确**——命中即所在行，不存在偏移；
- 同一行内同一模式只报告一次；同一行内不同模式会各报一条
  （例如一行里既读输入又拼接 SQL，会得到两条线索，因为它们要说明的事情不同）；
- **跨行书写的语句不会被识别**，因此这一层**必然漏报**。

### 误报控制

两条措施：

1. **一条线索必须匹配到明确的语法特征**，不做"包含某关键字"式的宽泛匹配。
2. **SQL 线索要求同一行内同时出现 SQL 关键字与拼接/格式化算子**，
   因此 `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
   这类**参数化写法不会命中**。

命令执行类的线索同样要求实参是动态的（变量、拼接或插值）：
`os.system('ls -la')`、`subprocess.run(["git", "status"])`、`exec.Command("git", "status")`
这类**固定字面量参数不会命中**——没有拼接就没有注入面，报出来只会制造噪音。
（`subprocess(..., shell=True)` 例外：它无论参数如何都会经过 shell 解释，因此单独报告。）

另有几类同名方法被显式排除：`re.compile(...)`、`model.eval()`、
`RegExp.prototype.exec`（`pattern.exec(s)`）都不是动态执行；
`el.innerHTML === cached` 是读取后比较，不是写入。这些若不在模式里排除掉，
误报会非常密集。

#### 仍然会误报的地方

逐行词法匹配**无法区分字符串字面量、正则字面量与真正的代码**。
一个具体的例子：ARGUS 自身的 `_SQL_KEYWORD` 正则里写有 `insert\s+into`，
其中的 `+` 是正则量词，但按行匹配会把它连同 `SELECT ... FROM` 一起
读成"SQL 关键字 + 字符串拼接"，从而报出一条线索。

在我们自己的后端代码上实测（25 个文件、3118 行，均为安全代码）：
报出 **2 条**线索，密度约 **0.64 条/千行**，两条都能按上述原因解释。

> 这个数字**不是精确率或召回率的估计**——没有人工标注的基准集，
> 它只是"在已知安全的代码上会产生多少噪音"的一个观察值。
> 正式的评估指标属于阶段 14 的工作。

### 线索类别

| `vulnerability_type` | 触发示例 | `cwe_id` |
|---|---|---|
| `sql_injection` | SQL 关键字与拼接/格式化出现在同一行 | `CWE-89` |
| `command_injection` | `os.system`/`system`/`Runtime.exec`/`exec.Command` 且实参为变量或拼接；`shell=True` | `CWE-78` |
| `unsafe_dynamic_execution` | `eval` / `exec` / `new Function` / PHP 的 `/e` 修饰符 | `CWE-95` |
| `xss` | `innerHTML =` / `dangerouslySetInnerHTML` / `v-html` / 模板的 `\| safe` | `CWE-79` |
| `unsafe_deserialization` | `pickle` / `marshal` / `dill` 的 `load(s)` | `CWE-502` |
| `untrusted_input_source` | `request.args` / `req.body` / `$_GET` / `getParameter` / `params[` | 无（本身不是缺陷） |

`untrusted_input_source` 的严重等级为 `info`、置信度 0.25：
它只是**数据来源标记**，用于与其他危险位置对照判断流向。前端展示时应当与
其余类别区别对待，不要把它渲染成"发现了一个漏洞"。

### 发现的 `id` 是稳定的

`id` 由 `source` + 线索标识 + 行号 + 证据片段哈希得到，**刻意排除了 `severity` 与 `confidence`**。
因此：同一段代码多次扫描得到相同的 `id`（前端列表 key 稳定、去重可直接按 `id` 做），
而润色文案、调整置信度都不会让用户看到一批"新"发现。

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
| `unsupported_file_type` | 415 | 扩展名不在 `ALLOWED_FILE_EXTENSIONS` 内，或文件名缺少扩展名 |
| `unsupported_encoding` | 422 | 内容无法按受支持的编码解码（含 NUL 字节，或控制字符过多，判定为非文本） |
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

**上传接口的错误（均由实际运行产出）**

扩展名不在白名单内 → 415：

```json
{
  "error": {
    "code": "unsupported_file_type",
    "message": "不支持的文件类型。",
    "details": [
      {
        "field": "file",
        "message": "扩展名 .exe 不在允许列表内。当前支持的类型：.go、.html、.java、.js、.jsx、.php、.py、.rb、.ts、.tsx、.vue。"
      }
    ]
  }
}
```

文件名含路径分隔符 → 422：

```json
{
  "error": {
    "code": "validation_error",
    "message": "上传的文件名不合法。",
    "details": [
      {
        "field": "file",
        "message": "filename 只能是文件名，不能包含路径分隔符"
      }
    ]
  }
}
```

文件名含冒号（盘符 / NTFS 数据流）→ 422：

```json
{
  "error": {
    "code": "validation_error",
    "message": "上传的文件名不合法。",
    "details": [
      {
        "field": "file",
        "message": "filename 不能包含冒号（可能构成盘符前缀或 NTFS 数据流）"
      }
    ]
  }
}
```

空文件 → 422：

```json
{
  "error": {
    "code": "empty_input",
    "message": "上传的文件内容为空。",
    "details": [
      {
        "field": "file",
        "message": "文件没有任何内容，无法进行分析。"
      }
    ]
  }
}
```

二进制内容 → 422：

```json
{
  "error": {
    "code": "unsupported_encoding",
    "message": "文件编码不受支持或内容不是文本。",
    "details": [
      {
        "field": "file",
        "message": "无法按 UTF-8 或 GBK 解码该文件。请将文件另存为 UTF-8 编码后重试。"
      }
    ]
  }
}
```

超限文件 → 413：

```json
{
  "error": {
    "code": "input_too_large",
    "message": "上传文件超过大小限制。",
    "details": [
      {
        "field": "file",
        "message": "文件已超过上限 1048576 字节（约 1024 KB），已停止读取。"
      }
    ]
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
