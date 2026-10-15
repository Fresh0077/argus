# ARGUS 后端（backend）

FastAPI 服务。当前处于**阶段 6：语言识别与特征提取**。

已实现：根路由、健康检查、代码文本提交接口、文件上传接口（输入校验与安全边界）、
语言识别、代码统计与结构特征、候选线索提取。

尚未接入：本地规则检测、Semgrep、LLM。

> ARGUS 是代码安全分析的**辅助**工具。
> `/api/v1/health` 返回 `ok` 只代表 Web 服务本身可用，不代表任何分析器已就绪。
>
> ⚠️ **当前只有「启发式」这一路分析。** 本地规则、Semgrep 与 LLM 尚未接入，
> 它们会在 `analyzer_status` 中标记为 `skipped`/`unavailable` 并给出原因。因此：
>
> - `findings` 中每一条的来源都是 `heuristic`，**是候选线索，不是已确认的漏洞**；
> - **`findings` 为空不代表代码安全**；
> - 只要还有分析器未执行，`status` 就是 `partial` 而非 `completed`。

---

## 目录结构

```
backend/
├─ app/
│  ├─ __init__.py          # 版本号常量
│  ├─ main.py              # FastAPI 应用入口：注册路由与 CORS
│  ├─ core/
│  │  ├─ config.py         # 唯一配置入口，读取项目根目录 .env
│  │  ├─ errors.py         # 统一异常处理与错误响应结构
│  │  └─ uploads.py        # 上传文件的类型、大小、编码校验（纯函数）
│  ├─ analyzers/           # 分析器层：只依赖纯文本，不碰 FastAPI、不读写文件
│  │  ├─ line_index.py     # 行号映射（不归一化换行符，保证行号与编辑器一致）
│  │  ├─ language.py       # 语言识别：显式指定 > 扩展名 > shebang/语法标记
│  │  ├─ stats.py          # 行数统计与结构提取（函数/类/导入，近似值）
│  │  ├─ clues.py          # 候选线索模式表（按语言分别登记）
│  │  └─ extractor.py      # 入口：串联以上步骤，产出 features + heuristic findings
│  ├─ schemas/             # Pydantic 契约模型
│  ├─ services/
│  │  └─ scan_service.py   # 扫描流程编排（逐项报告分析器状态）
│  └─ api/
│     ├─ router.py         # /api/v1 路由聚合
│     └─ routes/
│        ├─ health.py      # GET /health
│        └─ scan.py        # POST /scan、POST /scan/upload
├─ tests/
│  ├─ test_health.py             # 接口、CORS 与信息泄露防护测试
│  ├─ test_config.py             # 配置解析与安全约束测试
│  ├─ test_errors.py             # 统一错误结构与「不回显源代码」测试
│  ├─ test_schemas.py            # 契约模型测试
│  ├─ test_uploads.py            # 扩展名 / 大小 / 编码校验的单元测试
│  ├─ test_scan_api.py           # 两条扫描接口的集成测试
│  ├─ test_line_index.py         # 行号映射：CRLF / LF / CR 与末行无换行
│  ├─ test_language_detection.py # 语言识别优先级与「认不出来就认输」
│  ├─ test_feature_extraction.py # 统计、结构与端到端特征提取
│  └─ test_clue_extraction.py    # 候选线索：正例、反例与安全写法不误报
├─ pytest.ini
└─ requirements.txt
```

---

## 环境要求

- Python 3.11 及以上（本机实测 3.13.5）
- 无需 Node.js（前端在 `../frontend/`，属后续阶段）

> **注意：本机 `python3` 命令不可用**（会解析到 Windows 应用商店的别名并异常退出）。
> 本文所有命令一律使用 `python` 或 `py`。

---

## 安装与启动（Windows PowerShell）

```powershell
# 1. 进入后端目录
cd backend

# 2. 创建虚拟环境（必须，不要装到全局 Python）
python -m venv .venv

# 3. 激活虚拟环境
.\.venv\Scripts\Activate.ps1

#    若提示"禁止运行脚本"，说明执行策略受限，可只对当前用户放开：
#    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# 4. 安装依赖
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 5. 启动开发服务器（--reload 会在改动代码后自动重启）
python -m uvicorn app.main:app --reload --port 8000
```

也可从**项目根目录**启动，无需先 `cd`：

```powershell
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

启动后访问：

| 地址 | 说明 |
|---|---|
| http://127.0.0.1:8000/api/v1/health | 健康检查 |
| http://127.0.0.1:8000/ | 服务说明 |
| http://127.0.0.1:8000/docs | Swagger 交互式接口文档 |

预期返回：

```json
{"status": "ok", "service": "ARGUS API", "version": "0.1.0", "environment": "development"}
```

---

## 调用示例

> 以下示例的响应结构均由实际运行的代码产出。完整契约见 [`../docs/api.md`](../docs/api.md)。

### 提交代码文本

PowerShell：

```powershell
$body = @{
  source_code = 'query = "SELECT * FROM users WHERE id = " + user_id'
  language    = 'python'
  filename    = 'views.py'
} | ConvertTo-Json

Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/scan `
  -Method Post -ContentType 'application/json; charset=utf-8' -Body $body
```

Git Bash / curl：

```bash
curl -sS http://127.0.0.1:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"source_code": "query = \"SELECT * FROM users WHERE id = \" + user_id", "language": "python", "filename": "views.py"}'
```

响应（真实输出，`findings` 只保留一条、其余部分完整）：

```json
{
  "scan_id": "74503ffa4f88477992c2ab0eb1ce1019",
  "status": "partial",
  "detected_language": "python",
  "source_encoding": null,
  "findings": [
    {
      "id": "543dd8078c1d3bca",
      "title": "疑似 SQL 语句由字符串拼接或格式化构造",
      "vulnerability_type": "sql_injection",
      "severity": "low",
      "description": "启发式线索（尚未确认为漏洞）：疑似 SQL 语句由字符串拼接或格式化构造。需人工确认拼接部分是否来自不可信输入；若使用参数化占位符则不构成风险。",
      "evidence": "query = \"SELECT * FROM users WHERE id = \" + user_id",
      "line_start": 1,
      "line_end": 1,
      "recommendation": "请确认该语句是否受用户输入影响。若受影响的只是参数值，改用参数化查询（占位符 + 参数绑定）即可；若表名、列名、排序字段也来自输入，则需改用白名单映射，占位符无法覆盖这类位置。",
      "confidence": 0.45,
      "source": "heuristic",
      "cwe_id": "CWE-89"
    }
  ],
  "summary": {
    "total_findings": 1,
    "severity_counts": { "critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0 },
    "source_counts": { "heuristic": 1 }
  },
  "duration_ms": 0,
  "analyzer_status": [
    { "name": "language_detection", "state": "success", "reason": null, "duration_ms": 0, "findings_count": 0 },
    { "name": "feature_extraction", "state": "success", "reason": null, "duration_ms": null, "findings_count": 0 },
    { "name": "clue_extraction", "state": "success", "reason": null, "duration_ms": null, "findings_count": 1 },
    { "name": "rules", "state": "skipped", "reason": "本地规则检测将在阶段 7 接入，本次扫描未执行该分析器。", "duration_ms": null, "findings_count": 0 },
    { "name": "semgrep", "state": "skipped", "reason": "本次请求未启用该分析器（对应的 analysis_options 开关为 false）。", "duration_ms": null, "findings_count": 0 },
    { "name": "llm", "state": "skipped", "reason": "本次请求未启用该分析器（对应的 analysis_options 开关为 false）。", "duration_ms": null, "findings_count": 0 }
  ],
  "features": {
    "language": "python",
    "language_source": "explicit",
    "language_evidence": "调用方显式指定语言为 python",
    "stats": { "total_lines": 1, "non_blank_lines": 1, "total_chars": 51, "max_line_length": 51 },
    "structure": { "function_count": 0, "class_count": 0, "import_count": 0, "imports": [] },
    "notes": [
      "候选线索按 python 的语法特征逐行匹配得到，跨行书写的语句不会被识别，因此必然存在漏报。",
      "函数数与类数按语言声明模式匹配得到，属近似值：不解析语法树，无法识别匿名函数等形式。"
    ]
  }
}
```

> 注意这条发现是 `"source": "heuristic"` 且 `"severity": "low"`：
> 它标出一个**值得人工复核的位置**，而不是断言存在漏洞。
> `status` 为 `partial` 也是如实的——规则、Semgrep 与 LLM 都没有执行。

### 上传代码文件

PowerShell（`-Form` 需要 PowerShell 6.1 及以上；Windows PowerShell 5.1 请用下方的 curl）：

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/scan/upload `
  -Method Post -Form @{ file = Get-Item .\views.py }
```

Git Bash / curl：

```bash
curl -sS http://127.0.0.1:8000/api/v1/scan/upload \
  -F 'file=@./views.py;type=text/x-python'
```

响应与上例结构完全一致，区别是 `source_encoding` 会给出实际使用的编码
（如 `"utf-8"`、`"utf-8-sig"`、`"gbk"`、`"utf-16"`）。

### 常见失败

```bash
# 扩展名不在白名单 -> 415 unsupported_file_type
curl -sS http://127.0.0.1:8000/api/v1/scan/upload -F 'file=@./payload.exe'

# 文件名含路径分隔符 -> 422 validation_error
curl -sS http://127.0.0.1:8000/api/v1/scan/upload -F 'file=@./views.py;filename=../../etc/passwd.py'

# 空文件 -> 422 empty_input
curl -sS http://127.0.0.1:8000/api/v1/scan/upload -F 'file=@./empty.py'
```

---

## 运行测试

```powershell
# 在 backend/ 目录下
python -m pytest

# 也可从项目根目录运行
python -m pytest backend/tests
```

`pytest.ini` 中配置了 `pythonpath = .`，因此测试无需手动处理 `sys.path`，
也不依赖当前工作目录。

---

## 配置

所有配置集中定义在 `app/core/config.py`，通过**环境变量**或**项目根目录的 `.env`** 注入。

- 项目根目录的 [`.env.example`](../.env.example) 是模板；复制为 `.env` 后填写。
- **`.env` 已被 `.gitignore` 忽略，不得提交。**
- `.env` 的定位基于 `config.py` 的文件位置反推，**与当前工作目录无关**。
- 环境变量优先级高于 `.env` 文件。

当前已接入的配置项：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `APP_ENV` | `development` | 运行环境标识 |
| `APP_NAME` | `ARGUS API` | 服务名称 |
| `APP_HOST` | `127.0.0.1` | 绑定地址（默认仅回环） |
| `APP_PORT` | `8000` | 端口 |
| `LOG_LEVEL` | `INFO` | 日志级别 |
| `CORS_ALLOW_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | 允许跨域的来源，逗号分隔；留空则不启用 CORS |
| `MAX_SOURCE_CODE_CHARS` | `200000` | 代码文本长度上限（字符），JSON 与上传接口共用 |
| `MAX_UPLOAD_SIZE_BYTES` | `1048576` | 单个上传文件大小上限（字节） |
| `ALLOWED_FILE_EXTENSIONS` | `py,js,jsx,ts,tsx,php,java,go,rb,html,vue` | 允许上传的扩展名，逗号分隔；带不带前导点均可 |

> 扩充 `ALLOWED_FILE_EXTENSIONS` 时，请同步在 `app/core/uploads.py` 的
> `EXTENSION_LANGUAGE_MAP` 中登记新扩展名对应的语言。漏登记不会导致文件被拒，
> 但响应中的 `detected_language` 会变成 `null`。
> 测试 `test_default_allowed_extensions_match_language_map` 会在默认值上拦住这种漂移。

### 安全约束

- **`CORS_ALLOW_ORIGINS` 不允许包含 `*`。** 配置通配符会让服务在启动时直接报错退出，
  而不是带着不安全的配置继续运行。
- **`ALLOWED_FILE_EXTENSIONS` 不允许为空。** 空列表等于拒绝一切上传，几乎一定是配置失误，
  因此同样在启动时直接失败。
- CORS 默认只允许 Vite 开发服务器，不使用任意来源。
- 所有响应均不包含文件路径、密钥或异常栈。

---

## 安全说明

### 输入处理边界（阶段 5）

- 后端**不执行、不编译、不导入**任何待检测代码——提交内容自始至终只被当作字符串。
  有用例 `test_submitted_code_is_never_executed` 用一个"执行就会创建文件"的探针验证这一点。
- **文件类型只依据扩展名判断**，完全不读取客户端提交的 `Content-Type`：
  该头部由调用方随意填写，不构成安全依据。
- **上传文件全程在内存中处理**，不写入任何文件，也不产生由文件名派生的路径。
- **超限时立即停止读取**，而不是先读满再检查。
- 文件名校验覆盖 Windows 特有变体：盘符前缀（`C:`）、NTFS 数据流（`views.py:evil`）、
  保留设备名（`CON`/`NUL`/`AUX`/`PRN`）、尾随点、NUL 字节。
- **编码失败即报错，不用替换字符静默"修复"**；实际使用的编码通过 `source_encoding` 如实返回。
- 不向日志写入原始源代码；错误响应不回显用户提交的代码。

### 尚未接入的能力

- 本阶段尚未接入 LLM。接入后，代码会被发送到所配置的第三方服务商；
  不希望代码离开本机时请保持 `LLM_ENABLED=false`。

---

## 分析能力（阶段 6）

### 分析器状态

`analyzer_status` 中会出现 6 个分析器，它们独立报告状态：

| `name` | 当前状态 | 说明 |
|---|---|---|
| `language_detection` | 已接入 | 识别语言并给出依据；识别不出来时报 `skipped` |
| `feature_extraction` | 已接入 | 只要拿到输入就一定能执行 |
| `clue_extraction` | 已接入 | 依赖语言识别结果；语言未知时 `skipped` |
| `rules` | 未接入 | 阶段 7 |
| `semgrep` | 未接入 | 阶段 8，按 `enable_semgrep` 开关 |
| `llm` | 未接入 | 阶段 9，按 `enable_llm` 开关 |

`feature_extraction` 与 `clue_extraction` 分开报告，是因为「统计做了、线索没做」
是一种真实状态：语言未识别时统计仍能完成，线索提取会跳过。
合在一起会导致要么误报成功、要么误报失败。

语言识别、特征提取与线索提取共用一次调用，**耗时只计在 `language_detection` 上**，
另两项为 `null`——避免同一个数字被重复计数成三份。

### 语言识别

优先级：**显式指定的 `language` > 文件名扩展名 > 内容特征（shebang、语法标记）> 未识别**。

扩展名优先于内容特征，因为扩展名是确定性查表，内容只是启发式。
因此内容像 PHP 但名为 `views.py` 的文件会被判定为 `python`。

**识别不出来时返回 `null`，并且跳过候选线索提取。**
不使用 `"unknown"` 这类哨兵字符串；也不猜一个语言——按错误语言的模式去匹配，
会产出一批看似合理、实则无关的线索，比不产出更糟。
未识别时 `language_evidence` 仍会说明尝试过什么。

### 候选线索

`clue_extraction` 产出的是**值得人工复核的位置**，不是漏洞判定。硬性约束：

- `source` 恒为 `heuristic`；
- `severity` **最高只到 `low`**（`untrusted_input_source` 为 `info`）；
- `confidence` 在 **0.25–0.45** 之间；
- 措辞使用"疑似""检测到"，绝不写"存在漏洞"。

匹配是**逐行**的：行号因此一定准确，但**跨行书写的语句不会被识别**，
所以这一层**必然漏报**。这一点同时写在响应的 `features.notes` 里。

误报控制上做了两件事：

1. 每条线索都必须匹配到明确的语法特征，不做"包含某关键字"式的宽泛匹配；
2. **SQL 线索要求同一行内同时出现 SQL 关键字与拼接/格式化算子**，
   因此 `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
   这类参数化写法不会命中；
   **命令执行类线索要求实参是动态的**，因此 `os.system('ls -la')`、
   `exec.Command("git", "status")` 这类固定字面量参数也不会命中。

线索类别与对应的 CWE 见 [`../docs/api.md`](../docs/api.md#特征提取与候选线索)。

### 不做什么

- **不执行、不编译、不导入被分析的代码**，也不调用任何可能运行目标程序的工具；
- 不做数据流/污点分析（简单正则无法跨函数追踪，也不宣称能）；
- 不给出"总体安全分数"这类未经验证的合成指标。
