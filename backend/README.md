# ARGUS 后端（backend）

FastAPI 服务。当前处于**阶段 5：代码输入与文件上传**。

已实现：根路由、健康检查、代码文本提交接口、文件上传接口（输入校验与安全边界）。
**尚未接入任何分析器**——阶段 6 起依次加入语言识别、规则、Semgrep 与 LLM。

> ARGUS 是代码安全分析的**辅助**工具。
> `/api/v1/health` 返回 `ok` 只代表 Web 服务本身可用，不代表任何分析器已就绪。
>
> ⚠️ **阶段 5 的两条扫描接口都不会产出任何发现。** `findings` 恒为 `[]`，
> 每个分析器都会在 `analyzer_status` 中标记为 `skipped`/`unavailable` 并给出原因。
> **`findings` 为空不代表代码安全。**

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
│  ├─ schemas/             # Pydantic 契约模型
│  ├─ services/
│  │  └─ scan_service.py   # 扫描流程编排（阶段 5 只组装响应，不分析）
│  └─ api/
│     ├─ router.py         # /api/v1 路由聚合
│     └─ routes/
│        ├─ health.py      # GET /health
│        └─ scan.py        # POST /scan、POST /scan/upload
├─ tests/
│  ├─ test_health.py       # 接口、CORS 与信息泄露防护测试
│  ├─ test_config.py       # 配置解析与安全约束测试
│  ├─ test_errors.py       # 统一错误结构与「不回显源代码」测试
│  ├─ test_schemas.py      # 契约模型测试
│  ├─ test_uploads.py      # 扩展名 / 大小 / 编码校验的单元测试
│  └─ test_scan_api.py     # 两条扫描接口的集成测试
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

响应（阶段 5 真实输出，已省略 `summary` 与 `analyzer_status` 明细）：

```json
{
  "scan_id": "53b5e312ad5d43e7b4572a9181f700eb",
  "status": "partial",
  "detected_language": "python",
  "source_encoding": null,
  "findings": [],
  "duration_ms": 0
}
```

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
