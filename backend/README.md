# ARGUS 后端（backend）

FastAPI 服务。当前处于**阶段 3：项目骨架**，只提供根路由与健康检查，
尚未接入扫描、分析器、数据库与 LLM。

> ARGUS 是代码安全分析的**辅助**工具。`/api/v1/health` 返回 `ok` 只代表 Web 服务本身可用，
> 不代表任何分析器已就绪。

---

## 目录结构

```
backend/
├─ app/
│  ├─ __init__.py          # 版本号常量
│  ├─ main.py              # FastAPI 应用入口：注册路由与 CORS
│  ├─ core/
│  │  └─ config.py         # 唯一配置入口，读取项目根目录 .env
│  └─ api/
│     ├─ router.py         # /api/v1 路由聚合
│     └─ routes/
│        └─ health.py      # GET /health
├─ tests/
│  ├─ test_health.py       # 接口、CORS 与信息泄露防护测试
│  └─ test_config.py       # 配置解析与安全约束测试
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

### 安全约束

- **`CORS_ALLOW_ORIGINS` 不允许包含 `*`。** 配置通配符会让服务在启动时直接报错退出，
  而不是带着不安全的配置继续运行。
- CORS 默认只允许 Vite 开发服务器，不使用任意来源。
- 所有响应均不包含文件路径、密钥或异常栈。

---

## 安全说明

- 后端**不执行、不编译、不导入**任何待检测代码。
- 不向日志写入原始源代码。
- 本阶段尚未接入 LLM。接入后，代码会被发送到所配置的第三方服务商；
  不希望代码离开本机时请保持 `LLM_ENABLED=false`。
