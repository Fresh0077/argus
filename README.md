<div align="center">

# ARGUS

### 智能代码安全分析与 HTTP 请求审计平台

一个面向开发与安全学习场景的 Web 安全辅助工具：结合代码特征提取与可选的 LLM 语义分析，提供候选风险发现、HTTP 请求内容审计、修复建议和扫描报告管理。

**React · TypeScript · FastAPI · Python · SQLite · LLM**

</div>

---

## 项目简介

ARGUS 是一个前后端分离的代码安全分析平台，主要包含两个工作场景：

- **代码安全分析**：提交源码文本或上传单个代码文件，提取语言、行数及代码结构等特征；在显式启用并完成配置后，可调用兼容 OpenAI Chat Completions 接口的 LLM 进行语义分析，返回结构化的候选风险发现。
- **HTTP 请求包审计**：解析用户提供的 HTTP/1.x 请求文本，对敏感字段进行脱敏，展示待发送给模型的预览；用户确认后，才会将确认后的脱敏内容交给 LLM 分析。

平台还提供候选修复建议、差异预览、扫描历史以及 JSON / Markdown 报告导出。

> **定位声明**：ARGUS 是安全分析辅助工具，不是安全证明工具。模型结果可能误报或漏报；未发现问题不代表代码绝对安全。HTTP 请求包审计只分析报文文本，不会重放请求或访问目标服务，因此不属于 DAST，也不能据此确认服务端漏洞。

## 功能特性

### 1. 代码安全分析

- 支持粘贴源码文本或上传单个代码文件。
- 支持 Python、JavaScript、TypeScript、PHP、Java、Go、Ruby、HTML、Vue 等语言识别（具体上传扩展名以配置为准）。
- 提取代码行数、字符数、函数、类和导入等结构特征，为分析提供上下文；这些特征本身不判定代码是否安全。
- 可选接入 OpenAI-compatible LLM 服务，进行语义风险分析。
- 对模型输出进行结构化校验、漏洞类别校验和行号范围校验；证据片段由服务端根据源码与有效行号提取。
- 前端支持按严重程度、漏洞类型和来源筛选候选发现，并查看详情与代码证据。

### 2. HTTP 请求包审计

- 解析 HTTP/1.x 请求行、请求头、Query、Cookie 和请求 Body。
- 对 Authorization、Cookie、敏感参数及常见令牌形式进行脱敏。
- 采用“先预览、再确认”的两阶段流程：预览阶段不调用 LLM；确认阶段校验预览指纹后才发送用户确认的脱敏文本。
- 支持用户检查和编辑脱敏预览内容。
- 只分析报文中可观察到的风险信号，不推断需要服务端验证的 SQL 注入、XSS、越权等漏洞。

### 3. 候选修复建议

- 根据目标代码行附近的有限上下文请求 LLM 生成候选修复方案。
- 校验模型返回结构及修复内容，生成统一 Diff 供用户审阅。
- **不会自动修改、覆盖或执行用户的源代码。**

### 4. 历史记录与报告

- 使用 SQLite 保存扫描元数据、分析状态和候选发现。
- 支持历史记录分页查询、详情查看和删除。
- 支持导出 JSON 与 Markdown 格式报告。
- 历史记录和报告不保存完整源代码，仅保留必要的摘要与证据片段。

### 5. 安全与隐私设计

- LLM 默认关闭；只有服务端开关和请求级开关同时启用时才会调用模型。
- 启用 LLM 后，待分析代码或经确认的脱敏请求文本会发送到所配置的第三方模型服务商。请勿提交真实密钥、个人数据或未获授权的代码。
- 上传文件进行类型、大小和编码校验；服务不会执行、编译或导入待分析代码。
- 配置限制 CORS 来源；状态变更接口校验 Origin。
- 对模型输出进行字段、类别、置信度和行号校验；错误响应避免回显源码、密钥和内部异常栈。

## 技术栈

| 层次 | 技术 | 用途 |
|---|---|---|
| 前端 | React 18、TypeScript、Vite | Web 应用与交互界面 |
| UI | Ant Design 5 | 组件与页面布局 |
| 后端 | Python、FastAPI、Uvicorn | REST API 与业务编排 |
| 数据校验 | Pydantic、pydantic-settings | 请求/响应模型与配置管理 |
| HTTP 客户端 | httpx | 调用 OpenAI-compatible LLM API |
| 数据存储 | SQLite | 本地扫描历史 |
| 测试 | Pytest、HTTPX TestClient | 单元测试与接口集成测试 |

## 项目结构

```text
argus/
├── backend/
│   ├── app/
│   │   ├── analyzers/       # 代码特征、LLM、修复建议、HTTP 报文分析
│   │   ├── api/routes/      # FastAPI 路由
│   │   ├── core/            # 配置、异常处理、上传与安全约束
│   │   ├── llm/             # 统一的 LLM HTTP 客户端
│   │   ├── schemas/         # Pydantic 数据契约
│   │   └── services/        # 扫描、审计、历史与报告服务
│   ├── scripts/             # 样例集评估工具
│   ├── tests/               # 自动化测试
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # 页面组件
│   │   ├── pages/           # 代码扫描与请求审计页面
│   │   ├── services/        # API 客户端
│   │   ├── types/           # 前后端契约类型
│   │   └── utils/            # 过滤、格式化等工具
│   └── package.json
├── docs/                    # 架构、API、安全、评估等文档
├── test_samples/            # 人工标注的安全/风险/普通代码样例
├── .env.example             # 后端配置模板
└── README.md
```

## 环境要求

- Python 3.11 或更高版本
- Node.js `^20.19.0` 或 `>=22.12.0`
- npm 10 或更高版本

## 快速开始

以下以 Windows PowerShell 为例。后端和前端需要分别启动，并保持两个终端运行。

### 1. 获取项目

```bash
git clone https://github.com/Fresh0077/argus.git
cd argus
```

### 2. 配置并启动后端

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cd ..
Copy-Item .env.example .env
```

默认配置下 LLM 处于关闭状态，后端仍可启动并提供代码特征提取等功能。启动服务：

```powershell
python -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

### 3. 启动前端

在另一个终端中执行：

```powershell
cd frontend
npm install
npm run dev
```

浏览器访问：

```text
http://127.0.0.1:5173
```

开发环境下，Vite 会将 `/api` 请求代理到本地后端 `http://127.0.0.1:8000`。

### 4. 启用 LLM（可选）

编辑项目根目录的 `.env`，配置以下项目：

```dotenv
LLM_ENABLED=true
LLM_BASE_URL=https://你的模型服务地址/v1
LLM_API_KEY=你的_API_Key
LLM_MODEL=你的模型名称
```

保存后重启后端。除服务端配置外，发起代码扫描时还需要在请求选项中启用 LLM。

> **隐私提醒**：启用 LLM 后，代码内容会发送到你配置的第三方模型服务商；HTTP 请求审计则只会在用户确认脱敏预览后发送确认文本。请先确认数据授权与服务商的数据处理政策。不要将 `.env` 或 API Key 提交到 Git 仓库。

## API 与开发文档

后端启动后可访问：

| 地址 | 说明 |
|---|---|
| `http://127.0.0.1:8000/` | 服务信息 |
| `http://127.0.0.1:8000/api/v1/health` | 健康检查 |
| `http://127.0.0.1:8000/docs` | Swagger / OpenAPI 交互式文档 |

主要 API：

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/v1/scan` | 提交代码文本进行分析 |
| `POST` | `/api/v1/scan/upload` | 上传代码文件进行分析 |
| `POST` | `/api/v1/audit/request` | HTTP 请求包预览与审计 |
| `POST` | `/api/v1/repair` | 生成候选修复建议 |
| `GET` | `/api/v1/history` | 查询扫描历史 |
| `GET` | `/api/v1/history/{scan_id}` | 查询历史详情 |
| `DELETE` | `/api/v1/history/{scan_id}` | 删除历史记录 |
| `GET` | `/api/v1/history/{scan_id}/report` | 导出扫描报告 |

更多细节见 [`docs/api.md`](docs/api.md)、[`docs/analysis-design.md`](docs/analysis-design.md)、[`docs/request-audit.md`](docs/request-audit.md)、[`docs/security-review.md`](docs/security-review.md)。

## 测试

在项目根目录执行后端测试：

```powershell
cd backend
python -m pip install -r requirements.txt
python -m pytest
```

项目包含针对配置、安全边界、文件上传、语言识别、特征提取、LLM 输出解析、HTTP 报文解析与脱敏、历史记录、修复建议及报告导出的测试。

## 样例集与评估

`test_samples/` 提供人工标注的 `vulnerable`、`secure` 和 `benign` 样例，当前包含 33 个样例，覆盖多种语言及 SQL 注入、命令注入、XSS、不安全动态执行和不安全反序列化等类别。

如需运行真实 LLM 评估，在完成 LLM 配置后执行：

```powershell
cd backend
python -m scripts.evaluate --enable-llm
```

评估会将样例代码发送到配置的模型服务商。**当前仓库文档未记录已完成的真实 LLM Precision、Recall 或 F1 结果**，因此不应将任何未实测指标作为项目性能结论。评估口径与局限见 [`docs/evaluation.md`](docs/evaluation.md)。

## 当前能力边界

- 代码分析以单份源码文本为输入，不提供跨文件、跨函数的数据流或污点追踪分析。
- 代码特征提取只提供上下文信息，不独立判断漏洞。
- LLM 结果具有不确定性，可能误报或漏报；`findings` 为空不等于代码安全。
- HTTP 审计只解析 HTTP/1.x 报文文本，不发送网络请求、不重放请求、不访问目标，也不执行请求 Body。
- 候选修复仅供人工审阅，不自动应用补丁、不执行代码。
- 本项目不提供安全评分，也不替代专业代码审计、渗透测试或上线前安全验证。

## 版本与路线

ARGUS 仍在持续开发中。当前重点是完善分析质量评估、补充更多真实且可复现的测试样例、持续改进安全边界与开发文档。功能状态以仓库当前代码为准。

## License

如需开源分发，请在仓库中补充明确的 LICENSE 文件，并据此注明许可协议。
