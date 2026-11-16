# 安全审查与质量检查

> **注意：** 本文记录的是旧版多分析器实现（含 Semgrep / 本地规则）的安全审查。
> 这些组件随后已被移除；相关条目仅作为历史记录保留，当前代码不再包含它们。


> 阶段 18 产物。审查日期：2026-11-10。范围：`backend/`、`frontend/`、配置、文档与测试。
>
> 审查方式：逐项代码审阅 + 静态检索 + 运行测试/类型检查/构建。
> 本文件只记录**实际执行过**的检查；无法执行的工具会在“剩余风险”中注明。

## 1. 结论摘要

- 未发现“执行/导入用户代码”、SQL 注入、路径穿越或密钥进入前端/报告的高危缺陷。
- 修复了 4 项中风险问题：公网明文 HTTP 传输密钥、浏览器跨站触发扫描、Semgrep
  错误输出泄漏内部路径、文件名控制字符注入提示词。
- 另修复 2 项低风险问题：Semgrep 子进程继承 `LLM_API_KEY`、上传接口的过时说明。
- 仍存在**部署边界类**风险：无身份认证、无速率限制、无请求体上限。
  默认仅监听 `127.0.0.1`；若要暴露到回环地址之外，必须由反向代理补充认证、
  限流、TLS 与请求体限制。

## 2. 问题列表

### 2.1 中风险（已修复）

#### M1. 公网 `http://` 会明文传输 API key

- **证据**：`backend/app/llm/client.py` 原先只检查 `http://` / `https://` 前缀，
  然后直接把 key 放进 `Authorization: Bearer ...` 请求头。
- **影响**：若把 `LLM_BASE_URL` 配成公网 `http://` 地址，API key 与代码片段
  会以明文经过网络；日志里不会出现 key，但链路上的中间人可以读取。
- **修复**：`LlmClient` 现在只允许对本机/RFC1918 私有地址使用 `http://`，
  公网地址必须使用 `https://`。`localhost`、`127.0.0.1`、`::1`、私有 IP
  仍可用于本地模型服务。
- **测试**：`tests/test_llm.py` 的公网拒绝与本机/私有地址放行用例。

#### M2. CORS 不能阻止跨站“简单请求”

- **证据**：`backend/app/main.py` 只配置了 CORS 响应头；`POST /api/v1/scan/upload`
  接收 `multipart/form-data`，属于浏览器可跨站发送的简单请求。
- **影响**：用户浏览器中的恶意页面可以向 `http://127.0.0.1:8000` 提交表单，
  触发扫描（甚至带上 `enable_llm=true` 消耗模型额度）。CORS 只阻止读取响应，
  不阻止请求本身。
- **修复**：新增 `backend/app/core/security.py`，对会改变状态或产生费用的接口
  校验 `Origin`：
  - 无 `Origin`（curl/命令行）→ 允许；
  - 与请求 Host 同源（Swagger 页面）→ 允许；
  - 在 `CORS_ALLOW_ORIGINS` 中（Vite 开发服务器/独立前端）→ 允许；
  - 其他来源与 `Origin: null` → `403 forbidden`。
  挂载在 `POST /scan`、`POST /scan/upload`、`POST /repair`、`DELETE /history/{id}`。
- **测试**：`tests/test_security.py` 覆盖拒绝、`null`、配置来源、同源与无 Origin。

#### M3. Semgrep 的 stderr 进入对外状态、历史与报告

- **证据**：`backend/app/analyzers/semgrep/runner.py` 原先把 stderr 截断后写入
  `AnalyzerStatus.reason`；该字段会进入扫描响应、SQLite 历史与导出报告。
- **影响**：Semgrep 的报错可能包含临时目录（`argus-semgrep-*`）、规则文件路径
  或第三方包路径，违反“不向调用方暴露服务器内部路径”。
- **修复**：不再把 stderr 原文回传；只返回退出码与固定提示。子进程的
  stdout/stderr 改为 `DEVNULL`，也不再无限占用内存。
- **测试**：`tests/test_semgrep.py` 断言 stderr 内容、临时目录名与 `input.py`
  不会出现在失败原因里。

#### M4. 文件名允许控制字符

- **证据**：`backend/app/schemas/scan.py` 的 `validate_display_filename` 原先只拒绝
  空字符，未拒绝换行、回车、制表符与 DEL/C1 控制字符。
- **影响**：文件名会进入 LLM 提示词（`文件名：...` 一行）与报告。带换行的文件名
  可以伪造提示词结构，造成提示词注入；也会破坏单行日志/展示。
- **修复**：拒绝所有 C0/C1 控制字符（含换行、回车、制表符、DEL）；
  修复提示词中的文件名再用 JSON 引号包裹，明确它是数据而不是提示词结构。
- **测试**：`tests/test_schemas.py` 新增 `\n`、`\r`、`\t`、`\x7f`、`\x85` 用例。

### 2.2 低风险（已修复）

#### L1. Semgrep 子进程继承 `LLM_API_KEY`

- **证据**：`_subprocess_env()` 只删除 `SEMGREP_APP_TOKEN`，其余环境变量原样传给子进程。
- **影响**：若用户把 `LLM_API_KEY` 设在操作系统环境变量中，Semgrep 会继承它。
  Semgrep 正常不会使用该变量，但没有必要把无关密钥交给外部工具。
- **修复**：`_DROP_ENV` 增加 `LLM_API_KEY`；测试断言其不在子进程环境中。

#### L2. 上传接口的 LLM 开关说明过时

- **证据**：`backend/app/api/routes/scan.py` 的 Form 描述仍写着“当前版本尚未接入”。
- **影响**：接口文档误导用户，可能让人误以为启用无效。不是安全漏洞，但属于配置错误类问题。
- **修复**：改为说明“服务端未启用或缺少配置时会在 `analyzer_status` 中报 `unavailable`”。

## 3. 已验证无问题的检查项

| 检查项 | 结论与证据 |
|---|---|
| 是否执行/导入待检测代码 | 未发现。检索 `exec/eval/compile/__import__/importlib/runpy` 的命中均为正则 `re.compile`、注释或测试样例字符串；扫描链路只把输入当字符串处理。 |
| 上传大小/编码/扩展名 | `app/core/uploads.py` 使用扩展名白名单、字节与字符两条上限、UTF-8/GBK 严格解码、NUL 与控制字符比例检查；解码失败不回显底层异常。 |
| 文件上传路径穿越 | 文件名只作展示；Semgrep 临时文件名由语言枚举决定（`input.py`），不取上传文件名；临时目录用 `TemporaryDirectory` 自动清理。 |
| subprocess 调用 | `semgrep/runner.py` 使用参数列表、`shell=False`、显式超时、输出文件大小上限；关闭遥测与版本检查；删除敏感环境变量。 |
| SQLite 注入 | `history_service.py` 的所有值均通过 `?` 绑定；只有固定列名常量参与 f-string。 |
| 删除历史 | `DELETE /api/v1/history/{scan_id}` 参数化删除；不存在返回 404，二次删除仍为 404；测试覆盖。 |
| 密钥进入前端 | `git grep` 在 `frontend/src` 未发现 `api_key`/`secret`；前端只读取公开的 `VITE_API_BASE_URL`。 |
| 密钥进入 Git | 当前树无真实密钥；`git log -S` 对 `ghp_`、`github_pat_`、`AKIA` 均为 0 次提交；`sk-` 仅出现在测试的伪造值中。`.env`、`*.pem`、`*.key`、数据库文件均被忽略。 |
| 密钥进入日志/错误/报告 | 日志只记录异常类型、方法/路径，不记录请求体或查询串；LLM 错误文案不含 key/响应体；报告只含历史中的发现与证据片段。 |
| LLM 提示词注入 | 扫描与修复提示词均声明代码/发现为不可信数据，代码放在带随机后缀的标签内；发现元数据用 JSON 包裹；文件名控制字符已拒绝。 |
| LLM 输出校验 | `extra="forbid"`；行号必须在源码范围内；证据按行号从源码截取；非法 JSON/空内容/越界行号分别处理。 |
| 重复发现与置信度 | 规则/Semgrep/LLM 按 `(类型, 行)` 合并并保留原始证据；`confidence` 明确“不是漏洞概率”，未做跨来源相加。 |
| 前端 HTML 注入 | 未使用 `dangerouslySetInnerHTML`/`innerHTML`；所有发现文本由 React 转义；证据在 `<pre>` 中渲染；报告仅下载不渲染。 |
| Markdown 报告注入 | 生成时先 HTML 转义再转义 Markdown 控制字符；证据围栏按内容最长反引号串动态加长；测试覆盖 `<script>`、链接、表格管道与围栏注入。 |
| 错误状态 vs 未发现 | `status=partial` 与 `analyzer_status` 区分 skipped/unavailable/failed；前端零发现提示按状态分支；报告逐项列出分析器状态。 |
| 安全样例覆盖 | `test_samples/` 含 vulnerable/secure/benign；`test_evaluation.py` 校验样例中不包含私钥/`sk-` 标记；规则测试含正例、反例与安全写法。 |

## 4. 修复后执行的检查

| 命令 | 结果 |
|---|---|
| `cd backend && python -m pytest -q` | **827 passed**，1 个第三方弃用警告 |
| `cd frontend && npm run typecheck` | 通过 |
| `cd frontend && npm run build` | 通过；仅有原有的 >500 kB chunk 体积警告 |
| `python -m pip check` | 报告 `sse-starlette 3.5.0` 要求 `starlette>=0.49.1`，但锁定为 0.46.2（见 5.3） |
| `semgrep --version` | 1.182.1，CLI 可运行 |
| `npm audit` | **未能执行**：当前 npm 镜像不实现 audit API（404），不声称通过 |

> 移除本地规则、线索与 Semgrep 后，全量后端测试复跑为 **568 passed**（2026-11-16）；
> 本节其余结果仍指阶段 18 审查时的代码状态。

## 5. 剩余风险与暂未解决的问题

### 5.1 无身份认证、无速率限制（中，条件性）

- 当前服务默认绑定 `127.0.0.1`，没有登录/令牌，也没有按 IP 的速率限制。
- `Origin` 校验阻止了浏览器跨站请求，但本机进程或能直接访问回环地址的程序仍可
  无限调用扫描与修复接口；若把 `APP_HOST` 改为 `0.0.0.0`，风险会显著放大。
- **建议**：不要把本服务直接暴露到公网；需要远程访问时，放在带 TLS、认证与
  限流的反向代理之后，并显式配置 `CORS_ALLOW_ORIGINS`。

### 5.2 请求体大小限制不完整（中，条件性）

- 上传接口在读取分块时限制 1 MB，但 multipart 解析发生在路由之前；
  JSON 请求也要先被解析才能执行 `MAX_SOURCE_CODE_CHARS` 校验。
- 超大请求仍可能占用内存/临时空间。建议在反向代理层设置请求体上限；
  本项目当前未实现 ASGI 级的全量请求体计数。

### 5.3 可选 Semgrep 依赖与 Starlette 版本冲突（低）

- Semgrep 1.182.1 依赖 `mcp` → `sse-starlette`，后者要求 `starlette>=0.49.1`；
  而 FastAPI 0.115 要求 `starlette<0.47`，主依赖因此锁定 0.46.2。
- `pip check` 会报告该冲突；ARGUS 不导入 `sse-starlette`/`mcp`，Semgrep CLI
  实测可运行。**建议**：把 Semgrep 装到独立虚拟环境，或等待兼容版本；
  不要为了消除 `pip check` 而升级 Starlette，那会破坏 FastAPI 0.115 的兼容性。

### 5.4 依赖漏洞审计未完成（未知）

- `npm audit` 因镜像不实现审计接口而失败；Python 侧没有安装 `pip-audit`。
- 这不等于“没有漏洞”，只表示本次没有可用的自动化审计结果。建议在能访问
  官方审计源的环境中补跑。

### 5.5 历史数据保留与本地权限（低）

- 历史库包含扫描元数据、发现与最小证据片段；没有自动过期/清理策略。
- 文件权限依赖操作系统默认设置；共享机器上其他用户可能读取 `data/argus_history.db`。
- **建议**：用 `HISTORY_ENABLED=false` 关闭，或定期通过接口/删除文件清理；
  多用户环境应限制数据目录权限。

### 5.6 前端复制降级路径使用了弃用 API（低）

- `RepairSuggestionModal` 在 Clipboard API 不可用时回退到 `document.execCommand('copy')`。
  该 API 已弃用但仍可用；不涉及数据外传，仅影响旧浏览器。
- **建议**：后续可改为只提示用户手动复制，或使用新的异步剪贴板 API。

### 5.7 本地 HTTP 与代理环境（低）

- 服务本身是本地 HTTP；`LLM_BASE_URL` 已限制公网必须 HTTPS，但 `httpx` 默认
  会读取 `HTTP_PROXY`/`HTTPS_PROXY`。若代理不可信，请求（含 key）会经过代理。
- **建议**：只使用可信代理；如需强制直连，可在部署时清除代理环境变量。

### 5.8 请求包审计（阶段 19，条件性）

- 新增 `POST /api/v1/audit/request`，与扫描/修复/删除历史一样校验浏览器 `Origin`。
- 原始报文不写历史、数据库、日志或报告；LLM 只接收脱敏后的文本。
- 脱敏依赖头部名、参数名与已知令牌模式，**自定义格式的凭证可能漏脱敏**；
  因此前端强制展示预览并要求用户确认，预览指纹绑定确认内容。
- 该功能不重放请求、不访问目标；它不能确认服务端漏洞，结果统一为候选信号。
- 请求包审计只保留 LLM 这一路分析，没有本地规则；LLM 未启用或失败时没有候选发现，
  前端必须展示原因，不能把空结果读成“安全”。
- **剩余风险**：脱敏规则不是穷尽的；用户仍须在预览中人工检查。启用 LLM 时，
  脱敏后的报文会发送给第三方，隐私风险由用户确认承担。
