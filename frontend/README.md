# ARGUS 前端

ARGUS 的 Web 界面，使用 React + TypeScript + Vite + Ant Design 构建。

> ARGUS 是代码安全分析的**辅助工具**，不是安全证明工具。
> 前端只展示后端真实返回的分析结果，不提供伪造的演示数据。

## 环境要求

- Node.js `^20.19.0 || >=22.12.0`（本项目实测于 v24.12.0）
- npm 10+

## 启动与构建

### PowerShell

```powershell
cd frontend
npm install
Copy-Item .env.example .env   # 可选；留空则使用 Vite 开发代理
npm run dev                   # 开发服务器 http://localhost:5173
npm run build                 # 类型检查 + 生产构建，输出到 dist/
npm run preview               # 预览构建产物
npm run typecheck             # 只做 TypeScript 类型检查
```

### Git Bash

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
npm run build
npm run preview
npm run typecheck
```

后端默认地址为 `http://127.0.0.1:8000`。开发环境下，`/api` 请求由
[vite.config.ts](vite.config.ts) 中的代理转发到后端，因此 `.env` 中的
`VITE_API_BASE_URL` 可以留空；需要直连其他地址时再填写。

## 前后端联调启动顺序（PowerShell）

先启动后端，再启动前端；两个终端都要保持运行。

```powershell
# 终端 1：后端
cd D:\coursepractice\argus\backend
.\.venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING = "utf-8"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```powershell
# 终端 2：前端
cd D:\coursepractice\argus\frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

浏览器打开 `http://127.0.0.1:5173/`。顶部显示“服务状态：在线”说明前端已通过
`/api/v1/health` 连上后端；显示“不可达”时先检查后端端口与 Vite 代理目标。

## 目录职责

```
frontend/
├─ index.html                 # 页面入口
├─ vite.config.ts             # Vite 配置与开发代理
├─ .env.example               # 仅公开配置模板
└─ src/
   ├─ main.tsx                # React 挂载、antd 主题与中文语言包
   ├─ App.tsx                 # 应用外壳：品牌栏 + 主工作区 + 页脚
   ├─ pages/
   │  └─ ScanPage.tsx         # 输入/请求状态机、取消与重试
   ├─ components/             # 展示型组件
   │  ├─ AppHeader.tsx        # 品牌栏与真实健康检查
   │  ├─ AppFooter.tsx        # 工具定位、隐私与使用限制
   │  ├─ CodeInputPanel.tsx   # 代码输入、语言、文件与可选分析器
   │  ├─ ResultsPanel.tsx     # 结果区容器（空 / 加载 / 失败 / 结果）
   │  ├─ ScanResultView.tsx   # 一份扫描结果的组合视图
   │  ├─ ScanOverview.tsx     # 扫描摘要、分析器状态与编码提示
   │  ├─ AnalyzerStatusList.tsx
   │  ├─ AnalyzerNotices.tsx  # 失败、不可用或按需跳过的分析器提示
   │  ├─ SeverityStats.tsx    # 严重程度统计
   │  ├─ FindingExplorer.tsx  # 筛选、排序与列表/详情联动
   │  ├─ FindingFilters.tsx   # 严重程度/类型/来源筛选
   │  ├─ FindingList.tsx      # 候选发现列表（可键盘选择）
   │  ├─ FindingDetail.tsx    # 单条发现详情
   │  ├─ EvidenceBlock.tsx    # 长代码证据的折叠与滚动
   │  └─ NoFindingsNotice.tsx # 零发现时区分未启用/失败/已完成
   ├─ services/
   │  ├─ apiConfig.ts         # API 基地址读取（唯一配置入口）
   │  ├─ apiClient.ts         # 唯一发起 fetch 的地方：超时、取消、错误归类
   │  └─ scanErrors.ts        # 把请求异常翻译成可操作的界面文案
   ├─ types/
   │  ├─ scan.ts              # 与后端 schemas 对齐的契约类型
   │  └─ ui.ts                # 仅前端使用的界面状态类型
   ├─ constants/
   │  └─ labels.ts            # 枚举中文映射与未知值兜底
   ├─ utils/
   │  ├─ findings.ts          # 纯函数：默认排序与多条件筛选
   │  └─ format.ts            # 行号、耗时、置信度格式化
   └─ styles/
      └─ global.css           # 布局、风险等级配色与响应式样式
```

## 当前范围

前端已接通后端的扫描与上传接口：

- 支持粘贴代码、上传单个文件、手动指定或自动识别语言，以及按需启用
  Semgrep 与 LLM；
- 所有请求经 `services/apiClient.ts` 发出；开发环境通过 Vite 代理访问
  `/api`，也可用公开的 `VITE_API_BASE_URL` 直连后端；
- 顶部服务状态来自真实的 `/api/v1/health` 请求；扫描结果、摘要、分析器状态、
  耗时与严重程度统计全部来自后端，不使用演示数据；
- 结果区区分空、加载、失败与成功四种状态；加载时可取消，失败时可重试，
  输入变化后会清掉与当前输入不对应的旧结果；
- 对空输入、超限文件、不支持的文件类型、参数校验失败、后端不可达、请求超时
  与后端 5xx 分别给出提示；错误详情按字段名展示；
- 风险概览按 `critical` / `high` / `medium` / `low` / `info` 展示后端返回的
  真实计数和合计，不写死数字，也不生成“安全分数”；
- 候选发现默认按“严重程度从高到低、同等级按起始行号升序、行号缺失排最后”
  排序；可按严重程度、漏洞类型、分析来源多选筛选。同一维度内为“或”，
  不同维度之间为“且”；筛选结果为空时给出明确空状态，并说明空筛选不代表安全；
- 列表与详情联动；详情展示标题、类型、严重程度、描述、代码证据、行号、
  置信度、来源、修复建议，以及后端返回时的 CWE 编号；
- 每条发现都标注来源（本地规则 / 特征线索 / Semgrep / LLM）；未知枚举值
  保留原始值兜底显示，不白屏；
- 零发现时区分“已启用分析器未报告问题”“部分分析未执行”“分析器失败或不可用”，
  并单独列出本次未启用的可选分析器；所有零发现文案都强调“不等于代码安全”；
- 长代码证据默认限制高度、可在块内滚动，并提供展开/收起；展开只改变可视高度，
  不截断或改写证据；
- 列表项可用 Tab 聚焦，Enter 或空格切换当前详情；主要交互有可见焦点样式，
  风险与来源标签使用满足正文对比度的颜色；
- 窄屏（实测 390px）下筛选栏改为单列、列表与详情纵向排列，页面无横向滚动。

已知限制：

- 当前只有单文件与粘贴输入，没有目录扫描、历史记录或报告导出；
- 前端显示的是候选发现，不是“已确认漏洞”；没有发现也不代表代码安全；
- 筛选与排序只作用于当前响应，不会重新请求后端；
- 打包体积较大（antd 全量引入），后续可按需拆分，但不影响本地演示。

## 手工验收

以下步骤需在后端在线时执行，验收时以**实际响应**为准，不预设固定数字。

1. **计数与默认排序**：粘贴一段包含多种风险的 Python 代码并扫描。核对风险
   概览的五个等级数量与合计，是否等于列表条数；列表顺序应为严重程度从高到低，
   同级按起始行号升序，缺失行号的条目在最后。
2. **筛选与重置**：只选“高危”，核对“显示 X / 共 Y 条”与列表条数一致；
   再叠加一个漏洞类型，结果应收窄（不同维度为“且”）；叠加一个本次不存在的
   来源，应出现“当前筛选条件下没有候选发现”。点击“重置筛选”或“清除筛选”
   后恢复全部结果。
3. **详情字段**：切换列表项，详情应同步更新，并包含标题、类型、严重程度、
   描述、代码证据、行号、置信度、来源与修复建议；后端有 CWE 时显示对应编号。
4. **键盘操作**：用 Tab 聚焦列表项，按 Enter 与空格应能切换详情；焦点应有
   可见轮廓，`aria-pressed` 应随选中状态变化。
5. **长证据**：使用一条很长的源码行触发发现。证据块默认限制高度并可滚动，
   “展开全部代码证据”后高度增加，“收起代码证据”可恢复。
6. **零发现与未启用分析器**：扫描一段明显无风险的代码。应显示零发现说明，
   并分别写清“本次未启用”的可选分析器与“没有发现候选问题不等于代码安全”；
   开启 Semgrep 但环境中没有该可执行文件时，应显示“分析未完整完成”，
   不能显示成“未发现漏洞”。
7. **小屏可用性**：将浏览器宽度调到约 390px。筛选栏应为单列，列表与详情
   纵向排列，页面没有横向滚动条。
8. **服务状态**：关闭后端后重新扫描，应显示“无法连接后端”而不是“未发现
   漏洞”；恢复后端后可重试成功。

## 安全约定

- 前端只能配置公开的 `VITE_API_BASE_URL`；**禁止**把模型密钥写入任何
  `VITE_*` 变量，Vite 会将其打包进浏览器可见的产物。
- 所有扫描结果来自后端，前端不推导“安全分数”，也不把不同分析器的
  置信度相加。
- 用户提交的代码只在内存中处理；文件类型由后端校验。
- 行号缺失时显示“未能可靠定位”，不显示 0 或虚构行号。
