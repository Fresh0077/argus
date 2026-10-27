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
   │  ├─ FindingList.tsx      # 候选发现列表
   │  └─ FindingDetail.tsx    # 单条发现详情
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
- 分析器失败、不可用或按需跳过时会单独提示；未启用 LLM 不会被当作失败；
- 行号缺失时显示“未能可靠定位”，不补 0、不虚构；LLM 开启前的界面提示明确
  说明代码会发送到所配置的第三方服务商。

已知限制：

- 当前只有单文件与粘贴输入，没有目录扫描、历史记录或报告导出；
- 前端显示的是候选发现，不是“已确认漏洞”；没有发现也不代表代码安全；
- 打包体积较大（antd 全量引入），后续可按需拆分，但不影响本地演示。

## 安全约定

- 前端只能配置公开的 `VITE_API_BASE_URL`；**禁止**把模型密钥写入任何
  `VITE_*` 变量，Vite 会将其打包进浏览器可见的产物。
- 所有扫描结果来自后端，前端不推导“安全分数”，也不把不同分析器的
  置信度相加。
- 用户提交的代码只在内存中处理；文件类型由后端校验。
- 行号缺失时显示“未能可靠定位”，不显示 0 或虚构行号。
