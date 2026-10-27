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
   │  └─ ScanPage.tsx         # 主工作区状态与布局
   ├─ components/             # 展示型组件
   │  ├─ AppHeader.tsx        # 品牌栏与服务状态
   │  ├─ AppFooter.tsx        # 工具定位、隐私与使用限制
   │  ├─ CodeInputPanel.tsx   # 代码输入、语言、文件与可选分析器
   │  ├─ ResultsPanel.tsx     # 结果区容器（空 / 加载 / 失败 / 结果）
   │  ├─ ScanResultView.tsx   # 一份扫描结果的组合视图
   │  ├─ ScanOverview.tsx     # 扫描摘要与分析器状态
   │  ├─ AnalyzerStatusList.tsx
   │  ├─ SeverityStats.tsx    # 严重程度统计
   │  ├─ FindingList.tsx      # 候选发现列表
   │  └─ FindingDetail.tsx    # 单条发现详情
   ├─ services/
   │  └─ apiConfig.ts         # API 基地址读取（唯一配置入口）
   ├─ types/
   │  └─ scan.ts              # 与后端 schemas 对齐的契约类型
   ├─ constants/
   │  └─ labels.ts            # 枚举中文映射与未知值兜底
   ├─ utils/
   │  └─ format.ts            # 行号、耗时、置信度格式化
   └─ styles/
      └─ global.css           # 布局、风险等级配色与响应式样式
```

## 当前范围

本阶段只完成前端工程与页面框架：

- 代码输入、语言选择、文件选择与可选分析器开关可以操作；
- 结果区展示明确的空状态、加载状态与失败状态结构；
- **尚未发起后端请求**。点击“开始扫描”会提示接口将在联调阶段接入，
  不会生成任何模拟扫描结果；
- 扫描结果组件已按后端 `ScanResponse` 契约完成类型定义与渲染，
  联调阶段只需接入 `services/` 中的请求逻辑。

## 安全约定

- 前端只能配置公开的 `VITE_API_BASE_URL`；**禁止**把模型密钥写入任何
  `VITE_*` 变量，Vite 会将其打包进浏览器可见的产物。
- 所有扫描结果来自后端，前端不推导“安全分数”，也不把不同分析器的
  置信度相加。
- 用户提交的代码只在内存中处理；文件类型由后端校验。
- 行号缺失时显示“未能可靠定位”，不显示 0 或虚构行号。
