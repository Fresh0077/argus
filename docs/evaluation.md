# 样例集与 LLM 评估

> ARGUS 是代码安全分析的**辅助**工具。本文的 precision / recall / F1 只描述
> **这组最小样例上的 LLM 检测表现**，不是对真实项目检出率的估计，也不能证明代码安全。

## 1. 目的

评估回答一个问题：**在当前实现下，LLM 对已知类别的风险样例和安全写法分别表现如何？**

- 样例集位于 [`test_samples/`](../test_samples/)，按 `vulnerable` / `secure` / `benign`
  分类，覆盖 Python、JavaScript、PHP、Java、Go、Ruby、Vue 与 HTML。
- 样例**只被当作文本**读入分析器，不执行、不编译、不导入。
- 标签由人工按代码语义写入 `test_samples/manifest.json`，评估脚本不从分析结果反推标签。
- 当前只有 LLM 这一路分析；评估默认关闭 LLM，需显式传入 `--enable-llm`。

## 2. 样例集构成

当前共 **33 个样例**：

| 类型 | 数量 | 说明 |
|---|---:|---|
| 风险样例（vulnerable） | 18 | SQL 注入、命令注入、XSS、不安全动态执行、不安全反序列化 |
| 安全写法（secure） | 11 | 参数化 SQL、安全 DOM 写入、固定命令与参数、受限动态求值等 |
| 普通代码（benign） | 4 | 没有刻意展示安全问题的 Web 代码 |

机器可读标签见 `test_samples/manifest.json`；每个样例的说明见
[`test_samples/README.md`](../test_samples/README.md)。

## 3. 标签与匹配

一条标签由 **漏洞类别 + 危险调用所在行号** 组成：

```json
{ "vulnerability_type": "sql_injection", "line": 20 }
```

- 行号指向真正执行危险操作的那一行。
- `secure` / `benign` 样例不声明标签，只可能贡献误报。
- 只评估五类：
  `sql_injection`、`command_injection`、`xss`、`unsafe_dynamic_execution`、
  `unsafe_deserialization`。
- 一条发现与一条标签匹配，当且仅当：
  - `vulnerability_type` 相同；且
  - `abs(发现行号 - 标签行号) <= line_tolerance`（当前为 **2**）。
- 同一类别、同一行号的重复发现先去重。
- 没有行号的预期标签无法可靠匹配，因此样例标签必须给出行号。

## 4. 指标

- **precision** = TP / (TP + FP)
- **recall** = TP / (TP + FN)
- **F1** = 2PR / (P + R)
- 安全/普通样例的误报计入 precision；
- LLM 未成功分析的样例**不进入分母**，不会被当成“没发现问题”。

## 5. 运行方式

```powershell
# 在 backend/ 目录下
.\.venv\Scripts\python.exe -m scripts.evaluate --enable-llm
.\.venv\Scripts\python.exe -m scripts.evaluate --enable-llm --json result.json
```

⚠️ `--enable-llm` 会把样例代码发送到 `LLM_BASE_URL` 配置的第三方服务商。
未启用 LLM 或配置缺失时，脚本只报告 `disabled` / `unavailable`，不计算指标。

## 6. 当前结果

真实 LLM 指标**尚未在本环境运行**（需要真实 API key，并会把样例发送到第三方）。
在运行之前，不应声称任何 LLM precision / recall / F1 数值。

特征提取与样例清单的校验由测试覆盖；它们不代表漏洞检出率。

## 7. 局限

- 样例规模小，单个样本对指标影响很大。
- 只覆盖五类风险；提示词注入、越权、业务逻辑漏洞等不在指标内。
- LLM 结果不可复现，同一输入在不同时间可能得到不同结果。
- 评估脚本不测试服务端实现，只测试“模型是否在正确行号报告正确类别”。
- 运行 LLM 评估有费用与隐私成本；样例中不得包含真实凭证。
