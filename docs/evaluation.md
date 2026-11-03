# 样例集与检测效果评估

> ARGUS 是代码安全分析的**辅助**工具。本文的 precision / recall / F1 只描述
> **这组最小样例上的检测表现**，不是对真实项目检出率的估计，也不能证明代码安全。

## 1. 目的与范围

评估回答一个问题：**在当前实现下，ARGUS 对已知类别的风险样例和安全写法分别表现如何？**

- 样例集位于 [`test_samples/`](../test_samples/)，按 `vulnerable` / `secure` / `benign`
  分类，并覆盖 Python、JavaScript、PHP、Java、Go、Ruby、Vue 与 HTML。
- 评估对象是 ARGUS 的四路能力：本地规则、Semgrep（可用时）、LLM（配置后）与组合分析。
- 样例**只被当作文本**读入分析器，不执行、不编译、不导入。
- 标签由人工按代码语义写入 `test_samples/manifest.json`，评估脚本不从分析结果反推标签。

## 2. 样例集构成

当前共 **33 个样例**：

| 类型 | 数量 | 说明 |
|---|---:|---|
| 风险样例（vulnerable） | 18 | SQL 注入、命令注入、XSS、不安全动态执行、不安全反序列化 |
| 安全写法（secure） | 11 | 参数化 SQL、安全 DOM 写入、固定命令与参数、受限动态求值等 |
| 普通代码（benign） | 4 | 没有刻意展示安全问题的 Web 代码 |

风险样例与安全/普通样例接近平衡（18 : 15），避免只准备漏洞正例。
每个样例的语言、类别、风险原因与预期分析行为见
[`test_samples/README.md`](../test_samples/README.md)；机器可读标签见
[`test_samples/manifest.json`](../test_samples/manifest.json)。

## 3. 标签定义

一条标签由 **漏洞类别 + 危险调用所在行号** 组成，例如：

```json
{ "vulnerability_type": "sql_injection", "line": 20 }
```

- 行号指向**真正执行危险操作的那一行**（例如 `execute(...)`、`os.system(...)`、
  `innerHTML = ...`），不是变量赋值或导入行。
- `secure` / `benign` 样例不声明标签。它们在指标中只可能贡献误报。
- 仅评估以下五类：

  `sql_injection`、`command_injection`、`xss`、`unsafe_dynamic_execution`、
  `unsafe_deserialization`。

- `untrusted_input_source` 是启发式**线索**（“这里可能读到了外部输入”），
  按项目约定不是漏洞判定，因此不进入 precision / recall。它仍会出现在正常
  扫描结果的 `findings` 中，由前端单独展示。

## 4. 匹配规则

评估脚本 [`backend/scripts/evaluate.py`](../backend/scripts/evaluate.py)
对每个样例执行以下步骤：

1. 只保留五类风险中的发现；线索与未知类别不计入指标，单独计数。
2. 同一类别、同一行号的重复发现先去重，避免同一问题被多次计分。
3. 一条发现与一条标签匹配，当且仅当：
   - `vulnerability_type` 相同；且
   - `abs(发现行号 - 标签行号) <= line_tolerance`（当前为 **2**）。
4. 一对一开始匹配：每条标签最多匹配一条发现，每条发现最多匹配一条标签。
   匹配按标签顺序贪心进行。
5. 没有行号的发现无法与标签对齐，计为**误报**。
6. 每路分析器只统计**实际成功分析了该样例**的情况：
   - Semgrep 不分析 HTML / Vue，相关样例不进入 Semgrep 分母；
   - Semgrep 未安装、某样例执行失败时不进入分母；
   - LLM 未启用或未配置时不进入分母。
   “没有执行”不会被当成“没有发现问题”。

## 5. 指标计算

对每路分析器，把所有纳入分母的样例的计数相加：

```
TP = 成功匹配的标签数
FP = 未匹配任何标签的发现数
FN = 未被任何发现匹配的标签数

precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
```

分母为 0 时，对应指标显示为 **“—”**（`None`），不编造 0 或 1。
例如某路分析器只在一个无标签样例上报告了误报，则它的 recall 无法计算。

组合分析的合并顺序与生产环境一致：**本地规则 → Semgrep → LLM**。
同一类别、同一行号重复时保留先到的规则结果，并注明其他分析器的佐证。
组合分析的分母是“本地规则成功执行”的样例；Semgrep / LLM 不可用时自然退化为
可用部分，与线上降级行为一致。

评估脚本直接调用各分析器入口（不经过 HTTP），这样可以分别统计每一路的结果；
组合分析复用生产环境的 `merge_findings` / `merge_semgrep_findings` /
`merge_llm_findings`。样例语言取自清单中的声明，不依赖语言识别，
从而把“语言识别是否正确”与“漏洞检测是否正确”分开评估。

## 6. 运行方式

在 `backend/` 下：

```bash
# 规则 + Semgrep（Semgrep 未安装时自动跳过）
./.venv/Scripts/python.exe -m scripts.evaluate

# 只评估本地规则
./.venv/Scripts/python.exe -m scripts.evaluate --no-semgrep

# 显式启用 LLM 评估：需要 LLM_* 配置，样例代码会发送到第三方服务商
./.venv/Scripts/python.exe -m scripts.evaluate --enable-llm

# 写出机器可读结果
./.venv/Scripts/python.exe -m scripts.evaluate --no-semgrep --json eval-result.json
```

PowerShell 下把 `./.venv/Scripts/python.exe` 换成 `.\.venv\Scripts\python.exe`。
评估只读取 `test_samples/`，不会把样例写入日志或数据库。

## 7. 本次真实结果

以下结果由本机实际运行得到：

- 日期：2026-11-03
- 环境：Windows 11、Python 3.13.5、pytest 8.4.2
- Semgrep：1.182.1（本机安装，本地规则集，关闭遥测）
- LLM：未配置、未启用（默认不参与评估）
- 命令：`./.venv/Scripts/python.exe -m scripts.evaluate`

### 7.1 总体指标

| 分析器 | 评估样例 | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 本地规则 | 33 / 33 | 18 | 1 | 1 | 0.947 | 0.947 | 0.947 |
| Semgrep | 30 / 33 | 14 | 0 | 3 | 1.000 | 0.824 | 0.903 |
| LLM | — | — | — | — | — | — | — |
| 组合分析 | 33 / 33 | 19 | 1 | 0 | 0.950 | 1.000 | 0.974 |

Semgrep 的 30 / 33：其中 3 个样例（2 个 HTML、1 个 Vue）被 Semgrep 明确跳过，
不进入它的分母。LLM 未启用，因此四个指标均为“—”。

### 7.2 按类型

**本地规则**

| 类别 | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| sql_injection | 3 | 1 | 1 | 0.750 | 0.750 | 0.750 |
| command_injection | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| xss | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| unsafe_dynamic_execution | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| unsafe_deserialization | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

**Semgrep**

| 类别 | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| sql_injection | 3 | 0 | 1 | 1.000 | 0.750 | 0.857 |
| command_injection | 6 | 0 | 1 | 1.000 | 0.857 | 0.923 |
| xss | 1 | 0 | 1 | 1.000 | 0.500 | 0.667 |
| unsafe_dynamic_execution | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| unsafe_deserialization | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

**组合分析**

| 类别 | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| sql_injection | 4 | 1 | 0 | 0.800 | 1.000 | 0.889 |
| command_injection | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| xss | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| unsafe_dynamic_execution | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| unsafe_deserialization | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### 7.3 逐条差异

**本地规则**

- 漏报：`php-sql-injection-vulnerable`（`sql_injection@15`）。
  `$_GET` 经变量拼接后进入 PDO 查询，当前轻量来源跟踪没有把这条路径识别出来。
- 误报：`php-sql-prepared-safe`（`sql_injection@15`）。
  PDO 的 `$statement->execute([$id])` 第一个实参是绑定参数而不是 SQL 文本，
  规则把它当成了“动态 SQL”。这是一条真实的误报，未通过改样例来规避。

**Semgrep**

- 漏报：`go-sql-injection-vulnerable`（`sql_injection@19`）、
  `js-command-injection-vulnerable`（`command_injection@16`）、
  `php-reflected-xss-vulnerable`（`xss@12`）。
  原因是内置 Semgrep 规则集没有覆盖这三类“语言 × 类别”组合，不是样例标签有误。
- 未分析：`html-safe-filter-vulnerable`、`html-static-page-benign`、
  `vue-v-html-vulnerable`。Semgrep 不解析 HTML / Vue，明确记为跳过。

**组合分析**

- 规则漏报的 PHP SQL 注入由 Semgrep 补上，因此组合分析的 recall 为 1.000。
- 规则对 PDO 安全写法的误报仍然存在，组合分析的 precision 为 0.950。
- 组合分析没有让 Semgrep 覆盖 3 个非支持语言样例；这些样例仍由本地规则检查。

**LLM**

- 本次未配置 `LLM_*`，且默认不启用，因此没有发起任何模型请求。
- 不能根据空白结果声称“LLM 的检出能力如何”。配置后可运行
  `--enable-llm` 单独评估；启用意味着样例代码会被发送到所配置的第三方服务商。

## 8. 已知局限

1. **样例规模小。** 33 个最小样例足以解释规则与工具的行为差异，但单个样例
   就能明显改变指标，不能外推为真实项目上的检出率。
2. **样例类型不等于真实业务复杂度。** 没有跨文件调用、框架封装、ORM、
   前端构建产物或大型依赖链；这些正是静态分析容易误判或漏判的地方。
3. **规则层是逐行正则 + 单文件轻量来源跟踪。** 跨行、跨函数、跨文件的
   数据流不在覆盖范围内；安全写法也可能因为形态不同被误报（本次 PDO 案例）。
4. **Semgrep 只覆盖内置规则集登记的语言与类别。** 未覆盖不等于安全；
   HTML / Vue 由 Semgrep 明确跳过，不进入其分母。
5. **LLM 评估默认不运行，且结果不可完全复现。** 即使配置后运行，
   模型输出也会受提示词、上下文截断、服务商与采样参数影响；
   其 `confidence` 只是自评，不是漏洞概率。
6. **匹配使用行号容差 2。** 这能容忍报告位置在危险调用附近的差异，
   但也可能把同一行附近的不同问题误判为匹配；当前样例中未发现该情况。
7. **指标不包含严重等级、修复建议质量或证据可读性。** 评估的是“是否报告了
   正确类别与位置”，不是“报告是否足够有用”。
8. **线索未计入指标。** `untrusted_input_source` 是提示而非漏洞判定；
   这会低估“线索对人工排查的帮助”，但避免把提示当成检测能力。

## 9. 如何扩展样例

1. 在 `test_samples/<vulnerable|secure|benign>/<language>/` 下新增 UTF-8 样例。
2. 在 `manifest.json` 增加条目，写清语言、类别、风险原因、预期行为，
   并为风险样例标注危险调用所在行。
3. 在 `test_samples/README.md` 的对应表格补充一行说明。
4. 运行 `python -m pytest tests/test_evaluation.py` 校验清单，
   再运行 `python -m scripts.evaluate` 查看指标变化。
5. 不要根据评估结果修改标签来“提高分数”；标签只由代码语义决定。
