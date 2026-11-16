# 扫描报告导出

> **注意：** 文中的真实响应示例来自旧版多分析器时期。当前扫描只产生 LLM 发现；
> 旧历史记录中的其他来源仍可导出，但新报告不会出现它们。


> 阶段 17 产物。报告用于辅助人工复核，不是安全证明。

## 1. 数据来源与前提

报告**只从本地扫描历史生成**，不接收调用方提交的扫描结果。这样可以保证：

- 只有真实保存过的扫描结果才能导出，UI 中的示例数据无法混入；
- 报告的扫描时间、摘要、发现与分析器状态都来自同一次真实扫描；
- 历史关闭、记录不存在或记录损坏时，导出会明确失败，而不是生成空报告。

因此，导出报告需要同时满足：

1. `HISTORY_ENABLED=true`（默认开启）；
2. 扫描完成时历史写入成功（写入失败不影响扫描，但该次结果无法导出）；
3. `scan_id` 对应的记录仍然存在（未通过历史接口删除）。

## 2. 接口

```text
GET /api/v1/history/{scan_id}/report?format=json
GET /api/v1/history/{scan_id}/report?format=markdown
```

| 参数 | 说明 |
|---|---|
| `scan_id` | 32 位小写十六进制；非法格式返回 422 |
| `format` | `json`（默认）或 `markdown`；其他值返回 422 |

响应以附件返回：

```text
Content-Disposition: attachment; filename="argus-report-<scan_id>.json"
Content-Disposition: attachment; filename="argus-report-<scan_id>.md"
Content-Type: application/json; charset=utf-8
Content-Type: text/markdown; charset=utf-8
X-Content-Type-Options: nosniff
```

错误沿用历史接口：

| 状态码 | 错误码 | 场景 |
|---|---|---|
| 404 | `history_not_found` | 记录不存在或已删除 |
| 422 | `validation_error` | `scan_id` 或 `format` 不合法 |
| 503 | `history_disabled` | `HISTORY_ENABLED=false` |
| 503 | `history_unavailable` | 数据库不可用、版本不兼容或记录损坏 |

## 3. 报告内容

两部分格式包含相同的信息：

- 扫描编号、扫描时间、文件名、识别语言、扫描状态、解码方式、总耗时；
- 报告生成时间与报告结构版本；
- 摘要：候选发现总数、各严重等级计数、来源计数；
- 分析器状态：名称、状态、发现数、耗时、非成功状态的原因；
- 发现列表：标题、漏洞类型、严重等级、来源、置信度、位置、规则 ID、CWE、
  说明、最小证据片段、修复建议；
- 局限说明。

**不包含**：完整源代码、原始字节、请求体、API key、请求头、服务器路径、
其他扫描的记录。历史本身不保存源代码，报告中只有发现的最小证据片段。

## 4. 安全处理

### Markdown 转义

发现标题、说明、修复建议、文件名、分析器原因等文本可能包含用户代码片段或 Markdown
控制字符。生成 Markdown 时：

1. 先转义 HTML 字符（`&`、`<`、`>`），防止注入标签；
2. 再转义 Markdown 控制字符（反引号、星号、下划线、方括号、圆括号、`#`、`|` 等），
   防止伪造标题、链接、列表或表格结构；
3. 表格单元格内的换行替换为服务端生成的 `<br>`；
4. 证据片段放入代码围栏，围栏长度按内容中最长的反引号串自动加长，
   防止证据里的 ``` 提前闭合围栏。

JSON 报告由 `json.dumps` 序列化，字符串中的引号与控制字符会被正确转义。

### 文件名

文件名完全由服务端生成，形如 `argus-report-<32 位十六进制>.json` / `.md`，
不接受用户输入，不含路径分隔符、`..` 或盘符，因此不存在路径穿越风险。

## 5. 前端

- 扫描结果页底部提供「导出 JSON」「导出 Markdown」；
- 历史详情顶部也提供同样按钮；
- 下载通过 `fetch` 获取二进制内容，失败时显示后端返回的安全错误文案，
  不会把错误 JSON 当作报告保存；
- 报告不包含完整源代码，界面上也明确提示这一点。

## 6. 示例报告

以下内容由实际运行的 `TestClient` 请求生成（临时数据库；未启用 Semgrep 与 LLM，
因此状态为 `partial`）。扫描代码：

```python
import sqlite3


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(sql)
```

### 6.1 JSON（`format=json`）

```json
{
  "report_version": 1,
  "generated_at": "2026-11-05T09:43:26.114807Z",
  "scan": {
    "scan_id": "e4ccecb1b60f4453b7a588a1bb9ada03",
    "created_at": "2026-11-05T09:43:26Z",
    "filename": "views.py",
    "language": "python",
    "status": "partial",
    "source_encoding": null,
    "duration_ms": 0,
    "summary": {
      "total_findings": 2,
      "severity_counts": {
        "critical": 0,
        "high": 0,
        "medium": 1,
        "low": 1,
        "info": 0
      },
      "source_counts": {
        "heuristic": 1,
        "static_rule": 1
      }
    }
  },
  "analyzer_status": [
    {
      "name": "language_detection",
      "state": "success",
      "reason": null,
      "duration_ms": 0,
      "findings_count": 0
    },
    {
      "name": "feature_extraction",
      "state": "success",
      "reason": null,
      "duration_ms": null,
      "findings_count": 0
    },
    {
      "name": "clue_extraction",
      "state": "success",
      "reason": null,
      "duration_ms": null,
      "findings_count": 1
    },
    {
      "name": "rules",
      "state": "success",
      "reason": null,
      "duration_ms": 0,
      "findings_count": 1
    },
    {
      "name": "semgrep",
      "state": "skipped",
      "reason": "本次请求未启用该分析器（对应的 analysis_options 开关为 false）。",
      "duration_ms": null,
      "findings_count": 0
    },
    {
      "name": "llm",
      "state": "skipped",
      "reason": "本次请求未启用该分析器（对应的 analysis_options 开关为 false）。",
      "duration_ms": null,
      "findings_count": 0
    }
  ],
  "findings": [
    {
      "id": "0aa90923ec62922f",
      "title": "疑似 SQL 语句由字符串拼接或格式化构造",
      "vulnerability_type": "sql_injection",
      "severity": "low",
      "description": "启发式线索（尚未确认为漏洞）：疑似 SQL 语句由字符串拼接或格式化构造。需人工确认拼接部分是否来自不可信输入；若使用参数化占位符则不构成风险。",
      "evidence": "sql = \"SELECT * FROM users WHERE id = \" + user_id",
      "line_start": 6,
      "line_end": 6,
      "recommendation": "请确认该语句是否受用户输入影响。若受影响的只是参数值，改用参数化查询（占位符 + 参数绑定）即可；若表名、列名、排序字段也来自输入，则需改用白名单映射，占位符无法覆盖这类位置。",
      "confidence": 0.45,
      "source": "heuristic",
      "rule_id": null,
      "cwe_id": "CWE-89"
    },
    {
      "id": "d27edaf937cdd2da",
      "title": "疑似 SQL 注入：语句由外部输入动态构造后交给数据库执行",
      "vulnerability_type": "sql_injection",
      "severity": "medium",
      "description": "交给数据库执行的第一个实参（查询语句本身）不是写死的：它在本行被拼接或格式化，或者引用了本文件内可追溯到外部输入的变量。查询语句被外部内容改写后，查询的语义——条件、表、返回的列——都可能改变。需要人工确认：被拼进去的是**参数取值**还是**语句结构**。本行使用的 sql 在第 6 行由拼接或格式化构造。",
      "evidence": "return conn.execute(sql)",
      "line_start": 7,
      "line_end": 7,
      "recommendation": "改用参数化查询，把取值全部通过占位符绑定传入；表名、列名、排序方向等占位符覆盖不到的位置，改用固定白名单映射。不要用拼接或字符串格式化把内容嵌进 SQL 文本。",
      "confidence": 0.55,
      "source": "static_rule",
      "rule_id": "ARGUS-SQL-001",
      "cwe_id": "CWE-89"
    }
  ],
  "limitations": [
    "ARGUS 是代码安全分析的辅助工具，不是安全证明工具；未发现漏洞不代表代码绝对安全。",
    "分析结果来自规则匹配、特征启发式与（可选的）模型判断，均可能误报或漏报。",
    "confidence 表示分析器对自身判断的估计，不是漏洞真实发生的概率，也不能跨来源比较或相加。",
    "报告中不包含完整源代码，只保留候选发现的最小证据片段。",
    "若有分析器被跳过、不可用或失败，其结果不代表“没有问题”，请结合分析器状态判断。",
    "启用 LLM 时，扫描期间的代码片段已发送到所配置的第三方模型服务商。",
    "修复建议是候选方案，未经编译、执行或测试，应用前必须人工审查并重新测试。"
  ]
}
```

### 6.2 Markdown（`format=markdown`）

````markdown
# ARGUS 扫描报告

> 本报告由 ARGUS 自动生成，用于辅助人工复核，不是安全证明。

## 扫描信息

| 字段 | 值 |
|---|---|
| 扫描编号 | `e4ccecb1b60f4453b7a588a1bb9ada03` |
| 扫描时间 | 2026-11-05T09:43:26+00:00 |
| 文件名 | views\.py |
| 识别语言 | python |
| 扫描状态 | 部分完成（partial） |
| 源文件解码 | 未发生解码转换（JSON 提交） |
| 总耗时 | 0 ms |
| 报告生成时间 | 2026-11-05T09:43:26.119799+00:00 |

## 摘要

- 候选发现：2 条
- 严重等级：严重（critical） 0，高（high） 0，中（medium） 1，低（low） 1，提示（info） 0
- 来源统计：启发式线索（heuristic） 1；本地规则（static_rule） 1

## 分析器状态

| 分析器 | 状态 | 发现数 | 耗时 | 说明 |
|---|---|---|---|---|
| 语言识别（language_detection） | 成功（success） | 0 | 0 ms | — |
| 特征提取（feature_extraction） | 成功（success） | 0 | — | — |
| 候选线索（clue_extraction） | 成功（success） | 1 | — | — |
| 本地规则（rules） | 成功（success） | 1 | 0 ms | — |
| Semgrep（semgrep） | 跳过（skipped） | 0 | — | 本次请求未启用该分析器（对应的 analysis\_options 开关为 false）。 |
| LLM（llm） | 跳过（skipped） | 0 | — | 本次请求未启用该分析器（对应的 analysis\_options 开关为 false）。 |

## 候选发现

### 1. 疑似 SQL 语句由字符串拼接或格式化构造

| 字段 | 值 |
|---|---|
| 漏洞类型 | sql\_injection |
| 严重等级 | 低（low） |
| 来源 | 启发式线索（heuristic） |
| 置信度 | 0.45 |
| 位置 | 第 6 行 |
| 规则 | 未标注 |
| CWE | CWE\-89 |

**说明**

启发式线索（尚未确认为漏洞）：疑似 SQL 语句由字符串拼接或格式化构造。需人工确认拼接部分是否来自不可信输入；若使用参数化占位符则不构成风险。

**证据**

```
sql = "SELECT * FROM users WHERE id = " + user_id
```

**修复建议**

请确认该语句是否受用户输入影响。若受影响的只是参数值，改用参数化查询（占位符 \+ 参数绑定）即可；若表名、列名、排序字段也来自输入，则需改用白名单映射，占位符无法覆盖这类位置。

### 2. 疑似 SQL 注入：语句由外部输入动态构造后交给数据库执行

| 字段 | 值 |
|---|---|
| 漏洞类型 | sql\_injection |
| 严重等级 | 中（medium） |
| 来源 | 本地规则（static_rule） |
| 置信度 | 0.55 |
| 位置 | 第 7 行 |
| 规则 | ARGUS\-SQL\-001 |
| CWE | CWE\-89 |

**说明**

交给数据库执行的第一个实参（查询语句本身）不是写死的：它在本行被拼接或格式化，或者引用了本文件内可追溯到外部输入的变量。查询语句被外部内容改写后，查询的语义——条件、表、返回的列——都可能改变。需要人工确认：被拼进去的是\*\*参数取值\*\*还是\*\*语句结构\*\*。本行使用的 sql 在第 6 行由拼接或格式化构造。

**证据**

```
return conn.execute(sql)
```

**修复建议**

改用参数化查询，把取值全部通过占位符绑定传入；表名、列名、排序方向等占位符覆盖不到的位置，改用固定白名单映射。不要用拼接或字符串格式化把内容嵌进 SQL 文本。

## 局限说明

- ARGUS 是代码安全分析的辅助工具，不是安全证明工具；未发现漏洞不代表代码绝对安全。
- 分析结果来自规则匹配、特征启发式与（可选的）模型判断，均可能误报或漏报。
- confidence 表示分析器对自身判断的估计，不是漏洞真实发生的概率，也不能跨来源比较或相加。
- 报告中不包含完整源代码，只保留候选发现的最小证据片段。
- 若有分析器被跳过、不可用或失败，其结果不代表“没有问题”，请结合分析器状态判断。
- 启用 LLM 时，扫描期间的代码片段已发送到所配置的第三方模型服务商。
- 修复建议是候选方案，未经编译、执行或测试，应用前必须人工审查并重新测试。
````

## 7. 已知限制

- 报告依赖扫描历史；关闭历史后无法导出，也不提供"从当前页面直接导出"的旁路；
- 历史删除后，对应报告随之下线；
- HTML / PDF 尚未实现；
- 报告是扫描当时的快照，不会随后续规则调整而更新；
- 分析器状态中的 `skipped` / `failed` 不代表"没有问题"，报告中已单独列出。

## 8. 测试

```bash
cd backend
python -m pytest tests/test_report.py -q
```

覆盖：JSON 与历史详情一致、Markdown 必需章节、仅包含指定记录、不含源码、
文件名安全、HTML/Markdown 注入转义、代码围栏不可提前闭合、404/422/503。
