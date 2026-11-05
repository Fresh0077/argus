# 本地扫描历史（SQLite）

> 历史功能只记录**扫描结果**，不保存完整源代码。
> 历史中的候选发现仍是辅助判断，不是已确认的漏洞。

## 1. 目的与边界

扫描完成后，ARGUS 会把这次扫描的元数据与结果写入本机 SQLite 数据库，
供用户回看和删除。它解决的是"关掉页面后还能不能查到刚才那次扫描"，
不是审计日志，也不是多用户共享存储。

- **单机、单用户、本地文件。** 不引入数据库服务，不使用 ORM。
- **只存结果，不存输入。** 数据库中没有存放源代码正文的列。
- **写入失败不影响扫描。** 磁盘或数据库出错时，扫描响应照常返回，
  只在服务端记录一条不含源码与路径的日志。

## 2. 保存了哪些数据

每次扫描写入一行，包含：

| 字段 | 内容 |
|---|---|
| `scan_id` | 扫描编号（32 位小写十六进制，与响应中的 `scan_id` 一致） |
| `created_at` | 写入时间，UTC ISO 8601 |
| `filename` | 调用方提供的**展示用**文件名；未提供时为 NULL |
| `language` | 本次扫描识别出的语言；未识别时为 NULL |
| `status` | `completed` / `partial` / `failed` |
| `source_encoding` | 上传接口实际使用的解码方式；JSON 提交为 NULL |
| `duration_ms` | 本次扫描的真实耗时 |
| `total_findings` | 候选发现总数 |
| `severity_counts_json` | 按严重等级统计的数量 |
| `source_counts_json` | 按发现来源统计的数量 |
| `findings_json` | 完整候选发现列表（见下） |
| `analyzer_status_json` | 各分析器是否真正执行、原因与耗时 |

`findings_json` 保存每条候选发现的标题、类别、等级、说明、**最小必要证据片段**、
行号、修复建议、置信度、来源、规则 ID 与 CWE。除证据片段外，没有任何代码原文。

### 明确不保存的内容

- **完整源代码、上传文件的原始字节、提交的请求体。**
- **API key、环境变量、请求头。** 数据库里没有这些字段。
- **特征提取结果**（行数、导入列表等）与**分析开关**。
  想判断某次扫描跑过哪些分析器，请看保存下来的 `analyzer_status`。
- URL 与日志中也不会出现代码正文：历史接口只按 `scan_id` 查询。

> 证据片段来自分析器输出，可能包含危险调用所在的一行代码。
> 如果不希望任何代码片段落盘，请设置 `HISTORY_ENABLED=false`。

## 3. 数据库位置与 Git

默认位置：

```
<项目根>/data/argus_history.db
```

可通过 `HISTORY_DB_PATH` 修改：

- 绝对路径直接使用；
- 相对路径按**项目根**解析（不是当前工作目录），保证从仓库根或 `backend/` 启动都指向同一文件；
- 留空使用默认路径。

SQLite 在 WAL 模式下还会生成 `argus_history.db-wal` 与 `argus_history.db-shm`。
`.gitignore` 已覆盖：

```gitignore
*.db
*.sqlite
*.sqlite3
*.db-journal
*.db-wal
*.db-shm
argus_history.db*
data/
```

数据库文件、WAL 文件与 `data/` 目录都不会进入版本控制。
不要用 `git add -f` 强行提交它们。

## 4. 版本兼容

- 表 `schema_meta` 保存 `schema_version`，当前为 **1**。
- 打开数据库时会检查版本：
  - 低于当前版本：未来版本在这里逐级迁移（目前只有 v1，无需迁移）；
  - 高于当前版本：报"数据库由更新版本的程序创建"，历史接口返回 503，
    **不会按旧结构强读**，以免读出错误数据。
- 记录内容在读取时用 Pydantic 重新校验；损坏的 JSON 会报
  "记录内容无法读取"，而不是把半条数据返回给前端。

## 5. 接口

| 方法与路径 | 说明 | 成功 | 失败 |
|---|---|---|---|
| `GET /api/v1/history?page=1&page_size=20` | 分页列表，只含元数据 | 200 | 422 / 503 |
| `GET /api/v1/history/{scan_id}` | 单条详情，含发现与分析器状态 | 200 | 404 / 422 / 503 |
| `DELETE /api/v1/history/{scan_id}` | 永久删除一条记录 | 204（无响应体） | 404 / 422 / 503 |

约定：

- `page >= 1`；`1 <= page_size <= 100`，默认 20。非法值返回 422。
- 页码超出总页数返回空列表，不视为错误。
- `scan_id` 必须是 32 位小写十六进制，否则在进入业务逻辑前返回 422。
- 记录不存在返回 404，错误码 `history_not_found`。
- `HISTORY_ENABLED=false` 时：
  - 列表返回 200，`enabled=false`、`items=[]`、`total=0`；
  - 详情与删除返回 503，错误码 `history_disabled`。
- 数据库无法打开或版本不兼容时返回 503，错误码 `history_unavailable`；
  对外文案是固定中文说明，不含文件路径、SQL 或 traceback。

### 5.1 列表（真实响应）

```json
{
  "enabled": true,
  "items": [
    {
      "scan_id": "db25c6592b7c447e8664eb823996181d",
      "created_at": "2026-11-05T08:29:26Z",
      "filename": "views.py",
      "language": "python",
      "status": "partial",
      "source_encoding": null,
      "duration_ms": 0,
      "total_findings": 1,
      "severity_counts": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 0
      },
      "source_counts": {
        "heuristic": 1
      }
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20,
  "total_pages": 1
}
```

列表**不返回** `findings` 或 `analyzer_status`；详情才返回。

### 5.2 详情（真实响应，发现列表已截为 1 条）

```json
{
  "scan_id": "db25c6592b7c447e8664eb823996181d",
  "created_at": "2026-11-05T08:29:26Z",
  "filename": "views.py",
  "language": "python",
  "status": "partial",
  "source_encoding": null,
  "duration_ms": 0,
  "total_findings": 1,
  "severity_counts": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 1,
    "info": 0
  },
  "source_counts": {
    "heuristic": 1
  },
  "findings": [
    {
      "id": "543dd8078c1d3bca",
      "title": "疑似 SQL 语句由字符串拼接或格式化构造",
      "vulnerability_type": "sql_injection",
      "severity": "low",
      "description": "启发式线索（尚未确认为漏洞）：疑似 SQL 语句由字符串拼接或格式化构造。需人工确认拼接部分是否来自不可信输入；若使用参数化占位符则不构成风险。",
      "evidence": "query = \"SELECT * FROM users WHERE id = \" + user_id",
      "line_start": 1,
      "line_end": 1,
      "recommendation": "请确认该语句是否受用户输入影响。若受影响的只是参数值，改用参数化查询（占位符 + 参数绑定）即可；若表名、列名、排序字段也来自输入，则需改用白名单映射，占位符无法覆盖这类位置。",
      "confidence": 0.45,
      "source": "heuristic",
      "rule_id": null,
      "cwe_id": "CWE-89"
    }
  ],
  "analyzer_status": [
    {
      "name": "language_detection",
      "state": "success",
      "reason": null,
      "duration_ms": 0,
      "findings_count": 0
    },
    {
      "name": "semgrep",
      "state": "skipped",
      "reason": "本次请求未启用该分析器（对应的 analysis_options 开关为 false）。",
      "duration_ms": null,
      "findings_count": 0
    }
  ]
}
```

> 示例中的详情只保留了 `analyzer_status` 的前两项与一条发现；
> 实际响应包含全部分析器状态与全部发现。

### 5.3 删除与缺失记录

删除成功：

```http
DELETE /api/v1/history/db25c6592b7c447e8664eb823996181d
→ 204 No Content
```

再次读取同一编号：

```json
{
  "error": {
    "code": "history_not_found",
    "message": "扫描记录不存在或已被删除。",
    "details": []
  }
}
```

### 5.4 非法分页

```http
GET /api/v1/history?page=0
→ 422
```

```json
{
  "error": {
    "code": "validation_error",
    "message": "请求参数校验未通过，请检查提交的内容。",
    "details": [
      {
        "field": "page",
        "message": "取值必须大于或等于 1。"
      }
    ]
  }
}
```

## 6. 如何删除历史

1. **界面**：顶部“扫描历史” → 找到记录 → “删除” → 确认。
2. **接口**：`DELETE /api/v1/history/{scan_id}`（永久删除，无法通过接口恢复）。
3. **全部清除**：停止后端，删除数据库文件（及其 `-wal` / `-shm` 文件）：

```powershell
# PowerShell，在项目根目录
Remove-Item data\argus_history.db* -Force
```

```bash
# Git Bash，在项目根目录
rm -f data/argus_history.db*
```

删除后会重新创建空数据库；这是预期行为。

## 7. 配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `HISTORY_ENABLED` | `true` | 是否记录与开放历史。关闭后扫描功能不受影响 |
| `HISTORY_DB_PATH` | 空（`<项目根>/data/argus_history.db`） | 数据库文件路径；相对路径按项目根解析 |

改配置后需重启后端。修改存储位置不会自动搬运旧数据；
如需保留，请先停止服务再手动移动数据库文件。

## 8. 已知局限

1. 不是审计日志：用户可以删除任意记录，且没有身份与权限概念。
2. 没有自动清理策略：记录会一直保留，直到手动删除或清空数据库文件。
3. 结果快照不会随后续规则更新而重算；详情展示的是扫描当时的内容。
4. SQLite 适合单机单用户；并发写入靠 5 秒忙等待，不适合高并发场景。
5. 证据片段可能包含一行代码；如对此敏感，请关闭历史功能。
6. 不保存完整源代码，因此无法从历史重新扫描或还原文件。

## 9. 测试

历史相关测试位于 `backend/tests/test_history.py`，包括：

- 保存 → 列表 → 详情 → 删除的往返；
- 表结构无源码列、数据库内容不含源码标记、接口响应不含源码正文；
- 分页边界、非法 `scan_id`、缺失记录、关闭状态、数据库不可用、版本不兼容、记录损坏；
- 历史写入失败时扫描仍正常返回 200。

`backend/tests/conftest.py` 会把所有测试的历史路径指向临时目录并默认关闭历史，
确保测试不会写入开发者本机的真实数据库。
