# ARGUS 测试样例集

本目录用于验证检测能力与误报情况，配合
[`backend/scripts/evaluate.py`](../backend/scripts/evaluate.py) 计算
precision / recall / F1。评估方法与真实结果见
[`docs/evaluation.md`](../docs/evaluation.md)。

> ⚠️ **所有样例只用于静态分析，绝不可执行。**
> 样例中没有任何真实凭据、真实目标地址或可直接用于攻击真实系统的流程；
> 命令行样例只出现在源码文本中，评估脚本不会运行它们。

## 目录结构

```
test_samples/
├─ manifest.json          # 机器可读标签（评估脚本唯一标签来源）
├─ README.md              # 本文件：每个样例的语言、类别、风险原因与预期行为
├─ vulnerable/            # 含候选人造风险的样例
│  ├─ python/  javascript/  php/  java/  go/  ruby/  vue/  html/
├─ secure/                # 与风险样例对应的安全写法
│  ├─ python/  javascript/  php/  java/  go/  ruby/
└─ benign/                # 普通、无明显风险的 Web 代码
   ├─ python/  javascript/  html/  php/
```

三种样例的约定：

| kind | 含义 | 标签 |
|---|---|---|
| `vulnerable` | 演示一类风险的最小代码 | 必须至少一条 `(类别, 行号)` 预期发现 |
| `secure` | 针对某类风险的正确写法 | 不得声明预期发现 |
| `benign` | 普通业务代码，没有刻意展示安全问题 | 不得声明预期发现 |

## 标签与评估口径

- 标签是**人工按代码语义**写进 `manifest.json` 的，评估脚本不会根据分析结果反推。
- 参与指标的五类风险：`sql_injection`、`command_injection`、`xss`、
  `unsafe_dynamic_execution`、`unsafe_deserialization`。
- `untrusted_input_source` 是启发式**线索**，不是漏洞判定，不进入 precision / recall。
- 一条发现与一条标签匹配，需要**类别相同**且行号差不超过 2 行
  （`manifest.json` 的 `line_tolerance`）。
- 同一类别、同一行号的重复发现先去重；每条标签与每条发现最多匹配一次。
- 没有行号的发现无法与标签对齐，计为误报。
- `secure` / `benign` 样例上的任何五类发现都计为误报。
- LLM 没有实际分析的样例不进入
  的分母，报告中单独列出，不当作“没有发现问题”。

## 风险样例（vulnerable）

| id | 文件 | 语言 | 预期发现 | 风险原因 | 预期分析行为 |
|---|---|---|---|---|---|
| py-sql-injection-vulnerable | `vulnerable/python/sql_injection.py` | Python | `sql_injection@20` | 请求参数拼进 SQL 后执行 | LLM 应报告 |
| py-command-injection-vulnerable | `vulnerable/python/command_injection.py` | Python | `command_injection@18` | 请求参数拼进 `os.system` 命令 | LLM 应报告 |
| py-dynamic-execution-vulnerable | `vulnerable/python/dynamic_execution.py` | Python | `unsafe_dynamic_execution@16` | `eval` 执行请求参数 | LLM 应报告 |
| py-deserialization-vulnerable | `vulnerable/python/deserialization.py` | Python | `unsafe_deserialization@18` | `pickle.loads` 处理请求体 | LLM 应报告 |
| py-mixed-issues-vulnerable | `vulnerable/python/mixed_issues.py` | Python | `command_injection@18`、`unsafe_dynamic_execution@20` | 同一文件两处危险调用 | 两处都应报告，不能只报一处 |
| js-xss-innerhtml-vulnerable | `vulnerable/javascript/xss_innerhtml.js` | JavaScript | `xss@16` | 查询参数写入 `innerHTML` | LLM 应报告 |
| js-command-injection-vulnerable | `vulnerable/javascript/command_injection.js` | JavaScript | `command_injection@16` | 查询参数拼进 `child_process.exec` | LLM 应报告 |
| js-dynamic-execution-vulnerable | `vulnerable/javascript/dynamic_execution.js` | JavaScript | `unsafe_dynamic_execution@15` | 请求体交给 `eval` | LLM 应报告 |
| php-sql-injection-vulnerable | `vulnerable/php/sql_injection.php` | PHP | `sql_injection@15` | `$_GET` 拼进 PDO 查询 | LLM 应报告 |
| php-command-injection-vulnerable | `vulnerable/php/command_injection.php` | PHP | `command_injection@13` | `$_GET` 拼进 `system` | LLM 应报告 |
| php-reflected-xss-vulnerable | `vulnerable/php/reflected_xss.php` | PHP | `xss@12` | `echo` 直接输出 `$_GET` | LLM 应报告 |
| java-sql-injection-vulnerable | `vulnerable/java/sql_injection.java` | Java | `sql_injection@19` | 请求参数拼进 `Statement` 查询 | LLM 应报告 |
| java-command-injection-vulnerable | `vulnerable/java/command_injection.java` | Java | `command_injection@15` | 请求参数拼进 `Runtime.exec` | LLM 应报告 |
| go-sql-injection-vulnerable | `vulnerable/go/sql_injection.go` | Go | `sql_injection@19` | 请求参数拼进 `database/sql` 查询 | LLM 应报告 |
| go-command-injection-vulnerable | `vulnerable/go/command_injection.go` | Go | `command_injection@18` | 请求参数决定 `exec.Command` 程序名 | LLM 应报告 |
| ruby-command-injection-vulnerable | `vulnerable/ruby/command_injection.rb` | Ruby | `command_injection@9` | 请求参数插值进 `system` | LLM 应报告 |
| vue-v-html-vulnerable | `vulnerable/vue/v_html.vue` | Vue | `xss@4` | `v-html` 渲染查询字符串 | LLM 应报告 |
| html-safe-filter-vulnerable | `vulnerable/html/template_safe_filter.html` | HTML | `xss@9` | `| safe` 关闭模板转义 | LLM 应报告 |

## 安全写法样例（secure）

| id | 文件 | 语言 | 安全写法 | 为什么安全 | 预期分析行为 |
|---|---|---|---|---|---|
| py-sql-parameterized-safe | `secure/python/sql_parameterized.py` | Python | `execute(sql, (value,))` | SQL 文本固定，取值通过占位符绑定 | 不应报告 `sql_injection` |
| py-command-fixed-safe | `secure/python/command_fixed.py` | Python | `subprocess.run([...])` | 不经过 shell，外部内容只作为独立参数 | 不应报告 `command_injection` |
| py-dynamic-execution-safe | `secure/python/dynamic_execution_safe.py` | Python | `ast.literal_eval` | 只解析字面量，不执行任意代码 | 不应报告 `unsafe_dynamic_execution` |
| js-xss-textcontent-safe | `secure/javascript/xss_textcontent.js` | JavaScript | `textContent` | 纯文本写入，不解析 HTML | 不应报告 `xss` |
| js-command-fixed-safe | `secure/javascript/command_fixed.js` | JavaScript | `execFile('date', [...])` | 不经过 shell，命令与参数固定 | 不应报告 `command_injection` |
| php-sql-prepared-safe | `secure/php/sql_prepared.php` | PHP | PDO `prepare` + `execute([$id])` | SQL 文本固定，取值绑定 | 不应报告 `sql_injection`（LLM 可能误报，见局限） |
| php-command-fixed-safe | `secure/php/command_fixed.php` | PHP | `system('ls -la /var/www')` | 命令与参数完全写死 | 不应报告 `command_injection` |
| java-sql-prepared-safe | `secure/java/sql_prepared.java` | Java | `PreparedStatement` + `setString` | 查询文本固定，请求参数只作为绑定值 | 不应报告 `sql_injection` |
| java-command-fixed-safe | `secure/java/command_fixed.java` | Java | 固定参数的 `ProcessBuilder` | 命令与参数写死 | 不应报告 `command_injection` |
| go-command-fixed-safe | `secure/go/command_fixed.go` | Go | 固定参数的 `exec.Command` | 程序名与参数写死 | 不应报告 `command_injection` |
| ruby-command-fixed-safe | `secure/ruby/command_fixed.rb` | Ruby | `system('ls', '-la', ...)` | 命令与参数写死 | 不应报告 `command_injection` |

## 普通代码样例（benign）

| id | 文件 | 语言 | 说明 | 预期分析行为 |
|---|---|---|---|---|
| py-web-app-benign | `benign/python/web_app.py` | Python | Flask 文章与搜索接口，请求参数只作为 JSON 返回 | 不应报告五类风险 |
| js-web-app-benign | `benign/javascript/web_app.js` | JavaScript | Express 文章接口，没有 DOM HTML 写入或命令执行 | 不应报告五类风险 |
| html-static-page-benign | `benign/html/static_page.html` | HTML | 纯静态页面 | LLM 不应报告 |
| php-web-app-benign | `benign/php/web_app.php` | PHP | 白名单页面切换 + HTML 转义 | 不应报告五类风险 |

## 运行评估

在 `backend/` 下：

```powershell
# 显式启用 LLM 评估：需要 LLM_* 配置，样例代码会发送到第三方服务商
.\.venv\Scripts\python.exe -m scripts.evaluate --enable-llm

# 同时写出机器可读结果
.\.venv\Scripts\python.exe -m scripts.evaluate --enable-llm --json eval-result.json
```

Git Bash 下把 `python` 换成 `.venv/Scripts/python.exe` 即可。

## 已知局限

- 样例规模很小，单个样例就会明显改变 precision / recall，**不能外推为真实项目检出率**。
- 只做单文件分析；跨函数、跨文件、自研封装不在覆盖范围内。
- 评估只运行 LLM；结果不可复现，且需要真实 API key。
  更完整的限制见 `docs/evaluation.md`，未为了让指标好看而修改样例。
