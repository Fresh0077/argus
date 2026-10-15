"""本地规则表。

一条规则由四部分组成：**在哪找**（``pattern``）、**怎么排除**（``exclude``）、
**取哪段值**（``dynamic_value_at``）、**还要满足什么**（``require`` /
``require_taint``）。分开写是为了让每条规则都能被单独解释、单独测试，
而不是塞成一个谁也读不懂的大正则。

**触发条件分两档**，这是本表最重要的约定：

- **位置本身即危险**——``eval``、``unserialize``、``v-html``、``| safe``。
  这类写法出现在代码里就值得看一眼，命中即报告。
- **位置本身常见且多数无害**——``innerHTML =``、``execute(``、``system(``。
  这类必须再拿到证据才报告：值不是写死的，或者能追到外部来源。

**登记顺序即优先级**：同一行同一漏洞类别只产出一条发现，
按本表顺序取第一条命中的规则。因此更具体的规则必须写在更宽泛的规则之前。
"""

from __future__ import annotations

from app.analyzers.common import STRING_CONSTRUCTION
from app.analyzers.rules.model import Rule, ValuePosition
from app.analyzers.taint import TaintKind
from app.schemas.enums import Severity

# ---------------------------------------------------------------------------
# 适用语言
# ---------------------------------------------------------------------------

_PYTHON = frozenset({"python"})
#: TypeScript 与 Vue 单文件组件里的脚本按 JavaScript 处理。
_JS = frozenset({"javascript", "typescript", "vue"})
_PHP = frozenset({"php"})
_JAVA = frozenset({"java"})
_GO = frozenset({"go"})
_RUBY = frozenset({"ruby"})
_MARKUP = frozenset({"html", "vue"})

#: 除模板外的全部受支持语言。
_CODE = _PYTHON | _JS | _PHP | _JAVA | _GO | _RUBY

#: 这两种标记都算"来源线索"：直接来自外部输入，或者由拼接构造出来。
#: 后者同样值得报告——语句被拼出来的这件事本身就可疑，只是等级低一档。
_ANY_TAINT = frozenset({TaintKind.UNTRUSTED, TaintKind.CONSTRUCTED})


# ---------------------------------------------------------------------------
# 危险位置
# ---------------------------------------------------------------------------

#: SQL 危险位置：把语句交给数据库执行的那些调用。
#: 刻意不含 ``.exec(``——它是 JavaScript 正则的方法，与数据库无关。
_SQL_SINK = (
    r"\b(?:execute|executemany|executeQuery|executeUpdate|executeLargeUpdate"
    r"|createNativeQuery|createQuery|createSQLQuery|prepareStatement)\s*\("
    r"|\.\s*(?:query|raw|queryRow|queryContext)\s*\("
    r"|\b(?:Query|QueryRow|Exec)\s*\("
)

#: 命令执行危险位置。
_PY_SHELL_SINK = r"\b(?:os\.system|os\.popen|os\.spawn\w*)\s*\("
_JS_SHELL_SINK = (
    r"(?:(?<!\.)\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\("
    r"|child_process\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\()"
)


# ---------------------------------------------------------------------------
# 排除条件（安全写法）
# ---------------------------------------------------------------------------

#: 常见的 HTML 转义 / 净化函数。命中说明该位置的值已经被处理过。
#:
#: 刻意只列**明确的**函数名，不含 ``escape(``、``e(`` 这类通用短名——
#: 它们会误命中，把真正危险的位置一起放过去，比不排除更糟。
#: 反过来也要说清楚：命中它们只表示"有转义动作"，**不等于已经安全**，
#: 转义是否正确要看语境，那超出正则的判断范围。
_HTML_ESCAPERS = (
    r"\b(?:escapeHtml|escapeHTML|htmlEscape|sanitizeHtml|sanitizeHTML"
    r"|DOMPurify\s*\.\s*sanitize|htmlspecialchars|htmlentities|encodeForHTML"
    r"|HtmlUtils\s*\.\s*htmlEscape|StringEscapeUtils\s*\.\s*escapeHtml4"
    r"|html\s*\.\s*escape|markupsafe\s*\.\s*escape|escape\s*\.\s*html)\s*\("
)

#: shell 参数的转义函数。出现在同一行时不再按命令注入报告。
_SHELL_ESCAPERS = (
    r"\b(?:shlex\s*\.\s*quote|escapeshellarg|escapeshellcmd"
    r"|Shellwords\s*\.\s*(?:escape|shellescape)|Process\s*\.\s*escape)\s*\("
)


# ---------------------------------------------------------------------------
# 规则表
# ---------------------------------------------------------------------------

RULES: tuple[Rule, ...] = (
    # ===================== SQL 注入 =====================
    Rule(
        rule_id="ARGUS-SQL-001",
        vulnerability_type="sql_injection",
        title="疑似 SQL 注入：语句由外部输入动态构造后交给数据库执行",
        pattern=_SQL_SINK,
        languages=_CODE,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        # 「同行在拼接」或「引用了可追溯到外部输入的变量」满足其一即可：
        # 前者是语句在本行拼好就执行，后者是语句在前几行拼好、本行只负责执行。
        require=STRING_CONSTRUCTION,
        require_taint=_ANY_TAINT,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.55,
        confidence_with_source=0.8,
        cwe_id="CWE-89",
        description=(
            "交给数据库执行的第一个实参（查询语句本身）不是写死的："
            "它在本行被拼接或格式化，或者引用了本文件内可追溯到外部输入的变量。"
            "查询语句被外部内容改写后，查询的语义——条件、表、返回的列——都可能改变。"
            "需要人工确认：被拼进去的是**参数取值**还是**语句结构**。"
        ),
        recommendation=(
            "改用参数化查询，把取值全部通过占位符绑定传入；"
            "表名、列名、排序方向等占位符覆盖不到的位置，改用固定白名单映射。"
            "不要用拼接或字符串格式化把内容嵌进 SQL 文本。"
        ),
    ),
    # ===================== 命令注入 =====================
    Rule(
        rule_id="ARGUS-CMD-001",
        vulnerability_type="command_injection",
        title="疑似命令注入：系统命令由外部输入动态构造后交给 shell 执行",
        pattern=_PY_SHELL_SINK,
        languages=_PYTHON,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        exclude=_SHELL_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.55,
        confidence_with_source=0.8,
        cwe_id="CWE-78",
        description=(
            "实参不是固定命令：命令字符串由拼接构造，或引用了可追溯到外部输入的变量。"
            "这些接口会把整个字符串交给系统 shell 解释，"
            "其中的 ``;``、``|``、``&&``、``$()`` 都会被当作命令语法。"
            "需要人工确认：命令与参数是否可以被外部内容改变，"
            "以及是否真的需要经过 shell。"
        ),
        recommendation=(
            "优先改用不经 shell 的调用方式（参数以列表传入，例如 ``subprocess.run([...])`` "
            "且不加 ``shell=True``）；命令行本身固定时不要把外部内容拼进去；"
            "确实需要拼接时先做 shell 参数转义，并对外部内容做白名单校验。"
        ),
    ),
    Rule(
        rule_id="ARGUS-CMD-002",
        vulnerability_type="command_injection",
        title="疑似命令注入：subprocess 启用 shell 解释且命令含动态内容",
        pattern=r"\bsubprocess\s*\.\s*\w+\s*\(",
        languages=_PYTHON,
        require=r"\bshell\s*=\s*True",
        dynamic_value_at=ValuePosition.ALL_ARGUMENTS,
        exclude=_SHELL_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.55,
        confidence_with_source=0.8,
        cwe_id="CWE-78",
        description=(
            "``shell=True`` 会把整条命令交给系统 shell 解释，"
            "而实参里含有非字面量内容。此时参数中的 shell 元字符同样会被解释，"
            "拼接方式本身也容易出转义疏漏。"
            "需要人工确认：命令内容是否可能来自外部输入。"
        ),
        recommendation=(
            "去掉 ``shell=True``，把命令与参数作为列表传入；"
            "若必须使用 shell（例如需要管道、通配符），"
            "则命令模板必须完全写死，外部内容只作为参数并经转义后传入。"
        ),
    ),
    Rule(
        rule_id="ARGUS-CMD-003",
        vulnerability_type="command_injection",
        title="疑似命令注入：PHP 命令执行函数收到动态内容",
        pattern=r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
        languages=_PHP,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        exclude=_SHELL_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.55,
        confidence_with_source=0.8,
        cwe_id="CWE-78",
        description=(
            "这些函数会把字符串交给系统 shell 执行，而实参不是固定字面量。"
            "需要人工确认：实参是否直接或间接来自 ``$_GET``/``$_POST`` 等外部来源。"
        ),
        recommendation=(
            "避免通过 shell 执行外部命令；必须执行时使用 ``escapeshellarg()`` "
            "逐一转义参数，并对命令名本身使用白名单映射。"
        ),
    ),
    Rule(
        rule_id="ARGUS-CMD-004",
        vulnerability_type="command_injection",
        title="疑似命令注入：Node.js 子进程调用收到动态内容",
        pattern=_JS_SHELL_SINK,
        languages=_JS,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        exclude=_SHELL_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.5,
        confidence_with_source=0.75,
        cwe_id="CWE-78",
        description=(
            "``exec`` 系列会把命令字符串交给系统 shell 解释，而实参不是固定字面量。"
            "需要人工确认：命令内容是否可能来自请求参数等外部输入。"
        ),
        recommendation=(
            "改用 ``spawn``/``execFile`` 并以数组传入命令与参数——它们不经过 shell；"
            "必须拼接时对每一项做校验，不要依赖自行拼接引号来保证安全。"
        ),
    ),
    Rule(
        rule_id="ARGUS-CMD-005",
        vulnerability_type="command_injection",
        title="疑似命令注入：Java 进程调用收到动态内容",
        pattern=(
            r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("
            r"|\bnew\s+ProcessBuilder\s*\("
        ),
        languages=_JAVA,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        exclude=_SHELL_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.5,
        confidence_with_source=0.75,
        cwe_id="CWE-78",
        description=(
            "传入的命令不是固定字面量。``Runtime.exec`` 的单字符串重载会把内容"
            "按空白切分后执行，与控制参数列表的写法相比更难保证语义。"
            "需要人工确认：命令内容是否来自请求参数等外部输入。"
        ),
        recommendation=(
            "改用 ``ProcessBuilder`` 并把命令与参数分别作为独立元素传入；"
            "命令名本身固定，外部内容只允许出现在参数位置，且需校验。"
        ),
    ),
    Rule(
        rule_id="ARGUS-CMD-006",
        vulnerability_type="command_injection",
        title="疑似命令注入：Go 命令名由外部输入决定",
        pattern=r"\bexec\s*\.\s*Command\s*\(",
        languages=_GO,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.45,
        confidence_with_source=0.7,
        cwe_id="CWE-78",
        description=(
            "``exec.Command`` 的第一个实参是要执行的程序名，它由外部输入决定，"
            "攻击者可以借此换成任意可执行文件。``exec.Command`` 不经过 shell，"
            "因此**动态的参数**（而非程序名）不在此规则范围内。"
            "需要人工确认：程序名是否真的可以由外部输入改变。"
        ),
        recommendation=(
            "把可执行的程序名固定为字面量，外部输入只作为后续参数传入；"
            "确实需要按输入选择程序时，使用白名单映射到固定的程序路径。"
        ),
    ),
    Rule(
        rule_id="ARGUS-CMD-007",
        vulnerability_type="command_injection",
        title="疑似命令注入：Ruby 命令执行收到动态内容",
        pattern=r"\b(?:system|exec|spawn)\s*\(",
        languages=_RUBY,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        exclude=_SHELL_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.5,
        confidence_with_source=0.75,
        cwe_id="CWE-78",
        description=(
            "实参不是固定字面量。字符串形式的 ``system``/``exec`` 会经过 shell 解释，"
            "其中的元字符会被当作命令语法。"
            "需要人工确认：命令内容是否可能来自外部输入。"
        ),
        recommendation=(
            "改用数组形式（``system('cmd', arg)``）把命令与参数分开——它不经过 shell；"
            "并对外部内容做白名单校验。"
        ),
    ),
    Rule(
        rule_id="ARGUS-CMD-008",
        vulnerability_type="command_injection",
        title="疑似命令注入：Ruby 反引号或 %x{} 中含插值",
        # ``%x{`` 前不能用 ``\b``：``%`` 不是单词字符，``\b%x`` 要求它左边是
        # 单词字符、右边不是，两头都是非单词字符，断言永远不成立——
        # 写 ``\b%x\{`` 等于这个分支从来不匹配。改用"左边不是单词字符"。
        pattern=r"`[^`]*`|(?<![\w])%x\{",
        languages=_RUBY,
        dynamic_value_at=ValuePosition.NONE,
        require=STRING_CONSTRUCTION,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.55,
        confidence_with_source=0.8,
        cwe_id="CWE-78",
        description=(
            "反引号与 ``%x{}`` 会启动子进程执行其中的内容，"
            "而这里含有 ``#{}`` 插值，命令文本由运行时的值拼成。"
            "需要人工确认：插进去的内容是否可能来自外部输入。"
        ),
        recommendation=(
            "改用 ``system('cmd', arg)`` 这类不经过 shell 的数组形式；"
            "必须拼接时用 ``Shellwords.escape`` 转义每个参数。"
        ),
    ),
    # ===================== 跨站脚本 =====================
    Rule(
        rule_id="ARGUS-XSS-001",
        vulnerability_type="xss",
        title="疑似 XSS：把非字面量内容写入 innerHTML / outerHTML",
        pattern=r"\.\s*(?:innerHTML|outerHTML)\s*=(?!=)",
        languages=_JS,
        dynamic_value_at=ValuePosition.ASSIGNED_VALUE,
        exclude=_HTML_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.5,
        confidence_with_source=0.75,
        cwe_id="CWE-79",
        description=(
            "``innerHTML``/``outerHTML`` 会把内容解析成 HTML，其中的 ``<script>``"
            "与事件属性都会生效，而赋进去的不是写死的字符串。"
            "需要人工确认：这段内容的来源，以及它是否已经按 HTML 语境转义。"
        ),
        recommendation=(
            "优先改用 ``textContent`` 写入纯文本；确实需要富文本时，"
            "先用经过验证的净化库（如 DOMPurify）处理，并明确允许的标签与属性白名单。"
        ),
    ),
    Rule(
        rule_id="ARGUS-XSS-002",
        vulnerability_type="xss",
        title="疑似 XSS：document.write / insertAdjacentHTML 写入动态内容",
        pattern=r"\bdocument\s*\.\s*write(?:ln)?\s*\(|\binsertAdjacentHTML\s*\(",
        languages=_JS,
        dynamic_value_at=ValuePosition.ALL_ARGUMENTS,
        exclude=_HTML_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.5,
        confidence_with_source=0.75,
        cwe_id="CWE-79",
        description=(
            "这两个接口把字符串按 HTML 解析后插入文档，而传入的内容不是写死的。"
            "``document.write`` 还会在解析期间改写整个文档。"
            "需要人工确认：内容的来源与转义情况。"
        ),
        recommendation=(
            "改用 DOM API（``textContent``、``createElement``）构造节点；"
            "必须插入 HTML 时先净化，并限制允许的标签与属性。"
        ),
    ),
    Rule(
        rule_id="ARGUS-XSS-003",
        vulnerability_type="xss",
        title="疑似 XSS：React 中使用了 dangerouslySetInnerHTML",
        pattern=r"\bdangerouslySetInnerHTML\b",
        languages=_JS,
        exclude=_HTML_ESCAPERS,
        # JSX 不是调用，取不到"第一个实参"，所以按位置匹配；
        # 但"位置本身即危险"在这里不成立——``{{__html: '<b>hi</b>'}}``
        # 之类的写死内容是安全的，报出来只是噪音。
        # 因此要求 ``__html`` 绑定的不是字符串字面量。
        #
        # 空白必须放进前瞻里：``\s*`` 写在冒号后可以回溯成零个字符，
        # 于是前瞻看到的是空格而不是引号，"绑定了字面量"就漏过去了。
        require=r"__html\s*:(?!\s*['\"])",
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.45,
        confidence_with_source=0.7,
        cwe_id="CWE-79",
        description=(
            "该属性会跳过 React 的自动转义，直接按 HTML 渲染 ``__html`` 的内容，"
            "而绑定的不是写死的字符串。React 刻意用这个拗口的名字提醒使用者它不安全。"
            "需要人工确认：``__html`` 的内容是否经过净化、是否可能来自外部输入。"
        ),
        recommendation=(
            "尽量改用普通 JSX 插值（React 会自动转义）；"
            "必须渲染富文本时，先用 DOMPurify 等库净化，并限制允许的标签与属性。"
        ),
    ),
    Rule(
        rule_id="ARGUS-XSS-004",
        vulnerability_type="xss",
        title="疑似 XSS：模板中使用了 v-html 指令",
        pattern=r"\bv-html\s*=",
        languages=_MARKUP,
        exclude=_HTML_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.45,
        confidence_with_source=0.7,
        cwe_id="CWE-79",
        description=(
            "``v-html`` 会跳过 Vue 的自动转义，把绑定值按 HTML 渲染。"
            "需要人工确认：绑定值是否只可能来自可信内容；"
            "若绑定的是写死的常量，可以把这条发现判为误报。"
        ),
        recommendation=(
            "改用 ``{{ }}`` 插值（默认转义）；必须渲染富文本时先净化，"
            "或改用不解析 HTML 的渲染方式（例如 Markdown 转义后输出纯文本）。"
        ),
    ),
    Rule(
        rule_id="ARGUS-XSS-005",
        vulnerability_type="xss",
        title="疑似 XSS：模板输出被标记为不转义",
        pattern=r"\|\s*safe\b",
        languages=_MARKUP,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.45,
        confidence_with_source=0.7,
        cwe_id="CWE-79",
        description=(
            "``| safe`` 会关闭模板的自动转义，把内容原样输出到 HTML 中。"
            "需要人工确认：被标记为安全的内容是否真的可信；"
            "若输出的是写死的常量，可以把这条发现判为误报。"
        ),
        recommendation=(
            "尽量去掉 ``| safe``，让模板自动转义；"
            "必须输出富文本时先在后端净化，只保留允许的标签与属性。"
        ),
    ),
    Rule(
        rule_id="ARGUS-XSS-006",
        vulnerability_type="xss",
        title="疑似 XSS：PHP 直接输出超全局变量",
        pattern=r"\b(?:echo|print|printf)\b",
        languages=_PHP,
        require=r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b",
        exclude=_HTML_ESCAPERS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.5,
        confidence_with_source=0.75,
        cwe_id="CWE-79",
        description=(
            "同一行里既有输出语句、又直接读取了超全局变量，"
            "外部内容会原样进入 HTML。"
            "需要人工确认：该内容是否已经过 HTML 转义。"
        ),
        recommendation=(
            "输出前用 ``htmlspecialchars($value, ENT_QUOTES, 'UTF-8')`` 转义；"
            "注意属性、URL、JavaScript 三种语境需要各自的转义方式。"
        ),
    ),
    # ===================== 不安全动态执行 =====================
    Rule(
        rule_id="ARGUS-EXEC-001",
        vulnerability_type="unsafe_dynamic_execution",
        title="疑似代码注入：Python 动态执行函数收到动态内容",
        pattern=r"(?<!\.)\b(?:eval|exec|compile)\s*\(",
        languages=_PYTHON,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.6,
        confidence_with_source=0.85,
        cwe_id="CWE-95",
        description=(
            "``eval``/``exec``/``compile`` 会把字符串当作代码执行，"
            "而传入的内容不是写死的。一旦内容可被外部影响，"
            "效果等同于任意代码执行。"
            "需要人工确认：这段代码文本从哪里来。"
            "如果它是由程序自己生成的固定模板、且不含外部输入，可以判为误报。"
        ),
        recommendation=(
            "改用不需要动态求值的写法：``ast.literal_eval`` 解析字面量、"
            "字典做分派、``getattr`` 取属性。"
            "确实无法避免时，把可执行的文本限制在写死的白名单内。"
        ),
    ),
    Rule(
        rule_id="ARGUS-EXEC-002",
        vulnerability_type="unsafe_dynamic_execution",
        title="疑似代码注入：JavaScript eval / new Function 收到动态内容",
        pattern=r"(?<!\.)\beval\s*\(|\bnew\s+Function\s*\(",
        languages=_JS,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.6,
        confidence_with_source=0.85,
        cwe_id="CWE-95",
        description=(
            "``eval`` 与 ``new Function`` 会把字符串当作代码执行，"
            "而传入的内容不是写死的。它们还会在调用方的作用域内执行代码，"
            "因此能读到本不该被读到的变量。"
            "需要人工确认：这段代码文本从哪里来。"
        ),
        recommendation=(
            "改用 ``JSON.parse`` 解析数据、用显式映射代替动态调用；"
            "确实无法避免时，把可执行的文本限制在写死的白名单内。"
        ),
    ),
    Rule(
        rule_id="ARGUS-EXEC-003",
        vulnerability_type="unsafe_dynamic_execution",
        title="疑似代码注入：setTimeout / setInterval 传入字符串形式的代码",
        pattern=r"\bsetTimeout\s*\(|\bsetInterval\s*\(",
        languages=_JS,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        require_taint=_ANY_TAINT,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.5,
        confidence_with_source=0.75,
        cwe_id="CWE-95",
        description=(
            "``setTimeout``/``setInterval`` 的第一个实参可以是字符串，"
            "此时它会被当作代码执行；而这里传的字符串可以追到外部来源。"
            "需要人工确认：是否确实传入了字符串而不是函数。"
        ),
        recommendation="改为传入函数对象（``setTimeout(() => {...}, ms)``），不要传入代码字符串。",
    ),
    Rule(
        rule_id="ARGUS-EXEC-004",
        vulnerability_type="unsafe_dynamic_execution",
        title="疑似代码注入：PHP 动态执行收到动态内容",
        pattern=(
            r"(?<!\.)\beval\s*\(|\bassert\s*\(|\bcreate_function\s*\("
            r"|\bpreg_replace\s*\([^)]*/\w*e\w*['\"]"
        ),
        languages=_PHP,
        dynamic_value_at=ValuePosition.FIRST_ARGUMENT,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.6,
        confidence_with_source=0.85,
        cwe_id="CWE-95",
        description=(
            "``eval``、字符串形式的 ``assert``、``create_function`` "
            "以及 ``preg_replace`` 的 ``/e`` 修饰符都会把字符串当作代码执行。"
            "需要人工确认：被执行的文本从哪里来。"
        ),
        recommendation=(
            "用显式的分支或映射表代替动态执行；"
            "``preg_replace`` 的 ``/e`` 修饰符已废弃，改用 ``preg_replace_callback``。"
        ),
    ),
    # ===================== 不安全反序列化 =====================
    Rule(
        rule_id="ARGUS-DESER-001",
        vulnerability_type="unsafe_deserialization",
        title="疑似不安全反序列化：对非字面量数据调用 pickle 系列",
        pattern=r"\b(?:pickle|cPickle|dill|marshal|shelve)\s*\.\s*loads?\s*\(",
        languages=_PYTHON,
        dynamic_value_at=ValuePosition.ALL_ARGUMENTS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.55,
        confidence_with_source=0.8,
        cwe_id="CWE-502",
        description=(
            "这些格式的反序列化过程可以构造出在加载时执行任意代码的数据，"
            "而这里处理的不是写死的字面量。"
            "需要人工确认：数据的来源是否完全可信（例如只来自本机进程间的固定管道）。"
        ),
        recommendation=(
            "改用只表达数据的格式（JSON、MessagePack）并做结构校验；"
            "必须使用 pickle 时，只能处理完全可信来源的数据，"
            "不要对用户提交的内容调用 ``loads``。"
        ),
    ),
    Rule(
        rule_id="ARGUS-DESER-002",
        vulnerability_type="unsafe_deserialization",
        title="疑似不安全反序列化：Java 原生反序列化调用",
        pattern=(
            r"\bnew\s+ObjectInputStream\s*\(|\bnew\s+XMLDecoder\s*\("
            r"|\breadObject\s*\(|\breadUnshared\s*\("
        ),
        languages=_JAVA,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.55,
        confidence_with_source=0.8,
        cwe_id="CWE-502",
        description=(
            "Java 原生反序列化会依据字节流中的类信息还原对象，"
            "攻击者可以借此触发已有类的方法链。这类调用通常没有实参可查，"
            "因此只能标记调用位置本身。"
            "需要人工确认：被反序列化的字节流来自哪里。"
        ),
        recommendation=(
            "改用 JSON 等数据格式并做结构校验；"
            "必须使用原生反序列化时，启用 ``ObjectInputFilter`` 白名单，"
            "并确保数据来自可信来源。"
        ),
    ),
    Rule(
        rule_id="ARGUS-DESER-003",
        vulnerability_type="unsafe_deserialization",
        title="疑似不安全反序列化：PHP unserialize 收到动态数据",
        pattern=r"\bunserialize\s*\(",
        languages=_PHP,
        dynamic_value_at=ValuePosition.ALL_ARGUMENTS,
        severity=Severity.MEDIUM,
        severity_with_source=Severity.HIGH,
        confidence=0.55,
        confidence_with_source=0.8,
        cwe_id="CWE-502",
        description=(
            "``unserialize`` 会依据输入中的类型信息还原对象，"
            "并触发相应的魔术方法，而这里处理的数据不是写死的。"
            "需要人工确认：数据的来源是否可信。"
        ),
        recommendation=(
            "改用 ``json_decode``；若必须使用 ``unserialize``，"
            "设置 ``allowed_classes => false`` 或用 ``['allowed_classes' => [...]]`` 限制可还原的类。"
        ),
    ),
)


#: 按 ``rule_id`` 索引，便于按标识查找与在测试中核对。
RULES_BY_ID: dict[str, Rule] = {rule.rule_id: rule for rule in RULES}


def rules_for_language(language: str) -> tuple[Rule, ...]:
    """返回适用于该语言的规则，顺序即优先级。"""
    return tuple(rule for rule in RULES if language in rule.languages)
