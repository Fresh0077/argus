"""候选线索提取。

**这里产出的是"值得人工看一眼的位置"，不是"漏洞"。**
每条线索的措辞都刻意保持中性——写"检测到 eval 调用"，
不写"存在代码注入漏洞"。严重等级最高只到 ``LOW``，
置信度也压在 0.25–0.45：精确判定是规则检测器的职责，
本模块只负责把值得关注的位置从大段代码里挑出来。

误报控制：
- 一条线索必须**匹配到明确的语法特征**才产生，不做"包含某关键字"式的宽泛匹配。
- SQL 相关的线索要求同一行内**同时**出现 SQL 关键字与拼接/格式化算子，
  因此 `cursor.execute("... WHERE id = %s", (user_id,))` 这类参数化写法不会命中。
- 每种语言使用各自的模式表，不把一套正则套到所有语言上。

按行匹配：逐行扫描，因此行号天然准确，也天然实现对
「同一行不重复报告同一类线索」的去重。代价是跨行书写的语句不会被识别，
因此本模块**必然漏报**——这是已知且有意接受的局限。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.analyzers.line_index import LineIndex
from app.schemas.enums import Severity

#: 线索片段的最大长度。证据只保留最小必要上下文，
#: 不把整行之外的内容、更不把整个文件塞进响应。
MAX_SNIPPET_CHARS = 300

#: JS 系（含 Vue 单文件组件里的脚本）共用的模式集合键。
_JS_FAMILY = frozenset({"javascript", "typescript", "vue"})
_PHP = frozenset({"php"})
_PYTHON = frozenset({"python"})
_JAVA = frozenset({"java"})
_GO = frozenset({"go"})
_RUBY = frozenset({"ruby"})
_WEB_MARKUP = frozenset({"html", "vue"})


class CandidateClue(BaseModel):
    """一条候选线索。

    这是**内部分析上下文**，最终会被转换成 ``source=heuristic`` 的 ``Finding``
    再对外返回。分开建模是因为线索需要携带 ``cue_key``（用于生成稳定的发现 ID），
    而 ``Finding`` 不需要暴露这个概念。
    """

    model_config = ConfigDict(extra="forbid")

    #: 触发的模式标识。同一位置由同一模式产生时，多次扫描得到相同的 key。
    cue_key: Annotated[str, StringConstraints(min_length=1, max_length=80)]

    #: 漏洞类别标识，对应 ``Finding.vulnerability_type`` 使用的受控词表。
    category: Annotated[str, StringConstraints(min_length=1, max_length=100)]

    #: 面向用户的中性描述。长度上限与 ``Finding.title`` 对齐，
    #: 因为转换时它会直接成为标题，超出会被契约层拒绝。
    label: Annotated[str, StringConstraints(min_length=1, max_length=200)]

    #: 关键细节，用于补充 label，例如参数化写法的提示。
    detail: Annotated[str, StringConstraints(max_length=300)] = ""

    #: 命中位置的行号（1 起）。逐行扫描保证它一定准确。
    line: int

    #: 截断后的代码片段。
    snippet: Annotated[str, StringConstraints(max_length=MAX_SNIPPET_CHARS)]

    severity: Severity

    confidence: float

    cwe_id: str | None = None


@dataclass(frozen=True)
class CluePattern:
    """一条线索模式。

    ``require`` 是**同一行内还必须匹配**的附加条件，用来把宽泛的模式收紧。
    例如"行内有 SELECT"命中率极高，加上"且行内有字符串拼接"之后
    才真正具备提示价值。

    构造时传入的是**正则源码字符串**（下面的模式表因此保持可读），
    ``__post_init__`` 会把它编译成 ``re.Pattern`` 并存回同名字段，
    所以实例上的 ``pattern`` / ``require`` 是已编译对象。
    """

    cue_key: str
    category: str
    label: str
    pattern: str
    languages: frozenset[str]
    confidence: float
    detail: str = ""
    cwe_id: str | None = None
    severity: Severity = Severity.LOW
    require: str | None = None

    def __post_init__(self) -> None:
        # frozen dataclass 不能直接赋值，用 object.__setattr__ 绕过。
        # re.compile 自带缓存，重复构造同一模式不会重复解析。
        object.__setattr__(self, "pattern", re.compile(self.pattern))
        if self.require is not None:
            object.__setattr__(self, "require", re.compile(self.require))

    def matches(self, line: str) -> bool:
        """该模式是否命中这一行：主模式与附加条件都必须匹配。"""
        pattern: re.Pattern[str] = self.pattern  # type: ignore[assignment]
        if not pattern.search(line):
            return False
        if self.require is None:
            return True
        required: re.Pattern[str] = self.require  # type: ignore[assignment]
        return required.search(line) is not None


# ---------------------------------------------------------------------------
# 拼接 / 格式化的通用算子
# ---------------------------------------------------------------------------

#: 字符串拼接或插值的算子。
#:
#: 刻意**不包含单独的 ``%s``**：它在参数化查询里是占位符，
#: 放进来会让 `execute("... %s", (x,))` 这类安全写法被误报。
#: 真正的 ``%`` 格式化（`"...%s" % x`）由单独的 ``_PERCENT_FORMATTING`` 识别。
#:
#: ``\.[ \t]*\$`` 覆盖 PHP 的 ``.`` 拼接（``"..." . $id``）。
#: 只能要求点号后面紧跟 ``$``：单独一个 ``.`` 在几乎所有语言里
#: 都合法（成员访问、小数、方法链），放开来会让整个模式表失效。
_INTERPOLATION = r"(?:\+|\.format\s*\(|\$\{|\{[$\w]|f['\"]|\.[ \t]*\$)"

#: ``'... = %s' % user_id`` 这类百分号格式化。
#: 关键区别：``%`` 出现在**字符串结束引号之后**，
#: 而参数化写法的 ``%s`` 在引号内部——后者不能算作拼接。
_PERCENT_FORMATTING = r"""['"][ \t]*%[ \t]*[(\w'"]"""

#: "命令行的实参是动态的"这一判断，用于排除固定参数的命令调用。
#:
#: 满足其一即可：
#: - 调用括号后直接跟变量或另一层调用（``exec.Command(cmd)``、``system($_GET['c'])``）；
#: - 行内出现拼接、插值或百分号格式化。
#:
#: 反过来说，``subprocess.run(["git", "status"])`` 与
#: ``exec.Command("git", "status")`` 的实参全是字面量，没有注入面，
#: 报出来只会制造噪音——这正是 CLAUDE.md 要求"固定命令参数不得误报"的落点。
_DYNAMIC_ARGUMENT = (
    r"(?:\(\s*[$A-Za-z_][\w$\[\]'\"\->.]*\s*[,)]"
    r"|" + _INTERPOLATION + r"|" + _PERCENT_FORMATTING + r")"
)

#: SQL 语句开头的关键字。要求出现在行内，且大小写不敏感。
_SQL_KEYWORD = r"(?i)\b(?:select\b[^\n]{0,300}?\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b)"


# ---------------------------------------------------------------------------
# 模式表
# ---------------------------------------------------------------------------

CLUE_PATTERNS: tuple[CluePattern, ...] = (
    # ----- SQL -----
    CluePattern(
        cue_key="sql_dynamic_construction",
        category="sql_injection",
        label="疑似 SQL 语句由字符串拼接或格式化构造",
        pattern=_SQL_KEYWORD,
        require=_INTERPOLATION,
        languages=_PYTHON | _JS_FAMILY | _PHP | _JAVA | _GO | _RUBY,
        confidence=0.45,
        cwe_id="CWE-89",
        detail="需人工确认拼接部分是否来自不可信输入；若使用参数化占位符则不构成风险。",
    ),
    CluePattern(
        cue_key="sql_percent_formatting",
        category="sql_injection",
        label="疑似 SQL 语句使用百分号格式化构造",
        pattern=_SQL_KEYWORD,
        require=_PERCENT_FORMATTING,
        languages=_PYTHON,
        confidence=0.45,
        cwe_id="CWE-89",
        detail="若 ``%`` 作用于查询字符串而非参数元组，则拼接内容会进入 SQL 语义。",
    ),
    # ----- 命令执行 -----
    CluePattern(
        cue_key="shell_exec_python",
        category="command_injection",
        label="检测到系统命令调用",
        pattern=r"\b(?:os\.system|os\.popen|os\.spawn\w*)\s*\(",
        require=_DYNAMIC_ARGUMENT,
        languages=_PYTHON,
        confidence=0.45,
        cwe_id="CWE-78",
        detail="命令行由拼接或变量构造时需确认参数是否来自不可信输入；固定字面量参数风险较低。",
    ),
    CluePattern(
        cue_key="shell_subprocess_shell_true",
        category="command_injection",
        label="subprocess 调用启用了 shell 解释",
        pattern=r"\bsubprocess\.\w+\s*\([^)]*\bshell\s*=\s*True",
        languages=_PYTHON,
        confidence=0.4,
        cwe_id="CWE-78",
        detail="shell=True 会把命令交给系统 shell 解释，参数中的元字符可能被当作命令执行。",
    ),
    CluePattern(
        cue_key="shell_exec_php",
        category="command_injection",
        label="检测到 PHP 命令执行函数",
        pattern=r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
        require=_DYNAMIC_ARGUMENT,
        languages=_PHP,
        confidence=0.4,
        cwe_id="CWE-78",
        detail="需人工确认参数是否来自 $_GET/$_POST 等不可信来源。",
    ),
    CluePattern(
        cue_key="shell_exec_js",
        category="command_injection",
        label="检测到 Node.js 子进程调用",
        # 裸调用需要 ``(?<!\.)``：``pattern.exec(s)``、``/x/.exec(s)`` 是正则方法，
        # 与子进程毫无关系。带 ``child_process`` 的成员调用由第一个分支覆盖。
        pattern=r"\bchild_process\b|(?<!\.)\b(?:exec|execSync|spawn|spawnSync)\s*\(",
        require=_DYNAMIC_ARGUMENT,
        languages=_JS_FAMILY,
        confidence=0.35,
        cwe_id="CWE-78",
        detail="exec 系列会把命令交给 shell，优先确认是否可用 spawn 配合参数数组。",
    ),
    CluePattern(
        cue_key="shell_exec_java",
        category="command_injection",
        label="检测到 Java 命令执行调用",
        pattern=r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(|\bnew\s+ProcessBuilder\s*\(",
        require=_DYNAMIC_ARGUMENT,
        languages=_JAVA,
        confidence=0.4,
        cwe_id="CWE-78",
        detail="需人工确认命令参数是否来自请求参数等不可信来源。",
    ),
    CluePattern(
        cue_key="shell_exec_go",
        category="command_injection",
        label="检测到 Go 命令执行调用",
        pattern=r"\bexec\.Command\s*\(",
        require=_DYNAMIC_ARGUMENT,
        languages=_GO,
        confidence=0.35,
        cwe_id="CWE-78",
        detail="exec.Command 不经过 shell，但若命令或参数来自不可信输入仍需确认。",
    ),
    CluePattern(
        cue_key="shell_exec_ruby",
        category="command_injection",
        label="检测到 Ruby 命令执行调用",
        pattern=r"\b(?:system|exec|spawn)\s*\(|`[^`]*#\{|%x\{",
        require=_DYNAMIC_ARGUMENT,
        languages=_RUBY,
        confidence=0.4,
        cwe_id="CWE-78",
        detail="反引号与 %x{} 会启动子进程，插值内容会被当作命令执行。",
    ),
    # ----- 不安全动态执行 -----
    CluePattern(
        cue_key="dynamic_exec_python",
        category="unsafe_dynamic_execution",
        label="检测到动态执行函数调用",
        # ``(?<!\.)`` 排除 ``re.compile(...)``、``model.eval()`` 这类同名方法：
        # 它们与内置的动态执行函数毫无关系，而 ``re.compile`` 在 Python 里极其常见。
        pattern=r"(?<!\.)\b(?:eval|exec|compile)\s*\(",
        languages=_PYTHON,
        confidence=0.4,
        cwe_id="CWE-95",
        detail="若被执行的字符串包含外部输入，等同于任意代码执行。",
    ),
    CluePattern(
        cue_key="dynamic_exec_js",
        category="unsafe_dynamic_execution",
        label="检测到 JavaScript 动态执行",
        pattern=r"(?<!\.)\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*['\"]|\bsetInterval\s*\(\s*['\"]",
        languages=_JS_FAMILY,
        confidence=0.4,
        cwe_id="CWE-95",
        detail="传入字符串形式的代码会被解释执行，需确认其来源。",
    ),
    CluePattern(
        cue_key="dynamic_exec_php",
        category="unsafe_dynamic_execution",
        label="检测到 PHP 动态执行",
        pattern=r"\b(?:eval|assert|create_function)\s*\(|\bpreg_replace\s*\([^)]*/\w*e\w*['\"]",
        languages=_PHP,
        confidence=0.4,
        cwe_id="CWE-95",
        detail="/e 修饰符与 eval 都会把字符串当作代码执行。",
    ),
    # ----- 危险 HTML 输出 -----
    CluePattern(
        cue_key="html_sink_dom",
        category="xss",
        label="检测到危险的 DOM 写入位置",
        # ``=(?!=)`` 排除比较：``el.innerHTML === cached`` 是读取后比较，不是写入。
        pattern=r"\.(?:innerHTML|outerHTML)\s*=(?!=)|\bdocument\.write\s*\(|\binsertAdjacentHTML\s*\(",
        languages=_JS_FAMILY,
        confidence=0.4,
        cwe_id="CWE-79",
        detail="写入内容若包含未转义的用户输入，会导致脚本注入。",
    ),
    CluePattern(
        cue_key="html_sink_react",
        category="xss",
        label="检测到 React 的危险 HTML 注入属性",
        pattern=r"\bdangerouslySetInnerHTML\b",
        languages=_JS_FAMILY,
        confidence=0.45,
        cwe_id="CWE-79",
        detail="该属性会跳过 React 的转义，需确认内容经过净化。",
    ),
    CluePattern(
        cue_key="html_sink_vue",
        category="xss",
        label="检测到 Vue 的 v-html 指令",
        pattern=r"\bv-html\s*=",
        languages=_WEB_MARKUP,
        confidence=0.45,
        cwe_id="CWE-79",
        detail="v-html 会按 HTML 渲染，内容中的脚本可被执行。",
    ),
    CluePattern(
        cue_key="html_sink_template_safe_filter",
        category="xss",
        label="检测到模板中被标记为安全的输出",
        pattern=r"\|\s*safe\b|\{\{\s*[^}]*\|\s*safe",
        languages=_WEB_MARKUP,
        confidence=0.4,
        cwe_id="CWE-79",
        detail="该过滤器会关闭自动转义，需确认输出内容可信。",
    ),
    # ----- 不可信输入来源 -----
    CluePattern(
        cue_key="input_source_python",
        category="untrusted_input_source",
        label="检测到可能的用户输入来源",
        pattern=r"\brequest\.(?:args|form|values|json|data|GET|POST|COOKIE|FILES|headers)\b|\binput\s*\(",
        languages=_PYTHON,
        confidence=0.25,
        severity=Severity.INFO,
        detail="这是数据来源标记，本身不是缺陷；用于与危险调用位置对照判断流向。",
    ),
    CluePattern(
        cue_key="input_source_js",
        category="untrusted_input_source",
        label="检测到可能的请求输入来源",
        pattern=r"\breq(?:uest)?\.(?:query|body|params|cookies|headers)\b",
        languages=_JS_FAMILY,
        confidence=0.25,
        severity=Severity.INFO,
        detail="这是数据来源标记，本身不是缺陷。",
    ),
    CluePattern(
        cue_key="input_source_php",
        category="untrusted_input_source",
        label="检测到 PHP 超全局输入变量",
        pattern=r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b",
        languages=_PHP,
        confidence=0.25,
        severity=Severity.INFO,
        detail="这是数据来源标记，本身不是缺陷。",
    ),
    CluePattern(
        cue_key="input_source_java",
        category="untrusted_input_source",
        label="检测到 Servlet 请求参数读取",
        pattern=r"\bgetParameter(?:Values|Map)?\s*\(",
        languages=_JAVA,
        confidence=0.25,
        severity=Severity.INFO,
        detail="这是数据来源标记，本身不是缺陷。",
    ),
    CluePattern(
        cue_key="input_source_ruby",
        category="untrusted_input_source",
        label="检测到可能的请求参数来源",
        pattern=r"\bparams\s*\[",
        languages=_RUBY,
        confidence=0.25,
        severity=Severity.INFO,
        detail="这是数据来源标记，本身不是缺陷。",
    ),
    # ----- 不安全反序列化 -----
    CluePattern(
        cue_key="unsafe_deserialization_python",
        category="unsafe_deserialization",
        label="检测到不安全的反序列化调用",
        pattern=r"\b(?:pickle|cPickle|dill|marshal)\.loads?\s*\(",
        languages=_PYTHON,
        confidence=0.4,
        cwe_id="CWE-502",
        detail="这些格式可以构造出在反序列化时执行任意代码的数据，仅应对可信来源使用。",
    ),
)


def _snippet_of(line: str) -> str:
    """把一行代码裁剪成适合展示的证据片段。"""
    stripped = line.strip()
    if len(stripped) <= MAX_SNIPPET_CHARS:
        return stripped
    return stripped[: MAX_SNIPPET_CHARS - 1] + "…"


def applicable_patterns(language: str) -> tuple[CluePattern, ...]:
    """返回适用于该语言的模式。"""
    return tuple(pattern for pattern in CLUE_PATTERNS if language in pattern.languages)


def extract_clues(index: LineIndex, language: str) -> list[CandidateClue]:
    """逐行扫描，提取候选线索。

    参数：
        index: 已建立的行索引。
        language: **必须已识别**的语言。调用方在语言未知时不调用本函数，
            因为按错误语言的模式匹配会产生一批看似合理、实则无关的线索。

    返回：
        线索列表，按行号升序。同一行内同一模式只报告一次。
    """
    patterns = applicable_patterns(language)
    if not patterns:
        return []

    clues: list[CandidateClue] = []

    for line_no, line in enumerate(index.lines(), start=1):
        if not line.strip():
            continue

        for pattern in patterns:
            if not pattern.matches(line):
                continue

            clues.append(
                CandidateClue(
                    cue_key=pattern.cue_key,
                    category=pattern.category,
                    label=pattern.label,
                    detail=pattern.detail,
                    line=line_no,
                    snippet=_snippet_of(line),
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    cwe_id=pattern.cwe_id,
                )
            )

    return clues
