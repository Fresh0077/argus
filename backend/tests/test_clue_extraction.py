"""候选线索提取测试。

这一层最容易出的问题是**误报**：把安全的参数化查询、固定参数的命令调用
也标成"疑似漏洞"。用户被假警报淹几次之后就再也不会看报告了，
因此这里专门用一组"安全写法"用例把误报钉死。

同时锁定几条措辞与等级上的红线：
- 严重等级最高只到 ``low``，输入来源标记为 ``info``；
- ``confidence`` 不超过 0.45——它只是"值得看一眼"的强度，不是漏洞概率。
"""

from __future__ import annotations

import pytest

from app.analyzers.clues import CLUE_PATTERNS, extract_clues
from app.analyzers.line_index import LineIndex
from app.schemas.enums import Severity
from app.schemas.finding import MAX_EVIDENCE_CHARS

#: 阶段 6 允许出现的最高严重等级。判定"这是漏洞"是阶段 7 规则检测器的职责。
MAX_HEURISTIC_SEVERITY = Severity.LOW

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _clues(source: str, language: str):
    return extract_clues(LineIndex(source), language)


def _cue_keys(source: str, language: str) -> set[str]:
    return {clue.cue_key for clue in _clues(source, language)}


# ---------------------------------------------------------------------------
# 模式表自身的约束
# ---------------------------------------------------------------------------


def test_every_pattern_compiles_and_declares_a_language() -> None:
    assert CLUE_PATTERNS
    for pattern in CLUE_PATTERNS:
        assert pattern.languages, f"{pattern.cue_key} 没有声明适用语言"
        assert pattern.matches("") in (True, False)  # 已编译为 re.Pattern


def test_cue_keys_are_unique() -> None:
    """``cue_key`` 会参与发现 ID 的计算，重复会让两条不同的线索撞成同一条。"""
    keys = [pattern.cue_key for pattern in CLUE_PATTERNS]

    assert len(keys) == len(set(keys))


def test_no_pattern_exceeds_the_heuristic_severity_ceiling() -> None:
    """阶段 6 只负责标出"值得看的位置"，不允许声称高置信度的严重问题。"""
    for pattern in CLUE_PATTERNS:
        assert _SEVERITY_ORDER.index(pattern.severity) >= _SEVERITY_ORDER.index(MAX_HEURISTIC_SEVERITY), (
            f"{pattern.cue_key} 的严重等级 {pattern.severity.value} 超过了启发式线索的上限"
        )


def test_no_pattern_claims_high_confidence() -> None:
    for pattern in CLUE_PATTERNS:
        assert 0.0 < pattern.confidence <= 0.45, f"{pattern.cue_key} 的置信度 {pattern.confidence} 过高"


def test_patterns_are_registered_per_language_not_globally() -> None:
    """PHP 的命令执行函数不应该被拿去匹配 JavaScript。"""
    assert _cue_keys('system($cmd);', "javascript") == set()
    assert "shell_exec_php" in _cue_keys('system($cmd);', "php")


# ---------------------------------------------------------------------------
# 命中：应当报出来的
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("language", "source", "expected_cue"),
    [
        ("python", 'q = "SELECT * FROM users WHERE id = " + uid', "sql_dynamic_construction"),
        ("python", 'q = "SELECT * FROM t WHERE id = %s" % uid', "sql_percent_formatting"),
        ("python", 'q = "SELECT * FROM t WHERE id = {}".format(uid)', "sql_dynamic_construction"),
        ("python", 'q = f"SELECT * FROM t WHERE id = {uid}"', "sql_dynamic_construction"),
        ("javascript", 'const q = "SELECT * FROM t WHERE id = " + uid', "sql_dynamic_construction"),
        ("php", '$q = "SELECT * FROM t WHERE id = " . $id;', "sql_dynamic_construction"),
        ("python", 'os.system("ping " + host)', "shell_exec_python"),
        ("python", 'subprocess.run(cmd, shell=True)', "shell_subprocess_shell_true"),
        ("php", 'system($_GET["cmd"]);', "shell_exec_php"),
        ("javascript", 'child_process.exec("ls " + dir)', "shell_exec_js"),
        ("java", 'Runtime.getRuntime().exec(cmd);', "shell_exec_java"),
        ("go", 'exec.Command(cmd)', "shell_exec_go"),
        ("ruby", 'system("ls #{dir}")', "shell_exec_ruby"),
        ("python", 'eval(user_input)', "dynamic_exec_python"),
        ("javascript", 'eval(payload)', "dynamic_exec_js"),
        ("php", 'eval($code);', "dynamic_exec_php"),
        ("javascript", 'el.innerHTML = userInput', "html_sink_dom"),
        ("javascript", '<div dangerouslySetInnerHTML={{__html: raw}} />', "html_sink_react"),
        ("vue", '<div v-html="rawHtml"></div>', "html_sink_vue"),
        ("python", 'pickle.loads(data)', "unsafe_deserialization_python"),
        ("python", 'uid = request.args.get("id")', "input_source_python"),
        ("php", '$id = $_GET["id"];', "input_source_php"),
        ("java", 'String id = request.getParameter("id");', "input_source_java"),
        ("ruby", 'id = params[:id]', "input_source_ruby"),
    ],
)
def test_expected_clue_is_reported(language: str, source: str, expected_cue: str) -> None:
    assert expected_cue in _cue_keys(source, language)


def test_line_numbers_point_at_the_matching_line() -> None:
    source = "import os\n\n\ndef ping(host):\n    os.system('ping ' + host)\n"

    clues = _clues(source, "python")

    assert [clue.line for clue in clues] == [5]
    assert "os.system" in clues[0].snippet


def test_snippet_is_the_matched_line_stripped() -> None:
    clues = _clues("        os.system('ls ' + d)\n", "python")

    assert clues[0].snippet == "os.system('ls ' + d)"


def test_multiple_distinct_clues_on_one_line_are_both_reported() -> None:
    """同一行既读输入又拼接 SQL，两条线索都应给出：它们要说明的事情不同。"""
    source = 'q = "SELECT * FROM t WHERE id = " + request.args.get("id")'

    keys = _cue_keys(source, "python")

    assert "sql_dynamic_construction" in keys
    assert "input_source_python" in keys


def test_clues_are_returned_in_line_order() -> None:
    source = 'a = request.args.get("x")\nb = 1\nc = eval(a)\n'

    lines = [clue.line for clue in _clues(source, "python")]

    assert lines == sorted(lines)


def test_blank_lines_are_skipped() -> None:
    assert _clues("\n\n   \n\t\n", "python") == []


# ---------------------------------------------------------------------------
# 不命中：安全写法不得误报
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("language", "source"),
    [
        # 参数化查询：占位符在字符串内部，不是拼接。
        ("python", 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'),
        ("python", 'cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])'),
        ("python", 'cursor.execute("SELECT * FROM t WHERE a = :a AND b = :b", {"a": a, "b": b})'),
        ("javascript", 'db.query("SELECT * FROM users WHERE id = ?", [userId])'),
        ("javascript", 'db.query("SELECT * FROM t WHERE id = $1", [id])'),
        ("java", 'stmt.setString(1, userId);'),
        ("php", '$stmt->execute(["id" => $id]);'),
        # 完全没有 SQL 关键字的普通字符串拼接。
        ("python", 'greeting = "hello " + name'),
        ("javascript", 'const url = base + "/api/v1/items"'),
        # 固定字面量参数的命令调用：没有拼接、没有变量，就没有注入面。
        ("python", "subprocess.run(['git', 'status'], check=True)"),
        ("python", "os.system('ls -la')"),
        ("go", 'exec.Command("git", "status")'),
        ("java", 'Runtime.getRuntime().exec("hostname");'),
        ("php", 'system("ls -la");'),
        ("ruby", 'system("ls -la")'),
        # DOM 只读访问不是写入位置。
        ("javascript", 'const html = el.innerHTML'),
        ("javascript", 'const text = el.textContent'),
        # 动态执行的替代写法。
        ("javascript", 'JSON.parse(payload)'),
        ("python", "json.loads(payload)"),
        # eval 之外的正常调用。
        ("python", "evaluate_metrics(data)"),
        # 与动态执行同名的普通方法：``re.compile`` 在 Python 里极其常见，
        # ``RegExp.prototype.exec`` 同理。它们不是动态执行。
        ("python", 'PATTERN = re.compile(r"^[0-9]+$")'),
        ("python", "model.eval()"),
        ("javascript", "const m = pattern.exec(text)"),
        ("javascript", "const ok = /x/.exec(s)"),
        # 读取后再比较，不是写入。
        ("javascript", "if (el.innerHTML === cached) { return }"),
        ("javascript", "const same = a.innerHTML == b.innerHTML"),
    ],
)
def test_safe_code_produces_no_clue(language: str, source: str) -> None:
    assert _clues(source, language) == [], f"安全写法被误报：{source}"


@pytest.mark.parametrize(
    "source",
    [
        "x = 1",
        "def f():\n    return 2",
        "class Foo:\n    pass",
        "# 这里只是注释，提到 SELECT * FROM users 和 eval",
        "message = 'the eval function is dangerous'",
    ],
)
def test_unrelated_code_produces_no_clue(source: str) -> None:
    assert _clues(source, "python") == []


def test_subprocess_without_shell_true_is_not_reported() -> None:
    """``subprocess.run(cmd)`` 是推荐写法，不应与 ``shell=True`` 同等对待。"""
    assert "shell_subprocess_shell_true" not in _cue_keys("subprocess.run(cmd)", "python")


def test_innerhtml_read_is_not_confused_with_write() -> None:
    assert "html_sink_dom" not in _cue_keys("const a = el.innerHTML;", "javascript")
    assert "html_sink_dom" in _cue_keys("el.innerHTML = a;", "javascript")


# ---------------------------------------------------------------------------
# 边界
# ---------------------------------------------------------------------------


def test_empty_source_produces_no_clue() -> None:
    assert _clues("", "python") == []


def test_markup_patterns_apply_to_both_html_and_vue() -> None:
    """模板语法的线索不是 Vue 独有的：``.html`` 里同样可能是 Jinja/Django 模板。

    模板中的 ``| safe`` 会关闭自动转义，两种文件里都要标出来。
    """
    for language in ("html", "vue"):
        assert "html_sink_template_safe_filter" in _cue_keys("{{ user_bio | safe }}", language)


def test_unknown_language_produces_no_clue() -> None:
    """调用方本就不该在语言未知时调用，但真调用了也必须安全返回
    （模式表里没有任何条目声明支持这个语言）。"""
    assert _clues("eval(x)", "brainfuck") == []


def test_every_supported_language_has_at_least_one_pattern() -> None:
    """受支持的扩展名都应有对应的线索模式。

    否则用户拿到 ``clue_extraction: success`` 却永远得到 0 条线索，
    会把"这个语言的模式还没写"误读成"这段代码很干净"。
    """
    from app.core.uploads import EXTENSION_LANGUAGE_MAP

    covered = {language for pattern in CLUE_PATTERNS for language in pattern.languages}
    supported = set(EXTENSION_LANGUAGE_MAP.values())

    assert supported <= covered, f"缺少线索模式的语言：{sorted(supported - covered)}"


def test_snippet_is_truncated_for_very_long_lines() -> None:
    """证据只保留最小必要片段，不能被超长行把响应撑大。"""
    source = 'x = "' + "A" * 5_000 + '" + eval(y)\n'

    clues = _clues(source, "python")

    assert clues
    assert len(clues[0].snippet) <= 300
    assert len(clues[0].snippet) < MAX_EVIDENCE_CHARS


def test_clue_works_with_crlf_and_no_final_newline() -> None:
    source = 'a = 1\r\nb = eval(user)\r\nc = 3'

    clues = _clues(source, "python")

    assert [clue.line for clue in clues] == [2]


def test_clue_works_on_a_single_line_without_newline() -> None:
    clues = _clues("eval(user)", "python")

    assert [clue.line for clue in clues] == [1]


def test_duplicate_lines_each_report_their_own_line() -> None:
    """同样的两行代码出现在不同位置，应分别报告——用户要去两处改。"""
    clues = _clues("eval(a)\neval(a)\n", "python")

    assert [clue.line for clue in clues] == [1, 2]


def test_long_sql_keyword_span_is_bounded() -> None:
    """SQL 关键字之间允许跨一段距离，但不能无限跨——否则整行匹配的成本失控。"""
    source = "SELECT " + "x, " * 500 + "FROM t WHERE id = " + "y"

    clues = _clues(source, "python")

    # 关键字间隔远超限制时宁可不报，也不做无界匹配。
    assert all(clue.cue_key != "sql_dynamic_construction" for clue in clues)
