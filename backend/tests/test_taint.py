"""轻量来源跟踪的测试。

这一层的定位决定了测试的重点：它**不是**数据流分析，因此测试不去铺开
"跨函数、容器、别名"这些它明确不支持的场景，而是钉死两件事——

1. **它认得的要认得对**：来源表达式、赋值传播、拼接构造、按语言的模式表；
2. **它高估的后果有边界**：错判只会让等级偏高，不会凭空造出发现。

第 2 点靠一个不变式守住：任何一行的来源查询都只能**引用已有标记**，
不能自己产生新标记——发现的**有无**始终由规则模式决定，与这里无关。
"""

from __future__ import annotations

import pytest

from app.analyzers.line_index import LineIndex
from app.analyzers.taint import (
    MAX_TAINTED_NAMES,
    TaintKind,
    TaintMap,
    assigned_name,
    compute_taint,
    source_pattern_for,
)

_ALL = frozenset({TaintKind.UNTRUSTED, TaintKind.CONSTRUCTED})
_UNTRUSTED = frozenset({TaintKind.UNTRUSTED})
_CONSTRUCTED = frozenset({TaintKind.CONSTRUCTED})


def marks(language: str, source: str) -> dict[str, tuple[str, int, int, str]]:
    """把标记表压成便于断言的字典：变量名 → (种类, 行, 来源行, 来源变量)。"""
    taint = compute_taint(LineIndex(source), language)
    return {
        name: (entry.kind.value, entry.line, entry.source_line, entry.source_name)
        for name, entry in taint.entries().items()
    }


# ---------------------------------------------------------------------------
# 来源识别
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("language", "source", "name"),
    [
        ("python", 'uid = request.args.get("id")', "uid"),
        ("python", "name = input()", "name"),
        ("python", "argv = sys.argv", "argv"),
        ('python', 'token = os.environ["TOKEN"]', "token"),
        ("javascript", "const q = req.query.q;", "q"),
        ("javascript", "let t = request.body.token;", "t"),
        ("javascript", "let h = location.hash;", "h"),
        ("typescript", "let a = req.query.a;", "a"),
        ("vue", "let b = req.body.b;", "b"),
        ('php', '$uid = $_GET["id"];', "$uid"),
        ('php', '$body = file_get_contents("php://input");', "$body"),
        ('java', 'String id = request.getParameter("id");', "id"),
        ("go", 'id := r.URL.Query().Get("id")', "id"),
        ('go', 'cmd := r.FormValue("cmd")', "cmd"),
        ("ruby", 'id = params["id"]', "id"),
        ("ruby", "t = cookies[:token]", "t"),
    ],
)
def test_source_expressions_are_recognised(language: str, source: str, name: str) -> None:
    """每种语言各自登记了来源表达式，别把一套模式套到所有语言上。"""
    assert marks(language, source) == {name: ("untrusted", 1, 1, name)}


def test_go_short_declaration_is_recognised() -> None:
    """Go 的 ``:=`` 必须能被认成赋值。

    漏掉它会有一个很隐蔽的后果：Go 的来源模式全都登记着，却一条也匹配不上，
    因为没有任何一行被当成赋值语句——表面看不出问题，只是 Go 永远不升级等级。
    """
    assert marks("go", 'id := r.URL.Query().Get("id")') == {"id": ("untrusted", 1, 1, "id")}


@pytest.mark.parametrize("language", ["html", "cobol", "unknown"])
def test_languages_without_source_patterns_track_nothing(language: str) -> None:
    assert source_pattern_for(language) is None
    assert marks(language, 'x = request.args.get("a")') == {}


# ---------------------------------------------------------------------------
# 传播与构造
# ---------------------------------------------------------------------------


def test_alias_keeps_the_original_source_line() -> None:
    """``b = a`` 之后，``b`` 要指回最初那一行，而不是指向 ``b`` 自己。"""
    assert marks("python", 'a = request.args.get("x")\nb = a\n') == {
        "a": ("untrusted", 1, 1, "a"),
        "b": ("untrusted", 2, 1, "a"),
    }


def test_concatenation_is_marked_as_constructed() -> None:
    """语句被拼出来这件事本身就可疑，即使拼进去的是常量。"""
    assert marks("python", 'table = "users"\nq = "SELECT * FROM " + table\n') == {
        "q": ("constructed", 2, 2, "q")
    }


@pytest.mark.parametrize(
    ("language", "source"),
    [
        ("python", 'q = f"SELECT * FROM {table}"'),
        ("python", 'q = "SELECT * FROM %s" % table'),
        ("python", 'q = "SELECT * FROM {}".format(table)'),
        ("javascript", "const q = `SELECT * FROM ${table}`;"),
        ("ruby", 'q = "SELECT * FROM #{table}"'),
        ('php', '$q = "SELECT * FROM " . $table;'),
    ],
)
def test_each_construction_style_is_recognised(language: str, source: str) -> None:
    """各语言的拼接写法都要能被认出来，否则等级只能停在基础档。"""
    assert marks(language, source), f"{language} 的拼接写法没被识别：{source}"


def test_untrusted_is_never_downgraded_to_constructed() -> None:
    """已经确认来自外部输入的变量，之后被拼接也不能降级。

    降级会让一条本该是 high 的发现掉回 medium——
    "来源已知"这个最重要的信息反而在再赋值时丢了。
    """
    assert marks("python", 'a = request.form["u"]\na = "SELECT " + a\n') == {
        "a": ("untrusted", 1, 1, "a")
    }


def test_plain_arithmetic_is_over_approximated() -> None:
    """``i + j`` 会被当成拼接——这是**已知的高估**，测试把它钉在明处。

    不引入类型信息就分不清加法与拼接，而做类型推断超出了本层定位。
    后果有边界：只会让可疑位置的等级偏高，不会凭空造出发现
    （发现的有无由规则模式决定，见 ``test_marks_never_create_findings``）。
    """
    assert marks("python", "i = 0\nj = 1\ntotal = i + j\n") == {
        "total": ("constructed", 3, 3, "total")
    }


def test_numeric_literal_arithmetic_is_not_mistaken_for_concatenation() -> None:
    assert marks("python", "i = 0\ncount = i + 1\n") == {}


def test_comparison_is_not_an_assignment() -> None:
    """``==`` 不是赋值。认错会凭空造出一堆"来源变量"。"""
    assert marks("python", 'if a == request.args.get("x"):\n    pass\n') == {}


def test_comment_lines_produce_no_marks() -> None:
    """注释里的示例代码不该被当成真的读了外部输入。"""
    assert marks("python", '# uid = request.args.get("id")\n') == {}


def test_mark_count_is_capped() -> None:
    """超长或高度生成的代码不该让分析成本失控。"""
    source = "\n".join(f'v{i} = request.args.get("a")' for i in range(MAX_TAINTED_NAMES + 20))

    assert len(marks("python", source)) == MAX_TAINTED_NAMES


# ---------------------------------------------------------------------------
# 行内查询
# ---------------------------------------------------------------------------


def test_reference_in_finds_the_marked_variable() -> None:
    taint = compute_taint(LineIndex('uid = request.args.get("id")\n'), "python")

    entry = taint.reference_in("cursor.execute(sql + uid)", at_line=2)
    assert entry is not None
    assert entry.name == "uid"
    assert entry.source_line == 1


def test_reference_in_ignores_member_access() -> None:
    """``self.uid`` 里的 ``uid`` 不是我们跟踪的那个变量。"""
    taint = compute_taint(LineIndex('uid = request.args.get("id")\n'), "python")

    assert taint.reference_in("self.uid = 1", at_line=2) is None


def test_reference_in_respects_declaration_order() -> None:
    """第 1 行不能"看见"第 3 行才出现的变量。"""
    source = 'x = 1\n\ny = request.args.get("id")\n'
    taint = compute_taint(LineIndex(source), "python")

    assert taint.reference_in("f(y)", at_line=1) is None
    assert taint.reference_in("f(y)", at_line=3) is not None


def test_reference_in_can_exclude_the_assignment_target() -> None:
    """排除本行的赋值目标：它是被写入的一方，不是被读取的来源。"""
    taint = compute_taint(LineIndex('uid = request.args.get("id")\n'), "python")

    assert taint.reference_in("uid = f(uid)", at_line=2, exclude="uid") is None
    assert taint.reference_in("uid = f(uid)", at_line=2) is not None


def test_reference_in_filters_by_kind() -> None:
    source = 'a = request.args.get("x")\nq = "SELECT " + b\n'
    taint = compute_taint(LineIndex(source), "python")

    assert taint.reference_in('q = "SELECT " + b', _UNTRUSTED, at_line=2) is None
    assert taint.reference_in('q = "SELECT " + b', _CONSTRUCTED, at_line=2) is not None


def test_reference_in_returns_the_first_match_for_stable_wording() -> None:
    """同一行总是返回同一个变量，说明文案才不会在两次扫描之间变来变去。"""
    source = 'first = request.args.get("a")\nsecond = request.args.get("b")\n'
    taint = compute_taint(LineIndex(source), "python")

    assert taint.reference_in("f(first, second)", _ALL, at_line=3).name == "first"
    assert taint.reference_in("f(second, first)", _ALL, at_line=3).name == "second"


def test_empty_map_answers_nothing() -> None:
    assert TaintMap().reference_in("eval(x)", _ALL, at_line=1) is None


# ---------------------------------------------------------------------------
# 内联来源
# ---------------------------------------------------------------------------


def test_inline_source_finds_an_expression_written_in_place() -> None:
    """``system($_GET["cmd"])`` 没有中间变量，变量表里查不到它。"""
    taint = compute_taint(LineIndex(""), "php")

    entry = taint.inline_source('system($_GET["cmd"])', 4)
    assert entry is not None
    assert entry.inline is True
    assert entry.kind is TaintKind.UNTRUSTED
    assert entry.line == 4
    assert entry.source_line == 4, "来源表达式就在这一行，行号如实记录"


def test_inline_source_returns_nothing_for_ordinary_text() -> None:
    taint = compute_taint(LineIndex(""), "python")

    assert taint.inline_source("", 1) is None
    assert taint.inline_source("total + 1", 1) is None


def test_inline_source_is_disabled_without_a_source_pattern() -> None:
    """语言没有登记来源模式时，不能拿别的语言的关键字去匹配。"""
    taint = compute_taint(LineIndex(""), "html")

    assert taint.inline_source('echo $_GET["name"]', 1) is None


def test_variable_marks_are_not_inline() -> None:
    source = 'uid = request.args.get("id")\n'
    taint = compute_taint(LineIndex(source), "python")

    entry = taint.reference_in('f("SELECT " + uid)', at_line=2)
    assert entry is not None
    assert entry.inline is False


# ---------------------------------------------------------------------------
# 赋值目标
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("uid = f()", "uid"),
        ("$uid = f();", "$uid"),
        ("const q = f();", "q"),
        ("let q = f();", "q"),
        ("final String id = f();", "id"),
        ("id := f()", "id"),
        ("@name = f()", "@name"),
        ("obj.field = f()", None),
        ("if a == b:", None),
        ("a == b", None),
        ("for i in r:", None),
        ("return x", None),
        ("", None),
    ],
)
def test_assigned_name(line: str, expected: str | None) -> None:
    assert assigned_name(line) == expected


# ---------------------------------------------------------------------------
# 安全性质
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "",
        "\n",
        "a =",
        "= a",
        'a = "',
        "a = )(",
        "((((",
        "a = request.args.get(",
        "x" * 3000,
    ],
)
def test_taint_never_raises_on_degenerate_input(source: str) -> None:
    assert isinstance(compute_taint(LineIndex(source), "python"), TaintMap)


def test_marks_never_create_findings() -> None:
    """本层的安全性质：标记只影响等级，不影响"报不报"。

    这里用一条**只靠位置触发**的规则做验证——``args`` 被标记之后，
    原来不报的位置仍然不报（因为规则模式没命中），
    原来就报的位置等级变高。误判的方向因此是单一的。
    """
    from app.analyzers.rules import detect_rule_findings

    clean = "value = compute(args)\n"
    marked = 'args = request.args.get("a")\nvalue = compute(args)\n'

    assert detect_rule_findings(clean, "python").findings == []
    assert detect_rule_findings(marked, "python").findings == []
