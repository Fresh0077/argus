"""本地规则检测器的测试。

分三层，下一层都建立在前一层之上：

1. **规则表的不变量**——规则 ID 是否唯一、说明与建议是否齐全、等级与置信度
   是否自洽。这些没写对，下面两层测什么都白搭。
2. **每条规则的正例 / 反例 / 边界用例**——``RULE_CASES`` 逐条覆盖规则表，
   并有完整性测试确保"新增了规则却忘了写用例"会被发现。
   反例里刻意放了参数化 SQL、已转义输出、固定命令参数这些**安全写法**：
   把它们误报成漏洞，比漏报更伤使用者的信任。
3. **检测器整体行为**——去重、按语言筛选、语言未知时跳过、
   注释行不报、行号与 CRLF 源码对齐。

第二层直接调用单条规则的 ``evaluate``，而不是走 ``detect_rule_findings``：
后者按 ``(漏洞类别, 行号)`` 去重，同一类别里靠前的规则可能把后面的挡掉，
那样测出来的是"规则表顺序"而不是"这一条规则本身"。
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.analyzers.line_index import LineIndex
from app.analyzers.rules import RULES, RULES_BY_ID, detect_rule_findings, rules_for_language
from app.analyzers.taint import compute_taint
from app.core.uploads import EXTENSION_LANGUAGE_MAP
from app.schemas.enums import FindingSource, Severity

# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def hits(rule_id: str, language: str, source: str) -> tuple[int, ...]:
    """只跑指定的一条规则，返回命中的行号。

    与检测器保持一致：跳过空行与整行注释。
    """
    rule = RULES_BY_ID[rule_id]
    index = LineIndex(source)
    taint = compute_taint(index, language)
    return tuple(
        number
        for number, line in enumerate(index.lines(), start=1)
        if line.strip() and rule.evaluate(line, taint, number) is not None
    )


@dataclass(frozen=True)
class RuleCase:
    """一条规则的用例集合。

    命中结果用**行号元组**表示而不是布尔值：跨行传播的用例（先拼接、
    后执行）需要断言"命中的是执行那一行"，只断言"有命中"会让
    "报错行"这类问题溜过去。
    """

    rule_id: str
    language: str
    #: 必须命中的写法 → 期望命中的行号。
    positive: tuple[tuple[str, tuple[int, ...]], ...]
    #: 安全写法，必须一行都不命中。
    negative: tuple[str, ...]
    #: 容易判错的边界写法 → 期望命中的行号（空元组表示不该命中）。
    boundary: tuple[tuple[str, tuple[int, ...]], ...]


#: 单行源码的常规用例：命中就报第 1 行。
def _one(source: str) -> tuple[str, tuple[int, ...]]:
    """单行源码的常规用例：命中就报第 1 行。"""
    return (source, (1,))


def _rank(severity: Severity) -> int:
    """严重等级的高低。值越小越严重。"""
    return list(Severity).index(severity)


RULE_CASES: tuple[RuleCase, ...] = (
    # ===================== SQL 注入 =====================
    RuleCase(
        rule_id="ARGUS-SQL-001",
        language="python",
        positive=(
            _one('cursor.execute("SELECT * FROM users WHERE id = " + uid)'),
            # 语句在前一行拼好、这一行只负责执行：靠来源跟踪命中。
            ('sql = "SELECT * FROM users WHERE id = " + uid\ncursor.execute(sql)\n', (2,)),
        ),
        negative=(
            'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
            'cursor.execute("SELECT * FROM users WHERE id = ?", [uid])',
            'cursor.execute("SELECT 1")',
        ),
        boundary=(
            # 既拼接了语句、又绑定了参数：绑定参数救不了被改写的语句结构。
            ('cursor.execute("SELECT * FROM t ORDER BY " + col, (name,))', (1,)),
            # 只是取结果，不是执行位置。
            ("rows = cursor.fetchall()", ()),
            # 语句是常量、参数是变量：参数化查询，安全。
            ('cursor.execute("SELECT * FROM t WHERE a = %s", (name,))', ()),
        ),
    ),
    # ===================== 命令执行 =====================
    RuleCase(
        rule_id="ARGUS-CMD-001",
        language="python",
        positive=(_one('os.system("ping -c 1 " + host)'), _one("os.system(cmd)")),
        negative=(
            "os.system('ls -la')",
            'os.system("ls " + shlex.quote(name))',
        ),
        boundary=(
            ("os.system('hostname')", ()),
            ('os.popen("cat " + path)', (1,)),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-CMD-002",
        language="python",
        positive=(_one("subprocess.run(cmd, shell=True)"),),
        negative=(
            "subprocess.run(['git', 'status'], check=True)",
            "subprocess.run(cmd)",
        ),
        boundary=(
            # 没有 shell=True，字符串形式的命令不会被 shell 解释。
            ('subprocess.run("ls -la")', ()),
            ('subprocess.call("ls " + shlex.quote(name), shell=True)', ()),
            ("subprocess.Popen(args, shell=True)", (1,)),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-CMD-003",
        language="php",
        positive=(_one("system($cmd);"),),
        negative=("system('ls -la');", "system(escapeshellarg($cmd));"),
        boundary=(
            ("system($_GET['cmd']);", (1,)),
            ('$out = shell_exec("ls");', ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-CMD-004",
        language="javascript",
        positive=(_one('exec("ls " + dir, cb);'),),
        negative=(
            # 正则的 exec 方法，与子进程无关。
            "pattern.exec(text);",
            "exec('ls -la');",
        ),
        boundary=(
            ("child_process.exec(cmd, cb);", (1,)),
            ("regex.exec(line);", ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-CMD-005",
        language="java",
        positive=(_one("Runtime.getRuntime().exec(cmd);"),),
        negative=('Runtime.getRuntime().exec("ls -la");',),
        boundary=(
            ("new ProcessBuilder(userInput);", (1,)),
            # 变量恰好叫 runtime，但没有 getRuntime() 那一步。
            ("runtime.exec(cmd);", ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-CMD-006",
        language="go",
        positive=(_one("cmd := exec.Command(name)"),),
        negative=('cmd := exec.Command("ls", "-la")',),
        boundary=(
            ("exec.Command(args[0], args[1:]...)", (1,)),
            ('out, err := exec.Command("git", "status").Output()', ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-CMD-007",
        language="ruby",
        positive=(_one("system(cmd)"),),
        negative=("system('ls -la')", "system(Shellwords.escape(cmd))"),
        boundary=(
            ('system("#{cmd}")', (1,)),
            ("exec('ls')", ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-CMD-008",
        language="ruby",
        positive=(_one("files = `ls #{dir}`"),),
        negative=("files = `ls -la`",),
        boundary=(
            ("count = %x{wc -l #{path}}", (1,)),
            ("status = `git status`", ()),
        ),
    ),
    # ===================== 跨站脚本 =====================
    RuleCase(
        rule_id="ARGUS-XSS-001",
        language="javascript",
        positive=(_one("el.innerHTML = userInput;"),),
        negative=(
            "el.innerHTML = 'static text';",
            "el.innerHTML = escapeHtml(userInput);",
        ),
        boundary=(
            # 读取后比较，不是写入。
            ("const cached = el.innerHTML === a ? 1 : 2;", ()),
            ("el.innerHTML = `${a}`;", (1,)),
            ("el.outerHTML = '<b>' + name;", (1,)),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-XSS-002",
        language="javascript",
        positive=(_one("document.write(html);"),),
        negative=(
            "document.write('<b>hi</b>');",
            "document.write(escapeHtml(x));",
        ),
        boundary=(
            ("el.insertAdjacentHTML('beforeend', '<li>' + name);", (1,)),
            ("document.writeln('</body>');", ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-XSS-003",
        language="javascript",
        positive=(_one("const el = <div dangerouslySetInnerHTML={{__html: content}} />;"),),
        negative=(
            "const el = <div>{content}</div>;",
            "const el = <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}} />;",
        ),
        boundary=(
            # 绑定的是写死的 HTML，改不了，报出来只是噪音。
            ("const el = <div dangerouslySetInnerHTML={{__html: '<b>hi</b>'}} />;", ()),
            ("const el = <div dangerouslySetInnerHTML={{__html: rawHtml}} />;", (1,)),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-XSS-004",
        language="vue",
        positive=(_one('<div v-html="content"></div>'),),
        negative=("<div>{{ content }}</div>",),
        boundary=(
            ("<div v-html=\"DOMPurify.sanitize(content)\"></div>", ()),
            (('<p v-text="content"></p>'), ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-XSS-005",
        language="html",
        positive=(_one("{{ content | safe }}"),),
        negative=("{{ content }}",),
        boundary=(
            ("{{ user.bio | safe }}", (1,)),
            ("{{ user.bio | striptags }}", ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-XSS-006",
        language="php",
        positive=(_one('<?php echo $_GET["name"]; ?>'),),
        negative=(
            '<?php echo htmlspecialchars($_GET["name"]); ?>',
            '<?php echo "hello"; ?>',
        ),
        boundary=(
            ("<?php printf($_POST['tpl']); ?>", (1,)),
            ("<?php echo htmlentities($row['name']); ?>", ()),
        ),
    ),
    # ===================== 不安全动态执行 =====================
    RuleCase(
        rule_id="ARGUS-EXEC-001",
        language="python",
        positive=(_one("result = eval(payload)"),),
        negative=(
            "size = eval('1 + 2')",
            # 正则的 compile，与动态执行无关。
            "pattern = re.compile(r'x')",
        ),
        boundary=(
            ("model.eval()", ()),
            ('exec(f"x = {n}")', (1,)),
            ("compile(source, 'x', 'exec')", (1,)),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-EXEC-002",
        language="javascript",
        positive=(_one("const f = new Function(body);"),),
        negative=(
            "const f = new Function('return 1');",
            "const v = JSON.parse(text);",
        ),
        boundary=(
            ("eval(code);", (1,)),
            ("obj.eval(x);", ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-EXEC-003",
        language="javascript",
        # 位置常见且多半无害，必须有来源证据才报告。
        positive=(
            ("const cb = req.query.callback;\nsetTimeout(cb, 100);\n", (2,)),
        ),
        negative=(
            "setTimeout(fn, 100);",
            "setTimeout('doThing()', 100);",
        ),
        boundary=(
            ("setTimeout(handler, 100);", ()),
            ("setInterval(tick, 500);", ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-EXEC-004",
        language="php",
        positive=(_one("eval($code);"),),
        negative=("eval('1 + 2');",),
        boundary=(
            ("assert($check);", (1,)),
            ("$x = eval('return 1;');", ()),
        ),
    ),
    # ===================== 不安全反序列化 =====================
    RuleCase(
        rule_id="ARGUS-DESER-001",
        language="python",
        positive=(_one("obj = pickle.loads(payload)"),),
        negative=("obj = pickle.loads(b'{}')",),
        boundary=(
            ("data = json.loads(text);", ()),
            ("obj = pickle.loads(b64decode(raw));", (1,)),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-DESER-002",
        language="java",
        positive=(_one("ObjectInputStream ois = new ObjectInputStream(fis);"),),
        negative=("ByteArrayInputStream bis = new ByteArrayInputStream(data);",),
        boundary=(
            ("Object obj = ois.readObject();", (1,)),
            ("Object obj = mapper.readValue(json, User.class);", ()),
        ),
    ),
    RuleCase(
        rule_id="ARGUS-DESER-003",
        language="php",
        positive=(_one("$obj = unserialize($data);"),),
        negative=("$obj = json_decode($data);",),
        boundary=(
            ("$obj = unserialize('a:1:{}');", ()),
            ("$obj = unserialize(base64_decode($x));", (1,)),
        ),
    ),
)


# ---------------------------------------------------------------------------
# 第一层：规则表的不变量
# ---------------------------------------------------------------------------


def test_rule_ids_are_unique() -> None:
    ids = [rule.rule_id for rule in RULES]
    assert len(ids) == len(set(ids)), "规则 ID 重复会让发现 ID 失去区分度"


def test_rule_ids_follow_naming_convention() -> None:
    for rule in RULES:
        assert rule.rule_id.startswith("ARGUS-"), rule.rule_id
        assert rule.rule_id.replace("-", "").isalnum(), rule.rule_id


def test_every_rule_explains_itself() -> None:
    """规则必须自带说明与修复建议。

    没有建议的发现等于把问题丢回给用户，前端也没有可展示的修复方向。
    """
    for rule in RULES:
        assert rule.title.strip(), rule.rule_id
        assert rule.description.strip(), f"{rule.rule_id} 缺少风险说明"
        assert rule.recommendation.strip(), f"{rule.rule_id} 缺少修复建议"
        assert rule.cwe_id, f"{rule.rule_id} 没有登记 CWE"


def test_every_rule_declares_at_least_one_language() -> None:
    for rule in RULES:
        assert rule.languages, f"{rule.rule_id} 没有声明适用语言"


def test_rule_table_covers_every_supported_language() -> None:
    """上传白名单里能识别出的每一种语言，都要至少有一条规则。

    否则用户传了这种语言的文件，``rules`` 会报 success 却永远没有任何发现——
    看起来像"分析过了，没问题"，实际是"根本没有规则管这件事"。
    """
    for language in sorted(set(EXTENSION_LANGUAGE_MAP.values())):
        assert rules_for_language(language), f"{language} 没有任何规则"


def test_call_shaped_rules_match_an_open_paren() -> None:
    """声明了"取值位置"的规则，正则里必须真的有左括号。

    ``_value_at`` 靠匹配片段里的最后一个 ``(`` 定位实参；正则里没有括号时
    它只能安静地不报告。这条守卫让写错的规则在测试里暴露，而不是在线上漏报。
    """
    for rule in RULES:
        if rule.dynamic_value_at.value == "none":
            continue
        assert ("(" in rule.pattern.pattern), f"{rule.rule_id} 声明了取值位置却没有左括号"


def test_severity_never_exceeds_high() -> None:
    """规则层的等级上限是 high。

    单条正则只是**候选发现**，够不上 critical 所暗示的"已确认且后果严重"。
    把上限卡在这里，是为了不让一次正则命中在界面上被读成定论。
    """
    for rule in RULES:
        assert rule.severity is not Severity.CRITICAL, rule.rule_id
        if rule.severity_with_source is not None:
            assert rule.severity_with_source is not Severity.CRITICAL, rule.rule_id


def test_source_evidence_never_lowers_severity() -> None:
    """确认到来源只能升级，不能降级。"""
    for rule in RULES:
        if rule.severity_with_source is not None:
            assert _rank(rule.severity_with_source) <= _rank(rule.severity), rule.rule_id
        if rule.confidence_with_source is not None:
            assert rule.confidence_with_source >= rule.confidence, rule.rule_id


def test_confidence_is_a_probability() -> None:
    for rule in RULES:
        assert 0.0 <= rule.confidence <= 1.0, rule.rule_id
        if rule.confidence_with_source is not None:
            assert 0.0 <= rule.confidence_with_source <= 1.0, rule.rule_id


# ---------------------------------------------------------------------------
# 第二层：逐条规则的正例 / 反例 / 边界
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", RULE_CASES, ids=[case.rule_id for case in RULE_CASES])
def test_rule_positive_cases_hit(case: RuleCase) -> None:
    for source, expected in case.positive:
        assert hits(case.rule_id, case.language, source) == expected, (
            f"{case.rule_id} 漏报：{source!r}"
        )


@pytest.mark.parametrize("case", RULE_CASES, ids=[case.rule_id for case in RULE_CASES])
def test_rule_negative_cases_do_not_hit(case: RuleCase) -> None:
    """安全写法必须一行都不命中。

    这是本阶段最要紧的一组断言：参数化 SQL、已转义输出、固定命令参数
    一旦被误报，使用者很快就会不再相信任何一条发现。
    """
    for source in case.negative:
        assert hits(case.rule_id, case.language, source) == (), (
            f"{case.rule_id} 误报安全写法：{source!r}"
        )


@pytest.mark.parametrize("case", RULE_CASES, ids=[case.rule_id for case in RULE_CASES])
def test_rule_boundary_cases(case: RuleCase) -> None:
    for source, expected in case.boundary:
        assert hits(case.rule_id, case.language, source) == expected, (
            f"{case.rule_id} 边界判断不符：{source!r} 期望命中 {expected}"
        )


def test_every_rule_has_cases() -> None:
    """新增规则却忘了写用例时，这条测试会失败。"""
    covered = {case.rule_id for case in RULE_CASES}
    missing = sorted({rule.rule_id for rule in RULES} - covered)
    assert not missing, f"以下规则没有正反例：{missing}"


def test_cases_reference_existing_rules() -> None:
    unknown = sorted({case.rule_id for case in RULE_CASES} - set(RULES_BY_ID))
    assert not unknown, f"用例引用了不存在的规则：{unknown}"


def test_every_case_covers_positive_negative_and_boundary() -> None:
    for case in RULE_CASES:
        assert case.positive, f"{case.rule_id} 没有正例"
        assert case.negative, f"{case.rule_id} 没有反例"
        assert case.boundary, f"{case.rule_id} 没有边界用例"


# ---------------------------------------------------------------------------
# 第三层：检测器整体行为
# ---------------------------------------------------------------------------


def test_language_is_required_to_run() -> None:
    """语言未知时不检测，并且要说明原因。"""
    outcome = detect_rule_findings('cursor.execute("SELECT " + x)', None)

    assert outcome.findings == []
    assert outcome.skip_reason, "跳过检测却没有给出原因"


def test_language_without_rules_yields_nothing_but_is_not_a_skip() -> None:
    """语言认识但没有登记规则：那是"跑了、没结果"，不是"没跑"。"""
    outcome = detect_rule_findings("DISPLAY greeting.", "cobol")

    assert outcome.findings == []
    assert outcome.skip_reason is None


def test_same_line_and_category_is_reported_once() -> None:
    """同一行、同一漏洞类别只产出一条发现。

    两次 ``os.system`` 落在同一行，是同一处的同一个问题，
    报两遍会让使用者以为是两个缺陷。
    """
    outcome = detect_rule_findings('os.system(a)\nos.system(b)\n', "python")

    keys = [(finding.line_start, finding.vulnerability_type) for finding in outcome.findings]
    assert len(keys) == len(set(keys))
    assert keys == [(1, "command_injection"), (2, "command_injection")]


def test_findings_point_at_the_line_that_matches() -> None:
    """行号必须落在真正匹配的那一行，CRLF 也不能错位。

    行号错位会把使用者带到一行无辜的代码前，比不报还糟。
    """
    source = "\r\n\r\nos.system(cmd)\r\nx = 1\r\n"
    outcome = detect_rule_findings(source, "python")

    assert [finding.line_start for finding in outcome.findings] == [3]


def test_findings_carry_rule_id_and_rule_source() -> None:
    outcome = detect_rule_findings('os.system(cmd)\n', "python")

    finding = outcome.findings[0]
    assert finding.source is FindingSource.STATIC_RULE
    assert finding.rule_id in RULES_BY_ID
    assert finding.evidence == "os.system(cmd)"


def test_finding_ids_are_stable_across_runs() -> None:
    """同一份输入重复扫描，发现 ID 必须一致。

    否则前端每次刷新都会看到"新发现"，历史与去重都无从谈起。
    """
    source = 'sql = "SELECT * FROM t WHERE id = " + uid\ncursor.execute(sql)\n'

    first = detect_rule_findings(source, "python").findings
    second = detect_rule_findings(source, "python").findings

    assert [f.id for f in first] == [f.id for f in second]


def test_comment_only_lines_are_not_reported() -> None:
    """注释里举例说明"不要这么写"不该被报成漏洞。"""
    source = "# 不要这样写：eval(user_input)\nvalue = 1\n"

    assert detect_rule_findings(source, "python").findings == []


def test_rules_are_limited_to_the_given_language() -> None:
    """Python 的规则不得套到 JavaScript 上。

    ``os.system`` 在 JavaScript 里只是一个普通方法名。
    """
    outcome = detect_rule_findings("os.system(cmd)\n", "javascript")

    assert outcome.findings == []


@pytest.mark.parametrize(
    "source",
    [
        "",
        "\n\n\n",
        " ",
        "\r\n",
        "x" * 5000,
        '"""',
        "'",
        "(",
        ")",
        "((((((((((((((((((((",
        'f("',
        "\\",
        "\x00\x01",
        "select",
        "eval",
        "execute(",
    ],
)
def test_rules_never_raise_on_degenerate_input(source: str) -> None:
    """畸形输入只应导致"没发现"，不应让整次扫描崩掉。

    被分析的代码是**不可信数据**，它是不完整的、被截断的、含控制字符的
    都很正常；分析器对任何输入都必须给出结论，而不是抛异常。
    """
    outcome = detect_rule_findings(source, "python")

    assert isinstance(outcome.findings, list)
