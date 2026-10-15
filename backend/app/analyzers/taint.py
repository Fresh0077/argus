"""轻量来源跟踪（单文件、变量级、一阶传播）。

**这不是数据流分析，也不打算变成数据流分析。**
它只做一件很小的事：在一次扫描的源码里记下"哪些变量的值来自不可信输入"，
以及这件事发生在第几行。规则检测器据此把

    危险位置 + 来源可追溯        →  更高的等级
    危险位置 + 来源不明          →  基础等级

区分开，而不是把两者混为一谈。

明确的能力边界（不要在此基础上继续加码）：

- **不跨函数**：函数参数、返回值、跨文件引用都不追踪。参数在函数体内
  就是普通变量，除非它在本文件里被赋值过。
- **不处理别名与容器**：``a = b`` 会传播，但 ``d["k"] = b``、``obj.f = b``
  之后通过 ``d["k"]``、``obj.f`` 读取不被识别。
- **不识别净化**：``uid = int(uid)`` 之后仍然算不可信。是否已经安全
  交给规则自己的 ``exclude`` 判断——"转义是否针对当前语境"只有规则知道。
- **不区分作用域**：同名变量在不同函数里会互相干扰，可能把无关位置
  判成"来源可追溯"。

最后一条是关键：错判的**唯一**后果是等级与置信度偏高，
**不会凭空产生发现**——发现的有无始终由规则模式决定。
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from app.analyzers.common import COMMENT_PREFIXES, STRING_CONSTRUCTION
from app.analyzers.line_index import LineIndex

#: 最多跟踪多少个变量名。超长或高度生成的代码不应让分析成本失控；
#: 超过上限后不再记录新变量（已记录的不受影响）。
MAX_TAINTED_NAMES = 200


class TaintKind(str, Enum):
    """变量被标记的种类。"""

    #: 直接来自请求参数、标准输入等外部来源。
    UNTRUSTED = "untrusted"
    #: 由拼接或格式化构造出来的字符串。它是不是"脏"取决于拼进去的东西，
    #: 但在 SQL 这类场景里，"语句被拼出来的"本身就已经可疑。
    CONSTRUCTED = "constructed"


#: 不可信输入的来源表达式，按语言登记。
#:
#: 与 ``clues.py`` 里的 ``input_source_*`` 线索保持同一套判断口径：
#: 同一段代码在"来源标记"和"来源跟踪"两处得到矛盾的结论会让人无法判断该信哪个。
_SOURCE_PATTERNS: dict[str, str] = {
    "python": (
        r"(?:\brequest\.(?:args|form|values|json|data|GET|POST|COOKIE|FILES|headers)\b"
        r"|\binput\s*\(|\bsys\.argv\b|\bos\.environ\b)"
    ),
    "javascript": (
        r"(?:\breq(?:uest)?\.(?:query|body|params|cookies|headers|param)\b"
        r"|\bprocess\.argv\b|\blocation\.(?:search|hash|href)\b"
        r"|\bdocument\.(?:URL|referrer)\b|\bwindow\.name\b)"
    ),
    "php": r"(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b|\bphp://input\b)",
    "java": (
        r"(?:\bgetParameter(?:Values|Map)?\s*\(|\bgetHeader(?:s)?\s*\("
        r"|\bgetQueryString\s*\(|\bgetCookies\s*\()"
    ),
    "go": (
        r"(?:\br\.URL\.Query\s*\(|\br\.FormValue\s*\(|\br\.PostFormValue\s*\("
        r"|\bc\.Query\s*\(|\br\.URL\.Path\b)"
    ),
    "ruby": r"(?:\bparams\s*\[|\bcookies\s*\[|\brequest\.(?:params|query_string|body)\b)",
}

#: TypeScript 与 Vue 单文件组件里的脚本按 JavaScript 处理。
_ALIASES: dict[str, str] = {
    "typescript": "javascript",
    "vue": "javascript",
}

#: 赋值语句。``(?!=)`` 要求等号后面不是等号，
#: 否则 ``a == b``、``a >= b`` 会被当成赋值，凭空造出一堆"来源变量"。
#:
#: 前面允许一串声明关键字，是为了兼容 ``final String id = ...``、
#: ``const let`` 这类写法；这一组是固定枚举，不会退化成回溯灾难。
#:
#: 冒号是为了 Go 的 ``:=`` 短声明——漏掉它会让 Go 的来源跟踪**整个失效**：
#: 来源模式登记得再全，赋值语句一条都认不出来也白搭。
_ASSIGNMENT = re.compile(
    r"^\s*"
    r"(?:(?:const|let|var|final|static|val|my|local|String|int|long|boolean|def)\s+)*"
    r"([$@]?[A-Za-z_]\w*)"
    r"\s*:?\+?=(?!=)\s*"
    r"(.*)$"
)

#: 变量名中的标识符。``(?<![\w$.])`` 排除成员访问：
#: ``self.uid`` 与 ``obj.uid`` 里的 ``uid`` 不是我们跟踪的那个变量。
_IDENTIFIER = re.compile(r"(?<![\w$.])(?:[$@]?[A-Za-z_]\w*)")

#: 赋值的左侧不可能是这些词，命中说明这行不是普通赋值。
_RESERVED_NAMES = frozenset(
    {"if", "elif", "while", "for", "return", "assert", "print", "raise", "with", "case"}
)

#: 整行只是注释时直接跳过，注释里的示例代码不该产生来源变量。
#: 与规则检测层共用同一份定义（见 ``common.COMMENT_PREFIXES``）。
_COMMENT_PREFIXES = COMMENT_PREFIXES

@dataclass(frozen=True)
class TaintEntry:
    """一处来源标记。

    多数情况下它描述一个**变量**；当来源表达式直接写在危险位置上时
    （``system($_GET["cmd"])``），它描述的是那一段文本本身，此时 ``inline`` 为真。
    """

    name: str
    kind: TaintKind
    #: 该变量第一次被标记的行号（1 起）。用于判断"这一行能不能看见它"。
    line: int
    #: 追溯到的最早来源行号。直接来自请求参数时与 ``line`` 相同，
    #: 经由拼接传播时指向最初的来源，供说明文案引用。
    source_line: int
    #: 最初携带来源的变量名。直接来源时就是 ``name`` 自己。
    source_name: str
    #: 来源是不是**直接出现在被检查的那段文本里**，而不是经由变量中转。
    #: 为真时 ``line`` 指的是"这段文本所在的行"，而不是"变量被赋值的行"。
    inline: bool = False


def assigned_name(line: str) -> str | None:
    """这一行赋值给了哪个变量；不是普通赋值语句时返回 ``None``。

    用来把赋值语句**左侧**的名字排除在"本行引用到的来源"之外。
    左侧是被写入的一方，不是被读取的一方：``obj = pickle.loads(payload)``
    这一行里 ``obj`` 刚刚因为右边而被标记，若把它当成来源，说明文案会写成
    "本行使用的 obj ……"——指向正好反了，而真正该被指出的是 ``payload``。
    """
    matched = _ASSIGNMENT.match(line)
    if matched is None:
        return None
    name = matched.group(1)
    return None if name in _RESERVED_NAMES else name


class TaintMap:
    """一次扫描得到的来源标记表。

    表是不可变的，可以在多个规则之间共享。
    """

    __slots__ = ("_entries", "_source_pattern")

    def __init__(
        self,
        entries: dict[str, TaintEntry] | None = None,
        source_pattern: re.Pattern[str] | None = None,
    ) -> None:
        self._entries: dict[str, TaintEntry] = entries or {}
        #: 该语言的不可信来源表达式，供 ``inline_source`` 使用。
        #: 语言没有登记来源模式时为 ``None``，此时内联来源也一律不识别。
        self._source_pattern = source_pattern

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)

    def get(self, name: str) -> TaintEntry | None:
        return self._entries.get(name)

    def entries(self) -> Mapping[str, TaintEntry]:
        """全部标记的**只读视图**。

        返回 ``MappingProxyType`` 而不是内部字典：调用方拿到的是快照式视图，
        改不动它，也就不会有人试图"顺手调整一下标记"——
        标记一旦可以被外部修改，"错判只会让等级偏高"这条安全性质就不再成立。
        """
        return MappingProxyType(self._entries)
    def reference_in(
        self,
        line: str,
        kinds: frozenset[TaintKind] | None = None,
        *,
        at_line: int | None = None,
        exclude: str | None = None,
    ) -> TaintEntry | None:
        """这一行是否引用了被标记的变量？

        参数：
            line: 待检查的代码行。
            kinds: 只认这些标记种类；``None`` 表示不限。
            at_line: 只考虑在该行**之前或该行**被标记的变量。
                不传则忽略先后顺序。赋值与使用在同一行时（``a = f(x); g(a)``）
                也算可见，因此比较用的是"小于等于"。
            exclude: 不计入的变量名。调用方传入本行的赋值目标——
                它是在这一行被写入的一方，不是被读取的来源。

        返回：
            第一个命中的标记；没有命中返回 ``None``。

        取"第一个"而不是"最脏的那个"，是为了让说明文案稳定：
        同一行在多次扫描中总是引用同一个变量。
        """
        for token in _IDENTIFIER.findall(line):
            if token == exclude:
                continue
            entry = self._entries.get(token)
            if entry is None:
                continue
            if kinds is not None and entry.kind not in kinds:
                continue
            if at_line is not None and entry.line > at_line:
                continue
            return entry
        return None

    def inline_source(self, text: str, line_no: int) -> TaintEntry | None:
        """这段文本里是否**直接写着一个**不可信来源表达式？

        与 ``reference_in`` 的分工：那个查"引用了哪个变量"，这个查
        "来源表达式本身是否就写在这里"。``system($_GET["cmd"])`` 的实参
        没有任何中间变量，变量表里查不到它，但它显然比"来源不明的变量"
        更明确——这里就是外部输入灌进来的地方。

        这依然**不是**数据流分析：它只回答"这个位置上的文本本身是不是外部输入"，
        不回答那个值后来又流到了哪里。因此它只会让**已经命中规则**的位置
        升级，不会凭空产生发现。

        参数：
            text: 待检查的文本片段。传危险位置上取到的值，
                取不到具体值时传整行（已去掉行尾注释）。
            line_no: 该文本所在的行号。来源表达式确实就在这一行，如实记录。

        返回：
            命中时返回一个 ``inline=True`` 的标记，否则 ``None``。
        """
        if self._source_pattern is None or not text:
            return None
        matched = self._source_pattern.search(text)
        if matched is None:
            return None
        token = matched.group(0)
        return TaintEntry(
            name=token,
            kind=TaintKind.UNTRUSTED,
            line=line_no,
            source_line=line_no,
            source_name=token,
            inline=True,
        )


def source_pattern_for(language: str) -> re.Pattern[str] | None:
    """返回该语言的不可信来源模式；没有登记则返回 ``None``。"""
    key = _ALIASES.get(language, language)
    pattern = _SOURCE_PATTERNS.get(key)
    return re.compile(pattern) if pattern is not None else None


def compute_taint(index: LineIndex, language: str) -> TaintMap:
    """按行扫描，建立来源标记表。

    参数：
        index: 已建立的行索引。
        language: **必须已识别**的语言。调用方在语言未知时不调用本函数——
            用错误的来源模式去匹配，会得到一批看似合理、实则无关的标记。

    返回：
        ``TaintMap``。语言没有登记来源模式时返回空表，
        此时规则只会依据自身模式判断，不会因为"没有来源"而漏报。
    """
    source_pattern = source_pattern_for(language)
    if source_pattern is None:
        # 没有登记来源模式的语言（如 HTML）：内联来源也不识别，
        # 否则会拿别的语言的关键字去匹配，得到看似合理的错误结论。
        return TaintMap()

    construction = re.compile(STRING_CONSTRUCTION)
    entries: dict[str, TaintEntry] = {}

    for line_no, line in enumerate(index.lines(), start=1):
        if len(entries) >= MAX_TAINTED_NAMES:
            break

        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue

        matched = _ASSIGNMENT.match(line)
        if matched is None:
            continue

        name, rhs = matched.group(1), matched.group(2)
        if name in _RESERVED_NAMES or not rhs.strip():
            continue

        entry = _classify(name, rhs, line_no, entries, source_pattern, construction)
        if entry is None:
            continue

        existing = entries.get(name)
        # 不把已经确认的来源降级成"只是拼接出来的"。
        if existing is not None and existing.kind is TaintKind.UNTRUSTED:
            continue
        entries[name] = entry

    return TaintMap(entries, source_pattern)


def _classify(
    name: str,
    rhs: str,
    line_no: int,
    entries: dict[str, TaintEntry],
    source_pattern: re.Pattern[str],
    construction: re.Pattern[str],
) -> TaintEntry | None:
    """判断这次赋的值属于哪一类，返回相应的标记或 ``None``。"""
    # 顺序有意义：直接读外部输入最强；其次是"值来自已确认的外部输入"；
    # 再次才是"值是被拼出来的"。越靠前的结论越具体。
    if source_pattern.search(rhs):
        return TaintEntry(
            name=name, kind=TaintKind.UNTRUSTED, line=line_no, source_line=line_no, source_name=name
        )

    # 从右侧引用到的变量里继承标记。算术表达式里的名字也会被认出来，
    # 这在"多标一个变量"和"少标一个变量"之间选了前者。
    inherited = _inherit(rhs, entries)
    if inherited is not None:
        return TaintEntry(
            name=name,
            kind=TaintKind.UNTRUSTED if inherited.kind is TaintKind.UNTRUSTED else TaintKind.CONSTRUCTED,
            line=line_no,
            source_line=inherited.source_line,
            source_name=inherited.source_name,
        )

    if construction.search(rhs):
        return TaintEntry(
            name=name, kind=TaintKind.CONSTRUCTED, line=line_no, source_line=line_no, source_name=name
        )

    return None


def _inherit(rhs: str, entries: dict[str, TaintEntry]) -> TaintEntry | None:
    """右侧表达式引用到的、标记最强的那个变量。"""
    best: TaintEntry | None = None
    for token in _IDENTIFIER.findall(rhs):
        entry = entries.get(token)
        if entry is None:
            continue
        if entry.kind is TaintKind.UNTRUSTED:
            return entry
        if best is None:
            best = entry
    return best
