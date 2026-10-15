"""规则的建模与匹配。

一条 ``Rule`` 把"**怎么找**"和"**找到之后怎么讲**"绑在一起：定位正则、
附加条件、适用语言、等级、置信度、说明与修复建议。拆成两份清单存在
（一份模式表、一份文案表）迟早会对不上号——加了规则忘了加建议，
用户就会拿到一条没有修复方向的发现。

匹配的顺序是有讲究的，见 ``Rule.evaluate``。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from app.analyzers.common import snippet_of
from app.analyzers.taint import TaintEntry, TaintKind, TaintMap, assigned_name
from app.analyzers.rules.values import (
    argument_values,
    assigned_value,
    first_argument,
    is_constant_value,
    strip_line_comment,
)
from app.schemas.enums import Severity


class ValuePosition(str, Enum):
    """危险位置里"值"是哪一段。

    同一条规则只挑一段来检查，因为"值是不是写死的"这件事
    在不同危险位置上问的是不同的东西。
    """

    #: 不检查值。位置本身已经足够可疑（``eval``、``unserialize``、``v-html``），
    #: 或者压根没有"值"这个概念（模板里的 ``| safe`` 过滤器）。
    NONE = "none"

    #: 调用形式的危险位置，只看**第一个实参**。
    #: SQL 用它：``execute("... %s", (uid,))`` 的第二个实参是绑定参数，
    #: 恰恰是安全写法，把它算进来会把参数化查询误报成注入。
    FIRST_ARGUMENT = "first_argument"

    #: 调用形式的危险位置，**任一实参**是动态的就算。
    #: 命令执行用它：参数是变长的，危险的那个不一定在第一位。
    ALL_ARGUMENTS = "all_arguments"

    #: 赋值形式的危险位置，取等号右侧。
    ASSIGNED_VALUE = "assigned_value"


@dataclass(frozen=True)
class RuleHit:
    """一次规则命中。

    这是**内部分析上下文**，最终会被转换成 ``Finding`` 再对外返回。
    分开建模是因为命中需要携带"取到的值是哪一段""引用到了哪个来源变量"
    这类用于生成说明文案的信息，而 ``Finding`` 不需要暴露它们。
    """

    #: 命中所在行（1 起）。逐行匹配保证它一定准确。
    line: int

    #: 截断后的代码片段。
    evidence: str

    #: 危险位置上取到的值文本。仅用于测试与排查，不进入响应。
    value: str = ""

    #: 命中位置引用到的来源变量；没有则为 ``None``。
    taint: TaintEntry | None = None


@dataclass(frozen=True)
class Rule:
    """一条检测规则。

    ``pattern`` / ``require`` / ``exclude`` 传入的是**正则源码字符串**
    （规则表因此保持可读），``__post_init__`` 会编译后存回同名字段，
    所以实例上的这三个字段是已编译对象。
    """

    #: 规则唯一标识，形如 ``ARGUS-SQL-001``。
    #: 它参与发现 ID 的计算，因此**改这个值等于换了一条规则**，不要随手改。
    rule_id: str

    #: 漏洞类别，与 ``Finding.vulnerability_type`` 使用同一套受控词表。
    vulnerability_type: str

    #: 面向用户的标题，已经包含"疑似"等限定词。
    title: str

    #: **危险位置**的定位正则（不负责判断值是否危险，那是后面几步的事）。
    pattern: str

    #: 适用语言。规则按语言登记，绝不把一套模式套到所有语言上。
    languages: frozenset[str]

    #: 没有来源证据时的等级。
    severity: Severity = Severity.MEDIUM

    #: 没有来源证据时的置信度。
    confidence: float = 0.5

    #: 风险说明。必须写清"需要人工确认什么"，不能只描述匹配到了什么。
    description: str = ""

    #: 修复建议。
    recommendation: str = ""

    cwe_id: str | None = None

    #: 同一行里还必须匹配的附加条件。
    require: str | None = None

    #: 同一行里还必须引用了带这些标记之一的变量。
    #:
    #: 与 ``require`` **同时给出时是"或"的关系**：满足任一即可。
    #: SQL 规则正是靠这个组合覆盖两种写法——同行拼接，以及
    #: 语句在前几行拼好、这一行只负责执行。
    require_taint: frozenset[TaintKind] | None = None

    #: 排除条件：命中说明这是安全写法（已转义、已净化），不再报告。
    exclude: str | None = None

    #: 取哪一段值来做"是不是写死的"判断。
    dynamic_value_at: ValuePosition = ValuePosition.NONE

    #: 确认到来源时的等级与置信度。``None`` 表示不随来源变化。
    severity_with_source: Severity | None = None
    confidence_with_source: float | None = None

    def __post_init__(self) -> None:
        # frozen dataclass 不能直接赋值，用 object.__setattr__ 绕过。
        # re.compile 自带缓存，重复构造同一模式不会重复解析。
        object.__setattr__(self, "pattern", re.compile(self.pattern))
        if self.require is not None:
            object.__setattr__(self, "require", re.compile(self.require))
        if self.exclude is not None:
            object.__setattr__(self, "exclude", re.compile(self.exclude))

    def evaluate(self, line: str, taint: TaintMap, line_no: int) -> RuleHit | None:
        """这一行是否命中本规则；命中则返回 ``RuleHit``。

        判断分四步，任何一步不成立就立刻返回 ``None``：

        1. **定位**：``pattern`` 命中危险位置；
        2. **排除**：``exclude`` 未命中（已转义的写法在这里被放过）；
        3. **值**：危险位置上的值不是写死的常量；
        4. **触发条件**：``require`` / ``require_taint`` 至少满足一个。

        第 3 步放在第 4 步之前，是因为"值是不是常量"是更硬的证据：
        ``execute("SELECT 1")`` 不管有没有来源变量，都不该报。

        **来源查询与触发条件是两件事**：``require_taint`` 决定"这条规则要不要报"，
        而只要行内引用了可追溯的变量，说明文案里就该写出来、等级也该升一档——
        否则会出现"等级与其依据不一致"的发现：说明里不提来源，等级却按有来源给。
        因此这里无条件查一次来源，只有命中的行才会走到这一步，开销可以忽略。
        """
        matched = self.pattern.search(line)  # type: ignore[arg-type]
        if matched is None:
            return None

        if self.exclude is not None and self.exclude.search(line):  # type: ignore[union-attr]
            return None

        value = self._value_at(line, matched)
        if value is None:
            return None

        # 查来源时只看危险位置上的那段文本，而不是整行：
        # 同一行里另有一处请求参数读取（例如注释、或分号后的另一条语句）
        # 不构成"这个位置的输入来自外部"的证据。
        # ``ValuePosition.NONE`` 取不到具体值，退化为整行（去注释）。
        focus = value or strip_line_comment(line)
        target = assigned_name(line)

        inline = taint.inline_source(focus, line_no)
        entry = taint.reference_in(line, at_line=line_no, exclude=target) or inline

        if not self._triggered(line, taint, line_no, target, inline):
            return None

        return RuleHit(line=line_no, evidence=snippet_of(line), value=value, taint=entry)

    def _value_at(self, line: str, matched: re.Match[str]) -> str | None:
        """取出要检查的值；``ValuePosition.NONE`` 或值全是常量时返回 ``None``。"""
        position = self.dynamic_value_at
        if position is ValuePosition.NONE:
            return ""

        if position is ValuePosition.ASSIGNED_VALUE:
            value = assigned_value(line, matched.end())
            return None if is_constant_value(value) else value

        # 调用形式：定位正则以左括号结尾，取匹配片段里最后一个左括号。
        # 取最后一个是因为像 ``Runtime.getRuntime().exec(`` 这样前面还有别的括号。
        open_index = line.rfind("(", matched.start(), matched.end())
        if open_index < 0:
            # 正则写了调用形式却没有左括号，属于规则表自身的错误。
            # 返回 None 让这条规则安静地不报告——宁可漏报，也不能凭猜测定位。
            return None

        if position is ValuePosition.FIRST_ARGUMENT:
            value = first_argument(line, open_index)
            return None if is_constant_value(value) else value

        arguments = argument_values(line, open_index)
        dynamic = [item for item in arguments if not is_constant_value(item)]
        if not dynamic:
            return None
        return dynamic[0]

    def _triggered(
        self,
        line: str,
        taint: TaintMap,
        line_no: int,
        target: str | None,
        inline: TaintEntry | None,
    ) -> bool:
        """``require`` 与 ``require_taint`` 的合并判断。

        两者同时给出时是**"或"**：满足任一即触发。只给一个时，那一个说了算。
        这里按种类重新查一次来源，而不是复用上面"任意种类"的结果——
        行内可能同时出现构造型与不可信型变量，取到哪一个取决于书写顺序，
        不该让书写顺序决定规则是否触发。

        ``target`` 与 ``inline`` 由调用方算好传入，避免同一行重复查表。
        """
        if self.require is None and self.require_taint is None:
            return True
        if self.require is not None and self.require.search(line) is not None:  # type: ignore[union-attr]
            return True
        if self.require_taint is None:
            return False
        # 内联来源表达式固定在危险位置上，比变量中转更直接，同样算命中。
        # 它只有"不可信"一种，因此只在规则接受该种类时才作数。
        if inline is not None and TaintKind.UNTRUSTED in self.require_taint:
            return True
        return (
            taint.reference_in(
                line, self.require_taint, at_line=line_no, exclude=target
            )
            is not None
        )
