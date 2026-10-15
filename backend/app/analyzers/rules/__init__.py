"""本地规则检测器。

**这一层产出的是"疑似风险"（候选发现），不是"已确认的漏洞"。**
单条正则命中只能说明某个位置具备出问题的条件，是否真的可被利用
需要人来判断上下文——每一条发现的说明里都写明了要确认什么。

对外只需要 ``detect_rule_findings`` 一个入口；其余导出供测试与文档使用。

模块分工：

- ``model``：``Rule`` 的定义与匹配顺序；
- ``catalog``：规则表本身，是这一层最主要的产出物；
- ``values``：判断危险位置上的值是不是写死的常量；
- ``detector``：跑规则表并产出 ``Finding``。

来源跟踪在 ``app.analyzers.taint``，它不依赖本包，也可以被后续的
Semgrep / LLM 分析复用。
"""

from __future__ import annotations

from app.analyzers.rules.catalog import RULES, RULES_BY_ID, rules_for_language
from app.analyzers.rules.detector import RuleDetectionOutcome, detect_rule_findings
from app.analyzers.rules.model import Rule, RuleHit, ValuePosition

__all__ = [
    "RULES",
    "RULES_BY_ID",
    "Rule",
    "RuleDetectionOutcome",
    "RuleHit",
    "ValuePosition",
    "detect_rule_findings",
    "rules_for_language",
]
