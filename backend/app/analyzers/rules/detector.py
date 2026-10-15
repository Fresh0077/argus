"""规则检测器的执行入口。

这是**独立于其他分析器的一层接口**：给它源码和语言，它返回一批 ``Finding``。
它不碰 FastAPI、不读写文件、不知道 Semgrep 或 LLM 是否存在，
后续要与其他分析器组合时，只需要在编排层把它们的结果并起来。

**去重策略**：以 ``(漏洞类别, 行号)`` 为唯一键。同一行同一类别只产出一条发现，
因此
- 一条规则在同一行匹配到多处（例如一行里调了两次 ``os.system``）只报一次；
- 同一行被同类的两条规则同时命中时，按规则表声明顺序取第一条。

选 ``(类别, 行号)`` 而不是 ``(规则, 行号)``，是因为用户关心的是
"这一行有一个 SQL 注入问题"，而不是"有两套正则都想说这一行有问题"。
两条模式同时命中同一行属于规则表内部的表述问题，不该由用户看到两份。

**行号**：只报告**真正匹配到的那一行**，不推测、不模糊定位。
因此不存在"未能可靠定位"的发现——这一层要么给出准确行号，要么不报告。
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.common import COMMENT_PREFIXES
from app.analyzers.line_index import LineIndex
from app.analyzers.rules.catalog import rules_for_language
from app.analyzers.rules.model import Rule, RuleHit
from app.analyzers.taint import TaintEntry, TaintKind, compute_taint
from app.schemas.enums import FindingSource, Severity
from app.schemas.finding import Finding, make_finding_id

#: 语言未识别时的跳过原因。
#:
#: 措辞刻意不去复述语言识别失败的原因（那会在两个字段里出现同一句话），
#: 而是指明去哪里看依据。
_NO_LANGUAGE_REASON = (
    "未识别出语言，已跳过本地规则检测。规则按语言的语法特征登记，"
    "语言未知时无论套用哪一套模式，产出的都会是与代码无关的结果；"
    "本次未能识别的具体依据见 language_detection 的状态说明。"
)


@dataclass(frozen=True)
class RuleDetectionOutcome:
    """规则检测的结果。

    ``skip_reason`` 非空表示**本次没有执行检测**，与"执行了但没发现问题"
    是两件不同的事，调用方必须区分对待。
    """

    findings: list[Finding]
    skip_reason: str | None = None


def detect_rule_findings(
    source_code: str, language: str | None
) -> RuleDetectionOutcome:
    """对源码执行本地规则检测。

    参数：
        source_code: 待分析源码。**只被当作文本**，不执行、不编译、不导入。
        language: 已识别的语言；``None`` 表示未识别，此时跳过检测。

    返回：
        ``RuleDetectionOutcome``。本函数不抛异常——分析器出错不应让整次扫描失败，
        而"静默返回空结果"会把失败伪装成"没有发现问题"，因此失败的表达
        交由调用方通过 ``skip_reason`` 之外的机制处理（见编排层）。
    """
    if not language:
        return RuleDetectionOutcome(findings=[], skip_reason=_NO_LANGUAGE_REASON)

    rules = rules_for_language(language)
    if not rules:
        return RuleDetectionOutcome(findings=[])

    index = LineIndex(source_code)
    taint = compute_taint(index, language)

    findings: list[Finding] = []
    claimed: set[tuple[str, int]] = set()

    for line_no, line in enumerate(index.lines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        # 整行注释跳过：注释里举例说明"不要这样写 eval(x)"是极常见的写法，
        # 而按注释报出来的发现，用户跳过去只会看到一段说明文字。
        # 只判断整行，不做行内截断，理由见 ``common.COMMENT_PREFIXES``。
        if stripped.startswith(COMMENT_PREFIXES):
            continue

        for rule in rules:
            key = (rule.vulnerability_type, line_no)
            if key in claimed:
                continue

            hit = rule.evaluate(line, taint, line_no)
            if hit is None:
                continue

            claimed.add(key)
            findings.append(build_finding(rule, hit))

    return RuleDetectionOutcome(findings=findings)


def build_finding(rule: Rule, hit: RuleHit) -> Finding:
    """把一次命中转换成对外的 ``Finding``。

    等级与置信度在**确认到来源**时升一档，说明文案里补上来源所在的行——
    用户据此可以直接跳过去看数据是从哪里进来的。
    """
    entry = hit.taint
    has_source = entry is not None and entry.kind is TaintKind.UNTRUSTED

    severity: Severity = rule.severity
    confidence: float = rule.confidence
    if has_source:
        if rule.severity_with_source is not None:
            severity = rule.severity_with_source
        if rule.confidence_with_source is not None:
            confidence = rule.confidence_with_source

    description = rule.description
    if entry is not None:
        description = f"{description}{_source_sentence(entry)}"

    return Finding(
        id=make_finding_id(
            source=FindingSource.STATIC_RULE,
            rule_key=rule.rule_id,
            line_start=hit.line,
            line_end=hit.line,
            evidence=hit.evidence,
        ),
        rule_id=rule.rule_id,
        title=rule.title,
        vulnerability_type=rule.vulnerability_type,
        severity=severity,
        description=description,
        evidence=hit.evidence,
        line_start=hit.line,
        line_end=hit.line,
        recommendation=rule.recommendation,
        confidence=confidence,
        source=FindingSource.STATIC_RULE,
        cwe_id=rule.cwe_id,
    )


def _source_sentence(entry: TaintEntry) -> str:
    """把来源信息写成一句话，接在风险说明后面。

    三种情形分开写，因为它们给用户的下一步动作不同：
    内联来源要看这一行本身，直接来源要跳到变量的赋值行，
    传播来源还要顺着中间那个最初的变量名找回去。
    """
    if entry.inline:
        return (
            f"危险位置上直接出现了外部输入表达式 {entry.name}，"
            "中间没有经过任何变量中转。"
        )
    if entry.kind is TaintKind.UNTRUSTED:
        if entry.source_line == entry.line:
            return f"本行使用的 {entry.name} 在第 {entry.source_line} 行直接来自外部输入。"
        return (
            f"本行使用的 {entry.name} 可追溯到第 {entry.source_line} 行的外部输入"
            f"（最初由 {entry.source_name} 携带）。"
        )
    return f"本行使用的 {entry.name} 在第 {entry.line} 行由拼接或格式化构造。"
