"""特征提取入口。

把语言识别、统计、结构提取与候选线索提取串成一条流水线，
并给出**每一步是否真的执行了**的说明。

三条设计原则：

1. **不抛异常给调用方。** 特征提取是"锦上添花"的一步，
   它失败不应该让整次扫描变成 500。输入为空、长度为零这类情况
   都返回计数为 0 的结果，而不是报错。
2. **不猜测。** 语言识别不出来就是 ``None``，并跳过依赖语言的线索提取；
   函数数按模式计数得到的近似值会在 ``notes`` 里说明。
3. **候选线索只标位置，不下结论。** 转换出的 ``Finding`` 一律
   ``source=heuristic``、严重等级不超过 ``LOW``、置信度 0.25–0.45。
   措辞保留"疑似""检测到"这类限定，绝不写"存在漏洞"。
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.clues import CandidateClue, extract_clues
from app.analyzers.language import detect_language
from app.analyzers.line_index import LineIndex
from app.analyzers.stats import compute_stats, compute_structure
from app.schemas.enums import FindingSource
from app.schemas.features import FeatureExtractionResult
from app.schemas.finding import Finding, make_finding_id

#: 按漏洞类别给出的复核建议。
#:
#: 刻意都写成"确认……若是……则……"的**待确认**句式，而不是"应改为……"的
#: 断言句式：阶段 6 只是标出值得看的位置，还没到能断定有问题的时候。
_RECOMMENDATIONS: dict[str, str] = {
    "sql_injection": (
        "请确认该语句是否受用户输入影响。若受影响的只是参数值，"
        "改用参数化查询（占位符 + 参数绑定）即可；若表名、列名、排序字段也来自输入，"
        "则需改用白名单映射，占位符无法覆盖这类位置。"
    ),
    "command_injection": (
        "请确认命令参数是否来自不可信输入。若来自，优先改为参数数组调用并避免经过 shell；"
        "无法避免时对参数做白名单校验，不要依赖对特殊字符的转义。"
    ),
    "unsafe_dynamic_execution": (
        "请确认被执行的字符串来源。若包含外部输入，应改为显式的分支或映射表；"
        "很多场景其实只需要取字段或调用固定函数，无需动态执行。"
    ),
    "xss": (
        "请确认写入的内容是否经过转义或净化。优先使用框架的自动转义；"
        "确实需要渲染 HTML 时，使用经过审计的净化库处理，不要自行拼接过滤规则。"
    ),
    "untrusted_input_source": (
        "这是一处数据来源标记，本身不是缺陷。请沿该值的流向检查是否进入了"
        "命令执行、SQL 拼接、动态执行或 HTML 输出等危险位置；"
        "若确实如此，在进入危险位置之前做校验与转义。"
    ),
    "unsafe_deserialization": (
        "请确认数据来源是否可信。不可信的字节流不要交给可执行代码的反序列化格式，"
        "改用 JSON 这类纯数据格式；若格式由外部协议固定，至少加上完整性校验。"
    ),
}

#: 类别未登记时的兜底建议。
_FALLBACK_RECOMMENDATION = "请人工复核该位置的上下文与数据来源，确认是否存在实际风险。"


@dataclass(frozen=True)
class FeatureExtractionOutcome:
    """特征提取的完整产出。

    分成三部分而不是一个大对象，是因为调用方需要分别对待：
    ``features`` 进响应体，``findings`` 要与其他分析器的发现合并，
    ``clue_skip_reason`` 要变成 ``analyzer_status`` 里的一条状态。
    """

    features: FeatureExtractionResult

    #: 由候选线索转换出的发现，全部为 ``source=heuristic``。
    findings: list[Finding]

    #: 线索提取被跳过的原因；正常执行时为 None。
    clue_skip_reason: str | None


def _clue_to_finding(clue: CandidateClue) -> Finding:
    """把内部线索转换成对外的 ``Finding``。

    ``rule_key`` 用 ``cue_key`` 而不是标题：标题将来可能润色，
    而 ``cue_key`` 是稳定标识。``Finding.id`` 由它算出，
    因此改文案不会让前端看到一批"新"发现。
    """
    description = f"启发式线索（尚未确认为漏洞）：{clue.label}。"
    if clue.detail:
        description += clue.detail

    return Finding(
        id=make_finding_id(
            source=FindingSource.HEURISTIC,
            rule_key=clue.cue_key,
            line_start=clue.line,
            line_end=clue.line,
            evidence=clue.snippet,
        ),
        title=clue.label,
        vulnerability_type=clue.category,
        severity=clue.severity,
        description=description,
        evidence=clue.snippet,
        line_start=clue.line,
        line_end=clue.line,
        recommendation=_RECOMMENDATIONS.get(clue.category, _FALLBACK_RECOMMENDATION),
        confidence=clue.confidence,
        source=FindingSource.HEURISTIC,
        cwe_id=clue.cwe_id,
    )


def extract_features(
    source_code: str,
    *,
    filename: str | None = None,
    declared_language: str | None = None,
) -> FeatureExtractionOutcome:
    """对源码执行全部特征提取步骤。

    参数：
        source_code: 源码文本。不做换行符归一化，行号按原样计算。
        filename: 可选文件名，仅用于取扩展名判断语言。
        declared_language: 调用方显式指定的语言，优先级最高。

    返回：
        ``FeatureExtractionOutcome``。本函数不抛异常：无法识别的输入
        会体现在各个计数值为 0、``language`` 为 None 与 ``notes`` 中。
    """
    index = LineIndex(source_code)
    detection = detect_language(
        source_code, filename=filename, declared=declared_language
    )

    notes: list[str] = []
    clues: list[CandidateClue] = []
    clue_skip_reason: str | None = None

    if detection.language is None:
        # 语言未知时**不按任何语言去匹配线索**。
        # 拿一套猜出来的模式去扫，产出的是一批看似合理、实则无关的"发现"，
        # 比不产出更糟——用户会照着这些行号去查一个根本不存在的问题。
        # 不把 detection.evidence 原样嵌进来：它本身已经是一句
        # "无法识别语言：……"的完整说明，嵌进来会变成"未识别出语言
        # （无法识别语言：……）"这样的套娃。依据在 language_detection
        # 与 features.language_evidence 两处都能看到，这里只说明后果。
        clue_skip_reason = (
            "未识别出语言，已跳过候选线索提取。"
            "按未知语言的语法特征匹配会产出与代码无关的线索，因此不做推测；"
            "本次未能识别的具体依据见 language_detection 的状态说明。"
        )
        notes.append("未识别出语言，已跳过候选线索提取。")
    else:
        clues = extract_clues(index, detection.language)
        notes.append(
            f"候选线索按 {detection.language} 的语法特征逐行匹配得到，"
            "跨行书写的语句不会被识别，因此必然存在漏报。"
        )

    stats = compute_stats(index)
    structure, structure_notes = compute_structure(index, detection.language)
    notes.extend(structure_notes)

    features = FeatureExtractionResult(
        language=detection.language,
        language_source=detection.source,
        language_evidence=detection.evidence,
        stats=stats,
        structure=structure,
        notes=notes,
    )

    return FeatureExtractionOutcome(
        features=features,
        findings=[_clue_to_finding(clue) for clue in clues],
        clue_skip_reason=clue_skip_reason,
    )
