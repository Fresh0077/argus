"""扫描流程编排。

当前职责边界：**语言识别、特征提取与本地规则检测已接入，Semgrep/LLM 尚未接入**。

    已接入  语言识别 + 统计 + 结构 + 候选线索（启发式）+ 本地规则检测
    阶段 8  Semgrep（可选）
    阶段 9  LLM 语义分析
    阶段 10 多分析器整合

尚未接入的分析器会在 ``analyzer_status`` 中留下 ``skipped`` / ``unavailable``
状态与具体原因，**不会**让响应看起来像一次"跑完没发现问题"的正常扫描。
这一点很关键：``findings`` 为空只在所有分析器都成功时才可能意味着"没发现问题"。

每个分析器的耗时与发现数量都逐项真实计时、真实统计，
``summary`` 由 ``ScanSummary.from_findings`` 从实际结果算出。
"""

from __future__ import annotations

import time
import uuid

from app.analyzers.extractor import FeatureExtractionOutcome, extract_features
from app.analyzers.rules import RuleDetectionOutcome, detect_rule_findings
from app.schemas.enums import SEVERITY_RANK, AnalyzerName, AnalyzerState, FindingSource, ScanStatus
from app.schemas.finding import Finding
from app.schemas.scan import AnalyzerStatus, ScanRequest, ScanResponse, ScanSummary


def run_scan(request: ScanRequest, *, source_encoding: str | None = None) -> ScanResponse:
    """根据已校验的请求构造扫描响应。

    参数：
        request: 已经通过校验的扫描请求。两条入口（JSON 文本 / 文件上传）
            最终都会构造出同一个模型，因此本函数不需要知道输入来自哪里。
        source_encoding: 上传接口实际使用的解码方式；JSON 提交时为 ``None``。

    返回：
        ``ScanResponse``。``duration_ms`` 由真实计时得到，
        ``summary`` 由 ``ScanSummary.from_findings`` 从真实结果计算，
        两者都不接受调用方传入的数值。
    """
    started_at = time.perf_counter()

    # 特征提取一次性完成语言识别、统计、结构与候选线索，
    # 因此这三项共享同一次调用，但**分别报告状态**：
    # "统计做了、线索没做"（语言未识别）是一种真实且常见的状态。
    detection_started = time.perf_counter()
    outcome = extract_features(
        request.source_code,
        filename=request.filename,
        declared_language=request.language,
    )
    extraction_ms = int((time.perf_counter() - detection_started) * 1000)

    # 规则检测依赖语言识别结果，因此必须在这之后执行。
    # 它与特征提取是两次独立调用，所以耗时可单独测量（线索层无法）。
    rules_started = time.perf_counter()
    rule_outcome = detect_rule_findings(request.source_code, outcome.features.language)
    rules_ms = int((time.perf_counter() - rules_started) * 1000)

    findings = merge_findings(outcome.findings, rule_outcome.findings)

    # 语言识别、统计与线索提取同属一次 extract_features 调用，耗时无法拆分。
    # 因此只在 language_detection 上计入这次测量的耗时，其余两项填 None，
    # 而不是把同一个数字抄三遍——那会让人以为分别测了三次，
    # 也会让"三项耗时之和"远大于整体耗时。
    feature_status = AnalyzerStatus(
        name=AnalyzerName.FEATURE_EXTRACTION,
        state=AnalyzerState.SUCCESS,
        duration_ms=None,
        findings_count=0,
    )

    analyzer_status = [
        _language_status(outcome, extraction_ms),
        feature_status,
        _clue_status(outcome, findings),
        _rule_status(rule_outcome, rules_ms),
        _pending_or_unavailable(
            AnalyzerName.SEMGREP, request.analysis_options.enable_semgrep, "阶段 8", "Semgrep 静态分析"
        ),
        _pending_or_unavailable(
            AnalyzerName.LLM, request.analysis_options.enable_llm, "阶段 9", "LLM 语义分析"
        ),
    ]

    duration_ms = int((time.perf_counter() - started_at) * 1000)

    # 只要有分析器没成功执行，整体状态就是 partial。
    # 不使用 completed——那会暗示"该跑的都跑过了"，与事实不符。
    status = (
        ScanStatus.COMPLETED
        if all(item.state == AnalyzerState.SUCCESS for item in analyzer_status)
        else ScanStatus.PARTIAL
    )

    return ScanResponse(
        scan_id=uuid.uuid4().hex,
        status=status,
        detected_language=outcome.features.language,
        findings=findings,
        summary=ScanSummary.from_findings(findings),
        duration_ms=duration_ms,
        analyzer_status=analyzer_status,
        source_encoding=source_encoding,
        features=outcome.features,
    )


def merge_findings(clues: list[Finding], rules: list[Finding]) -> list[Finding]:
    """把启发式线索与规则发现并成一个有序列表。

    **规则命中所在的 (行, 漏洞类别) 上不再输出启发式线索。**
    两者说的事情完全相同，而规则给出的是同一个结论加上规则 ID、
    明确的触发条件和针对性的修复建议，信息量严格更大；
    再单独报一条只会让人以为是两个问题。

    未被规则覆盖的线索照常输出——它们补充的是规则不负责的信息，
    例如"这一行读了请求参数"这类来源标记。

    跨分析器（Semgrep、LLM）之间的合并不在这里做：它们的环境依赖与
    降级路径完全不同，那属于多分析器整合要单独处理的问题。
    """
    covered = {(finding.line_start, finding.vulnerability_type) for finding in rules}
    kept_clues = [
        clue for clue in clues if (clue.line_start, clue.vulnerability_type) not in covered
    ]
    return _sorted_by_location(kept_clues + rules)


def _sorted_by_location(findings: list[Finding]) -> list[Finding]:
    """按行号升序、同一行内按严重等级从高到低排列。

    排序键最后带上 ``id``：只按行号和等级排序时，同一批输入仍可能得到
    不同的顺序，前端列表会在重新扫描后莫名重排。
    """
    return sorted(
        findings,
        key=lambda item: (
            item.line_start is None,
            item.line_start or 0,
            SEVERITY_RANK[item.severity],
            item.id,
        ),
    )


def _language_status(outcome: FeatureExtractionOutcome, duration_ms: int) -> AnalyzerStatus:
    """语言识别的状态。

    识别不出来时报 ``skipped`` 而不是 ``success``：语言相关的一切分析
    都不会执行，报告 ``success`` 会让人以为"看过了，没问题"。
    """
    if outcome.features.language is None:
        return AnalyzerStatus(
            name=AnalyzerName.LANGUAGE_DETECTION,
            state=AnalyzerState.SKIPPED,
            reason=outcome.features.language_evidence,
            duration_ms=duration_ms,
        )
    return AnalyzerStatus(
        name=AnalyzerName.LANGUAGE_DETECTION,
        state=AnalyzerState.SUCCESS,
        duration_ms=duration_ms,
    )


def _clue_status(outcome: FeatureExtractionOutcome, findings: list[Finding]) -> AnalyzerStatus:
    """候选线索提取的状态。

    耗时填 ``None``：它和语言识别共用一次 ``extract_features`` 调用，
    无法单独计时（耗时计在 language_detection 那一条上）。

    ``findings_count`` 统计的是**最终响应里保留下来**的启发式发现数量。
    被规则覆盖而未输出的那部分不计入——各分析器的 ``findings_count``
    相加应当等于 ``summary.total_findings``，否则用户会以为有发现丢失了。
    覆盖策略见 ``merge_findings``。
    """
    if outcome.clue_skip_reason is not None:
        return AnalyzerStatus(
            name=AnalyzerName.CLUES,
            state=AnalyzerState.SKIPPED,
            reason=outcome.clue_skip_reason,
        )
    return AnalyzerStatus(
        name=AnalyzerName.CLUES,
        state=AnalyzerState.SUCCESS,
        findings_count=sum(1 for item in findings if item.source is FindingSource.HEURISTIC),
    )


def _rule_status(outcome: RuleDetectionOutcome, duration_ms: int) -> AnalyzerStatus:
    """本地规则检测的状态。

    规则检测不需要 API key、不依赖外部工具，只要语言识别成功就一定能跑，
    因此"没跑"只有一种原因：语言没识别出来。
    """
    if outcome.skip_reason is not None:
        return AnalyzerStatus(
            name=AnalyzerName.RULES,
            state=AnalyzerState.SKIPPED,
            reason=outcome.skip_reason,
        )
    return AnalyzerStatus(
        name=AnalyzerName.RULES,
        state=AnalyzerState.SUCCESS,
        duration_ms=duration_ms,
        findings_count=len(outcome.findings),
    )


def _pending_or_unavailable(
    name: AnalyzerName, enabled: bool, stage: str, label: str
) -> AnalyzerStatus:
    """按开关决定"未启用"还是"已启用但尚未接入"。

    两种情况的用户动作完全不同：前者需要改请求参数，后者需要等后续阶段。
    混为一谈会让用户反复修改一个改不动的东西。
    """
    if not enabled:
        return AnalyzerStatus(
            name=name,
            state=AnalyzerState.SKIPPED,
            reason="本次请求未启用该分析器（对应的 analysis_options 开关为 false）。",
            findings_count=0,
        )
    return AnalyzerStatus(
        name=name,
        state=AnalyzerState.UNAVAILABLE,
        reason=f"{label}将在{stage} 接入，即使已启用也不会在本次扫描中执行。",
        findings_count=0,
    )
