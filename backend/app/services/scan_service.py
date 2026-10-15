"""扫描流程编排。

当前职责边界：**语言识别与特征提取已接入，规则/Semgrep/LLM 尚未接入**。

    已接入  语言识别 + 统计 + 结构 + 候选线索（启发式）
    阶段 7  本地规则检测
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
from app.schemas.enums import AnalyzerName, AnalyzerState, ScanStatus
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

    language_status = _language_status(outcome, extraction_ms)
    clue_status = _clue_status(outcome)

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
        language_status,
        feature_status,
        clue_status,
        _pending(AnalyzerName.RULES, "阶段 7", "本地规则检测"),
        _pending_or_unavailable(
            AnalyzerName.SEMGREP, request.analysis_options.enable_semgrep, "阶段 8", "Semgrep 静态分析"
        ),
        _pending_or_unavailable(
            AnalyzerName.LLM, request.analysis_options.enable_llm, "阶段 9", "LLM 语义分析"
        ),
    ]

    findings = outcome.findings

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


def _clue_status(outcome: FeatureExtractionOutcome) -> AnalyzerStatus:
    """候选线索提取的状态。

    耗时填 None：它和语言识别共用一次 ``extract_features`` 调用，
    无法单独计时（耗时计在 language_detection 那一条上）。
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
        findings_count=len(outcome.findings),
    )


def _pending(name: AnalyzerName, stage: str, label: str) -> AnalyzerStatus:
    """尚未接入的分析器：标记为 skipped 并写明计划接入的阶段。"""
    return AnalyzerStatus(
        name=name,
        state=AnalyzerState.SKIPPED,
        reason=f"{label}将在{stage} 接入，本次扫描未执行该分析器。",
        findings_count=0,
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
