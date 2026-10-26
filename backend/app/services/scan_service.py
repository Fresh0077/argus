"""扫描流程编排。

当前职责边界：

    已接入  语言识别 + 统计 + 结构 + 候选线索（启发式）+ 本地规则检测
            + Semgrep（可选）+ LLM 语义分析（可选）
    未完成  多分析器整合的完整审查（阶段 10）

可选分析器被跳过或失败时，``analyzer_status`` 会留下 ``skipped`` /
``unavailable`` / ``failed`` 状态与具体原因，**不会**让响应看起来像一次
"跑完没发现问题"的正常扫描。这一点很关键：``findings`` 为空只在
所有分析器都成功时才可能意味着"没发现问题"。

每个分析器的耗时与发现数量都逐项真实计时、真实统计，
``summary`` 由 ``ScanSummary.from_findings`` 从实际结果算出。
"""

from __future__ import annotations

import time
import uuid

from app.analyzers.extractor import FeatureExtractionOutcome, extract_features
from app.analyzers.llm import LlmOutcome, detect_llm_findings
from app.analyzers.llm.detector import Completer
from app.analyzers.rules import RuleDetectionOutcome, detect_rule_findings
from app.analyzers.semgrep import SemgrepOutcome, detect_semgrep_findings
from app.core.config import settings
from app.schemas.enums import SEVERITY_RANK, AnalyzerName, AnalyzerState, FindingSource, ScanStatus
from app.schemas.finding import Finding
from app.schemas.scan import AnalyzerStatus, ScanRequest, ScanResponse, ScanSummary


def run_scan(
    request: ScanRequest,
    *,
    source_encoding: str | None = None,
    llm_client: Completer | None = None,
) -> ScanResponse:
    """根据已校验的请求构造扫描响应。

    参数：
        request: 已经通过校验的扫描请求。两条入口（JSON 文本 / 文件上传）
            最终都会构造出同一个模型，因此本函数不需要知道输入来自哪里。
        source_encoding: 上传接口实际使用的解码方式；JSON 提交时为 ``None``。
        llm_client: 仅供测试注入的模型客户端；生产调用留 ``None``，
            由 LLM 分析器按配置创建真实客户端。

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

    # Semgrep 只在请求显式启用时执行。它依赖外部进程，因此耗时单独测量；
    # 未启用时记为 None，而不是 0——"没跑"和"跑得很快"不是一回事。
    semgrep_outcome: SemgrepOutcome | None = None
    semgrep_ms: int | None = None
    if request.analysis_options.enable_semgrep:
        semgrep_started = time.perf_counter()
        semgrep_outcome = detect_semgrep_findings(
            request.source_code,
            outcome.features.language,
            command=settings.semgrep_command,
            timeout_seconds=settings.semgrep_timeout_seconds,
        )
        semgrep_ms = int((time.perf_counter() - semgrep_started) * 1000)

    findings = merge_findings(outcome.findings, rule_outcome.findings)
    if semgrep_outcome is not None:
        findings = merge_semgrep_findings(findings, semgrep_outcome.findings)

    # LLM 最后执行：它需要看到前面分析器的结果作为提示，但**独立判断**。
    # 没配置 key 时它会在自己的入口处直接报 unavailable，不会发起请求。
    llm_outcome: LlmOutcome | None = None
    llm_ms: int | None = None
    if request.analysis_options.enable_llm:
        llm_started = time.perf_counter()
        llm_outcome = detect_llm_findings(
            request.source_code,
            outcome.features.language,
            prior_findings=findings,
            client=llm_client,
        )
        llm_ms = int((time.perf_counter() - llm_started) * 1000)
        findings = merge_llm_findings(findings, llm_outcome.findings)

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
        _semgrep_status(
            request.analysis_options.enable_semgrep, semgrep_outcome, semgrep_ms, findings
        ),
        _llm_status(request.analysis_options.enable_llm, llm_outcome, llm_ms, findings),
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


def merge_semgrep_findings(
    findings: list[Finding], semgrep_findings: list[Finding]
) -> list[Finding]:
    """把 Semgrep 的结果并入已有列表，并处理跨分析器重复。

    去重键仍是 ``(漏洞类别, 行号)``——与规则层内部一致。两个分析器报同一位置
    同一类别时，保留**本地规则**那条，因为它的说明与修复建议更具体、不依赖
    外部工具；但 Semgrep 的命中不是"重复噪音"：两条独立路径得出同一结论，
    对用户来说是更强的证据。因此把 Semgrep 的规则 ID 记进保留那条的说明里，
    **既不出两条，也不丢掉第二个来源**。

    Semgrep 独有的发现正常追加。LLM 的合并在 ``merge_llm_findings`` 中进行。
    """
    by_key = {
        (finding.line_start, finding.vulnerability_type): index
        for index, finding in enumerate(findings)
    }
    merged = list(findings)

    for extra in semgrep_findings:
        key = (extra.line_start, extra.vulnerability_type)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = len(merged)
            merged.append(extra)
            continue

        kept = merged[existing]
        note = f" Semgrep 规则 {extra.rule_id} 在同一位置独立命中，两条结果互为佐证。"
        # 说明有长度上限；已经写过就不重复追加，重复扫描得到的结果保持不变。
        if note.strip() not in kept.description:
            merged[existing] = kept.model_copy(
                update={"description": f"{kept.description}{note}"}
            )

    return _sorted_by_location(merged)


def merge_llm_findings(findings: list[Finding], llm_findings: list[Finding]) -> list[Finding]:
    """把 LLM 的发现并入已有列表。

    去重键仍是 ``(漏洞类别, 行号)``。与 Semgrep 不同的是，LLM 的判断**证据强度更低**
    （模型可能受提示与上下文影响），因此重复时同样保留先到的规则/Semgrep 那条，
    只追加一句说明，不把模型的文字覆盖进去。

    **没有行号的发现不参与合并**：两个都定位不到的发现没有理由被当作同一条。
    """
    by_key = {
        (finding.line_start, finding.vulnerability_type): index
        for index, finding in enumerate(findings)
        if finding.line_start is not None
    }
    merged = list(findings)

    for extra in llm_findings:
        key = (extra.line_start, extra.vulnerability_type)
        existing = by_key.get(key) if extra.line_start is not None else None
        if existing is None:
            if extra.line_start is not None:
                by_key[key] = len(merged)
            merged.append(extra)
            continue

        kept = merged[existing]
        note = " LLM 在同一位置也给出判断，可互为参考；模型输出仍需人工确认。"
        if note.strip() not in kept.description:
            merged[existing] = kept.model_copy(
                update={"description": f"{kept.description}{note}"}
            )

    return _sorted_by_location(merged)


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


def _semgrep_status(
    enabled: bool,
    outcome: SemgrepOutcome | None,
    duration_ms: int | None,
    findings: list[Finding],
) -> AnalyzerStatus:
    """Semgrep 的状态。

    ``findings_count`` 与线索层口径一致，只统计**最终响应里保留下来**的
    Semgrep 发现：与本地规则重复而被合并进说明的那一条不计入，
    这样各项之和仍等于 ``summary.total_findings``。

    耗时对已尝试的调用如实记录，包括失败与不可用——它们同样消耗了时间；
    只有"没启用"才是 ``None``。
    """
    if not enabled or outcome is None:
        return AnalyzerStatus(
            name=AnalyzerName.SEMGREP,
            state=AnalyzerState.SKIPPED,
            reason="本次请求未启用该分析器（对应的 analysis_options 开关为 false）。",
            findings_count=0,
        )

    return AnalyzerStatus(
        name=AnalyzerName.SEMGREP,
        state=outcome.state,
        reason=outcome.reason,
        duration_ms=duration_ms,
        findings_count=sum(
            1 for finding in findings if finding.source is FindingSource.SEMGREP
        ),
    )


def _llm_status(
    enabled: bool,
    outcome: LlmOutcome | None,
    duration_ms: int | None,
    findings: list[Finding],
) -> AnalyzerStatus:
    """LLM 分析的状态。

    未启用时 ``duration_ms`` 为 ``None``；已启用时如实记录耗时，
    包括"配置缺失"与"调用失败"——它们同样代表这次扫描多花的时间
    （配置缺失通常不足 1 毫秒，但这不是伪造数据的理由）。

    ``findings_count`` 只统计最终响应中 ``source=llm`` 的发现，
    与其他分析器口径一致，保证各项之和等于 ``summary.total_findings``。
    """
    if not enabled or outcome is None:
        return AnalyzerStatus(
            name=AnalyzerName.LLM,
            state=AnalyzerState.SKIPPED,
            reason="本次请求未启用该分析器（对应的 analysis_options 开关为 false）。",
            findings_count=0,
        )

    return AnalyzerStatus(
        name=AnalyzerName.LLM,
        state=outcome.state,
        reason=outcome.reason,
        duration_ms=duration_ms,
        findings_count=sum(1 for finding in findings if finding.source is FindingSource.LLM),
    )
