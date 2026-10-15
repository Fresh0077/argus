"""扫描流程编排。

阶段 5 的职责边界：**只把合法输入转换成结构正确的响应**，
不执行任何分析。分析器会在后续阶段逐个接入：

    阶段 6  语言识别与特征提取
    阶段 7  本地规则检测
    阶段 8  Semgrep（可选）
    阶段 9  LLM 语义分析
    阶段 10 多分析器整合

因此本阶段的响应中 ``findings`` 恒为空列表，**这不代表代码安全**。
为了让这一点无法被误读，每个尚未接入的分析器都会在 ``analyzer_status``
中留下 ``skipped`` / ``unavailable`` 状态与具体原因，
而不是让响应看起来像一次"跑完没发现问题"的正常扫描。
"""

from __future__ import annotations

import time
import uuid

from app.core.uploads import extension_of, language_for_extension
from app.schemas.enums import AnalyzerName, AnalyzerState, ScanStatus
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

    detected_language, language_status = _resolve_language(request)
    analyzer_status = [
        language_status,
        _pending(AnalyzerName.FEATURE_EXTRACTION, "阶段 6", "语言特征提取"),
        _pending(AnalyzerName.RULES, "阶段 7", "本地规则检测"),
        _pending_or_unavailable(
            AnalyzerName.SEMGREP, request.analysis_options.enable_semgrep, "阶段 8", "Semgrep 静态分析"
        ),
        _pending_or_unavailable(
            AnalyzerName.LLM, request.analysis_options.enable_llm, "阶段 9", "LLM 语义分析"
        ),
    ]

    # 阶段 5 不产生任何发现。这里显式写成空列表而不是省略，
    # 是为了让"没有分析结果"和"分析器找到了 0 个问题"在代码层面就分开表达。
    findings: list[Finding] = []

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
        detected_language=detected_language,
        findings=findings,
        summary=ScanSummary.from_findings(findings),
        duration_ms=duration_ms,
        analyzer_status=analyzer_status,
        source_encoding=source_encoding,
    )


def _resolve_language(request: ScanRequest) -> tuple[str | None, AnalyzerStatus]:
    """确定 ``detected_language``，并给出对应的分析器状态。

    优先级：调用方显式指定的语言 > 按扩展名推断。
    扩展名推断是**确定性的查表**，不是启发式猜测，因此可以标为 success；
    真正的启发式识别（内容特征、shebang 等）在阶段 6 接入。
    """
    if request.language:
        return request.language, AnalyzerStatus(
            name=AnalyzerName.LANGUAGE_DETECTION,
            state=AnalyzerState.SUCCESS,
            duration_ms=0,
            findings_count=0,
        )

    if request.filename:
        inferred = language_for_extension(extension_of(request.filename))
        if inferred:
            return inferred, AnalyzerStatus(
                name=AnalyzerName.LANGUAGE_DETECTION,
                state=AnalyzerState.SUCCESS,
                duration_ms=0,
                findings_count=0,
            )

    return None, AnalyzerStatus(
        name=AnalyzerName.LANGUAGE_DETECTION,
        state=AnalyzerState.SKIPPED,
        reason=(
            "调用方未指定语言，且无法从文件名推断。"
            "基于内容的启发式识别将在阶段 6 接入，本次未识别语言。"
        ),
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
