"""扫描流程编排。

当前职责边界：

    语言识别 + 统计 + 结构提取（特征上下文）
    → LLM 语义分析
    → 统一响应组装

特征提取只提供上下文，不判定安全性；所有候选发现都来自 LLM。
LLM 未启用或失败时，``analyzer_status`` 必须如实说明，不能把空结果
读成“代码安全”。

单次扫描仍有总预算 ``SCAN_TIMEOUT_SECONDS``：用尽后不再启动 LLM，
调用时也会把超时收紧到剩余时间。
"""

from __future__ import annotations

import time
import uuid

from app.analyzers.extractor import extract_features
from app.analyzers.llm import LlmOutcome, detect_llm_findings
from app.analyzers.llm.detector import Completer
from app.core.config import settings
from app.schemas.enums import SEVERITY_RANK, AnalyzerName, AnalyzerState, ScanStatus
from app.schemas.features import FeatureExtractionResult
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
        llm_client: 仅供测试注入的模型客户端；生产调用留 ``None``。

    返回：
        ``ScanResponse``。``duration_ms`` 由真实计时得到，
        ``summary`` 由 ``ScanSummary.from_findings`` 从真实结果计算。
    """
    started_at = time.perf_counter()
    deadline = started_at + settings.scan_timeout_seconds

    extraction_started = time.perf_counter()
    features = extract_features(
        request.source_code,
        filename=request.filename,
        declared_language=request.language,
    )
    extraction_ms = int((time.perf_counter() - extraction_started) * 1000)

    findings: list[Finding] = []
    llm_outcome: LlmOutcome | None = None
    llm_ms: int | None = None
    llm_error: str | None = None

    if request.analysis_options.enable_llm:
        llm_started = time.perf_counter()
        remaining = deadline - llm_started
        if remaining <= 0:
            llm_error = _deadline_reason("LLM")
        else:
            try:
                llm_outcome = detect_llm_findings(
                    request.source_code,
                    features.language,
                    features=features,
                    client=llm_client,
                    timeout_seconds=_llm_request_timeout(remaining),
                )
            except Exception as exc:  # noqa: BLE001 - 分析器不得拖垮整次扫描
                llm_error = _unexpected_reason("LLM", exc)
        llm_ms = int((time.perf_counter() - llm_started) * 1000)
        if llm_outcome is not None:
            findings = _sorted_by_location(llm_outcome.findings)

    analyzer_status = [
        _language_status(features, extraction_ms),
        _feature_status(),
        _llm_status(
            request.analysis_options.enable_llm,
            llm_outcome,
            llm_ms,
            llm_error,
        ),
    ]

    status = (
        ScanStatus.COMPLETED
        if all(item.state == AnalyzerState.SUCCESS for item in analyzer_status)
        else ScanStatus.PARTIAL
    )

    return ScanResponse(
        scan_id=uuid.uuid4().hex,
        status=status,
        detected_language=features.language,
        findings=findings,
        summary=ScanSummary.from_findings(findings),
        duration_ms=int((time.perf_counter() - started_at) * 1000),
        analyzer_status=analyzer_status,
        source_encoding=source_encoding,
        features=features,
    )


def _sorted_by_location(findings: list[Finding]) -> list[Finding]:
    """按行号升序、同一行内按严重等级从高到低排列。"""
    return sorted(
        findings,
        key=lambda item: (
            item.line_start is None,
            item.line_start or 0,
            SEVERITY_RANK[item.severity],
            item.id,
        ),
    )


def _language_status(
    features: FeatureExtractionResult, duration_ms: int
) -> AnalyzerStatus:
    """语言识别的状态；无法识别时报 ``skipped`` 并带依据。"""
    if features.language is None:
        return AnalyzerStatus(
            name=AnalyzerName.LANGUAGE_DETECTION,
            state=AnalyzerState.SKIPPED,
            reason=features.language_evidence,
            duration_ms=duration_ms,
        )
    return AnalyzerStatus(
        name=AnalyzerName.LANGUAGE_DETECTION,
        state=AnalyzerState.SUCCESS,
        duration_ms=duration_ms,
    )


def _feature_status() -> AnalyzerStatus:
    """统计与结构提取的状态。

    它与语言识别共用一次调用，耗时已计入 ``language_detection``，
    这里不再重复记同一个数字。
    """
    return AnalyzerStatus(
        name=AnalyzerName.FEATURE_EXTRACTION,
        state=AnalyzerState.SUCCESS,
        duration_ms=None,
        findings_count=0,
    )


def _llm_status(
    enabled: bool,
    outcome: LlmOutcome | None,
    duration_ms: int | None,
    error_reason: str | None = None,
) -> AnalyzerStatus:
    """LLM 分析的状态。

    未启用时耗时为空；已启用时如实记录耗时，包括配置缺失与调用失败。
    """
    if not enabled:
        return AnalyzerStatus(
            name=AnalyzerName.LLM,
            state=AnalyzerState.SKIPPED,
            reason="本次请求未启用 LLM 分析。",
            findings_count=0,
        )

    if error_reason is not None or outcome is None:
        return AnalyzerStatus(
            name=AnalyzerName.LLM,
            state=AnalyzerState.FAILED,
            reason=error_reason or "LLM 分析器没有返回结果，本次未采用其结果。",
            duration_ms=duration_ms,
            findings_count=0,
        )

    return AnalyzerStatus(
        name=AnalyzerName.LLM,
        state=outcome.state,
        reason=outcome.reason,
        duration_ms=duration_ms,
        findings_count=len(outcome.findings),
    )


def _deadline_reason(analyzer: str) -> str:
    """总预算用尽时，未启动分析器的原因。"""
    return (
        f"本次扫描已超过总时限（SCAN_TIMEOUT_SECONDS="
        f"{settings.scan_timeout_seconds:g} 秒），未启动 {analyzer} 分析。"
        "可缩小输入或调整该配置后重试。"
    )


def _unexpected_reason(analyzer: str, exc: Exception) -> str:
    """未预期异常的对外原因；不包含异常原文，避免泄漏内部细节。"""
    return f"{analyzer} 分析过程中出现未预期错误（{type(exc).__name__}）。"


def _llm_request_timeout(remaining: float) -> float:
    """LLM 单次请求超时：不超过配置值，也不超过剩余预算。"""
    return max(0.1, min(settings.llm_timeout_seconds, remaining))
