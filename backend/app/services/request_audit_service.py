"""HTTP 请求包审计的编排层。

流程：

1. 解析原始报文（失败即拒绝，不做“尽量修一修”）；
2. 脱敏，得到可发送给 LLM 的文本与指纹；
3. 按需调用 LLM（必须已确认预览且指纹一致）；
4. 统计并返回带分析器状态的响应。

请求包审计只保留 LLM 这一路分析：预览阶段只做解析与脱敏，不产生发现。
本模块不做持久化：请求报文与审计结果都不写入历史或数据库。
"""

from __future__ import annotations

import hashlib
import secrets
import time
from urllib.parse import urlsplit

from app.analyzers.http_request.detector import (
    RequestLlmOutcome,
    detect_request_llm_findings,
)
from app.analyzers.http_request.parser import RawHttpRequest, parse_http_request
from app.analyzers.http_request.redaction import RedactionResult, redact_http_request
from app.analyzers.line_index import LineIndex
from app.core.config import settings
from app.schemas.enums import SEVERITY_RANK, AnalyzerState, RequestAnalyzerName
from app.schemas.finding import Finding
from app.schemas.http_request import (
    ParsedRequestSummary,
    RedactionSummary,
    RequestAnalyzerStatus,
    RequestAuditRequest,
    RequestAuditResponse,
    RequestBodySummary,
    RequestHeaderSummary,
    RequestParameterSummary,
)
from app.schemas.scan import ScanStatus, ScanSummary

#: 响应中最多列出的参数条数。完整数量由 ``parameter_count`` 给出，
#: 避免超长查询串把响应体撑大。
_MAX_SUMMARY_PARAMETERS = 200


class RequestAuditConfirmationError(ValueError):
    """启用 LLM 前缺少确认。"""


class RequestAuditPreviewOutdated(ValueError):
    """确认的预览指纹与当前报文不一致。"""


def audit_http_request(payload: RequestAuditRequest) -> RequestAuditResponse:
    """执行一次请求包审计。

    异常：
        RequestParseError：报文无法解析（路由层转 422）。
        RequestAuditConfirmationError：启用 LLM 但未确认预览（路由层转 422）。
        RequestAuditPreviewOutdated：指纹不一致（路由层转 409）。
    """
    start = time.perf_counter()

    edited = payload.redacted_request is not None
    if edited:
        # 用户在预览中手动修改过文本。以这段文本为准：
        # 不再对原文重新脱敏，否则用户的修改会被覆盖。
        audit_text = payload.redacted_request or ""
        request = parse_http_request(
            audit_text, max_chars=settings.max_http_request_chars
        )
        fingerprint = hashlib.sha256(audit_text.encode("utf-8")).hexdigest()
        redaction = RedactionResult(
            text=audit_text,
            fingerprint=fingerprint,
            redacted_count=0,
            categories=(),
        )
    else:
        request = parse_http_request(
            payload.raw_request, max_chars=settings.max_http_request_chars
        )
        redaction = redact_http_request(request)
    parsed_at = time.perf_counter()

    preview_only = payload.preview_only
    if preview_only:
        llm = RequestLlmOutcome(
            state=AnalyzerState.SKIPPED,
            reason="预览模式：未调用 LLM。预览阶段只解析与脱敏，不产生审计发现。",
        )
    else:
        if not payload.confirm_send:
            raise RequestAuditConfirmationError(
                "调用 LLM 前必须查看脱敏预览并确认发送。"
            )
        if payload.preview_fingerprint != redaction.fingerprint:
            raise RequestAuditPreviewOutdated(
                "脱敏预览与当前报文不一致（报文可能已被修改），请重新预览后再确认。"
            )
        llm = detect_request_llm_findings(
            redaction.text,
            method=request.method,
            http_version=request.http_version,
            scheme=request.scheme,
            content_type=request.body_content_type,
            body_kind=request.body_kind,
        )

    after_llm = time.perf_counter()

    findings = _sort_findings(llm.findings)
    analyzer_status = _build_status(
        llm=llm,
        parse_ms=int((parsed_at - start) * 1000),
        llm_ms=int((after_llm - parsed_at) * 1000),
    )

    status = (
        ScanStatus.COMPLETED
        if llm.state == AnalyzerState.SUCCESS
        else ScanStatus.PARTIAL
    )

    return RequestAuditResponse(
        audit_id=secrets.token_hex(8),
        status=status,
        preview_only=preview_only,
        edited=edited,
        parsed=_build_parsed_summary(request, redaction),
        redacted_request=redaction.text,
        preview_fingerprint=redaction.fingerprint,
        redaction=RedactionSummary(
            redacted_count=redaction.redacted_count,
            categories=list(redaction.categories),
        ),
        findings=findings,
        summary=ScanSummary.from_findings(findings),
        analyzer_status=analyzer_status,
        duration_ms=int((after_llm - start) * 1000),
        llm_invoked=llm.state in {AnalyzerState.SUCCESS, AnalyzerState.FAILED},
    )


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """按严重等级、行号与类别稳定排序。"""
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_RANK[item.severity],
            item.line_start or 0,
            item.vulnerability_type,
        ),
    )


def _build_status(
    *,
    llm: RequestLlmOutcome,
    parse_ms: int,
    llm_ms: int,
) -> list[RequestAnalyzerStatus]:
    """构造解析与 LLM 两部分状态；非成功状态必须带原因。"""
    return [
        RequestAnalyzerStatus(
            name=RequestAnalyzerName.PARSE,
            state=AnalyzerState.SUCCESS,
            duration_ms=parse_ms,
            findings_count=0,
        ),
        RequestAnalyzerStatus(
            name=RequestAnalyzerName.LLM,
            state=llm.state,
            reason=llm.reason,
            duration_ms=(
                llm_ms
                if llm.state in {AnalyzerState.SUCCESS, AnalyzerState.FAILED}
                else None
            ),
            findings_count=len(llm.findings),
        ),
    ]


def _safe_label(value: str, *, limit: int = 200) -> str:
    """去掉控制字符并截断，避免摘要里的名称破坏单行展示。"""
    cleaned = "".join(
        char
        for char in value
        if char >= " " and char != "\x7f" and not "\x80" <= char <= "\x9f"
    )
    return cleaned[:limit] or "unknown"


def _build_parsed_summary(
    request: RawHttpRequest, redaction: RedactionResult
) -> ParsedRequestSummary:
    """构造脱敏后的解析摘要。"""
    redacted_lines = redaction.text.split("\n")
    redacted_target = _redacted_target(request, redacted_lines)
    redacted_path = _path_of(redacted_target, request.scheme)

    return ParsedRequestSummary(
        method=request.method,
        target=redacted_target,
        path=redacted_path,
        http_version=request.http_version,
        scheme=request.scheme,
        header_count=len(request.headers),
        headers=[
            RequestHeaderSummary(name=_safe_label(header.name), line=header.line)
            for header in request.headers
        ],
        parameter_count=len(request.parameters),
        parameters=[
            RequestParameterSummary(
                name=_safe_label(parameter.name),
                location=parameter.location,
                line=parameter.line,
            )
            for parameter in request.parameters[:_MAX_SUMMARY_PARAMETERS]
        ],
        cookie_count=len(request.cookies),
        body=RequestBodySummary(
            kind=request.body_kind,
            content_type=(
                request.body_content_type[:200]
                if request.body_content_type is not None
                else None
            ),
            length=len(request.body),
            line_start=request.body_start_line if request.body else None,
        ),
        # 用 LineIndex 的行数语义：末尾换行是行终止符，不额外算一行。
        line_count=LineIndex(redaction.text).line_count,
    )


def _redacted_target(request: RawHttpRequest, redacted_lines: list[str]) -> str:
    """从脱敏后的请求行中取回目标部分。"""
    if not redacted_lines:
        return request.target
    parts = redacted_lines[0].split(" ", 2)
    if len(parts) == 3:
        return parts[1]
    return request.target


def _path_of(target: str, scheme: str | None) -> str:
    if scheme and "://" in target:
        return urlsplit(target).path or "/"
    return target.partition("?")[0] or "/"
