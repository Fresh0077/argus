"""HTTP 请求包审计接口。

    POST /api/v1/audit/request

安全边界（对应阶段 19 与 CLAUDE.md）：

- 只解析文本，不重放请求、不访问目标；
- LLM 调用前必须确认脱敏预览，且预览指纹必须与当前报文一致；
- 原始报文不写入历史、日志或报告；
- 解析失败与确认失败都返回稳定错误，不把内部路径或原始报文带回响应。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.analyzers.http_request.parser import RequestParseError
from app.core.errors import ApiError
from app.core.security import enforce_origin
from app.schemas.enums import ErrorCode
from app.schemas.http_request import RequestAuditRequest, RequestAuditResponse
from app.services.request_audit_service import (
    RequestAuditConfirmationError,
    RequestAuditPreviewOutdated,
    audit_http_request,
)

router = APIRouter(tags=["request-audit"], dependencies=[Depends(enforce_origin)])

_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    409: {"description": "脱敏预览与当前报文不一致"},
    422: {"description": "报文无法解析，或启用 LLM 前未确认脱敏预览"},
}


@router.post(
    "/audit/request",
    response_model=RequestAuditResponse,
    summary="审计 HTTP 请求包",
    description=(
        "解析并脱敏一段原始 HTTP 请求报文，然后调用 LLM 做语义审计。\n\n"
        "**这不是 DAST：** 服务端只读取文本，不会重放请求或访问目标，"
        "因此不能确认 SQL 注入、XSS、越权等服务端漏洞。\n\n"
        "**隐私：** 报文中的 Authorization、Cookie、敏感参数与已知令牌形态会被脱敏；"
        "调用 LLM 前必须先以 `preview_only=true` 获取脱敏预览，"
        "再携带 `confirm_send=true` 与 `preview_fingerprint` 发起正式审计。"
        "如需手动修改，可在正式审计时提交 `redacted_request`，"
        "服务端会以这段文本为准，不再重新脱敏。"
        "原始报文不会写入历史或数据库。\n\n"
        "请求包审计只保留 LLM 这一路分析：预览阶段只解析与脱敏，不产生发现；"
        "正式审计只有在你确认预览后才会调用 LLM；LLM 未配置或调用失败时，"
        "整体状态为 `partial`，且没有候选发现。"
    ),
    responses=_ERROR_RESPONSES,
)
def audit_request(payload: RequestAuditRequest) -> RequestAuditResponse:
    """执行请求包审计；异常在这里转换成稳定的 HTTP 错误。"""
    try:
        return audit_http_request(payload)
    except RequestParseError as exc:
        raise ApiError(
            status_code=422,
            code=ErrorCode.REQUEST_PARSE_FAILED,
            message=str(exc),
        ) from exc
    except RequestAuditConfirmationError as exc:
        raise ApiError(
            status_code=422,
            code=ErrorCode.REQUEST_CONFIRMATION_REQUIRED,
            message=str(exc),
        ) from exc
    except RequestAuditPreviewOutdated as exc:
        raise ApiError(
            status_code=409,
            code=ErrorCode.REQUEST_PREVIEW_OUTDATED,
            message=str(exc),
        ) from exc
