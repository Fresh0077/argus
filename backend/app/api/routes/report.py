"""扫描报告导出接口。

    GET /api/v1/history/{scan_id}/report?format=json|markdown

设计要点：

- **数据源是扫描历史**，不是调用方提交的内容。只有真实保存过的扫描结果
  才能导出，UI 中的示例数据无法混入报告；
- 报告不包含完整源代码（历史里没有存），只有候选发现的最小证据片段；
- 文件名由服务端固定生成，不接受用户输入，避免路径穿越；
- 历史关闭、记录不存在、记录损坏时，沿用历史接口的错误语义。
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Path, Query, Response

from app.core.errors import ApiError
from app.schemas.enums import ErrorCode
from app.schemas.report import ReportFormat
from app.services import report_service
from app.services.history_service import (
    HistoryDisabledError,
    HistoryNotFoundError,
    HistoryStoreError,
)

router = APIRouter(tags=["report"])

#: 扫描编号：uuid4().hex，固定 32 位小写十六进制。
ScanId = Annotated[
    str,
    Path(
        description="扫描编号，32 位小写十六进制",
        pattern=r"^[0-9a-f]{32}$",
    ),
]

_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    404: {"description": "扫描记录不存在"},
    422: {"description": "扫描编号或 format 参数不合法"},
    503: {"description": "历史功能未启用或数据库暂时不可用"},
}


@router.get(
    "/history/{scan_id}/report",
    summary="导出扫描报告",
    response_class=Response,
    description=(
        "从本地扫描历史生成报告，支持 `format=json`（默认）与 `format=markdown`。\n\n"
        "报告包含扫描编号、时间、语言、摘要、分析器状态、候选发现与局限说明；"
        "**不包含完整源代码**，只保留发现的最小证据片段。\n\n"
        "只有真实保存过的扫描结果才能导出；历史功能关闭或记录不存在时返回错误。\n\n"
        "响应以附件形式返回，文件名为 `argus-report-<scan_id>.json` 或 `.md`。"
    ),
    responses=_ERROR_RESPONSES,
)
def export_scan_report(
    scan_id: ScanId,
    report_format: Annotated[
        Literal["json", "markdown"],
        Query(alias="format", description="报告格式：json 或 markdown"),
    ] = "json",
) -> Response:
    """读取历史并返回报告附件。"""
    try:
        content, media_type, filename = report_service.export_report(
            scan_id, ReportFormat(report_format)
        )
    except HistoryDisabledError as exc:
        raise ApiError(
            status_code=503,
            code=ErrorCode.HISTORY_DISABLED,
            message=str(exc),
        ) from exc
    except HistoryNotFoundError as exc:
        raise ApiError(
            status_code=404,
            code=ErrorCode.HISTORY_NOT_FOUND,
            message=str(exc),
        ) from exc
    except HistoryStoreError as exc:
        raise ApiError(
            status_code=503,
            code=ErrorCode.HISTORY_UNAVAILABLE,
            message=str(exc),
        ) from exc

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # 报告下载后可能被浏览器直接打开；禁止 MIME 嗅探。
            "X-Content-Type-Options": "nosniff",
            # 报告包含扫描结果，不进入共享缓存。
            "Cache-Control": "no-store",
        },
    )
