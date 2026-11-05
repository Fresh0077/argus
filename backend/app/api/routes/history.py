"""扫描历史接口。

    GET    /api/v1/history              分页获取历史（元数据）
    GET    /api/v1/history/{scan_id}    读取一条历史详情（含发现）
    DELETE /api/v1/history/{scan_id}    删除一条历史

安全边界：

- 扫描编号必须是 32 位小写十六进制（与 ``uuid4().hex`` 一致），
  非法格式在进入业务逻辑前就被拒绝；
- 响应只包含数据库中的扫描结果，**不会返回源代码正文**（历史里本来就没有存）；
- 数据库不可用时返回固定文案的 503，不向调用方暴露文件路径、SQL 或 traceback。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query, Response

from app.core.errors import ApiError
from app.schemas.enums import ErrorCode
from app.schemas.history import (
    HISTORY_PAGE_SIZE_DEFAULT,
    HISTORY_PAGE_SIZE_MAX,
    HistoryDetail,
    HistoryListResponse,
)
from app.services import history_service

router = APIRouter(tags=["history"])

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
    422: {"description": "分页参数或扫描编号格式不合法"},
    503: {"description": "历史功能未启用或数据库暂时不可用"},
}


def _store_error(exc: history_service.HistoryStoreError) -> ApiError:
    """把服务层的数据库错误转换为对外统一的 503。

    ``HistoryStoreError`` 的文案本身就是固定中文说明，不含路径与 SQL，
    因此可以直接作为 ``message``；其他异常类型不会走到这里。
    """
    return ApiError(
        status_code=503,
        code=ErrorCode.HISTORY_UNAVAILABLE,
        message=str(exc),
    )


@router.get(
    "/history",
    response_model=HistoryListResponse,
    summary="分页获取扫描历史",
    description=(
        "按时间从新到旧返回扫描记录的**元数据**（不含发现明细与源代码）。\n\n"
        "每页条数上限 100。页数超出范围不会被当成错误，只返回空列表。\n\n"
        "若服务端通过 `HISTORY_ENABLED=false` 关闭了历史功能，"
        "响应中的 `enabled` 为 false，`items` 为空——这表示功能未启用，"
        "而不是“没有扫描记录”。\n\n"
        "历史记录只保存扫描元数据、摘要与候选发现结果，**不保存完整源代码**。"
    ),
    responses=_ERROR_RESPONSES,
)
def list_history(
    page: Annotated[int, Query(ge=1, le=100_000, description="页码，从 1 开始")] = 1,
    page_size: Annotated[
        int,
        Query(
            ge=1,
            le=HISTORY_PAGE_SIZE_MAX,
            description=f"每页条数，1–{HISTORY_PAGE_SIZE_MAX}",
        ),
    ] = HISTORY_PAGE_SIZE_DEFAULT,
) -> HistoryListResponse:
    """分页读取历史列表。"""
    try:
        return history_service.list_history(page=page, page_size=page_size)
    except history_service.HistoryStoreError as exc:
        raise _store_error(exc) from exc


@router.get(
    "/history/{scan_id}",
    response_model=HistoryDetail,
    summary="读取一条扫描历史详情",
    description=(
        "返回某次扫描的完整结果快照：元数据、摘要、候选发现与分析器状态。\n\n"
        "发现内容来自扫描当时的输出，不会因为之后修改规则集而改变。\n\n"
        "记录不存在时返回 404；历史功能关闭时返回 503。"
    ),
    responses=_ERROR_RESPONSES,
)
def get_history(scan_id: ScanId) -> HistoryDetail:
    """读取历史详情。"""
    try:
        return history_service.get_history(scan_id)
    except history_service.HistoryDisabledError as exc:
        raise ApiError(
            status_code=503,
            code=ErrorCode.HISTORY_DISABLED,
            message="扫描历史功能未在当前配置中启用。",
        ) from exc
    except history_service.HistoryNotFoundError as exc:
        raise ApiError(
            status_code=404,
            code=ErrorCode.HISTORY_NOT_FOUND,
            message="扫描记录不存在或已被删除。",
        ) from exc
    except history_service.HistoryStoreError as exc:
        raise _store_error(exc) from exc


@router.delete(
    "/history/{scan_id}",
    status_code=204,
    response_class=Response,
    summary="删除一条扫描历史",
    description=(
        "永久删除指定扫描记录。成功返回 204，无响应体。\n\n"
        "记录不存在返回 404；历史功能关闭返回 503。\n\n"
        "删除后无法通过接口恢复；如需全部清除，可直接停止服务后删除数据库文件。"
    ),
    responses=_ERROR_RESPONSES,
)
def delete_history(scan_id: ScanId) -> Response:
    """删除历史记录，成功时返回空响应。"""
    try:
        deleted = history_service.delete_history(scan_id)
    except history_service.HistoryDisabledError as exc:
        raise ApiError(
            status_code=503,
            code=ErrorCode.HISTORY_DISABLED,
            message="扫描历史功能未在当前配置中启用。",
        ) from exc
    except history_service.HistoryStoreError as exc:
        raise _store_error(exc) from exc

    if not deleted:
        raise ApiError(
            status_code=404,
            code=ErrorCode.HISTORY_NOT_FOUND,
            message="扫描记录不存在或已被删除。",
        )
    return Response(status_code=204)
