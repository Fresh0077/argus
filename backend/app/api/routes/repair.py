"""修复建议接口。

    POST /api/v1/repair    为一条候选发现生成可审阅的候选补丁

安全边界（对应阶段 16 与 CLAUDE.md 安全红线）：

- 不修改、不覆盖任何文件，也不执行修复后的代码；
- 只把发现所在行前后少量代码发给模型，不发送整个文件；
- 模型输出必须通过结构校验，错误响应只含固定中文说明；
- 修复建议不会写入扫描历史或数据库。
"""

from __future__ import annotations

from fastapi import APIRouter

from app.analyzers.repair import (
    RepairContextError,
    RepairModelError,
    RepairOutputError,
    RepairUnavailableError,
    generate_repair,
)
from app.core.errors import ApiError
from app.schemas.enums import ErrorCode
from app.schemas.repair import RepairRequest, RepairSuggestion

router = APIRouter(tags=["repair"])

_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    422: {"description": "发现缺少可靠行号、行号越界或上下文过长"},
    502: {"description": "模型调用失败或模型输出无法作为修复建议"},
    503: {"description": "LLM 未启用或缺少必要配置"},
}


@router.post(
    "/repair",
    response_model=RepairSuggestion,
    summary="为候选发现生成修复建议",
    description=(
        "根据一条 `Finding` 与对应源代码生成**候选补丁**。\n\n"
        "服务端只截取发现所在行前后各 10 行、且不超过 `LLM_MAX_INPUT_CHARS` 的上下文"
        "发送给模型，不会主动发送整个大文件（很短的文件可能整段落在窗口内）。\n\n"
        "返回的 `fixed_code`、`diff` 均由模型生成，未经编译、执行或测试；"
        "本接口**不会修改任何文件**。应用补丁前必须人工审查并在你的环境中重新测试。\n\n"
        "调用会使用配置的第三方模型服务，代码片段会发送到该服务商。"
    ),
    responses=_ERROR_RESPONSES,
)
def repair_code(request: RepairRequest) -> RepairSuggestion:
    """生成候选补丁；异常在这里转换成稳定的 HTTP 错误。"""
    try:
        return generate_repair(request)
    except RepairContextError as exc:
        raise ApiError(
            status_code=422,
            code=ErrorCode.REPAIR_CONTEXT_UNAVAILABLE,
            message=str(exc),
        ) from exc
    except RepairUnavailableError as exc:
        raise ApiError(
            status_code=503,
            code=ErrorCode.REPAIR_UNAVAILABLE,
            message=str(exc),
        ) from exc
    except RepairOutputError as exc:
        raise ApiError(
            status_code=502,
            code=ErrorCode.LLM_OUTPUT_INVALID,
            message=str(exc),
        ) from exc
    except RepairModelError as exc:
        raise ApiError(
            status_code=502,
            code=ErrorCode.REPAIR_FAILED,
            message=str(exc),
        ) from exc
