"""扫描输入接口。

本模块只负责**输入处理与安全校验**，分析本身由 ``scan_service`` 编排。
两条入口共用同一套校验与同一个响应构造流程：

    POST /api/v1/scan         应用内提交的 JSON 代码文本
    POST /api/v1/scan/upload  上传的单个代码文件

区别仅在于字节从哪里来、如何解码；解码之后一律构造成 ``ScanRequest``，
再由 ``scan_service.run_scan`` 统一处理。这样两条入口不可能出现
"JSON 提交被拒绝、文件上传却放行"这类校验不一致。

安全边界（对应 CLAUDE.md 安全红线第 1、4、5、6 条）：

- 全程只在内存中处理，**不写入任何文件**，也不产生任何由文件名派生的路径。
- 不执行、不编译、不导入被提交的代码——本模块与下游都只是把文本当字符串看。
- 类型判断只看扩展名，**完全不读 ``file.content_type``**。
- 大小限制在读取过程中生效：超限立即停止读取，而不是先读满再检查。
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile
from pydantic import ValidationError

from app.core.config import settings
from app.core.errors import ApiError, build_validation_details
from app.core.security import enforce_origin
from app.core.uploads import (
    decode_source_bytes,
    ensure_supported_extension,
    ensure_within_char_limit,
    language_for_extension,
)
from app.schemas.enums import ErrorCode
from app.schemas.errors import ErrorDetail
from app.schemas.scan import AnalysisOptions, ScanRequest, ScanResponse, validate_display_filename
from app.services.history_service import save_scan
from app.services.scan_service import run_scan

router = APIRouter(tags=["scan"], dependencies=[Depends(enforce_origin)])

#: 读取上传内容时的分块大小。
#: 取 64 KB 是一个折中：足够摊薄每次 await 的开销，又不会让单次分配过大。
_READ_CHUNK_SIZE = 64 * 1024

#: 两条接口共用的错误响应说明，写进 OpenAPI，方便在 /docs 中直接看到失败形态。
_ERROR_RESPONSES: dict[int | str, dict[str, object]] = {
    413: {"description": "提交内容超过大小限制"},
    415: {"description": "文件类型不受支持"},
    422: {"description": "请求参数或文件内容校验未通过"},
}


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="提交代码文本扫描",
    description=(
        "接收 JSON 格式的代码文本，执行语言识别、特征提取，并按请求开关执行 LLM 分析。\n\n"
        "响应中的 `analyzer_status` 逐项说明分析器是否真正执行过；"
        "未启用的标记为 `skipped`，缺少配置的标记为 `unavailable`，"
        "执行失败的标记为 `failed`，三者都会给出原因。\n\n"
        "总耗时受 `SCAN_TIMEOUT_SECONDS` 约束。"
        "`findings` 为空**不代表代码安全**：请先确认 `analyzer_status`，"
        "再结合 `disclaimer` 判断结论的强度。"
    ),
    responses=_ERROR_RESPONSES,
)
def scan_code(request: ScanRequest) -> ScanResponse:
    """校验并接收 JSON 代码文本。

    ``source_encoding`` 固定为 ``None``：JSON 请求体按规范即为 UTF-8，
    没有发生任何字符集转换。

    扫描完成后尝试写入历史。写入失败（磁盘、数据库或版本问题）只会记录
    一条不含源码的服务端日志，**不影响本次响应**。
    """
    response = run_scan(request)
    save_scan(response, filename=request.filename)
    return response


@router.post(
    "/scan/upload",
    response_model=ScanResponse,
    summary="上传单个代码文件扫描",
    description=(
        "以 `multipart/form-data` 接收单个代码文件（字段名 `file`）。\n\n"
        "文件类型**只依据扩展名判断**，不使用客户端提交的 MIME 类型。"
        "文件在内存中处理，不落盘、不执行。\n\n"
        "与 `POST /api/v1/scan` 共用同一套校验、特征提取与 LLM 分析流程，响应结构完全一致。"
    ),
    responses=_ERROR_RESPONSES,
)
async def scan_upload(
    file: Annotated[UploadFile, File(description="待扫描的单个代码文件")],
    language: Annotated[
        str | None, Form(description="可选的显式语言标识；省略时按扩展名推断")
    ] = None,
    enable_llm: Annotated[
        bool,
        Form(
            description=(
                "是否启用 LLM 分析；服务端 LLM_ENABLED=false 或缺少配置时"
                "会在 analyzer_status 中报 unavailable"
            )
        ),
    ] = False,
) -> ScanResponse:
    """校验上传文件并返回与 `/scan` 一致的响应。"""
    filename = _require_filename(file)
    extension = ensure_supported_extension(filename)

    data = await _read_limited(file)
    source_code, source_encoding = decode_source_bytes(data)
    # 字节数没超不代表字符数没超：1 MB 的 ASCII 文件有 100 多万字符。
    ensure_within_char_limit(source_code)

    request = _build_request(
        source_code=source_code,
        filename=filename,
        extension=extension,
        language=language,
        enable_llm=enable_llm,
    )
    response = run_scan(request, source_encoding=source_encoding)
    save_scan(response, filename=request.filename)
    return response


def _require_filename(file: UploadFile) -> str:
    """取出并校验用于展示的文件名。

    文件名在这里有两个用途：**显示来源**，以及**推断语言类型**。
    它绝不会被拼进任何路径——本模块不存在与文件系统交互的代码。
    """
    raw_name = file.filename or ""
    if not raw_name.strip():
        raise ApiError(
            status_code=422,
            code=ErrorCode.VALIDATION_ERROR,
            message="上传的文件缺少文件名。",
            details=[
                ErrorDetail(
                    field="file",
                    message="multipart 表单中必须包含 filename，否则无法判断文件类型。",
                )
            ],
        )

    try:
        validated = validate_display_filename(raw_name)
    except ValueError as exc:
        # validate_display_filename 抛出的是我们自己的中文说明，可以安全外传；
        # 但仍显式重建 ApiError，避免任何情况下把 traceback 带给调用方。
        raise ApiError(
            status_code=422,
            code=ErrorCode.VALIDATION_ERROR,
            message="上传的文件名不合法。",
            details=[ErrorDetail(field="file", message=str(exc))],
        ) from exc

    # validate_display_filename 仅在入参为 None 时返回 None，此处入参必为字符串。
    assert validated is not None
    return validated


async def _read_limited(file: UploadFile) -> bytes:
    """分块读取上传内容，累计超过上限立即中止。

    刻意不用 ``await file.read()``：那会把任意大小的内容一次性读进内存，
    等于把大小限制的决定权交给调用方。这里一旦越界就停止读取，
    剩余部分不会再进入内存，也不会被继续消费。
    """
    chunks: list[bytes] = []
    total = 0

    while True:
        chunk = await file.read(_READ_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > settings.max_upload_size_bytes:
            raise ApiError(
                status_code=413,
                code=ErrorCode.INPUT_TOO_LARGE,
                message="上传文件超过大小限制。",
                details=[
                    ErrorDetail(
                        field="file",
                        message=(
                            f"文件已超过上限 {settings.max_upload_size_bytes} 字节"
                            f"（约 {settings.max_upload_size_bytes // 1024} KB），已停止读取。"
                        ),
                    )
                ],
            )
        chunks.append(chunk)

    return b"".join(chunks)


def _build_request(
    *,
    source_code: str,
    filename: str,
    extension: str,
    language: str | None,
    enable_llm: bool,
) -> ScanRequest:
    """把上传内容组装成与 JSON 入口相同的请求模型。

    各字段在这里已经校验过一轮，但 ``ScanRequest`` 仍有自己的约束
    （例如 ``language`` 的字符集、``filename`` 的完整规则）。
    手工构造模型抛出的 ``ValidationError`` 不会被 FastAPI 的请求校验处理器捕获，
    若不转换就会变成 500，因此这里显式转成 422。
    """
    try:
        return ScanRequest(
            source_code=source_code,
            # 优先采用调用方显式指定的语言，否则按扩展名推断。
            language=language or language_for_extension(extension),
            filename=filename,
            analysis_options=AnalysisOptions(enable_llm=enable_llm),
        )
    except ValidationError as exc:
        raise ApiError(
            status_code=422,
            code=ErrorCode.VALIDATION_ERROR,
            message="上传内容校验未通过，请检查文件与表单参数。",
            details=build_validation_details(exc),
        ) from exc
