"""统一的异常处理与错误响应转换。

集中注册在应用入口，保证任何错误路径返回的都是同一套结构，
且**绝不把 Python traceback、服务器路径或密钥返回给调用方**。

处理策略：

- 请求校验失败 → 422，附字段级明细（不含用户原始输入）。
- 已知的 HTTP 异常 → 沿用其状态码，配中文说明。
- 其他未捕获异常 → 500，只返回通用提示；完整堆栈仅写入服务端日志。
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas.enums import ErrorCode
from app.schemas.errors import ErrorBody, ErrorDetail, ErrorResponse

logger = logging.getLogger(__name__)

#: 未捕获异常的对外统一说明。
#: 故意不含异常原文——异常消息里可能带文件路径、配置值甚至密钥片段。
GENERIC_INTERNAL_MESSAGE = "服务器内部错误，请稍后重试。"


class ApiError(Exception):
    """业务层抛出的、已经确定好对外表现错误。

    为什么不直接用 ``HTTPException``：通用处理器按**状态码**选择错误码与文案，
    因此 ``HTTPException(415, "缺少扩展名")`` 的说明会被"不支持的内容类型"覆盖。
    上传接口需要表达"415 但原因各不相同"的多种情况，所以在这里显式携带
    错误码、状态码与字段级明细。

    安全性：``message`` 与 ``details`` 直接面向用户，**只能填写我们自己的文案**，
    绝不允许把异常原文、文件路径或配置值原样塞进来。
    """

    def __init__(
        self,
        status_code: int,
        code: ErrorCode,
        message: str,
        details: list[ErrorDetail] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or []

#: 常见 HTTP 状态码的中文说明。
_HTTP_STATUS_MESSAGES: dict[int, str] = {
    400: "请求格式不正确。",
    401: "未通过身份验证。",
    403: "没有访问该资源的权限。",
    404: "请求的资源不存在。",
    405: "该请求方法不被允许。",
    409: "请求与当前资源状态冲突。",
    413: "提交的内容超过大小限制。",
    415: "不支持的内容类型。",
    422: "请求参数校验未通过，请检查提交的内容。",
    429: "请求过于频繁，请稍后重试。",
    500: GENERIC_INTERNAL_MESSAGE,
    503: "服务暂时不可用，请稍后重试。",
}

_HTTP_STATUS_CODES: dict[int, ErrorCode] = {
    400: ErrorCode.INVALID_REQUEST,
    404: ErrorCode.NOT_FOUND,
    405: ErrorCode.METHOD_NOT_ALLOWED,
    413: ErrorCode.INPUT_TOO_LARGE,
    415: ErrorCode.UNSUPPORTED_FILE_TYPE,
    422: ErrorCode.VALIDATION_ERROR,
    429: ErrorCode.INVALID_REQUEST,
    500: ErrorCode.INTERNAL_ERROR,
}

#: Validation 错误消息中需要剔除的内部字段名。
#: 这些字段属于实现细节，不应出现在对外响应中。
_HIDDEN_LOCATION_PARTS = {"body", "query", "path", "header", "cookie"}

#: Pydantic 内置错误类型 → 面向用户的中文说明模板。
#:
#: Pydantic 默认消息是英文的，直接透传会让中文界面出现
#: "Extra inputs are not permitted" 这类提示。此处只翻译本项目请求模型上
#: 会实际出现的类型；**未列出的类型保留原始消息**，而不是猜测含义或统一改写，
#: 以免丢失排错所需的细节。
_VALIDATION_MESSAGE_TEMPLATES: dict[str, str] = {
    "missing": "缺少必填字段。",
    "extra_forbidden": "不支持的字段，请检查字段名是否拼写正确。",
    "string_type": "应为字符串。",
    "bool_type": "应为布尔值（true 或 false）。",
    "bool_parsing": "应为布尔值（true 或 false）。",
    "int_type": "应为整数。",
    "int_parsing": "应为整数。",
    "float_type": "应为数值。",
    "float_parsing": "应为数值。",
    "list_type": "应为列表。",
    "dict_type": "应为对象。",
    "model_type": "应为对象。",
    "string_too_short": "长度不足，至少需要 {min_length} 个字符。",
    "string_too_long": "长度超限，最多允许 {max_length} 个字符。",
    "string_pattern_mismatch": "格式不合法，需匹配模式 {pattern}。",
    "greater_than": "取值必须大于 {gt}。",
    "greater_than_equal": "取值必须大于或等于 {ge}。",
    "less_than": "取值必须小于 {lt}。",
    "less_than_equal": "取值必须小于或等于 {le}。",
    "json_invalid": "请求体不是合法的 JSON。",
}


class _PlaceholderSafeDict(dict):
    """格式化模板时，缺失的占位符替换为 ``?`` 而不是抛异常。

    错误处理路径本身不应该再因为格式化失败而抛出新的异常。
    """

    def __missing__(self, key: object) -> str:
        return "?"


def _extract_safe_context(error: dict) -> dict[str, object]:
    """从 Pydantic 错误项中提取可安全格式化的上下文值。

    只接受 ``str``/``int``/``float``/``bool``。
    ``ctx`` 中还可能包含异常对象等无法安全序列化的内容，一律丢弃。
    """
    ctx = error.get("ctx")
    if not isinstance(ctx, dict):
        return {}
    return {
        str(key): value
        for key, value in ctx.items()
        if isinstance(value, (str, int, float, bool))
    }


def _localize_validation_message(error: dict) -> str:
    """把单条校验错误转换成面向用户的中文说明。"""
    error_type = str(error.get("type", ""))
    raw_message = str(error.get("msg", "")).strip()

    # 我们自己写的校验器抛出的是中文说明，去掉 Pydantic 追加的前缀即可。
    if error_type == "value_error":
        cleaned = raw_message.removeprefix("Value error, ").strip()
        return cleaned or "字段取值不合法。"

    template = _VALIDATION_MESSAGE_TEMPLATES.get(error_type)
    if template:
        return template.format_map(_PlaceholderSafeDict(_extract_safe_context(error)))

    # 未覆盖的类型：保留原始消息，便于定位问题。
    return raw_message or "字段取值不合法。"


def _error_json_response(
    status_code: int,
    code: ErrorCode,
    message: str,
    details: list[ErrorDetail] | None = None,
) -> JSONResponse:
    """把统一的错误结构序列化成 JSON 响应。"""
    body = ErrorResponse(
        error=ErrorBody(code=code, message=message, details=details or [])
    )
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


def _field_path(location: tuple[object, ...]) -> str | None:
    """把 Pydantic 的 ``loc`` 转成对外字段路径。

    去掉 ``body``/``query`` 这类位置前缀，只保留真正的字段名，
    例如 ``("body", "analysis_options", "enable_llm")`` → ``"analysis_options.enable_llm"``。
    """
    parts = [str(part) for part in location if str(part) not in _HIDDEN_LOCATION_PARTS]
    if not parts:
        return None
    return ".".join(parts)[:200]


def build_validation_details(exc: ValidationError) -> list[ErrorDetail]:
    """从校验异常构造字段级错误明细。

    只保留字段路径与原因说明。

    **刻意丢弃** Pydantic 错误项中的 ``input`` 与 ``ctx``：
    ``input`` 会原样携带用户提交的内容（可能是整段源代码），
    让它出现在错误响应里等于为源代码做了第二份副本；
    ``ctx`` 则可能包含异常对象，序列化后可能泄漏内部信息。
    只有经过筛选的标量上下文值才会被用于拼装提示文本。

    参数类型写成 ``ValidationError`` 而非 ``RequestValidationError``：
    路由内部手工构造 ``ScanRequest`` 时抛出的是前者，两者共用同一套转换逻辑。
    """
    details: list[ErrorDetail] = []
    for error in exc.errors():
        details.append(
            ErrorDetail(
                field=_field_path(tuple(error.get("loc", ()))),
                message=_localize_validation_message(error)[:300],
            )
        )
    return details


def register_exception_handlers(app: FastAPI) -> None:
    """为应用注册统一异常处理器。

    在 ``app/main.py`` 中调用一次。测试也可以用它在临时应用上验证错误格式。
    """

    @app.exception_handler(ApiError)
    async def _handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
        """业务层已明确指定错误码与文案，直接按其声明返回。"""
        return _error_json_response(
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            details=exc.details,
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return _error_json_response(
            status_code=422,
            code=ErrorCode.VALIDATION_ERROR,
            message=_HTTP_STATUS_MESSAGES[422],
            details=build_validation_details(exc),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code = _HTTP_STATUS_CODES.get(exc.status_code, ErrorCode.INVALID_REQUEST)
        message = _HTTP_STATUS_MESSAGES.get(exc.status_code)
        if message is None:
            # 仅当我们或框架显式提供了安全的说明文本时才透传。
            detail = exc.detail if isinstance(exc.detail, str) else ""
            message = detail.strip() or "请求无法处理。"
        return _error_json_response(exc.status_code, code, message)

    @app.exception_handler(Exception)
    async def _handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # 完整堆栈只写服务端日志；记录方法与路径即可，不记录查询串或请求体
        # （请求体可能包含用户提交的源代码）。
        logger.exception("未处理异常：%s %s", request.method, request.url.path)
        return _error_json_response(
            status_code=500,
            code=ErrorCode.INTERNAL_ERROR,
            message=GENERIC_INTERNAL_MESSAGE,
        )
