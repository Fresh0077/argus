"""跨站请求来源校验。

CORS 中间件只决定浏览器能否**读取**响应，不能阻止第三方页面发起
"简单请求"（例如 ``multipart/form-data`` 表单）。ARGUS 默认只监听回环地址，
但用户浏览器里的任意网页仍可能向 ``http://127.0.0.1:8000`` 提交表单，
触发扫描或消耗 LLM 额度。

因此对**会改变状态或产生费用**的接口额外校验 ``Origin``：

- 没有 ``Origin``：命令行客户端/curl，允许；
- ``Origin`` 与请求自身的 Host 一致：同源（例如 Swagger 页面），允许；
- ``Origin`` 在 ``CORS_ALLOW_ORIGINS`` 中：允许前端开发服务器/独立前端；
- 其他来源：403。

这不是完整的身份认证，只是阻止浏览器跨站发起请求。若要把服务暴露到
回环地址之外，仍需反向代理层的认证与速率限制。
"""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import Request

from app.core.config import settings
from app.core.errors import ApiError
from app.schemas.enums import ErrorCode


def enforce_origin(request: Request) -> None:
    """拒绝来自未配置来源的浏览器请求。

    作为 FastAPI 依赖挂载在扫描、修复、删除历史等接口上。
    """
    origin = request.headers.get("origin")
    if not origin:
        return

    normalized = origin.strip().rstrip("/").lower()
    allowed = {item.strip().rstrip("/").lower() for item in settings.cors_origins}
    if normalized in allowed or _is_same_origin(request, normalized):
        return

    raise ApiError(
        status_code=403,
        code=ErrorCode.FORBIDDEN,
        message="请求来源不被允许。",
    )


def _is_same_origin(request: Request, origin: str) -> bool:
    """判断 ``Origin`` 是否与本次请求的 Host 一致（同源请求）。"""
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False

    host = request.headers.get("host", "").strip().lower()
    return bool(host) and parsed.netloc.lower() == host
