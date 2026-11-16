"""健康检查路由。

用于确认后端已正确启动，以及前端在联调前探测服务可用性。
响应中只包含服务状态与版本等非敏感信息，不暴露路径、密钥或内部实现细节。
"""

from fastapi import APIRouter

from app import __version__
from app.core.config import settings

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    summary="服务健康检查",
    description=(
        "返回服务运行状态、版本与当前运行环境。\n\n"
        "本接口不需要认证，也不读写任何用户数据。"
    ),
)
def health_check() -> dict[str, str]:
    """返回服务健康状态。

    注意：``status`` 为 ``ok`` 只表示 Web 服务本身可用，
    不代表 LLM 分析器已配置或可用。
    """
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": __version__,
        "environment": settings.app_env,
    }
