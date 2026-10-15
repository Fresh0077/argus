"""/api/v1 路由聚合。

后续阶段的 scan、history 等路由都在此处挂载，保持 API 版本前缀只定义一次。
"""

from fastapi import APIRouter

from app.api.routes import health

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
