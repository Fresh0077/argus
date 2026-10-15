"""ARGUS 后端应用入口。

启动方式（二选一，都已验证可用）：

在 backend/ 目录下::

    python -m uvicorn app.main:app --reload --port 8000

在项目根目录下::

    python -m uvicorn app.main:app --app-dir backend --reload --port 8000

启动后：
    服务地址   http://127.0.0.1:8000
    接口文档   http://127.0.0.1:8000/docs
    健康检查   http://127.0.0.1:8000/api/v1/health
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.router import api_router
from app.core.config import settings

app = FastAPI(
    title="ARGUS API",
    description=(
        "ARGUS 智能代码安全分析平台后端服务。\n\n"
        "**定位说明：** ARGUS 是代码安全分析的辅助工具，不是安全证明工具。"
        "检测结果来自规则、启发式特征与（可选的）LLM 判断，均可能误报或漏报。"
        "未发现漏洞不代表代码绝对安全。\n\n"
        "**安全承诺：** 服务不会执行、编译或导入任何待检测的代码。"
    ),
    version=__version__,
)

# CORS：只允许配置中显式列出的来源。
# settings 在启动时已拒绝包含 '*' 的配置，因此这里不存在放开通配符的可能。
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )

app.include_router(api_router)


@app.get("/", tags=["meta"], summary="服务说明")
def root() -> dict[str, str]:
    """返回简短的服务说明与常用入口，方便浏览器直接访问确认服务已启动。"""
    return {
        "service": settings.app_name,
        "version": __version__,
        "description": "ARGUS 智能代码安全分析平台后端服务",
        "docs": "/docs",
        "health": "/api/v1/health",
    }
