"""ARGUS 后端统一配置入口。

所有配置项集中在此处定义，通过环境变量或项目根目录的 ``.env`` 文件注入，
避免在业务代码中散落硬编码配置。

安全约定：
- 本模块不提供任何密钥的默认值；密钥只能来自环境变量或本地 ``.env``。
- ``.env`` 已被 .gitignore 忽略，不得提交到版本控制。
- 配置项在启动时校验：非法的安全相关配置（例如 CORS 通配符）会让服务直接启动失败，
  而不是带着不安全的配置继续运行。
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# 依据本文件位置反推目录，而不是依赖当前工作目录（os.getcwd()）。
# 这样无论从项目根目录还是 backend/ 目录启动，读到的都是同一个 .env。
#   __file__      = <repo>/backend/app/core/config.py
#   parents[2]    = <repo>/backend
#   parents[2].parent = <repo>
BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    """应用配置。

    字段名不区分大小写地对应环境变量名，例如 ``app_port`` 对应 ``APP_PORT``。
    ``.env.example`` 中存在但本类尚未声明的变量会被忽略（``extra="ignore"``），
    以便后续阶段逐步接入，而不必一次声明全部配置。
    """

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- 应用基础配置 ---
    app_env: str = "development"
    app_name: str = "ARGUS API"
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    log_level: str = "INFO"

    # --- CORS ---
    # 允许跨域访问的来源，多个用英文逗号分隔。
    # 默认值指向 Vite 开发服务器，使本地开发开箱可用，且不涉及通配符。
    # 留空表示不启用 CORS 中间件。
    cors_allow_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- 扫描输入上限 ---
    # 直接提交的代码文本长度上限（字符）。
    # 约束在这里集中定义，避免在 schema 或路由中散落硬编码数字。
    max_source_code_chars: int = Field(default=200_000, gt=0)
    # 单个上传文件大小上限（字节），默认 1 MB。由阶段 5 的上传接口使用。
    max_upload_size_bytes: int = Field(default=1024 * 1024, gt=0)

    @field_validator("cors_allow_origins")
    @classmethod
    def _reject_wildcard_origin(cls, value: str) -> str:
        """拒绝通配符来源，防止把 API 暴露给任意站点。

        课程开发环境中应显式列出允许的来源，而不是图方便写 ``*``。
        """
        if "*" in value:
            raise ValueError(
                "CORS_ALLOW_ORIGINS 不允许包含通配符 '*'，请显式列出允许的来源"
                "（例如 http://localhost:5173）。"
            )
        return value

    @property
    def cors_origins(self) -> list[str]:
        """把逗号分隔的来源字符串解析为列表，并去掉空项与首尾空白。"""
        return [origin.strip() for origin in self.cors_allow_origins.split(",") if origin.strip()]

    @property
    def is_development(self) -> bool:
        return self.app_env.lower() == "development"


@lru_cache
def get_settings() -> Settings:
    """返回进程内缓存的配置实例，避免重复解析 .env。"""
    return Settings()


settings = get_settings()
