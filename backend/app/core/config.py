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

from pydantic import Field, SecretStr, field_validator
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

    # --- 可选静态分析器：Semgrep ---
    # Semgrep 未安装时值为空也无妨——分析器会报告 unavailable，其余功能不受影响。
    # 这里只允许指定可执行文件名或路径，不接受任何会被拼进命令行的参数：
    # 规则集路径固定为仓库内置的那一份（见 analyzers/semgrep/catalog.py）。
    semgrep_command: str = "semgrep"
    # 子进程超时（秒）。上限 300 秒：再长就该怀疑输入规模或环境问题了，
    # 而一次扫描让调用方等待五分钟以上也不合理。
    semgrep_timeout_seconds: float = Field(default=30.0, gt=0, le=300)

    # --- 可选 LLM 分析器 ---
    # 总开关。为 False 时即使请求里 enable_llm=True 也不会发起模型调用——
    # 这是让"代码不离开本机"成为一个可强制执行的配置，而不是一句口头承诺。
    llm_enabled: bool = False
    # OpenAI-compatible 服务地址，例如 https://api.example.com/v1。
    # 只接受 http(s)，由客户端再次校验。
    llm_base_url: str = ""
    # 用 SecretStr 承接：repr/日志里显示为 **********，避免密钥被意外打印。
    llm_api_key: SecretStr = SecretStr("")
    llm_model: str = ""
    llm_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    llm_max_output_tokens: int = Field(default=2_048, gt=0, le=32_000)
    # 额外重试次数，只对 429 / 5xx / 超时 / 网络错误生效。
    # 上限 5：再多的重试只会让用户等更久，且放大对服务商的压力。
    llm_max_retries: int = Field(default=2, ge=0, le=5)
    # 发送给模型的代码字符上限（含行号前缀）。超长代码按行截断，
    # 并在提示词里写明实际发送范围。
    llm_max_input_chars: int = Field(default=12_000, gt=0, le=200_000)

    # --- 上传文件类型白名单 ---
    # 允许上传的扩展名，多个用英文逗号分隔，可带前导点（".py" 与 "py" 等价）。
    #
    # 集中在此处而非写在路由中，是为了让"支持哪些文件类型"只有一个答案：
    # 路由、测试与文档都从这里取值，不会出现三处不一致。
    # 判断依据**只有扩展名**——客户端提交的 MIME 类型由调用方随意填写，不作为安全依据。
    allowed_file_extensions: str = "py,js,jsx,ts,tsx,php,java,go,rb,html,vue"

    @field_validator("allowed_file_extensions")
    @classmethod
    def _normalize_extensions(cls, value: str) -> str:
        """归一化扩展名列表，并拒绝空列表。

        允许列表为空意味着任何上传都会被拒绝，这几乎一定是配置失误，
        与其让它表现为"所有文件都不支持"，不如在启动时直接失败。
        """
        items: list[str] = []
        for raw in value.split(","):
            item = raw.strip().lower().lstrip(".")
            if item and item not in items:
                items.append(item)
        if not items:
            raise ValueError(
                "ALLOWED_FILE_EXTENSIONS 不能为空，至少需要配置一个扩展名（例如 py,js）。"
            )
        return ",".join(items)

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
    def allowed_extensions(self) -> frozenset[str]:
        """允许的扩展名集合（不含前导点，全小写）。

        返回 frozenset 而非 list：调用方只做成员判断，且不应在别处修改这份白名单。
        """
        return frozenset(self.allowed_file_extensions.split(","))

    @property
    def is_development(self) -> bool:
        return self.app_env.lower() == "development"


@lru_cache
def get_settings() -> Settings:
    """返回进程内缓存的配置实例，避免重复解析 .env。"""
    return Settings()


settings = get_settings()
