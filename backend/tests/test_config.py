"""配置模块测试。

重点验证安全相关的配置约束：CORS 不得使用通配符。
"""

import pytest
from pydantic import ValidationError

from app.core.config import BACKEND_DIR, PROJECT_ROOT, Settings
from app.core.config import settings as app_settings

# --- 路径解析 ---


def test_project_root_is_repo_root() -> None:
    """配置模块应能独立于当前工作目录定位到项目根目录。"""
    assert BACKEND_DIR.name == "backend"
    assert (PROJECT_ROOT / "backend").is_dir()
    assert (PROJECT_ROOT / ".env.example").is_file()


# --- CORS 解析 ---


def test_cors_origins_are_split_and_trimmed() -> None:
    """逗号分隔的来源应被正确拆分，空项与空白应被剔除。"""
    config = Settings(cors_allow_origins=" http://a.test , http://b.test ,")

    assert config.cors_origins == ["http://a.test", "http://b.test"]


def test_empty_cors_origins_disables_cors() -> None:
    """留空表示不启用 CORS，而不是回退到通配符。"""
    config = Settings(cors_allow_origins="")

    assert config.cors_origins == []


# --- 安全约束 ---


def test_default_cors_origins_contain_no_wildcard() -> None:
    """默认配置不得包含通配符。"""
    assert "*" not in app_settings.cors_origins


def test_wildcard_cors_origin_is_rejected() -> None:
    """配置 '*' 应直接报错，防止 API 暴露给任意站点。"""
    with pytest.raises(ValidationError, match="通配符"):
        Settings(cors_allow_origins="*")


def test_wildcard_mixed_with_valid_origin_is_rejected() -> None:
    """只要包含通配符就应拒绝，不能因为同时写了合法来源就放过。"""
    with pytest.raises(ValidationError, match="通配符"):
        Settings(cors_allow_origins="http://localhost:5173,*")


# --- 默认值 ---


def test_defaults_are_local_development_friendly() -> None:
    """默认配置应面向本地开发，且绑定回环地址而不是全网卡。"""
    config = Settings()

    assert config.app_env == "development"
    assert config.is_development is True
    assert config.app_host == "127.0.0.1"
    assert config.app_port == 8000
