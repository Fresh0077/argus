"""测试全局配置。

扫描接口在返回前会尝试写入历史。如果不在测试中隔离，
`POST /api/v1/scan` 的用例会把数据写进开发者本机的真实数据库文件。

因此这里默认关闭历史并把路径指到临时目录；历史相关测试会在自己的
fixture 中重新打开并指定临时路径。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def _isolate_history_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """所有测试默认不触碰真实的历史数据库。"""
    monkeypatch.setattr(settings, "history_enabled", False)
    monkeypatch.setattr(settings, "history_db_path", str(tmp_path / "argus_history.db"))
