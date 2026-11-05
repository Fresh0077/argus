"""扫描历史（SQLite）与相关接口的测试。

覆盖四类行为：

1. 保存 → 列表 → 详情 → 删除的完整往返；
2. **不保存完整源代码**（检查表结构与表中内容）；
3. 分页、非法 ID、缺失记录、数据库不可用与版本不兼容；
4. 历史写入失败不能影响扫描结果。

所有测试都使用临时数据库，不会触碰开发者本机的真实历史文件。
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import PROJECT_ROOT, settings
from app.main import app
from app.schemas.enums import ErrorCode
from app.schemas.scan import ScanRequest, ScanResponse
from app.services import history_service
from app.services.history_service import (
    HistoryDisabledError,
    HistoryNotFoundError,
    HistoryStoreError,
    delete_history,
    get_history,
    list_history,
    save_scan,
)
from app.services.scan_service import run_scan

client = TestClient(app)

SCAN_URL = "/api/v1/scan"
HISTORY_URL = "/api/v1/history"

SQL_SAMPLE = 'query = "SELECT * FROM users WHERE id = " + user_id\n'


@pytest.fixture
def history_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """启用历史，并把数据库指向测试专属的临时文件。"""
    monkeypatch.setattr(settings, "history_enabled", True)
    path = tmp_path / "history" / "argus_history.db"
    monkeypatch.setattr(settings, "history_db_path", str(path))
    return path


def make_scan(
    source_code: str = SQL_SAMPLE,
    *,
    language: str | None = "python",
    filename: str | None = "views.py",
) -> ScanResponse:
    """真实运行一次扫描，得到可写入历史的结果。"""
    return run_scan(
        ScanRequest(source_code=source_code, language=language, filename=filename)
    )


# ---------------------------------------------------------------------------
# 数据库位置
# ---------------------------------------------------------------------------


def test_history_database_path_defaults_to_project_data_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "history_db_path", "")
    assert settings.history_database_path == PROJECT_ROOT / "data" / "argus_history.db"

    # 相对路径按项目根解析，而不是当前工作目录。
    monkeypatch.setattr(settings, "history_db_path", "custom/history.db")
    assert settings.history_database_path == PROJECT_ROOT / "custom" / "history.db"


# ---------------------------------------------------------------------------
# 保存、读取、删除
# ---------------------------------------------------------------------------


def test_save_list_and_read_back(history_db: Path) -> None:
    response = make_scan()
    assert response.findings, "样例代码应至少产生一条候选发现，测试才有意义"

    assert save_scan(response, filename="views.py") is True

    page = list_history(page=1, page_size=20)
    assert page.enabled is True
    assert page.total == 1
    assert page.total_pages == 1
    item = page.items[0]

    assert item.scan_id == response.scan_id
    assert item.filename == "views.py"
    assert item.language == response.detected_language == "python"
    assert item.status is response.status
    assert item.duration_ms == response.duration_ms
    assert item.total_findings == response.summary.total_findings
    assert item.severity_counts == response.summary.severity_counts
    assert item.source_counts == response.summary.source_counts
    # 存的是 UTC 时间，带时区信息；前端负责转本地时间。
    assert item.created_at.utcoffset() is not None

    detail = get_history(response.scan_id)
    assert detail.findings == response.findings
    assert detail.analyzer_status == response.analyzer_status


def test_delete_removes_record(history_db: Path) -> None:
    response = make_scan()
    assert save_scan(response, filename=None) is True

    assert delete_history(response.scan_id) is True
    assert list_history(page=1, page_size=20).total == 0

    with pytest.raises(HistoryNotFoundError):
        get_history(response.scan_id)
    # 再删一次返回 False，而不是抛异常——路由层据此返回 404。
    assert delete_history(response.scan_id) is False


def test_missing_record_raises_not_found(history_db: Path) -> None:
    missing_id = "0" * 32
    with pytest.raises(HistoryNotFoundError):
        get_history(missing_id)
    assert delete_history(missing_id) is False


# ---------------------------------------------------------------------------
# 不保存完整源代码
# ---------------------------------------------------------------------------


def test_database_schema_has_no_source_code_column(history_db: Path) -> None:
    save_scan(make_scan(), filename="views.py")

    with sqlite3.connect(history_db) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(scan_history)")
        }
    assert "source_code" not in columns
    assert columns  # 表确实存在且非空


def test_source_body_is_not_written_to_database(history_db: Path) -> None:
    marker = "ARGUS_MARKER_MUST_NOT_BE_STORED"
    source = f'message = "{marker}"\nprint(message)\n'
    response = make_scan(source, language="python", filename="benign.py")
    assert response.summary.total_findings == 0

    assert save_scan(response, filename="benign.py") is True

    # 连接数据库（会同时读到 WAL 中的内容），把整行内容拼起来检查。
    # 只要有任何一列保存了源码正文，标记就会出现在这里。
    with sqlite3.connect(history_db) as connection:
        rows = connection.execute("SELECT * FROM scan_history").fetchall()
    assert marker not in repr(rows)

    detail = get_history(response.scan_id)
    assert "source_code" not in detail.model_dump()


# ---------------------------------------------------------------------------
# 分页与参数校验
# ---------------------------------------------------------------------------


def test_pagination_returns_disjoint_pages(history_db: Path) -> None:
    scan_ids = []
    for _ in range(5):
        response = make_scan()
        assert save_scan(response, filename="views.py") is True
        scan_ids.append(response.scan_id)

    first = list_history(page=1, page_size=2)
    second = list_history(page=2, page_size=2)
    third = list_history(page=3, page_size=2)
    beyond = list_history(page=4, page_size=2)

    assert first.total == second.total == 5
    assert first.total_pages == 3
    assert len(first.items) == len(second.items) == 2
    assert len(third.items) == 1
    assert beyond.items == []
    assert beyond.total == 5

    seen = {item.scan_id for page in (first, second, third) for item in page.items}
    assert seen == set(scan_ids)


@pytest.mark.parametrize(
    ("page", "page_size"),
    [(0, 20), (-1, 20), (1, 0), (1, -5), (1, history_service.HISTORY_PAGE_SIZE_MAX + 1)],
)
def test_invalid_pagination_is_rejected(
    history_db: Path, page: int, page_size: int
) -> None:
    with pytest.raises(ValueError):
        list_history(page=page, page_size=page_size)


# ---------------------------------------------------------------------------
# 关闭、损坏与版本不兼容
# ---------------------------------------------------------------------------


def test_disabled_history_does_not_touch_database(tmp_path: Path) -> None:
    # conftest 已把 history_enabled 设为 False。
    assert settings.history_enabled is False

    page = list_history(page=1, page_size=20)
    assert page.enabled is False
    assert page.items == []
    assert page.total == 0
    assert page.total_pages == 0

    response = make_scan()
    assert save_scan(response, filename="views.py") is False

    with pytest.raises(HistoryDisabledError):
        get_history(response.scan_id)
    with pytest.raises(HistoryDisabledError):
        delete_history(response.scan_id)

    assert not (tmp_path / "argus_history.db").exists()


def test_newer_schema_version_is_rejected(history_db: Path) -> None:
    history_db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(history_db) as connection:
        connection.execute(
            "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '99')"
        )
        connection.commit()

    with pytest.raises(HistoryStoreError):
        list_history(page=1, page_size=20)


def test_corrupted_detail_raises_store_error(history_db: Path) -> None:
    response = make_scan()
    assert save_scan(response, filename="views.py") is True

    with sqlite3.connect(history_db) as connection:
        connection.execute(
            "UPDATE scan_history SET findings_json = ? WHERE scan_id = ?",
            ("not-json", response.scan_id),
        )
        connection.commit()

    # 列表不读取 findings，仍然可用；只有详情会报错。
    assert list_history(page=1, page_size=20).total == 1
    with pytest.raises(HistoryStoreError):
        get_history(response.scan_id)


def test_save_failure_is_swallowed(
    history_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 把数据库路径指向一个目录：SQLite 无法把目录当作数据库文件打开。
    blocked = history_db.parent
    blocked.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "history_db_path", str(blocked))

    response = make_scan()
    assert save_scan(response, filename="views.py") is False

    with pytest.raises(HistoryStoreError):
        list_history(page=1, page_size=20)


# ---------------------------------------------------------------------------
# HTTP 接口
# ---------------------------------------------------------------------------


def test_scan_writes_history_and_api_round_trip(history_db: Path) -> None:
    scan_response = client.post(
        SCAN_URL,
        json={
            "source_code": SQL_SAMPLE,
            "language": "python",
            "filename": "views.py",
        },
    )
    assert scan_response.status_code == 200
    scan_body = scan_response.json()
    scan_id = scan_body["scan_id"]

    list_response = client.get(HISTORY_URL)
    assert list_response.status_code == 200
    list_body = list_response.json()
    assert list_body["enabled"] is True
    assert list_body["total"] == 1
    assert list_body["items"][0]["scan_id"] == scan_id
    assert list_body["items"][0]["filename"] == "views.py"
    # 列表不搬运发现明细。
    assert "findings" not in list_body["items"][0]

    detail_response = client.get(f"{HISTORY_URL}/{scan_id}")
    assert detail_response.status_code == 200
    detail_body = detail_response.json()
    assert detail_body["scan_id"] == scan_id
    assert len(detail_body["findings"]) == scan_body["summary"]["total_findings"]
    assert detail_body["analyzer_status"] == scan_body["analyzer_status"]
    assert "source_code" not in detail_body

    delete_response = client.delete(f"{HISTORY_URL}/{scan_id}")
    assert delete_response.status_code == 204
    assert delete_response.content == b""

    assert client.get(f"{HISTORY_URL}/{scan_id}").status_code == 404
    second_delete = client.delete(f"{HISTORY_URL}/{scan_id}")
    assert second_delete.status_code == 404
    assert second_delete.json()["error"]["code"] == ErrorCode.HISTORY_NOT_FOUND.value


def test_upload_history_records_encoding_and_filename(history_db: Path) -> None:
    upload = client.post(
        "/api/v1/scan/upload",
        files={"file": ("views.py", SQL_SAMPLE.encode("utf-8"), "text/x-python")},
    )
    assert upload.status_code == 200
    scan_id = upload.json()["scan_id"]

    detail = client.get(f"{HISTORY_URL}/{scan_id}").json()
    assert detail["filename"] == "views.py"
    assert detail["source_encoding"] == "utf-8"


@pytest.mark.parametrize(
    "query",
    ["page=0", "page=-1", "page_size=0", "page_size=101", "page=abc", "page_size=abc"],
)
def test_history_list_rejects_invalid_pagination(history_db: Path, query: str) -> None:
    response = client.get(f"{HISTORY_URL}?{query}")
    assert response.status_code == 422


@pytest.mark.parametrize(
    "scan_id",
    ["abc", "A" * 32, "0" * 31, "0" * 33, "0" * 31 + "g"],
)
def test_history_detail_rejects_invalid_scan_id(
    history_db: Path, scan_id: str
) -> None:
    assert client.get(f"{HISTORY_URL}/{scan_id}").status_code == 422
    assert client.delete(f"{HISTORY_URL}/{scan_id}").status_code == 422


def test_history_api_when_disabled() -> None:
    list_response = client.get(HISTORY_URL)
    assert list_response.status_code == 200
    assert list_response.json()["enabled"] is False
    assert list_response.json()["items"] == []

    scan_id = "0" * 32
    detail_response = client.get(f"{HISTORY_URL}/{scan_id}")
    assert detail_response.status_code == 503
    assert detail_response.json()["error"]["code"] == ErrorCode.HISTORY_DISABLED.value

    delete_response = client.delete(f"{HISTORY_URL}/{scan_id}")
    assert delete_response.status_code == 503
    assert delete_response.json()["error"]["code"] == ErrorCode.HISTORY_DISABLED.value


def test_scan_survives_history_database_failure(
    history_db: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    monkeypatch.setattr(settings, "history_db_path", str(blocked))

    scan_response = client.post(
        SCAN_URL,
        json={"source_code": "x = 1\n", "language": "python"},
    )
    # 历史写入失败不能影响扫描本身。
    assert scan_response.status_code == 200
    body = scan_response.json()
    assert body["scan_id"]
    assert body["summary"]["total_findings"] == 0

    history_response = client.get(HISTORY_URL)
    assert history_response.status_code == 503
    error = history_response.json()["error"]
    assert error["code"] == ErrorCode.HISTORY_UNAVAILABLE.value
    # 错误信息不得泄漏数据库路径或 SQL 细节。
    assert str(blocked) not in history_response.text
    assert "sqlite" not in history_response.text.lower()


def test_history_responses_do_not_contain_source_body(history_db: Path) -> None:
    marker = "ARGUS_MARKER_MUST_NOT_APPEAR_IN_API"
    scan = client.post(
        SCAN_URL,
        json={
            "source_code": f'message = "{marker}"\nprint(message)\n',
            "language": "python",
        },
    )
    scan_id = scan.json()["scan_id"]

    assert marker not in client.get(HISTORY_URL).text
    assert marker not in client.get(f"{HISTORY_URL}/{scan_id}").text
