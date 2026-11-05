"""本地扫描历史的 SQLite 读写。

为什么用标准库 ``sqlite3`` 而不是 ORM / 数据库服务：

- 历史功能只面对单机、单用户、数据量很小的场景；
- 少一个依赖就少一处安装失败的可能，课程演示也更稳定。

安全与数据边界（详见 docs/history.md）：

- **只保存扫描元数据、摘要、候选发现与分析器状态，不保存完整源代码。**
  表中不存在存放源码正文的列；发现里的 ``evidence`` 是分析器给出的最小片段。
- 数据库路径来自服务端配置，不接受任何请求参数；
- 数据库错误对外的说明是固定文案，不包含文件路径或 SQL 语句。

数据库版本：``schema_meta.schema_version`` 当前为 1。
若文件由更新版本的程序创建（version > 1），读写会报"不可用"而不是
按旧结构强读——那可能读出错误数据。
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from app.core.config import settings
from app.schemas.enums import FindingSource
from app.schemas.finding import Finding
from app.schemas.history import (
    HISTORY_PAGE_SIZE_MAX,
    HistoryDetail,
    HistoryItem,
    HistoryListResponse,
)
from app.schemas.scan import AnalyzerStatus, ScanResponse, SeverityCounts

logger = logging.getLogger(__name__)

#: 当前程序支持的数据库结构版本。
SCHEMA_VERSION = 1

_COLUMNS = (
    "scan_id, created_at, filename, language, status, source_encoding, "
    "duration_ms, total_findings, severity_counts_json, source_counts_json, "
    "findings_json, analyzer_status_json"
)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    scan_id              TEXT PRIMARY KEY,
    created_at           TEXT NOT NULL,
    filename             TEXT,
    language             TEXT,
    status               TEXT NOT NULL,
    source_encoding      TEXT,
    duration_ms          INTEGER NOT NULL,
    total_findings       INTEGER NOT NULL,
    severity_counts_json TEXT NOT NULL,
    source_counts_json   TEXT NOT NULL,
    findings_json        TEXT NOT NULL,
    analyzer_status_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_history_created_at
    ON scan_history (created_at DESC);
"""


class HistoryError(Exception):
    """历史功能相关错误的基类。"""


class HistoryDisabledError(HistoryError):
    """服务端配置关闭了历史功能。"""


class HistoryNotFoundError(HistoryError):
    """请求的扫描记录不存在。"""


class HistoryStoreError(HistoryError):
    """数据库不可用、版本不兼容或记录内容损坏。

    ``message`` 是可直接展示给用户的安全文案，不含路径与 SQL 细节。
    """


def _validate_pagination(page: int, page_size: int) -> None:
    """校验分页参数。

    路由层已用 ``Query(ge=...)`` 做过一次校验；这里再校验一次，
    是为了让直接调用服务层的代码（测试、脚本）也不会传入非法值。
    """
    if page < 1:
        raise ValueError("page 必须大于等于 1")
    if not 1 <= page_size <= HISTORY_PAGE_SIZE_MAX:
        raise ValueError(f"page_size 必须在 1 到 {HISTORY_PAGE_SIZE_MAX} 之间")


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    """打开数据库连接、确保表结构存在，并在离开时关闭。

    每次操作使用独立连接而不是全局连接：FastAPI 的同步路由运行在线程池里，
    共享连接需要额外处理线程安全；本地 SQLite 的建连开销可以忽略。
    """
    path = settings.history_database_path
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(path), timeout=5.0)
    except (OSError, sqlite3.Error) as exc:
        logger.warning("扫描历史数据库无法打开：%s", type(exc).__name__)
        raise HistoryStoreError("扫描历史数据库暂时不可用，请稍后重试。") from exc

    try:
        connection.row_factory = sqlite3.Row
        # WAL 让读与写不互相阻塞；失败时 SQLite 会退回默认模式，不视为错误。
        try:
            connection.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass
        _ensure_schema(connection)
        connection.commit()
        yield connection
    except sqlite3.Error as exc:
        logger.warning("扫描历史数据库操作失败：%s", type(exc).__name__)
        raise HistoryStoreError("扫描历史数据库暂时不可用，请稍后重试。") from exc
    finally:
        connection.close()


def _ensure_schema(connection: sqlite3.Connection) -> None:
    """建表并检查结构版本。"""
    connection.executescript(_SCHEMA_SQL)

    row = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        return

    try:
        version = int(row["value"])
    except (TypeError, ValueError) as exc:
        raise HistoryStoreError("扫描历史数据库的版本信息无法识别。") from exc

    if version > SCHEMA_VERSION:
        raise HistoryStoreError(
            "扫描历史数据库由更新版本的程序创建，当前版本无法读取。"
            "请升级程序或改用新的数据库文件。"
        )
    # version < SCHEMA_VERSION 时应在未来版本中逐级迁移。
    # 目前只有 v1，无需迁移，保留这段判断以说明升级路径。


def save_scan(response: ScanResponse, *, filename: str | None) -> bool:
    """把一次扫描的结果写入历史。

    参数：
        response: 已经完成的扫描响应。
        filename: 调用方提供的展示用文件名；没有则传 None。

    返回：
        True 表示已写入；False 表示历史功能被关闭或写入失败。

    **写入失败不会抛异常**：历史只是附加能力，不能因为磁盘或数据库问题
    让用户丢失本次扫描结果。失败只写一条不含源码与路径的服务端日志。
    """
    if not settings.history_enabled:
        return False

    created_at = datetime.now(timezone.utc)
    params = (
        response.scan_id,
        created_at.isoformat(timespec="seconds"),
        filename,
        response.detected_language,
        response.status.value,
        response.source_encoding,
        response.duration_ms,
        response.summary.total_findings,
        json.dumps(
            response.summary.severity_counts.model_dump(mode="json"),
            ensure_ascii=False,
        ),
        json.dumps(
            {key.value: value for key, value in response.summary.source_counts.items()},
            ensure_ascii=False,
        ),
        json.dumps(
            [item.model_dump(mode="json") for item in response.findings],
            ensure_ascii=False,
        ),
        json.dumps(
            [item.model_dump(mode="json") for item in response.analyzer_status],
            ensure_ascii=False,
        ),
    )

    try:
        with _connection() as connection:
            connection.execute(
                f"INSERT OR REPLACE INTO scan_history ({_COLUMNS}) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params,
            )
            connection.commit()
    except HistoryStoreError:
        # _connection 已记录失败类型；这里不再重复记录，也不向外抛出。
        return False
    return True


def list_history(page: int, page_size: int) -> HistoryListResponse:
    """分页读取扫描历史，按时间从新到旧排列。

    历史功能关闭时不访问数据库，返回 ``enabled=False`` 的空列表——
    这不是错误，前端应提示"功能未启用"而不是"没有记录"。
    """
    _validate_pagination(page, page_size)

    if not settings.history_enabled:
        return HistoryListResponse(
            enabled=False,
            items=[],
            total=0,
            page=page,
            page_size=page_size,
            total_pages=0,
        )

    offset = (page - 1) * page_size
    with _connection() as connection:
        total = int(
            connection.execute("SELECT COUNT(*) AS total FROM scan_history").fetchone()[
                "total"
            ]
        )
        rows = connection.execute(
            f"SELECT {_COLUMNS} FROM scan_history "
            "ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
            (page_size, offset),
        ).fetchall()

    items = [_row_to_item(row) for row in rows]
    total_pages = (total + page_size - 1) // page_size if total else 0
    return HistoryListResponse(
        enabled=True,
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


def get_history(scan_id: str) -> HistoryDetail:
    """读取一条扫描历史的完整结果。

    异常：
        HistoryDisabledError: 历史功能关闭。
        HistoryNotFoundError: 记录不存在。
        HistoryStoreError: 数据库不可用或记录损坏。
    """
    if not settings.history_enabled:
        raise HistoryDisabledError("扫描历史功能未启用。")

    with _connection() as connection:
        row = connection.execute(
            f"SELECT {_COLUMNS} FROM scan_history WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()

    if row is None:
        raise HistoryNotFoundError("扫描记录不存在。")
    return _row_to_detail(row)


def delete_history(scan_id: str) -> bool:
    """删除一条扫描历史。

    返回 True 表示确实删掉了一条记录，False 表示记录本来就不存在。
    """
    if not settings.history_enabled:
        raise HistoryDisabledError("扫描历史功能未启用。")

    with _connection() as connection:
        cursor = connection.execute(
            "DELETE FROM scan_history WHERE scan_id = ?", (scan_id,)
        )
        connection.commit()
        return cursor.rowcount > 0


def _row_to_item(row: sqlite3.Row) -> HistoryItem:
    """把数据库行转换为列表项，并校验存储的内容仍可解析。"""
    severity_counts, source_counts = _parse_summary(row)
    try:
        return HistoryItem(
            scan_id=row["scan_id"],
            created_at=_parse_created_at(row["created_at"]),
            filename=row["filename"],
            language=row["language"],
            status=row["status"],
            source_encoding=row["source_encoding"],
            duration_ms=row["duration_ms"],
            total_findings=row["total_findings"],
            severity_counts=severity_counts,
            source_counts=source_counts,
        )
    except ValidationError as exc:
        logger.warning("扫描历史记录内容无法解析：%s", type(exc).__name__)
        raise HistoryStoreError("扫描历史记录的内容无法读取，可能已损坏。") from exc


def _row_to_detail(row: sqlite3.Row) -> HistoryDetail:
    """把数据库行转换为详情，包含发现与分析器状态。"""
    item = _row_to_item(row)
    try:
        raw_findings: Any = json.loads(row["findings_json"])
        raw_status: Any = json.loads(row["analyzer_status_json"])
        findings = [Finding.model_validate(entry) for entry in raw_findings]
        analyzer_status = [
            AnalyzerStatus.model_validate(entry) for entry in raw_status
        ]
    except (ValueError, TypeError, ValidationError) as exc:
        logger.warning("扫描历史记录内容无法解析：%s", type(exc).__name__)
        raise HistoryStoreError("扫描历史记录的内容无法读取，可能已损坏。") from exc

    return HistoryDetail(
        **item.model_dump(),
        findings=findings,
        analyzer_status=analyzer_status,
    )


def _parse_summary(
    row: sqlite3.Row,
) -> tuple[SeverityCounts, dict[FindingSource, int]]:
    """解析摘要中的严重等级与来源计数。"""
    try:
        severity_counts = SeverityCounts.model_validate(
            json.loads(row["severity_counts_json"])
        )
        raw_sources = json.loads(row["source_counts_json"])
        source_counts = {
            FindingSource(key): int(value) for key, value in raw_sources.items()
        }
    except (ValueError, TypeError, AttributeError, ValidationError) as exc:
        logger.warning("扫描历史摘要无法解析：%s", type(exc).__name__)
        raise HistoryStoreError("扫描历史记录的内容无法读取，可能已损坏。") from exc
    return severity_counts, source_counts


def _parse_created_at(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        logger.warning("扫描历史时间无法解析：%s", type(exc).__name__)
        raise HistoryStoreError("扫描历史记录的时间信息无法读取。") from exc
