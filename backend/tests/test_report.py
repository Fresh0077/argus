"""扫描报告导出的测试。

重点：

1. 报告内容与真实历史详情一致，不混入 UI 或伪造数据；
2. 不含完整源代码、API key 或路径；
3. Markdown 对用户可控文本做转义，证据围栏不会被内容提前闭合；
4. 历史关闭、记录不存在、数据库不可用、格式非法时返回正确错误。
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.schemas.enums import (
    AnalyzerName,
    AnalyzerState,
    ErrorCode,
    FindingSource,
    ScanStatus,
    Severity,
)
from app.schemas.finding import Finding
from app.schemas.history import HistoryDetail
from app.schemas.report import ReportFormat
from app.schemas.scan import AnalyzerStatus, ScanRequest, ScanResponse, SeverityCounts
from app.services.history_service import get_history, save_scan
from app.services.report_service import build_report, export_report, render_markdown
from app.services.scan_service import run_scan

client = TestClient(app)

SQL_SAMPLE = 'query = "SELECT * FROM users WHERE id = " + user_id\n'


@pytest.fixture
def history_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """启用历史，并把数据库指向测试专属的临时文件。"""
    monkeypatch.setattr(settings, "history_enabled", True)
    path = tmp_path / "report" / "argus_history.db"
    monkeypatch.setattr(settings, "history_db_path", str(path))
    return path


def stored_scan(
    source_code: str = SQL_SAMPLE, *, filename: str | None = "views.py"
) -> ScanResponse:
    response = run_scan(
        ScanRequest(source_code=source_code, language="python", filename=filename)
    )
    assert save_scan(response, filename=filename) is True
    return response


def report_url(scan_id: str, report_format: str = "json") -> str:
    return f"/api/v1/history/{scan_id}/report?format={report_format}"


# ---------------------------------------------------------------------------
# 内容与真实结果一致
# ---------------------------------------------------------------------------


def test_json_report_matches_history_detail(history_db: Path) -> None:
    scan = stored_scan()
    detail = get_history(scan.scan_id)

    response = client.get(report_url(scan.scan_id))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()

    assert body["report_version"] == 1
    assert body["scan"]["scan_id"] == detail.scan_id
    # Pydantic 把 UTC 序列化为 "Z"，比较时间点而不是字符串写法。
    created_at = datetime.fromisoformat(
        body["scan"]["created_at"].replace("Z", "+00:00")
    )
    assert created_at == detail.created_at
    assert body["scan"]["filename"] == detail.filename
    assert body["scan"]["language"] == detail.language
    assert body["scan"]["status"] == detail.status.value
    assert body["scan"]["summary"]["total_findings"] == detail.total_findings
    assert body["findings"] == [
        finding.model_dump(mode="json") for finding in detail.findings
    ]
    assert body["analyzer_status"] == [
        status.model_dump(mode="json") for status in detail.analyzer_status
    ]
    assert len(body["limitations"]) > 0
    assert "source_code" not in response.text


def test_markdown_report_contains_required_sections(history_db: Path) -> None:
    scan = stored_scan()

    response = client.get(report_url(scan.scan_id, "markdown"))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    text = response.text
    assert text.startswith("# ARGUS 扫描报告")
    assert scan.scan_id in text
    assert "## 扫描信息" in text
    assert "## 摘要" in text
    assert "## 分析器状态" in text
    assert "## 候选发现" in text
    assert "## 局限说明" in text
    assert "未经编译、执行或测试" in text


def test_report_only_contains_requested_scan(history_db: Path) -> None:
    first = stored_scan(SQL_SAMPLE, filename="first.py")
    second = stored_scan("x = 1\n", filename="second.py")

    response = client.get(report_url(first.scan_id, "markdown"))

    assert first.scan_id in response.text
    assert second.scan_id not in response.text
    assert "second.py" not in response.text


# ---------------------------------------------------------------------------
# 敏感信息
# ---------------------------------------------------------------------------


def test_report_does_not_contain_source_body(history_db: Path) -> None:
    marker = "ARGUS_REPORT_MUST_NOT_CONTAIN_SOURCE"
    scan = stored_scan(f'message = "{marker}"\nprint(message)\n', filename="benign.py")

    for report_format in ("json", "markdown"):
        response = client.get(report_url(scan.scan_id, report_format))
        assert response.status_code == 200
        assert marker not in response.text


def test_report_filename_is_generated_and_safe(history_db: Path) -> None:
    scan = stored_scan()

    for report_format, extension in (("json", "json"), ("markdown", "md")):
        response = client.get(report_url(scan.scan_id, report_format))
        disposition = response.headers["content-disposition"]
        expected = f'attachment; filename="argus-report-{scan.scan_id}.{extension}"'
        assert disposition == expected
        assert ".." not in disposition
        assert "/" not in disposition
        assert "\\" not in disposition


# ---------------------------------------------------------------------------
# Markdown 转义
# ---------------------------------------------------------------------------


def _crafted_detail() -> HistoryDetail:
    finding = Finding(
        id="crafted",
        title='<script>alert("x")</script> [link](javascript:alert(1)) | pipe',
        vulnerability_type="xss",
        severity=Severity.HIGH,
        description="<img src=x onerror=alert(1)>\n## 伪标题\n- 伪列表",
        evidence="before ``` after\n# 这不是标题",
        line_start=1,
        line_end=1,
        recommendation="![img](x) `code` **bold**",
        confidence=0.5,
        source=FindingSource.STATIC_RULE,
    )
    return HistoryDetail(
        scan_id="a" * 32,
        created_at=datetime.now(timezone.utc),
        filename="<b>views.py</b>",
        language="python",
        status=ScanStatus.PARTIAL,
        source_encoding=None,
        duration_ms=1,
        total_findings=1,
        severity_counts=SeverityCounts(high=1),
        source_counts={FindingSource.STATIC_RULE: 1},
        findings=[finding],
        analyzer_status=[
            AnalyzerStatus(name=AnalyzerName.RULES, state=AnalyzerState.SUCCESS)
        ],
    )


def test_markdown_escapes_user_controlled_text() -> None:
    text = render_markdown(build_report(_crafted_detail()))

    # HTML 被转义，不会变成可执行标签。
    assert "<script>" not in text
    assert "<img" not in text
    assert "&lt;script&gt;" in text
    assert "&lt;img" in text
    # Markdown 链接/图片语法与表格分隔符被转义。
    assert "[link](" not in text
    assert "![img](" not in text
    assert "\\| pipe" in text
    # 行首标题/列表标记被转义，不会改变文档结构。
    assert "\n## 伪标题" not in text
    assert "\n- 伪列表" not in text
    # 文件名也经过转义。
    assert "<b>views.py</b>" not in text


def test_markdown_evidence_fence_cannot_be_closed_by_content() -> None:
    text = render_markdown(build_report(_crafted_detail()))

    # 证据里有三个连续反引号，围栏必须自动加长到四个。
    assert "````" in text
    assert "before ``` after" in text


# ---------------------------------------------------------------------------
# 错误处理
# ---------------------------------------------------------------------------


def test_invalid_format_returns_422(history_db: Path) -> None:
    scan = stored_scan()
    response = client.get(f"/api/v1/history/{scan.scan_id}/report?format=html")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == ErrorCode.VALIDATION_ERROR.value


def test_invalid_scan_id_returns_422(history_db: Path) -> None:
    assert client.get("/api/v1/history/abc/report").status_code == 422


def test_missing_record_returns_404(history_db: Path) -> None:
    response = client.get(report_url("0" * 32))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == ErrorCode.HISTORY_NOT_FOUND.value


def test_history_disabled_returns_503() -> None:
    # conftest 已关闭历史。
    response = client.get(report_url("0" * 32))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == ErrorCode.HISTORY_DISABLED.value


def test_store_failure_returns_503(
    history_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocked = history_db.parent
    blocked.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "history_db_path", str(blocked))

    response = client.get(report_url("0" * 32))

    assert response.status_code == 503
    assert (
        response.json()["error"]["code"] == ErrorCode.HISTORY_UNAVAILABLE.value
    )
    assert str(blocked) not in response.text
    assert "sqlite" not in response.text.lower()


def test_export_report_service_returns_media_type_and_name(history_db: Path) -> None:
    scan = stored_scan()

    content, media_type, filename = export_report(scan.scan_id, ReportFormat.MARKDOWN)

    assert media_type.startswith("text/markdown")
    assert filename == f"argus-report-{scan.scan_id}.md"
    assert content.startswith("# ARGUS 扫描报告")
