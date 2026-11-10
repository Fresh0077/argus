"""跨站来源校验与安全边界的接口测试。

CORS 只限制浏览器读取响应，不能阻止第三方页面发起简单请求。
这里验证会改变状态/产生费用的接口会拒绝未配置的浏览器来源。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.schemas.enums import ErrorCode

client = TestClient(app)

SCAN_URL = "/api/v1/scan"
SCAN_BODY = {"source_code": "x = 1\n", "language": "python"}


def test_scan_rejects_disallowed_browser_origin() -> None:
    response = client.post(
        SCAN_URL,
        json=SCAN_BODY,
        headers={"Origin": "http://evil.example"},
    )

    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == ErrorCode.FORBIDDEN.value
    assert "来源" in error["message"]


def test_scan_rejects_null_origin() -> None:
    response = client.post(SCAN_URL, json=SCAN_BODY, headers={"Origin": "null"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == ErrorCode.FORBIDDEN.value


def test_scan_allows_configured_frontend_origin() -> None:
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
        response = client.post(
            SCAN_URL, json=SCAN_BODY, headers={"Origin": origin}
        )
        assert response.status_code == 200


def test_scan_allows_same_origin_and_non_browser_clients() -> None:
    # Swagger 页面与 API 同源；命令行客户端通常不带 Origin。
    assert (
        client.post(
            SCAN_URL, json=SCAN_BODY, headers={"Origin": "http://testserver"}
        ).status_code
        == 200
    )
    assert client.post(SCAN_URL, json=SCAN_BODY).status_code == 200


def test_repair_rejects_disallowed_origin_before_llm_call() -> None:
    response = client.post(
        "/api/v1/repair",
        json={
            "source_code": "x = 1\n",
            "language": "python",
            "finding": {
                "id": "f1",
                "title": "测试发现",
                "vulnerability_type": "sql_injection",
                "severity": "medium",
                "description": "测试",
                "evidence": "x = 1",
                "line_start": 1,
                "line_end": 1,
                "recommendation": "测试",
                "confidence": 0.5,
                "source": "static_rule",
            },
        },
        headers={"Origin": "http://evil.example"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == ErrorCode.FORBIDDEN.value


def test_delete_history_rejects_disallowed_origin() -> None:
    response = client.delete(
        f"/api/v1/history/{'0' * 32}",
        headers={"Origin": "http://evil.example"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == ErrorCode.FORBIDDEN.value
