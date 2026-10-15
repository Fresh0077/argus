"""接口测试：根路由、健康检查与 CORS 行为。"""

from fastapi.testclient import TestClient

from app import __version__
from app.main import app

client = TestClient(app)


# --- 正常输入 ---


def test_root_returns_service_info() -> None:
    """根路由应返回服务说明与常用入口。"""
    response = client.get("/")

    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "ARGUS API"
    assert body["version"] == __version__
    assert body["health"] == "/api/v1/health"
    assert body["docs"] == "/docs"


def test_health_check_returns_ok() -> None:
    """健康检查应返回 ok 状态、服务名与版本。"""
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "ARGUS API"
    assert body["version"] == __version__
    assert "environment" in body


def test_openapi_schema_is_available() -> None:
    """OpenAPI 文档应可生成，且包含已注册的接口。"""
    response = client.get("/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/" in paths
    assert "/api/v1/health" in paths


# --- 安全边界 ---


def test_health_check_does_not_leak_internal_details() -> None:
    """健康检查响应不得包含路径、密钥或异常栈等内部信息。"""
    body = client.get("/api/v1/health").text.lower()

    for leaked in ("traceback", "api_key", "apikey", "password", "secret", "c:\\", "d:\\"):
        assert leaked not in body, f"响应中不应出现 {leaked!r}"


def test_root_does_not_leak_internal_details() -> None:
    """根路由响应同样不应暴露内部信息。"""
    body = client.get("/").text.lower()

    for leaked in ("traceback", "api_key", "password", "c:\\", "d:\\"):
        assert leaked not in body, f"响应中不应出现 {leaked!r}"


# --- 非法输入 ---


def test_unknown_route_returns_404() -> None:
    """不存在的路由应返回 404，而不是 500。"""
    response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404


def test_health_check_rejects_wrong_method() -> None:
    """健康检查只接受 GET，POST 应返回 405。"""
    response = client.post("/api/v1/health")

    assert response.status_code == 405


# --- CORS ---


def test_cors_preflight_allows_vite_dev_server() -> None:
    """来自 Vite 开发服务器的预检请求应被允许。"""
    response = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_cors_preflight_rejects_unknown_origin() -> None:
    """未列入白名单的来源不应获得 CORS 许可头。"""
    response = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert "access-control-allow-origin" not in response.headers
