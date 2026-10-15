"""统一错误响应测试。

核心目标有两个：
1. 所有错误路径返回同一套结构，前端可以统一处理；
2. 错误响应**不得泄漏**内部信息，也**不得回显用户提交的源代码**。

其中第 2 点用独立测试验证：FastAPI/Pydantic 默认的 422 响应会把出错的输入
原样放在 ``input`` 字段里返回。对 ``source_code`` 而言，这等于把用户提交的
整段代码复制进错误响应，进而可能被写入访问日志，因此必须确认已被剥离。
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.errors import GENERIC_INTERNAL_MESSAGE, register_exception_handlers
from app.main import app as real_app
from app.schemas.enums import ErrorCode
from app.schemas.errors import ErrorBody, ErrorDetail, ErrorResponse
from app.schemas.scan import ScanRequest

client = TestClient(real_app)

# 与真实应用使用同一套处理器与契约模型，但不向生产路由引入仅为测试而存在的接口。
probe_app = FastAPI()
register_exception_handlers(probe_app)

#: 用于验证「响应不得回显源代码」的标记串。
SECRET_MARKER = "TOTALLY_SECRET_SOURCE_MARKER"


@probe_app.post("/probe/scan")
def _probe_scan(request: ScanRequest) -> dict[str, bool]:
    return {"ok": True}


@probe_app.get("/probe/boom")
def _probe_boom() -> None:
    # 故意在异常消息中放入类似内部路径与密钥的内容，验证它不会外泄。
    raise RuntimeError(r"内部失败 C:\Users\someone\secret\config.py token=sk-should-not-leak")


probe_client = TestClient(probe_app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# 真实应用上的常规错误路径
# ---------------------------------------------------------------------------


def test_unknown_route_returns_structured_error() -> None:
    response = client.get("/api/v1/definitely-not-here")

    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == ErrorCode.NOT_FOUND.value
    assert body["error"]["message"]
    assert body["error"]["details"] == []


def test_wrong_method_returns_structured_error() -> None:
    response = client.post("/api/v1/health")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == ErrorCode.METHOD_NOT_ALLOWED.value


def test_error_response_uses_single_top_level_key() -> None:
    """错误结构固定为 {"error": {...}}，不混入其他顶层字段。"""
    body = client.get("/api/v1/nope").json()

    assert set(body) == {"error"}
    assert set(body["error"]) <= {"code", "message", "details"}


# ---------------------------------------------------------------------------
# 校验失败（422）
# ---------------------------------------------------------------------------


def test_validation_error_has_structured_details() -> None:
    response = probe_client.post("/probe/scan", json={"source_code": "   "})

    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == ErrorCode.VALIDATION_ERROR.value
    assert len(body["error"]["details"]) == 1
    assert body["error"]["details"][0]["field"] == "source_code"
    assert "不能为空" in body["error"]["details"][0]["message"]


def test_validation_error_does_not_echo_submitted_source_code() -> None:
    """超长源代码校验失败时，错误响应不得回显源代码。

    这是最危险的场景：``source_code`` 本身校验失败时，
    Pydantic 原始错误项中的 ``input`` 就是**整段源代码**。
    若原样透传，错误响应会变成源代码的第二份副本，
    并可能被访问日志记录下来。
    """
    oversized = SECRET_MARKER + "a" * (settings.max_source_code_chars + 1)

    response = probe_client.post("/probe/scan", json={"source_code": oversized})

    assert response.status_code == 422
    assert SECRET_MARKER not in response.text
    # 响应体应当很小：只包含错误码、说明与字段名，不携带 200 KB 的输入。
    assert len(response.text) < 1_000


def test_validation_error_does_not_echo_input_for_other_field_failures() -> None:
    """其他字段校验失败时同样不回显原始输入。"""
    response = probe_client.post(
        "/probe/scan",
        json={"source_code": f"x = 1  # {SECRET_MARKER}", "language": "not a language!"},
    )

    assert response.status_code == 422
    assert SECRET_MARKER not in response.text


def test_nested_field_path_is_reported() -> None:
    response = probe_client.post(
        "/probe/scan",
        json={"source_code": "x = 1", "analysis_options": {"enable_llmm": True}},
    )

    assert response.status_code == 422
    fields = [detail["field"] for detail in response.json()["error"]["details"]]
    assert "analysis_options.enable_llmm" in fields


def test_missing_body_is_reported_as_validation_error() -> None:
    response = probe_client.post("/probe/scan")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == ErrorCode.VALIDATION_ERROR.value


def test_malformed_json_is_reported_as_validation_error() -> None:
    response = probe_client.post(
        "/probe/scan",
        content=b"{not valid json",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == ErrorCode.VALIDATION_ERROR.value


def test_validation_detail_message_has_no_pydantic_prefix() -> None:
    """内部前缀 "Value error, " 应被清理，提示更干净。"""
    response = probe_client.post("/probe/scan", json={"source_code": ""})

    message = response.json()["error"]["details"][0]["message"]
    assert not message.startswith("Value error")


# ---------------------------------------------------------------------------
# 校验提示的本地化
# ---------------------------------------------------------------------------


def test_extra_field_message_is_localized() -> None:
    """Pydantic 的英文提示应被替换为中文说明。"""
    response = probe_client.post(
        "/probe/scan",
        json={"source_code": "x = 1", "analysis_options": {"enable_llmm": True}},
    )

    message = response.json()["error"]["details"][0]["message"]
    assert "不支持的字段" in message
    assert "Extra inputs" not in message


def test_pattern_mismatch_message_is_localized_and_keeps_pattern() -> None:
    """本地化后仍要保留具体约束，否则用户不知道该改成什么格式。"""
    response = probe_client.post(
        "/probe/scan", json={"source_code": "x = 1", "language": "not a language!"}
    )

    message = response.json()["error"]["details"][0]["message"]
    assert "格式不合法" in message
    assert "String should match" not in message
    assert "^[a-z0-9+#._-]+$" in message


def test_missing_field_message_is_localized() -> None:
    response = probe_client.post("/probe/scan", json={})

    messages = [detail["message"] for detail in response.json()["error"]["details"]]
    assert any("缺少必填字段" in message for message in messages)


def test_custom_validator_message_is_preserved() -> None:
    """我们自己的校验器已经给出中文说明，不应被模板改写。"""
    response = probe_client.post(
        "/probe/scan", json={"source_code": "x = 1", "filename": "../../etc/passwd"}
    )

    message = response.json()["error"]["details"][0]["message"]
    assert "路径分隔符" in message


# ---------------------------------------------------------------------------
# 未预期异常（500）
# ---------------------------------------------------------------------------


def test_unhandled_exception_returns_generic_message() -> None:
    response = probe_client.get("/probe/boom")

    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == ErrorCode.INTERNAL_ERROR.value
    assert body["error"]["message"] == GENERIC_INTERNAL_MESSAGE


def test_unhandled_exception_does_not_leak_internals() -> None:
    """500 响应不得包含异常原文、堆栈、文件路径或密钥片段。"""
    response = probe_client.get("/probe/boom")
    text = response.text.lower()

    for leaked in ("traceback", "runtimeerror", "sk-should-not-leak", "c:\\", "secret"):
        assert leaked not in text, f"500 响应中不应出现 {leaked!r}"


# ---------------------------------------------------------------------------
# ErrorResponse 模型自身
# ---------------------------------------------------------------------------


def test_error_body_details_default_to_empty_list() -> None:
    body = ErrorBody(code=ErrorCode.NOT_FOUND, message="请求的资源不存在。")

    assert body.details == []


def test_error_response_rejects_empty_message() -> None:
    with pytest.raises(Exception):
        ErrorBody(code=ErrorCode.NOT_FOUND, message="")


def test_error_detail_rejects_unknown_fields() -> None:
    with pytest.raises(Exception):
        ErrorDetail(message="x", unexpected="y")


def test_error_response_serializes_code_as_string() -> None:
    payload = ErrorResponse(
        error=ErrorBody(code=ErrorCode.INPUT_TOO_LARGE, message="提交的内容超过大小限制。")
    ).model_dump(mode="json")

    assert payload["error"]["code"] == "input_too_large"
