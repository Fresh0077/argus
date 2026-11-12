"""请求报文脱敏测试。

断言的核心不是“占位符出现了”，而是**原值不再出现在将要发送的文本里**，
同时行数保持不变，便于后续行号继续可信。
"""

from __future__ import annotations

from app.analyzers.http_request.parser import parse_http_request
from app.analyzers.http_request.redaction import (
    contains_token_like,
    is_sensitive_name,
    redact_http_request,
)
from app.schemas.http_request import REDACTED_PLACEHOLDER


def redact(raw: str):
    request = parse_http_request(raw, max_chars=20_000)
    return request, redact_http_request(request)


SAMPLE = (
    "POST /login?next=/home&token=supersecret123 HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop\r\n"
    "Cookie: session=abc123; theme=dark\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"username":"alice","password":"hunter2","note":"<script>alert(1)</script>"}'
)


def test_sensitive_values_do_not_survive_redaction() -> None:
    _, result = redact(SAMPLE)

    for secret in (
        "supersecret123",
        "eyJhbGciOiJIUzI1NiJ9",
        "abcdefghijklmnop",
        "abc123",
        "hunter2",
    ):
        assert secret not in result.text

    assert "token=<REDACTED>" in result.text
    assert "Bearer <REDACTED>" in result.text
    assert "session=<REDACTED>" in result.text
    assert '"password":"<REDACTED>"' in result.text
    # 非敏感字段与普通代码样式内容保留，便于模型理解上下文。
    assert "username" in result.text
    assert "<script>alert(1)</script>" in result.text


def test_redaction_keeps_line_count() -> None:
    request, result = redact(SAMPLE)
    assert len(result.text.split("\n")) == len(request.lines)


def test_redaction_is_deterministic() -> None:
    _, first = redact(SAMPLE)
    _, second = redact(SAMPLE)
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64
    assert first.redacted_count == second.redacted_count


def test_redaction_reports_categories_without_values() -> None:
    _, result = redact(SAMPLE)
    joined = ",".join(result.categories)

    assert "query:token" in joined
    assert "header:authorization" in joined
    assert "header:cookie" in joined
    assert "body:password" in joined
    assert "supersecret123" not in joined


def test_absolute_form_userinfo_is_redacted() -> None:
    raw = "GET http://user:pass@example.com/path HTTP/1.1\nHost: example.com\n\n"
    _, result = redact(raw)
    assert "user:pass" not in result.text
    assert "<REDACTED>@example.com" in result.text


def test_token_in_non_sensitive_body_field_is_redacted() -> None:
    raw = (
        "POST /api HTTP/1.1\n"
        "Content-Type: text/plain\n"
        "\n"
        "value=sk-abcdefghijklmnopqrstuvwxyz123456"
    )
    _, result = redact(raw)
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in result.text
    assert REDACTED_PLACEHOLDER in result.text


def test_json_numeric_sensitive_value_is_redacted() -> None:
    raw = (
        "POST /api HTTP/1.1\n"
        "Content-Type: application/json\n"
        "\n"
        '{"otp": 123456, "count": 2}'
    )
    _, result = redact(raw)
    assert "123456" not in result.text
    assert '"otp": "<REDACTED>"' in result.text
    assert '"count": 2' in result.text


def test_set_cookie_attributes_are_not_values() -> None:
    raw = (
        "POST /api HTTP/1.1\n"
        "Set-Cookie: session=abc123; Path=/; HttpOnly; SameSite=Lax\n"
        "\n"
    )
    _, result = redact(raw)
    assert "abc123" not in result.text
    assert "Path=/" in result.text
    assert "HttpOnly" in result.text
    assert "SameSite=Lax" in result.text


def test_sensitive_name_detection() -> None:
    assert is_sensitive_name("password")
    assert is_sensitive_name("user_token")
    assert is_sensitive_name("X-CSRF-Token")
    assert not is_sensitive_name("username")
    assert not is_sensitive_name("page")


def test_token_like_detection() -> None:
    assert contains_token_like("Bearer abcdefghijklmnop")
    assert contains_token_like("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop")
    assert contains_token_like("sk-abcdefghijklmnopqrstuvwxyz")
    assert not contains_token_like("hello world")
