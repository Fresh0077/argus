"""HTTP 请求报文解析测试。

重点覆盖行号、CRLF/LF、头部与 body 边界、畸形输入与不支持的形式。
所有内容只被当作文本解析，不会发起网络请求。
"""

from __future__ import annotations

import pytest

from app.analyzers.http_request.parser import RequestParseError, parse_http_request


def parse(raw: str, max_chars: int = 20_000):
    return parse_http_request(raw, max_chars=max_chars)


SIMPLE_GET = (
    "GET /search?q=hello&page=2 HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Accept: */*\r\n"
    "\r\n"
)


def test_parses_request_line_headers_and_query() -> None:
    request = parse(SIMPLE_GET)

    assert request.method == "GET"
    assert request.target == "/search?q=hello&page=2"
    assert request.path == "/search"
    assert request.query == "q=hello&page=2"
    assert request.http_version == "HTTP/1.1"
    assert request.scheme is None
    assert request.authority is None
    assert [header.name for header in request.headers] == ["Host", "Accept"]
    assert [header.line for header in request.headers] == [2, 3]
    assert request.body == ""
    assert request.body_kind == "none"
    assert request.parameters[0].name == "q"
    assert request.parameters[0].value == "hello"
    assert request.parameters[0].line == 1


def test_crlf_and_lf_produce_same_structure() -> None:
    lf = SIMPLE_GET.replace("\r\n", "\n")
    crlf_request = parse(SIMPLE_GET)
    lf_request = parse(lf)

    assert crlf_request.method == lf_request.method
    assert crlf_request.headers == lf_request.headers
    assert crlf_request.parameters == lf_request.parameters


def test_duplicate_headers_are_preserved_in_order() -> None:
    raw = (
        "GET / HTTP/1.1\n"
        "Host: example.com\n"
        "X-Test: first\n"
        "X-Test: second\n"
        "\n"
    )
    request = parse(raw)

    assert request.header_values("x-test") == ["first", "second"]


def test_absolute_form_records_scheme_and_authority() -> None:
    raw = (
        "GET http://user:pass@example.com/path?token=abc HTTP/1.1\n"
        "Host: example.com\n"
        "\n"
    )
    request = parse(raw)

    assert request.scheme == "http"
    assert request.authority == "user:pass@example.com"
    assert request.path == "/path"
    assert request.query == "token=abc"


def test_json_body_is_classified_and_validated() -> None:
    raw = (
        "POST /api HTTP/1.1\n"
        "Content-Type: application/json\n"
        "\n"
        '{"user": "alice", "n": 1}'
    )
    request = parse(raw)

    assert request.body_kind == "json"
    assert request.body_json_valid is True
    assert request.body_looks_json is True
    assert request.body_start_line == 4


def test_invalid_json_body_is_marked_invalid() -> None:
    raw = (
        "POST /api HTTP/1.1\n"
        "Content-Type: application/json\n"
        "\n"
        '{"user": '
    )
    request = parse(raw)

    assert request.body_kind == "json"
    assert request.body_json_valid is False


def test_urlencoded_body_parameters_keep_real_line_numbers() -> None:
    raw = (
        "POST /login HTTP/1.1\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "\n"
        "user=alice&password=secret&next=%2Fhome"
    )
    request = parse(raw)

    assert request.body_kind == "urlencoded"
    body_params = [item for item in request.parameters if item.location == "body"]
    assert [item.name for item in body_params] == ["user", "password", "next"]
    assert [item.line for item in body_params] == [4, 4, 4]
    assert body_params[2].value == "/home"


def test_cookie_header_parameters_are_parsed() -> None:
    raw = (
        "GET / HTTP/1.1\n"
        "Cookie: session=abc123; theme=dark\n"
        "\n"
    )
    request = parse(raw)

    assert [(item.name, item.value, item.line) for item in request.cookies] == [
        ("session", "abc123", 2),
        ("theme", "dark", 2),
    ]


def test_origin_form_path_starting_with_double_slash_is_preserved() -> None:
    request = parse("GET //foo/bar?x=1 HTTP/1.1\nHost: example.com\n\n")
    assert request.path == "//foo/bar"
    assert request.query == "x=1"
    assert request.authority is None


def test_options_asterisk_is_supported() -> None:
    request = parse("OPTIONS * HTTP/1.1\nHost: example.com\n\n")
    assert request.path == "*"
    assert request.query == ""


@pytest.mark.parametrize(
    "raw, message",
    [
        ("GET / HTTP/1.1\nHost: example.com", "空行"),
        ("GET /only-two\n\n", "三部分"),
        ("123 / HTTP/1.1\n\n", "方法"),
        ("GET / HTTP/1.1.1\n\n", "协议版本"),
        ("GET / HTTP/1.1\n Host: folded\n\n", "折叠头"),
        ("GET / HTTP/1.1\nBadHeader\n\n", "请求头"),
        ("CONNECT example.com:443 HTTP/1.1\n\n", "目标形式"),
        ("GET http://[::1/ HTTP/1.1\n\n", "目标不合法"),
    ],
)
def test_malformed_requests_are_rejected(raw: str, message: str) -> None:
    with pytest.raises(RequestParseError, match=message):
        parse(raw)


def test_empty_and_null_inputs_are_rejected() -> None:
    with pytest.raises(RequestParseError, match="为空"):
        parse("   ")
    with pytest.raises(RequestParseError, match="NUL"):
        parse("GET / HTTP/1.1\n\n\x00")


def test_oversized_request_is_rejected() -> None:
    raw = "GET / HTTP/1.1\nHost: example.com\n\n" + "a" * 100
    with pytest.raises(RequestParseError, match="上限"):
        parse(raw, max_chars=50)


def test_lone_cr_is_rejected() -> None:
    with pytest.raises(RequestParseError, match="回车符"):
        parse("GET / HTTP/1.1\rHost: example.com\r\n\r\n")
