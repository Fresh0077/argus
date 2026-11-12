"""原始 HTTP 请求报文解析。

设计原则：

1. **只解析文本。** 不建立连接、不发送请求、不执行任何内容。
2. **行号必须真实。** 请求行是第 1 行，头部依次编号，body 从空行之后开始。
   无法可靠定位时不猜。
3. **畸形输入明确失败。** 缺少请求行、缺少空行、头部折叠、超长、含 NUL
   等情况直接报错，不静默截断或"尽量修一修"。
4. **保留原始片段。** 脱敏与证据展示都需要原文；解析阶段不修改用户输入。

当前只支持常见的 HTTP/1.x 文本报文：

- 请求行：``METHOD TARGET HTTP/1.1``；
- origin-form（``/path?query``）与 absolute-form（``http://host/path?query``）；
- ``OPTIONS *``；
- ``CONNECT host:port`` 的 authority-form 不支持，会明确报错。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import unquote, unquote_plus, urlsplit

from app.schemas.http_request import MAX_REQUEST_LINES

#: 头部数量上限。正常浏览器请求远低于这个值，超过时更可能是误粘贴或恶意输入。
MAX_HEADERS = 200

#: 请求目标长度上限。
MAX_TARGET_LENGTH = 8_192

_METHOD_PATTERN = re.compile(r"^[A-Za-z]{1,32}$")
_HTTP_VERSION_PATTERN = re.compile(r"^HTTP/\d(?:\.\d)?$")
_ABSOLUTE_TARGET_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

ParameterLocation = Literal["query", "body", "cookie"]
BodyKind = Literal["none", "urlencoded", "json", "multipart", "text"]


class RequestParseError(ValueError):
    """原始报文不符合当前支持的 HTTP 文本格式。"""


@dataclass(frozen=True)
class RawHeader:
    """一条头部，保留名称、值与原报文行号。"""

    name: str
    value: str
    line: int


@dataclass(frozen=True)
class RawParameter:
    """一个参数。

    ``name`` / ``value`` 是解码后的值，便于匹配敏感名称；
    ``raw_name`` / ``raw_value`` 保留原始写法，脱敏时按原样重建。
    """

    name: str
    value: str
    raw_name: str
    raw_value: str
    location: ParameterLocation
    line: int


@dataclass(frozen=True)
class RawHttpRequest:
    """解析后的请求。"""

    method: str
    target: str
    path: str
    query: str
    http_version: str
    #: 仅 absolute-form 能确定；origin-form 无法从报文本身判断协议。
    scheme: str | None
    authority: str | None
    headers: tuple[RawHeader, ...]
    parameters: tuple[RawParameter, ...]
    cookies: tuple[RawParameter, ...]
    body: str
    body_content_type: str | None
    body_kind: BodyKind
    body_json_valid: bool | None
    body_looks_json: bool
    body_looks_urlencoded: bool
    #: 规范化换行后的原始行（``\\r\\n`` → ``\\n``）。
    lines: tuple[str, ...]
    #: body 第一行在报文中的行号；没有 body 时与最后一行一致。
    body_start_line: int

    def header(self, name: str) -> RawHeader | None:
        """按名称（不区分大小写）取第一条头部。"""
        lowered = name.lower()
        for header in self.headers:
            if header.name.lower() == lowered:
                return header
        return None

    def header_values(self, name: str) -> list[str]:
        """按名称取全部同名头部的值，保持原顺序。"""
        lowered = name.lower()
        return [header.value for header in self.headers if header.name.lower() == lowered]


def parse_http_request(raw: str, *, max_chars: int) -> RawHttpRequest:
    """把原始报文解析为 ``RawHttpRequest``。

    参数：
        raw: 用户提交的原始文本。
        max_chars: 字符上限；超过直接拒绝。

    异常：
        ``RequestParseError``：报文为空、超长、含 NUL、换行不合法或结构不符合支持范围。
    """
    if max_chars <= 0:
        raise ValueError("max_chars 必须为正数")
    if not raw.strip():
        raise RequestParseError("请求报文为空。")
    if len(raw) > max_chars:
        raise RequestParseError(
            f"请求报文长度 {len(raw)} 超过上限 {max_chars} 个字符。"
        )
    if "\x00" in raw:
        raise RequestParseError("请求报文包含空字符（NUL），当前只支持文本报文。")

    # 只接受 CRLF 或 LF。孤立的 CR 会让行号与编辑器显示不一致。
    without_crlf = raw.replace("\r\n", "")
    if "\r" in without_crlf:
        raise RequestParseError("请求报文包含孤立的回车符（CR），请使用 CRLF 或 LF。")

    normalized = raw.replace("\r\n", "\n")
    lines = normalized.split("\n")
    if len(lines) > MAX_REQUEST_LINES:
        raise RequestParseError(
            f"请求报文共有 {len(lines)} 行，超过上限 {MAX_REQUEST_LINES} 行。"
        )

    method, target, http_version = _parse_request_line(lines[0])
    path, query, scheme, authority = _parse_target(target)

    separator = _find_header_separator(lines)
    header_lines = lines[1:separator]
    headers = _parse_headers(header_lines)

    body = "\n".join(lines[separator + 1 :])
    body_start_line = separator + 2  # 分隔空行是第 separator+1 行
    content_type = _first_header_value(headers, "content-type")
    body_kind, body_json_valid, body_looks_json, body_looks_urlencoded = _classify_body(
        body, content_type
    )

    query_parameters = _parse_query_parameters(query)
    cookie_parameters = _parse_cookie_parameters(headers)
    body_parameters = (
        _parse_urlencoded_body(body, body_start_line)
        if body_kind == "urlencoded"
        else ()
    )

    return RawHttpRequest(
        method=method,
        target=target,
        path=path,
        query=query,
        http_version=http_version,
        scheme=scheme,
        authority=authority,
        headers=headers,
        parameters=(*query_parameters, *body_parameters, *cookie_parameters),
        cookies=cookie_parameters,
        body=body,
        body_content_type=content_type,
        body_kind=body_kind,
        body_json_valid=body_json_valid,
        body_looks_json=body_looks_json,
        body_looks_urlencoded=body_looks_urlencoded,
        lines=tuple(lines),
        body_start_line=body_start_line,
    )


def _parse_request_line(line: str) -> tuple[str, str, str]:
    """解析请求行，返回 ``(方法, 目标, 协议版本)``。"""
    if not line.strip():
        raise RequestParseError("请求报文的第一行不能为空。")

    parts = line.split()
    if len(parts) != 3:
        raise RequestParseError(
            "请求行必须由「方法 目标 协议版本」三部分组成，例如 GET /api?x=1 HTTP/1.1。"
        )

    method, target, version = parts
    if not _METHOD_PATTERN.fullmatch(method):
        raise RequestParseError("请求方法只能由英文字母组成。")
    if not _HTTP_VERSION_PATTERN.fullmatch(version):
        raise RequestParseError("协议版本必须形如 HTTP/1.1 或 HTTP/2。")
    if len(target) > MAX_TARGET_LENGTH:
        raise RequestParseError(f"请求目标长度超过上限 {MAX_TARGET_LENGTH} 个字符。")

    return method.upper(), target, version


def _parse_target(target: str) -> tuple[str, str, str | None, str | None]:
    """解析请求目标，返回 ``(path, query, scheme, authority)``。"""
    if target == "*":
        return "*", "", None, None

    if target.startswith("/"):
        # 不能对 origin-form 直接调用 urlsplit：以 ``//`` 开头的合法路径
        # 会被当成 network-path reference，路径前缀被吞掉。这里手工切分。
        if "#" in target:
            raise RequestParseError("请求目标不能包含片段（#...）。")
        path_text, separator, query_text = target.partition("?")
        return path_text or "/", query_text if separator else "", None, None

    if _ABSOLUTE_TARGET_PATTERN.match(target):
        try:
            parsed = urlsplit(target)
        except ValueError as exc:
            # 例如未闭合的 IPv6 方括号；不能让它变成 500。
            raise RequestParseError("absolute-form 请求目标不合法。") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise RequestParseError("absolute-form 只支持 http:// 或 https:// 目标。")
        if not parsed.netloc:
            raise RequestParseError("absolute-form 目标缺少主机名。")
        if parsed.fragment:
            raise RequestParseError("请求目标不能包含片段（#...）。")
        return parsed.path or "/", parsed.query, parsed.scheme.lower(), parsed.netloc

    raise RequestParseError(
        "不支持的请求目标形式；请使用 /path?query 或 http(s)://host/path?query。"
    )


def _find_header_separator(lines: list[str]) -> int:
    """找到头部与 body 之间的空行。缺少空行时报错。"""
    for index in range(1, len(lines)):
        if lines[index] == "":
            return index
    raise RequestParseError("请求头之后缺少空行，无法确定 body 的起始位置。")


def _parse_headers(lines: list[str]) -> tuple[RawHeader, ...]:
    """解析头部行；拒绝折叠头与不合法的名称。"""
    if len(lines) > MAX_HEADERS:
        raise RequestParseError(f"请求头数量 {len(lines)} 超过上限 {MAX_HEADERS}。")

    headers: list[RawHeader] = []
    for offset, line in enumerate(lines, start=2):
        if line == "":
            raise RequestParseError("请求头中间出现了空行，报文结构不合法。")
        if line[0] in {" ", "\t"}:
            raise RequestParseError("不支持折叠头（以空白开头的续行）。")
        if ":" not in line:
            raise RequestParseError(f"第 {offset} 行不是合法的请求头。")

        name, value = line.split(":", 1)
        if not _HEADER_NAME_PATTERN.fullmatch(name):
            raise RequestParseError(f"第 {offset} 行的请求头名称不合法。")
        headers.append(RawHeader(name=name, value=value.strip(" \t"), line=offset))

    return tuple(headers)


def _first_header_value(headers: tuple[RawHeader, ...], name: str) -> str | None:
    lowered = name.lower()
    for header in headers:
        if header.name.lower() == lowered:
            return header.value
    return None


def _classify_body(
    body: str, content_type: str | None
) -> tuple[BodyKind, bool | None, bool, bool]:
    """判断 body 形态，并给出 JSON 是否合法。"""
    if body == "":
        return "none", None, False, False

    lowered = (content_type or "").lower()
    stripped = body.lstrip()
    looks_json = stripped.startswith("{") or stripped.startswith("[")
    looks_urlencoded = (
        "=" in body
        and not looks_json
        and "<" not in body
        and all("=" in pair for pair in body.split("&") if pair.strip())
    )

    json_valid: bool | None = None
    if looks_json or "json" in lowered:
        try:
            json.loads(body)
            json_valid = True
        except (json.JSONDecodeError, ValueError, RecursionError):
            # 极深的嵌套可能触发 RecursionError；同样按“非法 JSON”处理，
            # 不让请求解析因为一份恶意 body 变成 500。
            json_valid = False

    if "multipart/form-data" in lowered:
        kind: BodyKind = "multipart"
    elif "application/x-www-form-urlencoded" in lowered:
        kind = "urlencoded"
    elif "json" in lowered:
        kind = "json"
    elif looks_json:
        kind = "json"
    elif looks_urlencoded:
        kind = "urlencoded"
    else:
        kind = "text"

    return kind, json_valid, looks_json, looks_urlencoded


def _parse_query_parameters(query: str) -> tuple[RawParameter, ...]:
    """解析查询串；空名称的片段跳过。"""
    parameters: list[RawParameter] = []
    if not query:
        return ()

    for raw_pair in query.split("&"):
        if not raw_pair:
            continue
        raw_name, _, raw_value = raw_pair.partition("=")
        if raw_name == "":
            continue
        parameters.append(
            RawParameter(
                name=unquote_plus(raw_name),
                value=unquote_plus(raw_value),
                raw_name=raw_name,
                raw_value=raw_value,
                location="query",
                line=1,
            )
        )
    return tuple(parameters)


def _parse_cookie_parameters(headers: tuple[RawHeader, ...]) -> tuple[RawParameter, ...]:
    """解析 ``Cookie`` 头；保留名称用于展示，值只用于敏感匹配。"""
    cookie_header = _first_header_value(headers, "cookie")
    if cookie_header is None:
        return ()

    parameters: list[RawParameter] = []
    for raw_pair in cookie_header.split(";"):
        piece = raw_pair.strip()
        if not piece:
            continue
        raw_name, _, raw_value = piece.partition("=")
        if raw_name.strip() == "":
            continue
        parameters.append(
            RawParameter(
                name=unquote(raw_name.strip()),
                value=unquote(raw_value.strip()),
                raw_name=raw_name.strip(),
                raw_value=raw_value.strip(),
                location="cookie",
                line=_header_line(headers, "cookie") or 1,
            )
        )
    return tuple(parameters)


def _parse_urlencoded_body(body: str, body_start_line: int) -> tuple[RawParameter, ...]:
    """解析表单 body，并按字符偏移计算每条参数的真实行号。"""
    parameters: list[RawParameter] = []
    offset = 0

    for raw_pair in body.split("&"):
        pair_start = offset
        offset += len(raw_pair) + 1
        if not raw_pair:
            continue

        raw_name, _, raw_value = raw_pair.partition("=")
        if raw_name == "":
            continue
        line = body_start_line + body[:pair_start].count("\n")
        parameters.append(
            RawParameter(
                name=unquote_plus(raw_name),
                value=unquote_plus(raw_value),
                raw_name=raw_name,
                raw_value=raw_value,
                location="body",
                line=line,
            )
        )

    return tuple(parameters)


def _header_line(headers: tuple[RawHeader, ...], name: str) -> int | None:
    lowered = name.lower()
    for header in headers:
        if header.name.lower() == lowered:
            return header.line
    return None
