"""发送给 LLM 前的敏感信息脱敏。

请求报文里经常带有真实的 Cookie、Authorization、会话令牌与个人信息，
其敏感程度通常高于源码。这里的策略是**宁可多脱敏，不可漏脱敏**：

- 已知敏感头部（Authorization、Cookie、X-API-Key 等）的值整体替换；
- 参数名命中敏感词（password、token、secret、session 等）时替换值；
- 已知令牌形态（JWT、Bearer、sk-、AKIA、GitHub token）即使在普通位置也替换；
- Cookie 的值默认全部替换，只保留名称，便于模型判断“有会话凭证”。

脱敏只改变同一行内的文本，不改变行数，因此后续行号仍然可信。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from app.analyzers.http_request.parser import RawHeader, RawHttpRequest
from app.schemas.http_request import REDACTED_PLACEHOLDER

#: 值需要整体替换的头部（名称不区分大小写）。
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)

#: Set-Cookie 中的属性名，不能当成“值”脱敏。
_COOKIE_ATTRIBUTES = frozenset(
    {
        "path",
        "domain",
        "expires",
        "max-age",
        "samesite",
        "secure",
        "httponly",
        "priority",
        "partitioned",
        "comment",
        "version",
    }
)

#: 参数名中一旦出现这些片段，就按敏感字段处理。
_SENSITIVE_NAME_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "client_secret",
    "credential",
    "sessionid",
    "session_id",
    "csrf",
    "xsrf",
)

_SENSITIVE_EXACT_NAMES = frozenset(
    {
        "pwd",
        "pass",
        "auth",
        "authorization",
        "authentication",
        "session",
        "jsessionid",
        "phpsessid",
        "otp",
    }
)

#: 已知令牌形态。只收高置信度模式，避免把普通 base64 或代码片段误当成密钥。
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # JWT
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # OpenAI / 常见兼容服务商的 sk- 前缀
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    # AWS Access Key ID
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # GitHub token
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
)

_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_BASIC_PATTERN = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{8,}")

#: JSON 中的 ``"key": value`` 片段。值可以是字符串、数字、布尔或 null。
_JSON_KV_PATTERN = re.compile(
    r'(?P<prefix>"(?P<key>(?:[^"\\]|\\.)*)"\s*:\s*)'
    r'(?P<value>"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)'
)


@dataclass(frozen=True)
class RedactionResult:
    """脱敏后的文本与统计。"""

    text: str
    fingerprint: str
    redacted_count: int
    categories: tuple[str, ...]


def is_sensitive_name(name: str) -> bool:
    """判断参数名/字段名是否可能承载凭证。"""
    normalized = unquote_plus(name).strip().strip("[]").lower()
    if not normalized:
        return False
    if normalized in _SENSITIVE_EXACT_NAMES:
        return True

    compact = normalized.replace("-", "_")
    if compact in _SENSITIVE_EXACT_NAMES:
        return True
    return any(part in compact for part in _SENSITIVE_NAME_PARTS)


def contains_token_like(text: str) -> bool:
    """判断文本中是否包含已知令牌形态。"""
    if not text:
        return False
    if _BEARER_PATTERN.search(text) or _BASIC_PATTERN.search(text):
        return True
    return any(pattern.search(text) for pattern in _TOKEN_PATTERNS)


def redact_http_request(request: RawHttpRequest) -> RedactionResult:
    """对整段报文脱敏，返回新文本与指纹。

    行数保持不变；同一行内的替换不会引入换行。
    """
    lines = list(request.lines)
    categories: list[str] = []
    count = 0

    # 请求行。
    redacted_target, target_count, target_categories = _redact_target(request)
    lines[0] = f"{request.method} {redacted_target} {request.http_version}"
    count += target_count
    categories.extend(target_categories)

    # 头部。
    for header in request.headers:
        index = header.line - 1
        if 0 <= index < len(lines):
            new_line, header_count, header_categories = _redact_header(header)
            lines[index] = new_line
            count += header_count
            categories.extend(header_categories)

    # body。
    for index in range(request.body_start_line - 1, len(lines)):
        if index < 0 or index >= len(lines):
            continue
        new_line, body_count, body_categories = _redact_body_line(
            lines[index], request.body_kind
        )
        lines[index] = new_line
        count += body_count
        categories.extend(body_categories)

    text = "\n".join(lines)
    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return RedactionResult(
        text=text,
        fingerprint=fingerprint,
        redacted_count=count,
        categories=tuple(sorted(set(categories))),
    )


def _redact_target(request: RawHttpRequest) -> tuple[str, int, list[str]]:
    """脱敏请求行中的目标部分。"""
    target = request.target
    if target == "*":
        return target, 0, []

    count = 0
    categories: list[str] = []

    if request.scheme and "://" in target:
        parsed = urlsplit(target)
        netloc = parsed.netloc
        if "@" in netloc:
            _, host = netloc.rsplit("@", 1)
            netloc = f"{REDACTED_PLACEHOLDER}@{host}"
            count += 1
            categories.append("url:userinfo")

        path, path_count, path_categories = _redact_text(parsed.path)
        count += path_count
        categories.extend(f"path:{item}" for item in path_categories)

        query, query_count, query_categories = _redact_query(parsed.query)
        count += query_count
        categories.extend(query_categories)

        return (
            urlunsplit((parsed.scheme, netloc, path, query, "")),
            count,
            categories,
        )

    path_text, sep, query_text = target.partition("?")
    path, path_count, path_categories = _redact_text(path_text)
    count += path_count
    categories.extend(f"path:{item}" for item in path_categories)

    if sep:
        query, query_count, query_categories = _redact_query(query_text)
        count += query_count
        categories.extend(query_categories)
        return f"{path}?{query}", count, categories

    return path, count, categories


def _redact_query(query: str) -> tuple[str, int, list[str]]:
    """逐条脱敏查询参数，保留参数名。"""
    if not query:
        return query, 0, []

    count = 0
    categories: list[str] = []
    pieces: list[str] = []

    for raw_pair in query.split("&"):
        if not raw_pair:
            pieces.append(raw_pair)
            continue

        raw_name, sep, raw_value = raw_pair.partition("=")
        name = unquote_plus(raw_name)
        value = unquote_plus(raw_value)
        if is_sensitive_name(name) or contains_token_like(value):
            pieces.append(f"{raw_name}={REDACTED_PLACEHOLDER}")
            count += 1
            categories.append(f"query:{name or 'unknown'}")
        else:
            pieces.append(raw_pair)

    return "&".join(pieces), count, categories


def _redact_header(header: RawHeader) -> tuple[str, int, list[str]]:
    """脱敏单条头部，返回 ``(新行, 替换数, 类别)``。"""
    lowered = header.name.lower()

    if lowered == "cookie":
        value, count = _redact_cookie_pairs(header.value, redact_all=True)
        return f"{header.name}: {value}", count, ["header:cookie"] if count else []

    if lowered == "set-cookie":
        value, count = _redact_cookie_pairs(header.value, redact_all=False)
        return f"{header.name}: {value}", count, ["header:set-cookie"] if count else []

    if lowered in SENSITIVE_HEADERS:
        return (
            f"{header.name}: {_redact_authorization_value(header.value)}",
            1,
            [f"header:{lowered}"],
        )

    value, count, _ = _redact_text(header.value)
    categories = [f"header:{lowered}:token"] if count else []
    return f"{header.name}: {value}", count, categories


def _redact_cookie_pairs(value: str, *, redact_all: bool) -> tuple[str, int]:
    """脱敏 Cookie / Set-Cookie 的 name=value 对。

    ``redact_all=True`` 用于请求中的 Cookie：值全部替换，只保留名称。
    ``redact_all=False`` 用于 Set-Cookie：只替换值，跳过 Path/HttpOnly 等属性。
    """
    pieces: list[str] = []
    count = 0

    for raw_pair in value.split(";"):
        piece = raw_pair.strip()
        if not piece:
            continue

        raw_name, sep, raw_value = piece.partition("=")
        name = raw_name.strip()
        lowered = name.lower()

        if redact_all:
            should_redact = bool(sep)
        else:
            should_redact = bool(sep) and lowered not in _COOKIE_ATTRIBUTES

        if should_redact and raw_value.strip() != REDACTED_PLACEHOLDER:
            pieces.append(f"{name}={REDACTED_PLACEHOLDER}")
            count += 1
        else:
            pieces.append(piece)

    return "; ".join(pieces), count


def _redact_authorization_value(value: str) -> str:
    """保留 Authorization 的认证方案，只替换凭证。"""
    scheme, sep, credential = value.partition(" ")
    if sep and scheme and credential:
        return f"{scheme} {REDACTED_PLACEHOLDER}"
    return REDACTED_PLACEHOLDER


def _redact_body_line(line: str, kind: str) -> tuple[str, int, list[str]]:
    """脱敏 body 的一行。"""
    if kind == "urlencoded" and ("&" in line or "=" in line):
        return _redact_urlencoded_line(line)
    if kind == "json":
        return _redact_json_line(line)
    return _redact_text(line)


def _redact_urlencoded_line(line: str) -> tuple[str, int, list[str]]:
    count = 0
    categories: list[str] = []
    pieces: list[str] = []

    for raw_pair in line.split("&"):
        if not raw_pair:
            pieces.append(raw_pair)
            continue

        raw_name, sep, raw_value = raw_pair.partition("=")
        name = unquote_plus(raw_name)
        value = unquote_plus(raw_value)
        if sep and (is_sensitive_name(name) or contains_token_like(value)):
            pieces.append(f"{raw_name}={REDACTED_PLACEHOLDER}")
            count += 1
            categories.append(f"body:{name or 'unknown'}")
        else:
            value_text, value_count, _ = _redact_text(raw_pair)
            pieces.append(value_text)
            count += value_count
            if value_count:
                categories.append("body:token")

    return "&".join(pieces), count, categories


def _redact_json_line(line: str) -> tuple[str, int, list[str]]:
    count = 0
    categories: list[str] = []

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        raw_key = match.group("key")
        try:
            key = json.loads(f'"{raw_key}"')
        except (json.JSONDecodeError, ValueError):
            key = raw_key

        if is_sensitive_name(str(key)):
            count += 1
            categories.append(f"body:{key}")
            return f'{match.group("prefix")}"{REDACTED_PLACEHOLDER}"'
        return match.group(0)

    redacted = _JSON_KV_PATTERN.sub(replace, line)
    redacted, token_count, _ = _redact_text(redacted)
    if token_count:
        count += token_count
        categories.append("body:token")
    return redacted, count, categories


def _redact_text(text: str) -> tuple[str, int, list[str]]:
    """替换文本中的已知令牌形态。"""
    if not text:
        return text, 0, []

    count = 0
    categories: list[str] = []

    def replace_bearer(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        categories.append("token:bearer")
        scheme = match.group(0).split(maxsplit=1)[0]
        return f"{scheme} {REDACTED_PLACEHOLDER}"

    updated = _BEARER_PATTERN.sub(replace_bearer, text)
    updated = _BASIC_PATTERN.sub(replace_bearer, updated)

    for pattern in _TOKEN_PATTERNS:
        matches = len(pattern.findall(updated))
        if matches:
            updated = pattern.sub(REDACTED_PLACEHOLDER, updated)
            count += matches
            categories.append("token")

    return updated, count, categories
