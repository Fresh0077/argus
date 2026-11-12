"""HTTP 请求包审计（阶段 19）。

模块分工：

- ``parser``：把原始报文解析成结构化对象，保留真实行号；
- ``redaction``：发送给 LLM 前替换敏感头部、参数与令牌；
- ``prompt`` / ``llm_parser`` / ``detector``：LLM 语义审计。

本包**不做任何网络访问**，也不会重放请求。
"""

from app.analyzers.http_request.detector import RequestLlmOutcome, detect_request_llm_findings
from app.analyzers.http_request.parser import (
    RawHeader,
    RawHttpRequest,
    RawParameter,
    RequestParseError,
    parse_http_request,
)
from app.analyzers.http_request.redaction import (
    RedactionResult,
    contains_token_like,
    is_sensitive_name,
    redact_http_request,
)

__all__ = [
    "RawHeader",
    "RawHttpRequest",
    "RawParameter",
    "RedactionResult",
    "RequestLlmOutcome",
    "RequestParseError",
    "contains_token_like",
    "detect_request_llm_findings",
    "is_sensitive_name",
    "parse_http_request",
    "redact_http_request",
]
