"""请求包审计的 LLM 入口。

与源码 LLM 分析器一样，本模块只负责“可用性判断 → 构造提示词 → 调用模型
→ 校验输出 → 返回状态”，**不抛异常给调用方**：

- 未启用 / 未配置 → ``skipped`` / ``unavailable``；
- 调用失败或输出不合格 → ``failed`` 并说明原因；
- 无论哪种情况，本地解析与脱敏结果都不受影响。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.analyzers.http_request.llm_parser import parse_request_llm_output
from app.analyzers.http_request.prompt import build_request_prompt
from app.analyzers.llm.parser import LlmOutputError
from app.core.config import Settings, settings as default_settings
from app.llm.client import LlmClient, missing_settings
from app.llm.errors import (
    LlmConfigurationError,
    LlmError,
    LlmNetworkError,
    LlmRateLimitError,
    LlmResponseFormatError,
    LlmResponseTooLargeError,
    LlmServerError,
    LlmTimeoutError,
)
from app.schemas.enums import AnalyzerState
from app.schemas.finding import Finding

_MAX_REASON_CHARS = 500


class Completer(Protocol):
    def complete(self, system: str, user: str) -> str: ...


@dataclass(frozen=True)
class RequestLlmOutcome:
    state: AnalyzerState
    findings: list[Finding] = field(default_factory=list)
    reason: str | None = None


def detect_request_llm_findings(
    redacted_request: str,
    *,
    method: str,
    http_version: str,
    scheme: str | None,
    content_type: str | None,
    body_kind: str,
    client: Completer | None = None,
    config: Settings | None = None,
    timeout_seconds: float | None = None,
) -> RequestLlmOutcome:
    """对脱敏后的请求报文调用模型，返回发现与状态。"""
    cfg = config or default_settings

    if not cfg.llm_enabled:
        return RequestLlmOutcome(
            state=AnalyzerState.SKIPPED,
            reason="服务端未启用 LLM 分析（LLM_ENABLED=false）。",
        )

    missing = missing_settings(
        base_url=cfg.llm_base_url, api_key=cfg.llm_api_key, model=cfg.llm_model
    )
    if missing:
        return RequestLlmOutcome(
            state=AnalyzerState.UNAVAILABLE,
            reason=_truncate(f"未配置 {', '.join(missing)}，LLM 审计不会执行。"),
        )

    request_timeout = cfg.llm_timeout_seconds
    if timeout_seconds is not None:
        request_timeout = max(0.1, min(cfg.llm_timeout_seconds, timeout_seconds))

    owns_client = client is None
    active: Completer
    if client is None:
        try:
            active = LlmClient(
                base_url=cfg.llm_base_url,
                api_key=cfg.llm_api_key,
                model=cfg.llm_model,
                timeout_seconds=request_timeout,
                max_output_tokens=cfg.llm_max_output_tokens,
                max_retries=cfg.llm_max_retries,
            )
        except LlmConfigurationError as exc:
            return RequestLlmOutcome(
                state=AnalyzerState.UNAVAILABLE, reason=_truncate(str(exc))
            )
    else:
        active = client

    try:
        try:
            prompt = build_request_prompt(
                redacted_request=redacted_request,
                method=method,
                http_version=http_version,
                scheme=scheme,
                content_type=content_type,
                body_kind=body_kind,
                max_input_chars=cfg.llm_max_input_chars,
            )
        except ValueError as exc:
            return RequestLlmOutcome(
                state=AnalyzerState.UNAVAILABLE,
                reason=_truncate(f"LLM 配置不合法：{exc}"),
            )

        raw = active.complete(prompt.system, prompt.user)
        parsed = parse_request_llm_output(
            raw,
            redacted_request=redacted_request,
            included_lines=prompt.included_lines,
        )
        return RequestLlmOutcome(state=AnalyzerState.SUCCESS, findings=parsed.findings)
    except LlmOutputError as exc:
        # 包括请求审计自己的 RequestLlmOutputError（它是本类的子类）。
        return RequestLlmOutcome(
            state=AnalyzerState.FAILED,
            reason=_truncate(f"模型输出不可用：{exc}"),
        )
    except LlmError as exc:
        return RequestLlmOutcome(
            state=AnalyzerState.FAILED,
            reason=_truncate(_failure_reason(exc, cfg, request_timeout)),
        )
    finally:
        if owns_client and isinstance(active, LlmClient):
            active.close()


def _failure_reason(exc: LlmError, cfg: Settings, timeout_seconds: float) -> str:
    retry_note = (
        f"已重试 {cfg.llm_max_retries} 次" if cfg.llm_max_retries > 0 else "未重试"
    )
    if isinstance(exc, LlmTimeoutError):
        return (
            f"调用模型服务超时（本次请求上限 {timeout_seconds:g} 秒），{retry_note}。"
            "可在配置中调整 LLM_TIMEOUT_SECONDS。"
        )
    if isinstance(exc, LlmRateLimitError):
        return f"模型服务返回 429（限流），{retry_note}。"
    if isinstance(exc, LlmServerError):
        return f"{exc}（服务端错误），{retry_note}。"
    if isinstance(exc, LlmNetworkError):
        return f"{exc}{retry_note}。"
    if isinstance(exc, (LlmResponseTooLargeError, LlmResponseFormatError)):
        return str(exc)
    return f"模型调用失败：{exc}"


def _truncate(text: str) -> str:
    if len(text) <= _MAX_REASON_CHARS:
        return text
    return text[: _MAX_REASON_CHARS - 1] + "…"
