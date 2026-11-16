"""LLM 分析器入口。

编排顺序：**可用性判断 → 构造提示词 → 调用模型 → 校验输出 → 统一状态**。

两条不可动摇的规则：

- **没有配置就不发请求。** 缺少 API key / 地址 / 模型名时直接报 ``unavailable``，
  不是失败、更不是"没发现问题"。
- **LLM 失败不能伪装成“没发现”。** 这里只返回状态对象，不抛异常给扫描流程。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.analyzers.line_index import LineIndex
from app.analyzers.llm.parser import LlmOutputError, parse_llm_output
from app.analyzers.llm.prompt import build_prompt
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
from app.schemas.features import FeatureExtractionResult
from app.schemas.finding import Finding

#: ``analyzer_status.reason`` 的长度上限。
_MAX_REASON_CHARS = 500


class Completer(Protocol):
    """检测器需要的最小客户端接口，便于测试注入假实现。"""

    def complete(self, system: str, user: str) -> str: ...


@dataclass(frozen=True)
class LlmOutcome:
    """LLM 分析的结果与状态。"""

    state: AnalyzerState

    #: 通过校验的发现（``source=llm``）。
    findings: list[Finding] = field(default_factory=list)

    #: 非 success 状态的原因；成功时为 ``None``。
    reason: str | None = None


def detect_llm_findings(
    source_code: str,
    language: str | None,
    *,
    features: FeatureExtractionResult | None = None,
    client: Completer | None = None,
    config: Settings | None = None,
    timeout_seconds: float | None = None,
) -> LlmOutcome:
    """调用模型分析代码，返回统一的发现与状态。

    参数：
        source_code: 待分析源码。
        language: 已识别的语言；``None`` 表示未识别（仍可分析）。
        features: 特征提取结果，作为代码规模与依赖上下文传给模型。
        client: 测试注入用的客户端；``None`` 时按配置创建真实客户端。
        config: 测试注入用的配置；``None`` 时使用全局配置。
        timeout_seconds: 本次请求的超时上限；``None`` 表示使用
            ``LLM_TIMEOUT_SECONDS``。编排层在扫描预算不足时传入更小的值。

    返回：
        ``LlmOutcome``。本函数不抛异常——所有可预见的失败都变成状态与原因。
    """
    cfg = config or default_settings

    if not cfg.llm_enabled:
        return LlmOutcome(
            state=AnalyzerState.SKIPPED,
            reason="服务端未启用 LLM 分析（LLM_ENABLED=false）。",
        )

    missing = missing_settings(
        base_url=cfg.llm_base_url, api_key=cfg.llm_api_key, model=cfg.llm_model
    )
    if missing:
        return LlmOutcome(
            state=AnalyzerState.UNAVAILABLE,
            reason=_truncate(f"未配置 {', '.join(missing)}，LLM 分析不会执行。"),
        )

    request_timeout = cfg.llm_timeout_seconds
    if timeout_seconds is not None:
        # 编排层可能传入一个压缩后的预算；下限 0.1 秒避免 httpx 收到非正数超时。
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
            return LlmOutcome(
                state=AnalyzerState.UNAVAILABLE, reason=_truncate(str(exc))
            )
    else:
        active = client

    try:
        index = LineIndex(source_code)
        try:
            prompt = build_prompt(
                index=index,
                language=language,
                features=features,
                max_input_chars=cfg.llm_max_input_chars,
            )
        except ValueError as exc:
            return LlmOutcome(
                state=AnalyzerState.UNAVAILABLE,
                reason=_truncate(f"LLM 配置不合法：{exc}"),
            )

        raw = active.complete(prompt.system, prompt.user)
        parsed = parse_llm_output(raw, index)
        return LlmOutcome(state=AnalyzerState.SUCCESS, findings=parsed.findings)
    except LlmOutputError as exc:
        return LlmOutcome(
            state=AnalyzerState.FAILED,
            reason=_truncate(f"模型输出不可用：{exc}"),
        )
    except LlmError as exc:
        return LlmOutcome(
            state=AnalyzerState.FAILED,
            reason=_truncate(_failure_reason(exc, cfg, request_timeout)),
        )
    finally:
        if owns_client and isinstance(active, LlmClient):
            active.close()


def _failure_reason(exc: LlmError, cfg: Settings, timeout_seconds: float) -> str:
    """把客户端异常翻译成用户能据此行动的原因。

    不拼接请求头、响应体或源代码；重试次数让用户知道这不是"第一次失败"。
    ``timeout_seconds`` 是本次请求实际使用的上限，可能小于配置值。
    """
    retry_note = (
        f"已重试 {cfg.llm_max_retries} 次" if cfg.llm_max_retries > 0 else "未重试"
    )

    if isinstance(exc, LlmTimeoutError):
        return (
            f"调用模型服务超时（本次请求上限 {timeout_seconds:g} 秒），"
            f"{retry_note}。可在配置中调整 LLM_TIMEOUT_SECONDS。"
        )
    if isinstance(exc, LlmRateLimitError):
        return f"模型服务返回 429（限流），{retry_note}。"
    if isinstance(exc, LlmServerError):
        return f"{exc}（服务端错误），{retry_note}。"
    if isinstance(exc, LlmNetworkError):
        return f"{exc}{retry_note}。"
    if isinstance(exc, LlmResponseTooLargeError):
        return str(exc)
    if isinstance(exc, LlmResponseFormatError):
        return str(exc)

    return f"模型调用失败：{exc}"


def _truncate(text: str) -> str:
    """把原因限制在契约允许的长度内。"""
    if len(text) <= _MAX_REASON_CHARS:
        return text
    return text[: _MAX_REASON_CHARS - 1] + "…"
