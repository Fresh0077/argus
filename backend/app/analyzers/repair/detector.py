"""修复建议的编排入口。

流程：**可用性检查 → 构造最小上下文 → 调用模型 → 校验输出 → 计算 diff**。

安全边界：

- 没有启用或缺少配置时**不发起请求**，直接报"不可用"；
- 只发送发现所在行前后少量行，不发送整个文件；
- API key 只由 ``LlmClient`` 从配置读取，本模块不打印、不拼接它；
- 错误说明里不包含模型响应体、请求头或源代码；
- 返回的补丁**不写入任何文件**，也不会被执行。
"""

from __future__ import annotations

import difflib

from app.analyzers.line_index import LineIndex
from app.analyzers.llm.detector import Completer
from app.analyzers.repair.context import (
    RepairContext,
    RepairContextError,
    build_repair_context,
)
from app.analyzers.repair.parser import RepairOutputError, parse_repair_output
from app.analyzers.repair.prompt import build_repair_prompt, truncate_finding_text
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
from app.schemas.repair import RepairRequest, RepairSuggestion


class RepairUnavailableError(Exception):
    """服务端未启用 LLM 或缺少必要配置。"""


class RepairModelError(Exception):
    """模型调用失败（超时、限流、网络或服务端错误）。"""


def generate_repair(
    request: RepairRequest,
    *,
    client: Completer | None = None,
    config: Settings | None = None,
) -> RepairSuggestion:
    """为一条候选发现生成候选补丁。

    参数：
        request: 已校验的修复请求。
        client: 测试注入用的模型客户端；``None`` 时按配置创建真实客户端。
        config: 测试注入用的配置；``None`` 时使用全局配置。

    异常：
        RepairUnavailableError: LLM 未启用或缺少配置。
        RepairContextError: 发现没有可靠行号、行号越界或目标行过长。
        RepairModelError: 模型调用失败。
        RepairOutputError: 模型输出不合格。
    """
    cfg = config or default_settings

    if not cfg.llm_enabled:
        raise RepairUnavailableError(
            "服务端未启用 LLM 修复功能（LLM_ENABLED=false），无法生成修复建议。"
        )

    missing = missing_settings(
        base_url=cfg.llm_base_url, api_key=cfg.llm_api_key, model=cfg.llm_model
    )
    if missing:
        raise RepairUnavailableError(
            f"未配置 {', '.join(missing)}，无法生成修复建议。"
        )

    index = LineIndex(request.source_code)
    context = build_repair_context(
        index, request.finding, max_chars=cfg.llm_max_input_chars
    )

    prompt = build_repair_prompt(
        context=context,
        finding_summary=_finding_summary(request),
        language=request.language,
        filename=request.filename,
        total_lines=index.line_count,
    )

    owns_client = client is None
    active: Completer
    if client is None:
        try:
            active = _create_client(cfg)
        except LlmConfigurationError as exc:
            raise RepairUnavailableError(f"LLM 配置不合法：{exc}") from exc
    else:
        active = client

    try:
        raw = active.complete(prompt.system, prompt.user)
    except LlmError as exc:
        raise RepairModelError(_failure_reason(exc, cfg)) from exc
    finally:
        if owns_client and isinstance(active, LlmClient):
            active.close()

    parsed = parse_repair_output(raw, original_code=context.original_code)

    return RepairSuggestion(
        finding_id=request.finding.id,
        original_code=context.original_code,
        fixed_code=parsed.fixed_code,
        diff=_unified_diff(context, parsed.fixed_code),
        excerpt_line_start=context.excerpt_line_start,
        excerpt_line_end=context.excerpt_line_end,
        context_line_start=context.context_line_start,
        context_line_end=context.context_line_end,
        repair_idea=parsed.repair_idea,
        explanation=parsed.explanation,
        compatibility_impact=parsed.compatibility_impact,
        unconfirmed_premises=parsed.unconfirmed_premises,
    )


def _create_client(cfg: Settings) -> LlmClient:
    """按配置创建客户端；测试会替换本函数以注入假实现。"""
    return LlmClient(
        base_url=cfg.llm_base_url,
        api_key=cfg.llm_api_key,
        model=cfg.llm_model,
        timeout_seconds=cfg.llm_timeout_seconds,
        max_output_tokens=cfg.llm_max_output_tokens,
        max_retries=cfg.llm_max_retries,
    )


def _finding_summary(request: RepairRequest) -> dict[str, object]:
    """只提取修复所需的发现信息，并裁剪长文本。"""
    finding = request.finding
    return {
        "title": finding.title,
        "vulnerability_type": finding.vulnerability_type,
        "severity": finding.severity.value,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "rule_id": finding.rule_id,
        "cwe_id": finding.cwe_id,
        "evidence": truncate_finding_text(finding.evidence),
        "description": truncate_finding_text(finding.description),
        "recommendation": truncate_finding_text(finding.recommendation),
    }


def _unified_diff(context: RepairContext, fixed_code: str) -> str:
    """用标准库计算原始片段与候选补丁的 unified diff。"""
    diff_lines = difflib.unified_diff(
        context.original_code.splitlines(),
        fixed_code.splitlines(),
        fromfile=f"原始代码（第 {context.excerpt_line_start}–{context.excerpt_line_end} 行）",
        tofile="候选补丁",
        lineterm="",
        n=3,
    )
    return "\n".join(diff_lines)


def _failure_reason(exc: LlmError, cfg: Settings) -> str:
    """把客户端异常翻译成用户能据此行动的原因。

    不拼接请求头、响应体或源代码；只保留异常类型对应的固定说明。
    """
    retry_note = (
        f"已重试 {cfg.llm_max_retries} 次" if cfg.llm_max_retries > 0 else "未重试"
    )

    if isinstance(exc, LlmTimeoutError):
        return (
            f"调用模型服务超时（本次请求上限 {cfg.llm_timeout_seconds:g} 秒），"
            f"{retry_note}。可在配置中调整 LLM_TIMEOUT_SECONDS。"
        )
    if isinstance(exc, LlmRateLimitError):
        return f"模型服务返回 429（限流），{retry_note}。"
    if isinstance(exc, LlmServerError):
        return f"模型服务返回服务端错误（{retry_note}）。"
    if isinstance(exc, LlmNetworkError):
        return f"无法连接模型服务（{retry_note}），请检查 LLM_BASE_URL 与网络。"
    if isinstance(exc, LlmResponseTooLargeError):
        return str(exc)
    if isinstance(exc, LlmResponseFormatError):
        return str(exc)

    return "模型调用失败，未能生成修复建议。"
