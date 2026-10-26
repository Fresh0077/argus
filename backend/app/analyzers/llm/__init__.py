"""LLM 分析器。

与 ``semgrep`` 子包一样，对外只暴露一个入口 ``detect_llm_findings`` 和结果类型。
提示词与解析分开放在 ``prompt`` / ``parser``，便于单独测试。
"""

from app.analyzers.llm.detector import LlmOutcome, detect_llm_findings
from app.analyzers.llm.parser import LlmOutputError, LlmParseResult, parse_llm_output
from app.analyzers.llm.prompt import (
    ALLOWED_VULNERABILITY_TYPES,
    SYSTEM_PROMPT,
    PromptBuild,
    build_prompt,
)

__all__ = [
    "ALLOWED_VULNERABILITY_TYPES",
    "SYSTEM_PROMPT",
    "LlmOutcome",
    "LlmOutputError",
    "LlmParseResult",
    "PromptBuild",
    "build_prompt",
    "detect_llm_findings",
    "parse_llm_output",
]
