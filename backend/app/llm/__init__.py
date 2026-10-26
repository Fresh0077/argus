"""模型服务封装。

本包只负责"把消息发出去、把文本拿回来"，不构造提示词、不解析分析结果。
提示词与分析结果的校验在 ``app.analyzers.llm`` 中，便于分别测试，
也避免把厂商细节混进分析逻辑。
"""

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

__all__ = [
    "LlmClient",
    "LlmConfigurationError",
    "LlmError",
    "LlmNetworkError",
    "LlmRateLimitError",
    "LlmResponseFormatError",
    "LlmResponseTooLargeError",
    "LlmServerError",
    "LlmTimeoutError",
    "missing_settings",
]
