"""模型客户端异常。

把"调用为什么失败"分成可区分的类型，调用方才能给出有用的状态说明：
用户看到「服务商限流」和看到「输出不是 JSON」需要采取的动作完全不同。

异常消息会直接进入 ``analyzer_status.reason``，因此：

- **不包含 API key、请求头或完整响应体**；
- 不包含源代码；
- 只写用户能据此判断"下一步怎么办"的信息。
"""

from __future__ import annotations


class LlmError(Exception):
    """模型调用的基类异常。"""


class LlmConfigurationError(LlmError):
    """配置缺失或不完整（例如没有 API key）。

    这不是"失败"，而是"不可用"：没有配置就根本不应该发起请求。
    """


class LlmTimeoutError(LlmError):
    """请求超时。"""


class LlmNetworkError(LlmError):
    """网络层错误：连接失败、连接被重置等。"""


class LlmRateLimitError(LlmError):
    """服务商限流（HTTP 429）。"""


class LlmServerError(LlmError):
    """服务商返回 5xx。"""


class LlmResponseTooLargeError(LlmError):
    """响应体超过上限。"""


class LlmResponseFormatError(LlmError):
    """响应不是预期的 OpenAI-compatible 结构（缺 choices / content 为空等）。"""
