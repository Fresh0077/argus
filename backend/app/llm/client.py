"""OpenAI-compatible 模型客户端。

这是整个项目里**唯一**发起模型请求的地方。业务代码只依赖
``LlmClient.complete()`` 这个接口，换服务商时只需要保证对方兼容
``POST {base_url}/chat/completions`` 的请求与响应结构。

安全约定：

- API key 来自配置（环境变量），本模块不读取、不打印、不写入任何文件；
- 异常消息不含 key、请求头、响应体或源代码；
- 不跟随重定向——``Authorization`` 头不应被带到另一个地址；
- 响应体有字节上限，且按块读取，超过上限立即停止。

重试只针对"再试一次可能成功"的错误：429、5xx、超时与网络错误。
4xx（除 429）以及输出格式错误**不重试**——重试不会让坏 JSON 变好。
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic import SecretStr

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

#: 响应体上限。正常的安全分析输出只有几 KB；
#: 超过这个数字通常意味着配置错了接口，或服务商返回了异常内容。
MAX_RESPONSE_BYTES = 256 * 1024

#: 触发重试的 HTTP 状态码。
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

#: 重试的初始等待（秒），之后逐次翻倍。
_INITIAL_BACKOFF_SECONDS = 0.5
_MAX_BACKOFF_SECONDS = 4.0


def missing_settings(
    *,
    base_url: str,
    api_key: SecretStr | str,
    model: str,
) -> list[str]:
    """返回缺失的配置项名称（环境变量名），供 ``unavailable`` 的说明使用。

    只返回**名称**，永远不返回值——即使调用方不小心把 key 传进来，
    key 也不会出现在任何字符串里。
    """
    missing: list[str] = []
    if not base_url.strip():
        missing.append("LLM_BASE_URL")
    key_value = api_key.get_secret_value() if isinstance(api_key, SecretStr) else str(api_key)
    if not key_value.strip():
        missing.append("LLM_API_KEY")
    if not model.strip():
        missing.append("LLM_MODEL")
    return missing


class LlmClient:
    """最小化的 chat completions 客户端。

    参数：
        base_url: 服务地址，例如 ``https://api.example.com/v1``。
            只接受 ``http://`` 或 ``https://``。末尾的 ``/`` 可有可无。
        api_key: API key。用 ``SecretStr`` 承接，避免被 repr 打印出来。
        model: 模型名。
        timeout_seconds: 单次请求超时（秒）。
        max_output_tokens: 输出 token 上限，透传给服务商。
        max_retries: 额外重试次数（0 表示只尝试一次）。
        transport: 测试注入用的 httpx transport；生产环境留 ``None``。
        sleep: 测试注入用的等待函数；生产环境留 ``None``。
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: SecretStr | str,
        model: str,
        timeout_seconds: float,
        max_output_tokens: int,
        max_retries: int,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        normalized = base_url.strip()
        if not normalized.startswith(("http://", "https://")):
            raise LlmConfigurationError(
                "LLM_BASE_URL 必须以 http:// 或 https:// 开头。"
            )

        self._base_url = normalized.rstrip("/") + "/"
        self._api_key = (
            api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
        )
        self._model = model.strip()
        self._max_output_tokens = max_output_tokens
        self._max_retries = max(0, max_retries)
        self._sleep = sleep or time.sleep

        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
            # 不跟随重定向：Authorization 头不能被带到另一个地址。
            follow_redirects=False,
        )

    def close(self) -> None:
        """关闭底层连接池。"""
        self._client.close()

    def __enter__(self) -> "LlmClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def complete(self, system: str, user: str) -> str:
        """发送一轮对话，返回模型的文本输出。

        参数：
            system: 系统提示词。
            user: 用户消息（待分析代码与分析上下文）。

        返回：
            模型返回的文本内容。

        异常：
            ``LlmTimeoutError`` / ``LlmNetworkError`` / ``LlmRateLimitError`` /
            ``LlmServerError`` / ``LlmResponseTooLargeError`` /
            ``LlmResponseFormatError``，全部是 ``LlmError`` 的子类。
        """
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": self._max_output_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        last_error: LlmError | None = None
        for attempt in range(self._max_retries + 1):
            try:
                return self._request_once(payload, headers)
            except (LlmRateLimitError, LlmServerError, LlmTimeoutError, LlmNetworkError) as exc:
                last_error = exc
                if attempt >= self._max_retries:
                    break
                self._sleep(min(_INITIAL_BACKOFF_SECONDS * (2**attempt), _MAX_BACKOFF_SECONDS))

        if last_error is None:  # 理论上不可达；留一个显式错误，避免断言在 -O 下消失
            raise LlmError("模型调用在未产生结果的情况下结束。")
        raise last_error

    def _request_once(self, payload: dict[str, Any], headers: dict[str, str]) -> str:
        """执行一次请求并按块读取响应。"""
        try:
            with self._client.stream(
                "POST", "chat/completions", json=payload, headers=headers
            ) as response:
                status = response.status_code

                if status == 429:
                    raise LlmRateLimitError("模型服务返回 429（请求过多或限流）。")
                if status >= 500:
                    raise LlmServerError(f"模型服务返回 {status}，属于服务端错误。")
                if 300 <= status < 400:
                    raise LlmResponseFormatError(
                        f"模型服务返回了重定向（HTTP {status}），出于安全考虑未跟随。"
                        "请把 LLM_BASE_URL 配置为最终地址。"
                    )
                if status >= 400:
                    # 不回显响应体：某些服务商会在错误信息里带出请求内容。
                    raise LlmResponseFormatError(
                        f"模型服务返回 {status}，请检查 LLM_BASE_URL、LLM_MODEL "
                        "与 API key 是否正确。"
                    )

                body = _read_limited(response)
        except httpx.TimeoutException as exc:
            raise LlmTimeoutError("调用模型服务超时。") from exc
        except httpx.HTTPError as exc:
            # 只保留异常类型，不拼接底层消息：它可能包含内部地址。
            raise LlmNetworkError(
                f"无法连接模型服务（{type(exc).__name__}），请检查 LLM_BASE_URL 与网络。"
            ) from exc

        return _extract_content(body)


def _read_limited(response: httpx.Response) -> bytes:
    """按块读取响应体，超过上限立即停止。"""
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise LlmResponseTooLargeError(
                f"模型响应超过 {MAX_RESPONSE_BYTES // 1024} KB 上限，已停止读取。"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _extract_content(body: bytes) -> str:
    """从 OpenAI-compatible 响应中取出 ``choices[0].message.content``。"""
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LlmResponseFormatError("模型服务返回的内容不是合法 JSON。") from exc

    if not isinstance(payload, dict):
        raise LlmResponseFormatError("模型服务的响应不是 JSON 对象。")

    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LlmResponseFormatError("模型服务的响应缺少 choices 列表。")

    first = choices[0]
    message = first.get("message") if isinstance(first, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise LlmResponseFormatError("模型返回了空内容。")

    return content
