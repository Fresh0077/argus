"""统一错误响应格式。

所有错误响应都使用同一结构，便于前端统一处理：

.. code-block:: json

    {
      "error": {
        "code": "validation_error",
        "message": "请求参数校验未通过，请检查提交的内容。",
        "details": [{"field": "source_code", "message": "source_code 不能为空或仅包含空白字符"}]
      }
    }

安全要求（CLAUDE.md 安全红线）：

- ``message`` 与 ``details`` 中**不得**出现 Python traceback、服务器文件路径、
  API key、环境变量或任何内部实现细节。
- ``details`` 中**不得回显用户提交的原始内容**。校验失败时只说明「哪个字段、
  为什么不合法」，不把 ``source_code`` 原样放进错误响应——
  否则错误响应会变成源代码的副本，容易被误写入日志。
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.schemas.enums import ErrorCode

#: 单条错误详情的长度上限，避免异常信息过长撑爆响应。
MAX_DETAIL_MESSAGE_CHARS = 300


class ErrorDetail(BaseModel):
    """单个字段级别的错误说明。"""

    model_config = ConfigDict(extra="forbid")

    #: 出错的字段路径，例如 ``source_code``。非字段级错误时为 None。
    field: str | None = Field(default=None, max_length=200)

    #: 面向用户的原因说明，不包含内部细节，也不回显原始输入。
    message: Annotated[str, StringConstraints(min_length=1, max_length=MAX_DETAIL_MESSAGE_CHARS)]


class ErrorBody(BaseModel):
    """错误主体。"""

    model_config = ConfigDict(extra="forbid")

    #: 机器可读的错误码，供前端做分支处理。
    code: ErrorCode

    #: 面向用户的中文说明。
    message: Annotated[str, StringConstraints(min_length=1, max_length=500)]

    #: 字段级错误明细。没有明细时为空列表，而不是 null。
    details: list[ErrorDetail] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """统一错误响应。"""

    model_config = ConfigDict(extra="forbid")

    error: ErrorBody
