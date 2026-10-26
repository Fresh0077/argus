"""LLM 输出的传输对象（DTO）。

模型的返回是**不可信数据**：可能是坏 JSON、缺字段、编造行号、
或者塞进一个不在词表里的漏洞类别。因此先由这组模型做严格校验，
再转换成项目的 ``Finding``，而不是让 LLM 的 JSON 直接进入公共契约。

与 ``Finding`` 的区别（刻意分成两个模型）：

- ``Finding`` 使用 ``extra="ignore"``，因为它同时承接自家分析器的输出；
- ``LlmFinding`` 使用 ``extra="forbid"``，因为字段名拼错、多出未约定的键
  都说明模型没有按约定输出，宁可丢弃这一条也不猜。
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.schemas.enums import Severity

#: 允许 LLM 报告的漏洞类别。
#:
#: 刻意**不含** ``untrusted_input_source``：那是数据来源标记，不是缺陷。
#: 也不接受自由文本——类别是后续去重、排序与统计的键，不能任由模型发明。
LlmVulnerabilityType = Literal[
    "sql_injection",
    "command_injection",
    "xss",
    "unsafe_dynamic_execution",
    "unsafe_deserialization",
]

#: 模型一次最多应报告的条数（提示词里也写了 10；这里允许到 50，
#: 是为了不让"模型多写了两条"被当成整次输出作废）。
MAX_LLM_FINDINGS = 50


class LlmFinding(BaseModel):
    """模型返回的单条发现。

    所有字符串字段会去掉首尾空白；空标题、空说明等视为不合法。
    """

    model_config = ConfigDict(extra="forbid")

    title: Annotated[str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)]
    vulnerability_type: LlmVulnerabilityType
    severity: Severity
    description: Annotated[
        str, StringConstraints(min_length=1, max_length=4_000, strip_whitespace=True)
    ]
    #: 模型给出的代码片段。**不直接采用**：转换时会按行号从源码取真实文本。
    evidence: Annotated[str, StringConstraints(max_length=2_000, strip_whitespace=True)] = ""
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    recommendation: Annotated[
        str, StringConstraints(min_length=1, max_length=4_000, strip_whitespace=True)
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    cwe_id: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)] | None = None

    @field_validator("vulnerability_type", mode="before")
    @classmethod
    def _normalize_type(cls, value: object) -> object:
        """容忍大小写与首尾空白；取值本身仍必须是词表内的值。"""
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("line_start", "line_end", mode="before")
    @classmethod
    def _reject_bool_line(cls, value: object) -> object:
        """``True``/``False`` 不能被当成行号 1/0。"""
        if isinstance(value, bool):
            raise ValueError("行号必须是整数，不能是布尔值")
        return value
