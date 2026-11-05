"""修复建议的请求与响应契约。

设计边界（对应阶段 16）：

- 修复建议是**候选补丁**，不是已经验证的修复；
- 后端只接收已存在的发现与源代码文本，**不写回任何文件**；
- 模型输出先由 ``RepairModelOutput`` 严格校验，再转换成对外的
  ``RepairSuggestion``，不把模型 JSON 直接透传给前端。

请求里带 ``source_code`` 是刻意的：扫描历史不保存源代码（见阶段 15），
因此修复流程必须由调用方重新提供本次要修复的代码。服务端只用它
提取最小上下文并计算差异，不会持久化。
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.schemas.finding import Finding
from app.schemas.scan import LanguageId, validate_display_filename, validate_source_code

#: 对外固定的风险声明。放在契约里，前端无法「忘记」展示。
REPAIR_DISCLAIMER = (
    "修复建议由 LLM 生成，未经编译、执行或测试，可能不正确或引入新问题。"
    "应用前必须人工审查，并在你的运行环境中重新测试。"
    "ARGUS 不会自动修改或覆盖原始文件。"
)

#: 模型单次返回的修复代码长度上限（字符）。
#: 与 ``LLM_MAX_OUTPUT_TOKENS`` 相互独立：token 上限约束模型输出，
#: 这里约束我们愿意接收的文本量，防止异常响应撑大前端。
MAX_REPAIR_FIXED_CODE_CHARS = 12_000

#: 修复思路 / 解释 / 兼容性影响 / 单条前提的长度上限。
MAX_REPAIR_IDEA_CHARS = 2_000
MAX_REPAIR_EXPLANATION_CHARS = 4_000
MAX_REPAIR_COMPATIBILITY_CHARS = 2_000
MAX_REPAIR_PREMISE_CHARS = 300
MAX_REPAIR_PREMISES = 10


class RepairRequest(BaseModel):
    """``POST /api/v1/repair`` 的请求体。"""

    model_config = ConfigDict(extra="forbid")

    source_code: str

    #: 语言标识；省略时按未知语言处理，不阻止修复流程。
    language: LanguageId | None = None

    #: 仅用于展示与建议下载文件名，不参与任何文件系统操作。
    filename: str | None = None

    #: 要修复的候选发现。会校验行号是否落在 ``source_code`` 范围内。
    finding: Finding

    @field_validator("source_code")
    @classmethod
    def _validate_source_code(cls, value: str) -> str:
        return validate_source_code(value)

    @field_validator("language", mode="before")
    @classmethod
    def _normalize_language(cls, value: object) -> object:
        if isinstance(value, str):
            normalized = value.strip().lower()
            return normalized or None
        return value

    @field_validator("filename", mode="before")
    @classmethod
    def _validate_filename(cls, value: object) -> object:
        if isinstance(value, str):
            return validate_display_filename(value)
        return value


class RepairModelOutput(BaseModel):
    """模型返回的修复结果（传输对象）。

    使用 ``extra="forbid"``：字段拼错或缺少约定字段说明模型没有按格式输出，
    宁可报告「输出不可用」，也不猜测它想表达什么。
    """

    model_config = ConfigDict(extra="forbid")

    repair_idea: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_REPAIR_IDEA_CHARS, strip_whitespace=True
        ),
    ]

    #: 修复后的代码。**不去首尾空白**：缩进属于代码本身。
    #: 允许为空字符串，解析层会把"空"解释为模型未能给出可靠修复。
    fixed_code: Annotated[str, StringConstraints(max_length=MAX_REPAIR_FIXED_CODE_CHARS)]

    explanation: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=MAX_REPAIR_EXPLANATION_CHARS,
            strip_whitespace=True,
        ),
    ]

    compatibility_impact: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=MAX_REPAIR_COMPATIBILITY_CHARS,
            strip_whitespace=True,
        ),
    ]

    #: 模型未能确认的前提。没有时可以返回空列表，不得编造。
    unconfirmed_premises: list[
        Annotated[
            str,
            StringConstraints(
                min_length=1, max_length=MAX_REPAIR_PREMISE_CHARS, strip_whitespace=True
            ),
        ]
    ] = Field(default_factory=list, max_length=MAX_REPAIR_PREMISES)


class RepairSuggestion(BaseModel):
    """一条可审阅的候选补丁。

    ``original_code`` 与 ``diff`` 都由服务端根据真实源码计算，
    不采用模型返回的代码片段作为「原始内容」。
    """

    #: 与原始发现关联；前端据此确认补丁属于哪条 Finding。
    finding_id: Annotated[str, StringConstraints(min_length=1, max_length=64)]

    #: 待替换的真实原始代码（第 ``excerpt_line_start``–``excerpt_line_end`` 行）。
    original_code: str

    #: 模型给出的替换代码。
    fixed_code: str

    #: 服务端计算的 unified diff；为空表示没有可展示的差异。
    diff: str

    #: 被替换的行范围（1 起，含两端）。
    excerpt_line_start: int = Field(ge=1)
    excerpt_line_end: int = Field(ge=1)

    #: 实际发送给模型的上下文行范围（1 起，含两端）。
    context_line_start: int = Field(ge=1)
    context_line_end: int = Field(ge=1)

    repair_idea: str
    explanation: str
    compatibility_impact: str
    unconfirmed_premises: list[str] = Field(default_factory=list)

    disclaimer: str = REPAIR_DISCLAIMER
