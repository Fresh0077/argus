"""HTTP 请求包审计的请求/响应契约。

与源码扫描刻意分开：输入是一段**原始请求报文**，行号指向报文行，
而不是某种语言的源码。因此这里不复用 ``ScanRequest``，但复用
``Finding`` 与 ``ScanSummary`` 的严重等级、来源与统计语义；分析器状态
使用请求审计自己的枚举，避免请求专用取值混入扫描契约。

安全边界（对应阶段 19 与 CLAUDE.md）：

- 只做文本解析，**不重放请求、不向目标发起任何网络请求**；
- LLM 只能收到脱敏后的报文；调用前必须由用户确认预览；
- 原始报文不进入历史、日志或报告；
- 所有发现都是候选发现：请求包审计不能确认服务端漏洞。
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.schemas.enums import AnalyzerState, RequestAnalyzerName, Severity
from app.schemas.finding import Finding
from app.schemas.scan import ScanStatus, ScanSummary

#: 单个报文允许的最大行数。超过时拒绝，避免用超长文本拖慢解析与提示词构造。
MAX_REQUEST_LINES = 20_000

#: 脱敏后仍可能出现在响应里的占位符。它不是密钥，只是表示原值已被替换。
REDACTED_PLACEHOLDER = "<REDACTED>"

#: 请求包审计的固定声明。放在契约里，前端无法「忘记」展示。
REQUEST_AUDIT_DISCLAIMER = (
    "请求包审计只分析报文文本本身，不会重放请求或访问目标。"
    "它能发现敏感信息位置、明文传输、Content-Type 不一致等风险信号，"
    "但不能确认服务端是否存在 SQL 注入、XSS、越权等漏洞——"
    "这些必须结合服务端代码、响应与人工复核。"
    "未发现风险不代表该请求安全。"
    "启用 LLM 时，脱敏后的报文会发送到所配置的第三方模型服务商。"
)

#: 请求包审计允许报告的类别。
#:
#: 刻意只收录「从一段请求报文里可观察或可作为信号」的类别：
#: 不收录 SQL 注入、XSS 等需要服务端代码才能确认的漏洞类别，
#: 避免把「请求里有攻击载荷」误说成「服务端存在漏洞」。
RequestVulnerabilityType = Literal[
    "sensitive_data_in_url",
    "credentials_in_plaintext",
    "missing_csrf_token",
    "content_type_mismatch",
    "suspicious_payload_pattern",
]

#: 请求体形态。``none`` 表示没有 body，与「空字符串 body」区分开。
RequestBodyKind = Literal["none", "urlencoded", "json", "multipart", "text"]


#: 单次 LLM 审计最多接收的发现条数。超出部分丢弃并计入 dropped，
#: 不因为模型多写几条就让整次分析作废。
MAX_REQUEST_LLM_FINDINGS = 20


class RequestLlmFinding(BaseModel):
    """模型返回的单条请求审计发现（严格校验）。

    与 ``LlmFinding`` 一样使用 ``extra="forbid"``：字段拼错或多出未约定的键
    都说明模型没有按约定输出，宁可丢弃这一条。
    """

    model_config = ConfigDict(extra="forbid")

    title: Annotated[
        str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)
    ]
    vulnerability_type: RequestVulnerabilityType
    severity: Severity
    description: Annotated[
        str, StringConstraints(min_length=1, max_length=4_000, strip_whitespace=True)
    ]
    #: 必须是脱敏报文的逐字子串；解析阶段会再核对。
    evidence: Annotated[
        str, StringConstraints(min_length=1, max_length=2_000, strip_whitespace=True)
    ]
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    recommendation: Annotated[
        str, StringConstraints(min_length=1, max_length=4_000, strip_whitespace=True)
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    cwe_id: Annotated[
        str, StringConstraints(strip_whitespace=True, max_length=64)
    ] | None = None

    @field_validator("vulnerability_type", mode="before")
    @classmethod
    def _normalize_type(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("line_start", "line_end", mode="before")
    @classmethod
    def _reject_bool_line(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("行号必须是整数，不能是布尔值")
        return value


# ``from __future__ import annotations`` 会把注解保留为字符串；在部分
# Pydantic 版本下，首次在另一个模块中校验该模型时需要显式重建。
RequestLlmFinding.model_rebuild()


class RequestAuditRequest(BaseModel):
    """``POST /api/v1/audit/request`` 的请求体。"""

    model_config = ConfigDict(extra="forbid")

    #: 原始 HTTP 请求报文（支持 CRLF/LF）。
    raw_request: str

    #: 用户在预览中手动编辑后的文本。提供时**以它为准**发送给 LLM，
    #: 服务端不会再对原文重新脱敏；行号与证据都基于这段文本。
    redacted_request: str | None = None

    #: 仅生成解析摘要与脱敏预览，不调用 LLM，也不产生审计发现。
    preview_only: bool = False

    #: 用户已查看脱敏预览并确认发送。正式审计时必填 true。
    confirm_send: bool = False

    #: 预览响应返回的指纹；调用 LLM 时必须与当前脱敏报文一致。
    preview_fingerprint: Annotated[
        str, StringConstraints(pattern=r"^[0-9a-f]{64}$")
    ] | None = None

    @field_validator("raw_request")
    @classmethod
    def _validate_raw_request(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("raw_request 不能为空或仅包含空白字符")
        if "\x00" in value:
            raise ValueError("raw_request 不能包含空字符（NUL），请确认提交的是文本报文")
        # 上限由路由层按配置校验；这里只拦住明显不合法的输入。
        return value

    @field_validator("redacted_request")
    @classmethod
    def _validate_redacted_request(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.strip():
            raise ValueError("redacted_request 不能为空或仅包含空白字符")
        if "\x00" in value:
            raise ValueError("redacted_request 不能包含空字符（NUL）")
        return value

    @model_validator(mode="after")
    def _validate_preview_mode(self) -> "RequestAuditRequest":
        if self.preview_only and self.redacted_request is not None:
            raise ValueError("preview_only 模式只接受 raw_request，不接受 redacted_request")
        return self


class RequestHeaderSummary(BaseModel):
    """头部摘要：只暴露名称与行号，不暴露值。"""

    name: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    line: int = Field(ge=1)


class RequestParameterSummary(BaseModel):
    """参数摘要：只暴露名称、位置与行号，不暴露值。"""

    name: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    location: Literal["query", "body", "cookie"]
    line: int = Field(ge=1)


class RequestBodySummary(BaseModel):
    """请求体摘要。"""

    kind: RequestBodyKind
    content_type: Annotated[str, StringConstraints(max_length=200)] | None = None
    length: int = Field(ge=0)
    line_start: int | None = Field(default=None, ge=1)


class ParsedRequestSummary(BaseModel):
    """解析结果的**脱敏摘要**。

    不包含任何头部值、参数值或完整请求体；这些只通过 ``redacted_request``
    展示，且其中的敏感值已被替换。
    """

    method: str
    target: str
    path: str
    http_version: str
    scheme: str | None = None
    header_count: int = Field(ge=0)
    headers: list[RequestHeaderSummary] = Field(default_factory=list)
    parameter_count: int = Field(ge=0)
    parameters: list[RequestParameterSummary] = Field(default_factory=list)
    cookie_count: int = Field(ge=0)
    body: RequestBodySummary
    line_count: int = Field(ge=1)


class RedactionSummary(BaseModel):
    """脱敏统计。只记录「替换了多少处」与类别，不回显原值。"""

    redacted_count: int = Field(ge=0)
    categories: list[str] = Field(default_factory=list)


class RequestAnalyzerStatus(BaseModel):
    """请求包审计中单个分析器的状态。

    与扫描的 ``AnalyzerStatus`` 结构相同，但 ``name`` 使用请求审计自己的枚举，
    避免把请求审计专用的分析器名混进源码扫描契约。
    """

    name: RequestAnalyzerName
    state: AnalyzerState
    reason: Annotated[
        str, StringConstraints(min_length=1, max_length=500)
    ] | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    findings_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _require_reason_for_non_success(self) -> "RequestAnalyzerStatus":
        if self.state != AnalyzerState.SUCCESS and not self.reason:
            raise ValueError(
                f"分析器 {self.name.value} 的状态为 {self.state.value} 时，必须提供 reason 说明原因"
            )
        return self


class RequestAuditResponse(BaseModel):
    """请求包审计结果。

    ``status == "partial"`` 表示 LLM 未执行（预览、未启用、未配置或失败）。
    请求包审计只保留 LLM 这一路分析，因此此时 ``findings`` 为空；
    前端必须结合 ``analyzer_status`` 展示原因，不能把空结果读成“安全”。
    """

    audit_id: Annotated[str, StringConstraints(min_length=8, max_length=64)]
    status: ScanStatus
    preview_only: bool

    #: 本次审计使用的文本是否经过用户手动编辑。
    edited: bool = False

    #: 解析摘要（已脱敏）。
    parsed: ParsedRequestSummary

    #: 将要（或已经）发送给 LLM 的脱敏报文全文。
    redacted_request: str

    #: 脱敏指纹。预览与确认之间用它绑定同一次内容。
    preview_fingerprint: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

    redaction: RedactionSummary

    #: LLM 审计发现（``source=llm``）；未调用或执行失败时为空。
    #:
    #: 请求包审计只保留 LLM 这一路分析：预览阶段不会产生发现，
    #: 必须启用 LLM 并确认脱敏内容后才有结果。
    findings: list[Finding] = Field(default_factory=list)

    summary: ScanSummary
    analyzer_status: list[RequestAnalyzerStatus] = Field(default_factory=list)
    duration_ms: int = Field(ge=0)
    llm_invoked: bool = False
    disclaimer: str = REQUEST_AUDIT_DISCLAIMER
