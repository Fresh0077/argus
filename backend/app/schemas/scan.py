"""扫描请求/响应模型。

这是前后端对接的核心契约：

- 请求：``ScanRequest``
- 响应：``ScanResponse``（其中包含 ``Finding`` 列表、``ScanSummary`` 与 ``AnalyzerStatus``）

设计原则：``summary`` 与 ``duration_ms`` 等统计字段**必须由真实结果计算**，
不允许由调用方随意填写，因此优先通过工厂方法（``ScanSummary.from_findings``）构造。
"""

from __future__ import annotations

from typing import Annotated, Sequence

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from app.core.config import settings
from app.schemas.enums import AnalyzerName, AnalyzerState, FindingSource, ScanStatus, Severity
from app.schemas.features import FeatureExtractionResult
from app.schemas.finding import Finding

#: 语言标识，例如 ``python``、``javascript``、``c++``。
#: 取值统一小写；无法识别时使用 ``unknown``，后者是合法取值而非错误。
LanguageId = Annotated[str, StringConstraints(min_length=1, max_length=32, pattern=r"^[a-z0-9+#._-]+$")]

#: 每次响应都会带上的定位声明。
#: 放在契约里而不是仅写在文档中，是为了让前端无法「忘记」展示它。
DEFAULT_DISCLAIMER = (
    "ARGUS 是代码安全分析的辅助工具，不是安全证明工具。"
    "结果来自规则匹配、特征启发式与（可选的）模型判断，均可能误报或漏报。"
    "confidence 表示分析器对自身判断的估计，不是漏洞真实发生的概率。"
    "未发现漏洞不代表代码绝对安全，请结合人工复核。"
    "启用 LLM 分析时，提交的代码会发送到所配置的第三方模型服务商，请勿提交敏感代码。"
)

#: 文件名长度上限（含扩展名）。
MAX_FILENAME_CHARS = 255

#: Windows 保留设备名，不能作为文件名使用。
_WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def validate_display_filename(value: str | None) -> str | None:
    """校验作为**展示信息**的文件名。

    这里的 ``filename`` 只用于在结果中显示来源，
    绝不允许被拼接成文件系统路径（见 CLAUDE.md 安全红线第 5 条）。

    拦截范围覆盖 Windows 特有的路径变体：路径分隔符、``..`` 跳转、
    盘符前缀与 NTFS 数据流（``C:`` / ``file.py:evil`` 中的冒号）、
    保留设备名（``CON``/``NUL``/``AUX``/``PRN``/``COM1``…）、
    尾随点（Windows 会静默丢弃）以及空字符。

    上传接口（阶段 5）与 JSON 接口共用本函数，
    避免出现「JSON 接口放行、上传接口拦截」的不一致。

    首尾空白会被去除而不是报错：该字段仅作展示，去空白不影响任何判定，
    且 Windows 本身也会丢弃文件名末尾的空格，报错反而让用户困惑。
    """
    if value is None:
        return None

    name = value.strip()
    if not name:
        raise ValueError("filename 不能为空字符串（不需要文件名时请省略该字段）")

    if len(name) > MAX_FILENAME_CHARS:
        raise ValueError(f"filename 长度不能超过 {MAX_FILENAME_CHARS} 个字符")

    if "\x00" in name:
        raise ValueError("filename 不能包含空字符")

    # 路径分隔符：出现在文件名中说明调用方在传路径，直接拒绝。
    if "/" in name or "\\" in name:
        raise ValueError("filename 只能是文件名，不能包含路径分隔符")

    # 冒号：既能构造盘符前缀（C:），也能构造 NTFS 数据流（file.py:evil）。
    # 两者都是 Windows 特有的绕过手法，合法的文件名不会包含冒号。
    if ":" in name:
        raise ValueError("filename 不能包含冒号（可能构成盘符前缀或 NTFS 数据流）")

    # 相对路径跳转。
    if name in {".", ".."} or ".." in name:
        raise ValueError("filename 不能包含 '..'")

    # 尾随点：Windows 会静默丢弃，使 "views.py." 与 "views.py" 指向同一文件。
    # 这里显式拒绝，避免同一个名字存在两种写法。
    if name.endswith("."):
        raise ValueError("filename 不能以点结尾")

    # Windows 保留设备名（大小写不敏感）。
    stem = name.split(".", 1)[0].lower()
    if stem in _WINDOWS_RESERVED_NAMES:
        raise ValueError(f"filename 不能使用系统保留名称：{stem}")

    return name


class AnalysisOptions(BaseModel):
    """可选的分析配置。

    未知字段会直接报错（``extra="forbid"``），避免前端把字段名拼错后
    配置静默失效——那会让人误以为「已经启用了 LLM 但没发现问题」。

    后续阶段若需要新增配置项（例如最低严重等级过滤），在此追加字段，
    并同步更新 docs/api.md。
    """

    model_config = ConfigDict(extra="forbid")

    #: 是否启用 LLM 辅助分析。默认关闭：未配置 API key 时系统仍应可用。
    #: 即使此处为 True，服务端在缺少配置时也只能降级为不可用状态，
    #: 并在 analyzer_status 中如实说明，而不是报错或假装分析过。
    enable_llm: bool = False

    #: 是否启用 Semgrep 静态分析器。即使此处为 True，
    #: 未安装 Semgrep 时也必须降级为 unavailable，不得导致整个扫描失败。
    enable_semgrep: bool = False


class ScanRequest(BaseModel):
    """提交代码进行扫描的请求。

    对应 ``POST /api/v1/scan``（JSON 代码文本）。
    单文件上传使用 ``POST /api/v1/scan/upload``，其表单字段与解析结果
    最终也会构造成本模型，保证两条入口的分析流程完全一致。
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "source_code": "query = \"SELECT * FROM users WHERE id = \" + user_id",
                "language": "python",
                "filename": "views.py",
                "analysis_options": {"enable_llm": False, "enable_semgrep": False},
            }
        },
    )

    #: 待检测的源代码文本。
    #: 长度上限取自配置 ``MAX_SOURCE_CODE_CHARS``，不在本文件硬编码。
    source_code: str

    #: 语言标识。省略时由后端自动识别（阶段 6）。
    language: LanguageId | None = None

    #: 文件名，仅用于展示来源，不参与任何文件系统操作。
    filename: str | None = None

    #: 可选分析配置。
    analysis_options: AnalysisOptions = Field(default_factory=AnalysisOptions)

    # --- 校验 ---

    @field_validator("source_code")
    @classmethod
    def _validate_source_code(cls, value: str) -> str:
        """拒绝空内容与超长内容。

        不在这里做 ``strip()``：代码的缩进和首尾空行可能有意义，
        交给分析器按语言规则处理。
        """
        if not value.strip():
            raise ValueError("source_code 不能为空或仅包含空白字符")

        limit = settings.max_source_code_chars
        if len(value) > limit:
            raise ValueError(f"source_code 长度 {len(value)} 超过上限 {limit} 个字符")

        return value

    @field_validator("language", mode="before")
    @classmethod
    def _normalize_language(cls, value: object) -> object:
        """语言标识统一转为小写并去除首尾空白；空字符串视为未提供。"""
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


class AnalyzerStatus(BaseModel):
    """单个分析器的执行状态。

    **必须区分「分析失败」与「未发现漏洞」**：``state`` 为 ``failed`` 时
    不代表代码安全，只代表该项分析没有产出可信结论。
    """

    name: AnalyzerName

    #: 执行状态。
    state: AnalyzerState

    #: 跳过 / 不可用 / 失败的具体原因，例如「未安装 Semgrep」「未配置 LLM_API_KEY」。
    #: 非 success 状态必须给出原因，否则用户无法判断结果是「没问题」还是「没跑」。
    reason: Annotated[str, StringConstraints(min_length=1, max_length=500)] | None = None

    #: 该分析器耗时（毫秒）。未执行时为 None。
    duration_ms: int | None = Field(default=None, ge=0)

    #: 该分析器报告的发现数量。0 表示未发现问题，不代表分析失败。
    findings_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _require_reason_for_non_success(self) -> "AnalyzerStatus":
        """非成功状态必须说明原因。

        这是硬约束：缺少原因的失败状态会被误读为「没有风险」。
        """
        if self.state != AnalyzerState.SUCCESS and not self.reason:
            raise ValueError(
                f"分析器 {self.name.value} 的状态为 {self.state.value} 时，必须提供 reason 说明原因"
            )
        return self


class SeverityCounts(BaseModel):
    """按严重等级统计的发现数量。

    使用固定字段而非自由字典，保证前端拿到的结构永远包含全部等级，
    不需要处理「某个等级缺失」的情况。
    """

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


class ScanSummary(BaseModel):
    """扫描结果摘要。

    必须由 ``from_findings()`` 基于真实结果计算，**不允许编造统计数字**。
    """

    total_findings: int = Field(ge=0)
    severity_counts: SeverityCounts
    #: 按来源统计，用于向用户说明「这些结论分别来自哪里」。
    source_counts: dict[FindingSource, int] = Field(default_factory=dict)

    @classmethod
    def from_findings(cls, findings: Sequence[Finding]) -> "ScanSummary":
        """根据实际发现列表统计摘要。

        这是构造 ``ScanSummary`` 的推荐方式，能把「统计」与「结果」绑定，
        避免出现摘要数字与 findings 对不上的情况。
        """
        severity_tally = {severity.value: 0 for severity in Severity}
        source_tally: dict[FindingSource, int] = {}

        for finding in findings:
            severity_tally[finding.severity.value] += 1
            source_tally[finding.source] = source_tally.get(finding.source, 0) + 1

        return cls(
            total_findings=len(findings),
            severity_counts=SeverityCounts(**severity_tally),
            source_counts=source_tally,
        )


class ScanResponse(BaseModel):
    """扫描结果响应。

    即使部分分析器失败，也必须返回已经成功的那部分结果，
    并通过 ``analyzer_status`` 与 ``status`` 如实反映整体情况。
    """

    #: 本次扫描的标识符，用于关联历史记录（阶段 15）与修复建议（阶段 16）。
    scan_id: Annotated[str, StringConstraints(min_length=8, max_length=64)]

    #: 整体状态。``partial`` 表示有分析器被跳过或失败，但结果仍可用。
    status: ScanStatus

    #: 识别出的语言；无法识别时为 None（前端显示「未知语言」）。
    detected_language: LanguageId | None = None

    #: 上传文件的解码方式，例如 ``utf-8`` / ``utf-8-sig`` / ``gbk`` / ``utf-16``。
    #:
    #: 仅上传接口会填写；JSON 提交按规范固定为 UTF-8，此处为 None。
    #: 之所以要暴露出来：当 UTF-8 解不开而落到 GBK 兜底时，
    #: 用户需要知道发生了字符集转换，否则界面上一切正常、内容却已不是原意。
    source_encoding: str | None = None

    #: 候选发现列表。空列表表示**本次分析未发现问题**，
    #: 其含义取决于 analyzer_status：若有分析器 failed，则不能读作「代码安全」。
    findings: list[Finding] = Field(default_factory=list)

    #: 由真实结果计算的摘要。
    summary: ScanSummary

    #: 实际耗时（毫秒），必须由真实计时获得。
    duration_ms: int = Field(ge=0)

    #: 各分析器的执行状态。
    analyzer_status: list[AnalyzerStatus] = Field(default_factory=list)

    #: 特征提取结果（语言依据、统计量、结构信息与处理说明）。
    #:
    #: 为 None 表示特征提取未能执行。它与"提取到了但计数为 0"必须能区分开：
    #: 整个字段为 None 时前端应显示「未执行特征提取」，
    #: 而不是显示一排 0 让人以为代码是空的。
    features: FeatureExtractionResult | None = None

    #: 定位声明，默认使用 ``DEFAULT_DISCLAIMER``。
    disclaimer: str = DEFAULT_DISCLAIMER
