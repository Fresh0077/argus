"""扫描报告的契约模型。

报告的数据来源是**已保存的扫描历史**，不接受调用方直接提交扫描结果：
这样能保证"只导出实际存在的扫描结果"，也避免把 UI 中的示例数据写进报告。

报告刻意**不包含完整源代码**：历史里本来就没有存，报告只带发现的最小证据片段。
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.schemas.finding import Finding
from app.schemas.scan import AnalyzerStatus, LanguageId, ScanStatus, ScanSummary

#: 报告结构版本。字段变更时递增，便于调用方判断兼容性。
REPORT_VERSION = 1

#: 每份报告都会附带的局限说明。放在契约里，避免不同导出格式各写一份而漂移。
REPORT_LIMITATIONS: tuple[str, ...] = (
    "ARGUS 是代码安全分析的辅助工具，不是安全证明工具；未发现漏洞不代表代码绝对安全。",
    "分析结果来自规则匹配、特征启发式与（可选的）模型判断，均可能误报或漏报。",
    "confidence 表示分析器对自身判断的估计，不是漏洞真实发生的概率，也不能跨来源比较或相加。",
    "报告中不包含完整源代码，只保留候选发现的最小证据片段。",
    "若有分析器被跳过、不可用或失败，其结果不代表“没有问题”，请结合分析器状态判断。",
    "启用 LLM 时，扫描期间的代码片段已发送到所配置的第三方模型服务商。",
    "修复建议是候选方案，未经编译、执行或测试，应用前必须人工审查并重新测试。",
)

#: 报告的文件名前缀与扩展名由服务端固定生成，不接受用户输入。
REPORT_FILENAME_PREFIX = "argus-report-"


class ReportFormat(str, Enum):
    """支持的导出格式。"""

    JSON = "json"
    MARKDOWN = "markdown"

    @property
    def extension(self) -> str:
        return "json" if self is ReportFormat.JSON else "md"

    @property
    def media_type(self) -> str:
        if self is ReportFormat.JSON:
            return "application/json; charset=utf-8"
        return "text/markdown; charset=utf-8"


class ReportScan(BaseModel):
    """报告中的扫描信息。"""

    scan_id: str
    created_at: datetime
    filename: str | None = None
    language: LanguageId | None = None
    status: ScanStatus
    source_encoding: str | None = None
    duration_ms: int = Field(ge=0)
    summary: ScanSummary


class ScanReport(BaseModel):
    """一份完整的扫描报告。"""

    report_version: int = REPORT_VERSION
    generated_at: datetime
    scan: ReportScan
    analyzer_status: list[AnalyzerStatus] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=lambda: list(REPORT_LIMITATIONS))
