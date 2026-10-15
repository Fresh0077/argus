"""API 契约层。

本目录是 ARGUS 前后端数据契约的**唯一来源**。
前端 ``frontend/src/types/`` 中的类型必须与本层保持一致。

设计约定：
- 枚举值统一使用小写英文，避免大小写不一致导致的比较错误。
- 未知值一律用 ``None`` 表示，不使用 0、-1 等哨兵值，避免与真实数据混淆。
"""

from app.schemas.enums import (
    SEVERITY_RANK,
    AnalyzerName,
    AnalyzerState,
    ErrorCode,
    FindingSource,
    ScanStatus,
    Severity,
)
from app.schemas.errors import ErrorBody, ErrorDetail, ErrorResponse
from app.schemas.finding import Finding, make_finding_id
from app.schemas.scan import (
    DEFAULT_DISCLAIMER,
    AnalysisOptions,
    AnalyzerStatus,
    ScanRequest,
    ScanResponse,
    ScanSummary,
    SeverityCounts,
)

__all__ = [
    "DEFAULT_DISCLAIMER",
    "SEVERITY_RANK",
    "AnalysisOptions",
    "AnalyzerName",
    "AnalyzerState",
    "AnalyzerStatus",
    "ErrorBody",
    "ErrorCode",
    "ErrorDetail",
    "ErrorResponse",
    "Finding",
    "FindingSource",
    "ScanRequest",
    "ScanResponse",
    "ScanStatus",
    "ScanSummary",
    "Severity",
    "SeverityCounts",
    "make_finding_id",
]
