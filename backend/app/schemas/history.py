"""扫描历史的 API 契约。

列表接口只返回元数据，详情接口才返回候选发现与分析器状态：
历史列表可能很长，没必要为每一行都搬运完整结果。
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

from app.schemas.enums import FindingSource, ScanStatus
from app.schemas.finding import Finding
from app.schemas.scan import AnalyzerStatus, SeverityCounts

#: 列表默认每页条数。
HISTORY_PAGE_SIZE_DEFAULT = 20
#: 每页条数上限。限制上限是为了避免一次请求把整张表读进内存。
HISTORY_PAGE_SIZE_MAX = 100

ScanId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]


class HistoryItem(BaseModel):
    """列表中的一条扫描历史（不含发现明细）。"""

    scan_id: ScanId
    #: UTC 时间；前端负责转换为本地时间展示。
    created_at: datetime
    #: 调用方提供的展示用文件名；没有时为 None。
    filename: str | None = None
    #: 本次扫描识别出的语言；未识别时为 None。
    language: str | None = None
    status: ScanStatus
    #: 上传接口实际使用的解码方式；JSON 提交为 None。
    source_encoding: str | None = None
    duration_ms: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    severity_counts: SeverityCounts
    source_counts: dict[FindingSource, int] = Field(default_factory=dict)


class HistoryDetail(HistoryItem):
    """一条扫描历史的完整结果。

    ``findings`` 与 ``analyzer_status`` 来自扫描当时的结果快照，
    不会因为之后修改规则集而改变。
    """

    findings: list[Finding] = Field(default_factory=list)
    analyzer_status: list[AnalyzerStatus] = Field(default_factory=list)


class HistoryListResponse(BaseModel):
    """分页后的历史列表。

    ``enabled`` 为 False 表示服务端通过 ``HISTORY_ENABLED=false`` 关闭了历史功能，
    此时 ``items`` 为空、``total`` 为 0，而不是"一条记录都没有"。
    """

    enabled: bool
    items: list[HistoryItem] = Field(default_factory=list)
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    #: 总页数；没有记录时为 0。
    total_pages: int = Field(ge=0)
