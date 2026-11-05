"""扫描报告的生成与序列化。

数据来源固定为**扫描历史**（阶段 15）：

- 历史只保存结果，不保存完整源代码，因此报告天然不会包含源码正文；
- 只有真实写入过历史的结果才能导出，不会接受调用方伪造的扫描数据；
- 历史关闭、记录不存在或记录损坏时，沿用历史接口的错误语义。

Markdown 转义策略：

- 先做 HTML 转义（``& < >``），再转义 Markdown 控制字符，
  防止发现标题、说明等用户可控文本注入 HTML 或改写文档结构；
- 证据片段放在代码围栏中，围栏长度按内容里最长的反引号串动态加长，
  避免证据里的 ``` 提前闭合围栏；
- 表格单元格里的换行替换成我们自己生成的 ``<br>``。
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from app.schemas.enums import AnalyzerName, AnalyzerState, FindingSource, ScanStatus, Severity
from app.schemas.finding import Finding
from app.schemas.history import HistoryDetail
from app.schemas.report import (
    REPORT_FILENAME_PREFIX,
    REPORT_LIMITATIONS,
    ReportFormat,
    ReportScan,
    ScanReport,
)
from app.schemas.scan import ScanSummary
from app.services.history_service import get_history

#: Markdown 控制字符。先做 HTML 转义，再处理这些字符。
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~>])")

_HTML_ESCAPE = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})

_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "严重",
    Severity.HIGH: "高",
    Severity.MEDIUM: "中",
    Severity.LOW: "低",
    Severity.INFO: "提示",
}

_SOURCE_LABELS: dict[FindingSource, str] = {
    FindingSource.STATIC_RULE: "本地规则",
    FindingSource.HEURISTIC: "启发式线索",
    FindingSource.SEMGREP: "Semgrep",
    FindingSource.LLM: "LLM",
}

_STATUS_LABELS: dict[ScanStatus, str] = {
    ScanStatus.COMPLETED: "完成",
    ScanStatus.PARTIAL: "部分完成",
    ScanStatus.FAILED: "失败",
}

_STATE_LABELS: dict[AnalyzerState, str] = {
    AnalyzerState.SUCCESS: "成功",
    AnalyzerState.SKIPPED: "跳过",
    AnalyzerState.UNAVAILABLE: "不可用",
    AnalyzerState.FAILED: "失败",
}

_ANALYZER_LABELS: dict[AnalyzerName, str] = {
    AnalyzerName.LANGUAGE_DETECTION: "语言识别",
    AnalyzerName.FEATURE_EXTRACTION: "特征提取",
    AnalyzerName.CLUES: "候选线索",
    AnalyzerName.RULES: "本地规则",
    AnalyzerName.SEMGREP: "Semgrep",
    AnalyzerName.LLM: "LLM",
}


def build_report(detail: HistoryDetail) -> ScanReport:
    """把一条历史详情转换成报告模型。

    报告中的所有统计都直接取自历史记录，不重新计算、不补充推测值。
    """
    return ScanReport(
        generated_at=datetime.now(timezone.utc),
        scan=ReportScan(
            scan_id=detail.scan_id,
            created_at=detail.created_at,
            filename=detail.filename,
            language=detail.language,
            status=detail.status,
            source_encoding=detail.source_encoding,
            duration_ms=detail.duration_ms,
            summary=ScanSummary(
                total_findings=detail.total_findings,
                severity_counts=detail.severity_counts,
                source_counts=detail.source_counts,
            ),
        ),
        analyzer_status=detail.analyzer_status,
        findings=detail.findings,
        limitations=list(REPORT_LIMITATIONS),
    )


def export_report(
    scan_id: str, report_format: ReportFormat
) -> tuple[str, str, str]:
    """读取历史并生成报告。

    返回：
        ``(内容, media_type, 文件名)``。文件名完全由服务端生成。

    异常：
        ``HistoryDisabledError`` / ``HistoryNotFoundError`` / ``HistoryStoreError``：
        与历史接口一致，由路由层转换成对应状态码。
    """
    detail = get_history(scan_id)
    report = build_report(detail)

    if report_format is ReportFormat.JSON:
        content = json.dumps(
            report.model_dump(mode="json"), ensure_ascii=False, indent=2
        )
    else:
        content = render_markdown(report)

    filename = (
        f"{REPORT_FILENAME_PREFIX}{detail.scan_id}.{report_format.extension}"
    )
    return content + "\n", report_format.media_type, filename


def escape_markdown(text: str) -> str:
    """转义用户可控文本，防止 HTML / Markdown 注入。

    先转义 HTML 字符，再转义 Markdown 控制字符。换行保留，
    让报告中的说明可以正常分段；行首的 ``#``、``>``、``-`` 等已被转义，
    不会变成标题、引用或列表。
    """
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text.translate(_HTML_ESCAPE))


def render_markdown(report: ScanReport) -> str:
    """把报告渲染成 Markdown 文本。"""
    scan = report.scan
    lines: list[str] = [
        "# ARGUS 扫描报告",
        "",
        "> 本报告由 ARGUS 自动生成，用于辅助人工复核，不是安全证明。",
        "",
        "## 扫描信息",
        "",
        "| 字段 | 值 |",
        "|---|---|",
        f"| 扫描编号 | `{scan.scan_id}` |",
        f"| 扫描时间 | {_plain(_format_datetime(scan.created_at))} |",
        f"| 文件名 | {_cell(scan.filename or '未提供')} |",
        f"| 识别语言 | {_plain(scan.language or '未识别')} |",
        f"| 扫描状态 | {_plain(_status_label(scan.status))} |",
        f"| 源文件解码 | {_plain(scan.source_encoding or '未发生解码转换（JSON 提交）')} |",
        f"| 总耗时 | {scan.duration_ms} ms |",
        f"| 报告生成时间 | {_plain(_format_datetime(report.generated_at))} |",
        "",
        "## 摘要",
        "",
        f"- 候选发现：{scan.summary.total_findings} 条",
        (
            "- 严重等级："
            + "，".join(
                f"{_severity_label(severity)} "
                f"{getattr(scan.summary.severity_counts, severity.value)}"
                for severity in Severity
            )
        ),
        f"- 来源统计：{_plain(_source_summary(scan.summary))}",
        "",
        "## 分析器状态",
        "",
    ]

    if report.analyzer_status:
        lines.extend(
            [
                "| 分析器 | 状态 | 发现数 | 耗时 | 说明 |",
                "|---|---|---|---|---|",
            ]
        )
        for status in report.analyzer_status:
            duration = f"{status.duration_ms} ms" if status.duration_ms is not None else "—"
            lines.append(
                "| "
                + " | ".join(
                    [
                        _plain(_analyzer_label(status.name)),
                        _plain(_state_label(status.state)),
                        str(status.findings_count),
                        duration,
                        _cell(status.reason or "—"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("未记录分析器状态。")

    lines.extend(["", "## 候选发现", ""])

    if report.findings:
        for index, finding in enumerate(report.findings, start=1):
            lines.extend(_render_finding(index, finding))
    else:
        lines.extend(
            [
                "本次分析没有记录到候选发现。",
                "",
                "**没有发现不代表代码安全**，请先确认上面的分析器状态里没有被跳过或失败的分析器。",
                "",
            ]
        )

    lines.extend(["## 局限说明", ""])
    lines.extend(f"- {escape_markdown(item)}" for item in report.limitations)
    lines.append("")

    return "\n".join(lines)


def _render_finding(index: int, finding: Finding) -> list[str]:
    """渲染单条发现。所有文本都经过转义；证据放在代码围栏里。"""
    if finding.line_start is None:
        location = "未能可靠定位"
    elif finding.line_end is not None and finding.line_end != finding.line_start:
        location = f"第 {finding.line_start}–{finding.line_end} 行"
    else:
        location = f"第 {finding.line_start} 行"

    rows = [
        ("漏洞类型", _cell(finding.vulnerability_type)),
        ("严重等级", _plain(_severity_label(finding.severity))),
        ("来源", _plain(_source_label(finding.source))),
        ("置信度", f"{finding.confidence:.2f}"),
        ("位置", _plain(location)),
        ("规则", _cell(finding.rule_id or "未标注")),
        ("CWE", _cell(finding.cwe_id or "未标注")),
    ]

    body = [
        f"### {index}. {escape_markdown(finding.title)}",
        "",
        "| 字段 | 值 |",
        "|---|---|",
        *[f"| {label} | {value} |" for label, value in rows],
        "",
        "**说明**",
        "",
        escape_markdown(finding.description) or "（无说明）",
        "",
        "**证据**",
        "",
    ]
    body.append(
        _fenced_code(finding.evidence) if finding.evidence.strip() else "（无证据片段）"
    )
    body.extend(
        [
            "",
            "**修复建议**",
            "",
            escape_markdown(finding.recommendation) or "（无修复建议）",
            "",
        ]
    )
    return body


def _fenced_code(text: str) -> str:
    """用动态长度的反引号围栏包裹证据，防止内容提前闭合围栏。"""
    runs = re.findall(r"`+", text)
    fence = "`" * max(3, max((len(run) for run in runs), default=0) + 1)
    return f"{fence}\n{text}\n{fence}"


def _cell(value: object) -> str:
    """转义表格单元格；换行用我们自己生成的 ``<br>`` 表示。

    只用于可能包含用户可控文本的值（文件名、证据说明、分析器原因等）。
    """
    return escape_markdown(str(value)).replace("\n", "<br>")


def _plain(value: object) -> str:
    """渲染由服务端生成的受控值（时间、枚举标签、计数），不做 Markdown 转义。"""
    return str(value).replace("\n", " ")


def _format_datetime(value: datetime) -> str:
    """统一使用带时区的 ISO 8601 表示，前端/读者可自行转本地时间。"""
    return value.isoformat()


def _status_label(value: ScanStatus) -> str:
    return f"{_STATUS_LABELS.get(value, value.value)}（{value.value}）"


def _state_label(value: AnalyzerState) -> str:
    return f"{_STATE_LABELS.get(value, value.value)}（{value.value}）"


def _severity_label(value: Severity) -> str:
    return f"{_SEVERITY_LABELS.get(value, value.value)}（{value.value}）"


def _source_label(value: FindingSource) -> str:
    return f"{_SOURCE_LABELS.get(value, value.value)}（{value.value}）"


def _analyzer_label(value: AnalyzerName) -> str:
    return f"{_ANALYZER_LABELS.get(value, value.value)}（{value.value}）"


def _source_summary(summary: ScanSummary) -> str:
    if not summary.source_counts:
        return "无"
    return "；".join(
        f"{_source_label(source)} {count}"
        for source, count in summary.source_counts.items()
    )
