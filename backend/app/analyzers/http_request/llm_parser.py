"""校验模型返回的请求包审计结果。

校验比源码 LLM 解析更严格，原因是请求报文里的头部与 body 更容易被
用来做提示词注入，而且模型没有源码可依赖：

1. 每条发现必须通过 ``RequestLlmFinding`` 的严格结构校验；
2. ``evidence`` 必须是脱敏报文的逐字子串；
3. 行号必须落在本次实际发送给模型的行范围内；
4. 证据必须能在所给行范围内找到；
5. 模型多给的条目只丢弃该条，不整次作废；但如果声称有发现却全部不合格，
   整次分析报失败，不能把“输出全是垃圾”报告成“没发现问题”。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import ValidationError

from app.analyzers.line_index import LineIndex
from app.analyzers.llm.parser import load_json_object
from app.analyzers.llm.parser import LlmOutputError as _BaseLlmOutputError
from app.schemas.enums import FindingSource, Severity
from app.schemas.finding import Finding, make_finding_id
from app.schemas.http_request import MAX_REQUEST_LLM_FINDINGS, RequestLlmFinding

_CWE_PATTERN = re.compile(r"CWE-\d{1,5}")

_QUALIFIER = (
    "（本条为 LLM 对脱敏请求报文的判断；请求包审计不能确认服务端漏洞，"
    "仍需结合服务端代码与人工复核。）"
)

#: ``Finding.description`` 的上限。
_MAX_DESCRIPTION_CHARS = 4_000


class RequestLlmOutputError(_BaseLlmOutputError):
    """模型输出无法作为请求包审计结果使用。"""


@dataclass(frozen=True)
class RequestLlmParseResult:
    findings: list[Finding]
    dropped: int
    total_items: int


def parse_request_llm_output(
    raw: str,
    *,
    redacted_request: str,
    included_lines: int,
) -> RequestLlmParseResult:
    """解析模型输出并转换成 ``Finding``。

    参数：
        raw: 模型原始输出。
        redacted_request: 实际发送给模型的脱敏报文全文。
        included_lines: 实际发送的行数（截断时小于总行数）。
    """
    payload = load_json_object(raw)
    items = payload.get("findings")
    if not isinstance(items, list):
        raise RequestLlmOutputError("模型输出缺少 findings 列表。")

    total_items = min(len(items), MAX_REQUEST_LLM_FINDINGS)
    dropped = max(0, len(items) - MAX_REQUEST_LLM_FINDINGS)

    index = LineIndex(redacted_request)
    lines = index.lines()
    visible = max(0, min(included_lines, len(lines)))

    findings: list[Finding] = []
    claimed: set[tuple[str, int]] = set()

    for item in items[:MAX_REQUEST_LLM_FINDINGS]:
        finding = _convert(item, lines, visible)
        if finding is None:
            dropped += 1
            continue

        key = (finding.vulnerability_type, finding.line_start or 0)
        if key in claimed:
            dropped += 1
            continue
        claimed.add(key)
        findings.append(finding)

    if total_items > 0 and not findings:
        raise RequestLlmOutputError(
            f"模型返回了 {total_items} 条发现，但没有一条通过结构校验、"
            "证据核对或行号核对。"
        )

    return RequestLlmParseResult(
        findings=findings, dropped=dropped, total_items=total_items
    )


def _convert(
    item: object, lines: list[str], visible_lines: int
) -> Finding | None:
    if not isinstance(item, dict):
        return None

    try:
        parsed = RequestLlmFinding.model_validate(item)
    except ValidationError:
        return None

    evidence = parsed.evidence.strip()
    if not evidence or evidence not in "\n".join(lines[:visible_lines]):
        return None

    located = _locate(parsed, lines, visible_lines, evidence)
    if located is None:
        return None
    line_start, line_end = located

    severity = _cap_severity(parsed.vulnerability_type, parsed.severity)
    description = _with_qualifier(parsed.description)

    return Finding(
        id=make_finding_id(
            source=FindingSource.LLM,
            rule_key=f"llm.request.{parsed.vulnerability_type}",
            line_start=line_start,
            line_end=line_end,
            evidence=evidence,
        ),
        rule_id=f"llm.request.{parsed.vulnerability_type}",
        title=parsed.title,
        vulnerability_type=parsed.vulnerability_type,
        severity=severity,
        description=description,
        evidence=evidence,
        line_start=line_start,
        line_end=line_end,
        recommendation=parsed.recommendation,
        confidence=parsed.confidence,
        source=FindingSource.LLM,
        cwe_id=_extract_cwe(parsed.cwe_id),
    )


def _locate(
    parsed: RequestLlmFinding,
    lines: list[str],
    visible_lines: int,
    evidence: str,
) -> tuple[int, int] | None:
    """核对或推导行号。

    模型给了行号时，核对它是否落在本次发送范围内，并确认证据确实出现在
    该范围内的某段文本中。模型没给行号时，仅在证据能唯一匹配一行时推导，
    多处匹配则丢弃——猜一个行号比不报更糟。
    """
    if parsed.line_start is None:
        matches = [
            index
            for index, line in enumerate(lines[:visible_lines], start=1)
            if evidence in line
        ]
        if len(matches) != 1:
            return None
        return matches[0], matches[0]

    start = parsed.line_start
    if not 1 <= start <= visible_lines:
        return None

    end = parsed.line_end if parsed.line_end is not None else start
    if not start <= end <= visible_lines:
        return None

    window = "\n".join(lines[start - 1 : end])
    if evidence not in window:
        return None

    return start, end


def _cap_severity(vulnerability_type: str, severity: Severity) -> Severity:
    """按类别收紧等级：没有服务端代码，不能给出 critical。

    - 所有类别最高 high；
    - ``missing_csrf_token`` 只是“未观察到”的信号，最高 low；
    - ``content_type_mismatch`` / ``suspicious_payload_pattern`` 需要服务端
      或响应才能判断影响，最高 medium。
    """
    if severity == Severity.CRITICAL:
        severity = Severity.HIGH

    if vulnerability_type == "missing_csrf_token":
        return Severity.LOW if severity != Severity.INFO else Severity.INFO
    if vulnerability_type in {"content_type_mismatch", "suspicious_payload_pattern"}:
        return Severity.MEDIUM if severity in {Severity.HIGH, Severity.CRITICAL} else severity
    return severity


def _with_qualifier(description: str) -> str:
    room = _MAX_DESCRIPTION_CHARS - len(_QUALIFIER)
    if room <= 0:
        return _QUALIFIER[:_MAX_DESCRIPTION_CHARS]
    return description[:room] + _QUALIFIER


def _extract_cwe(value: str | None) -> str | None:
    if not value:
        return None
    matched = _CWE_PATTERN.search(value)
    return matched.group(0) if matched else None
