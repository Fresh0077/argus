"""把 Semgrep 的 JSON 结果转换成统一的 ``Finding``。

转换过程中有三件事必须由我们自己做，不能依赖 Semgrep：

1. **证据要自己取。** OSS 版返回的 ``extra.lines`` 恒为字符串
   ``"requires login"``，不是源码内容；直接拿来当证据会向用户展示一句
   和代码无关的话。这里按行号从原始源码里截取。
2. **行号要自己校验。** 越界的行号一律丢弃，不钳制、不猜测。
   钳制会造出一个看起来合理、实际指向别处的行号。
3. **等级要自己映射。** Semgrep 的 ``ERROR``/``WARNING``/``INFO`` 是它自己的
   尺度，转换成项目等级时上限为 ``high``。
"""

from __future__ import annotations

import re
from typing import Any

from app.analyzers.common import snippet_of
from app.analyzers.line_index import LineIndex
from app.analyzers.semgrep.catalog import (
    CONFIDENCE_BY_SEVERITY,
    FALLBACK_RECOMMENDATION,
    FALLBACK_VULNERABILITY_TYPE,
    SEVERITY_MAP,
)
from app.schemas.enums import FindingSource, Severity
from app.schemas.finding import Finding, make_finding_id

#: 与 ``schemas.finding.CweId`` 保持一致。
_CWE_PATTERN = re.compile(r"CWE-\d{1,5}")

#: ``rule_id`` 字段的长度上限，与 ``Finding.rule_id`` 的约束一致。
_MAX_RULE_ID_CHARS = 120


class SemgrepOutputError(ValueError):
    """Semgrep 的输出结构不符合预期。"""


def parse_semgrep_output(
    payload: dict[str, object], index: LineIndex
) -> list[Finding]:
    """把一份 Semgrep JSON 输出转换成发现列表。

    参数：
        payload: ``json.loads`` 之后的 Semgrep 输出。
        index: 原始源码的行索引，用于取证据与校验行号。

    返回：
        ``Finding`` 列表，按 ``(漏洞类别, 起始行)`` 去重。

    异常：
        ``SemgrepOutputError``：``results`` 不是列表，或 Semgrep 自报
        执行错误。后者意味着结果可能不完整，**不能**当作一次成功分析。
    """
    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        raise SemgrepOutputError(_describe_errors(errors))

    results = payload.get("results")
    if not isinstance(results, list):
        raise SemgrepOutputError("Semgrep 输出缺少 results 列表。")

    findings: list[Finding] = []
    claimed: set[tuple[str, int]] = set()

    for item in results:
        finding = _convert(item, index)
        if finding is None:
            continue
        key = (finding.vulnerability_type, finding.line_start or 0)
        if key in claimed:
            continue
        claimed.add(key)
        findings.append(finding)

    return findings


def _convert(item: object, index: LineIndex) -> Finding | None:
    """转换单条结果；结构不合法或行号越界时返回 ``None``。"""
    if not isinstance(item, dict):
        return None

    check_id = item.get("check_id")
    if not isinstance(check_id, str) or not check_id.strip():
        return None

    start = item.get("start")
    end = item.get("end")
    line_start = _line_number(start)
    if line_start is None:
        return None
    line_end = _line_number(end) or line_start
    if line_end < line_start:
        line_end = line_start

    # 行号必须落在源码范围内，否则丢弃：不钳制、不猜测。
    if line_start > index.line_count or line_end > index.line_count:
        return None

    extra = item.get("extra")
    extra_map = extra if isinstance(extra, dict) else {}
    metadata = extra_map.get("metadata")
    metadata_map = metadata if isinstance(metadata, dict) else {}

    rule_id = check_id.strip()[:_MAX_RULE_ID_CHARS]
    message = _text(extra_map.get("message")) or check_id
    vulnerability_type = (
        _text(metadata_map.get("argus-type")) or FALLBACK_VULNERABILITY_TYPE
    )
    title = _text(metadata_map.get("argus-title")) or message
    recommendation = (
        _text(metadata_map.get("argus-recommendation")) or FALLBACK_RECOMMENDATION
    )
    severity = SEVERITY_MAP.get(
        (_text(extra_map.get("severity")) or "").upper(), Severity.MEDIUM
    )

    evidence = snippet_of(index.line_text(line_start))

    return Finding(
        id=make_finding_id(
            source=FindingSource.SEMGREP,
            rule_key=rule_id,
            line_start=line_start,
            line_end=line_end,
            evidence=evidence,
        ),
        rule_id=rule_id,
        title=title[:200],
        vulnerability_type=vulnerability_type[:100],
        severity=severity,
        description=_description(message, rule_id),
        evidence=evidence,
        line_start=line_start,
        line_end=line_end,
        recommendation=recommendation[:4_000],
        confidence=CONFIDENCE_BY_SEVERITY[severity],
        source=FindingSource.SEMGREP,
        cwe_id=_cwe_from_metadata(metadata_map.get("cwe")),
    )


def _description(message: str, rule_id: str) -> str:
    """说明文案：规则自己的描述 + 一句关于证据强度的限定。"""
    lead = message.strip()[:1_000]
    return (
        f"{lead}（Semgrep 规则 {rule_id}）。该规则在函数内数据流上确认了"
        "「外部输入 → 该位置」的路径，但没有判断上游是否已有校验或白名单，"
        "因此这仍是一条候选发现。"
    )


def _line_number(value: object) -> int | None:
    """从 ``{"line": N}`` 结构中取出正整数行号。"""
    if not isinstance(value, dict):
        return None
    line = value.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    return line


def _text(value: object) -> str | None:
    """取出非空字符串，其余类型一律视为缺失。"""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _cwe_from_metadata(value: object) -> str | None:
    """从元数据里提取 CWE 编号。

    Semgrep 的惯例是把 CWE 写成 ``"CWE-89: SQL Injection"`` 或这类字符串的列表，
    因此这里按模式提取，而不是要求规则作者写成裸编号。取不到就留空——
    硬套一个相近的编号比留空更误导。
    """
    candidates = value if isinstance(value, list) else [value]
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        matched = _CWE_PATTERN.search(candidate)
        if matched is not None:
            return matched.group(0)
    return None


def _describe_errors(errors: list[Any]) -> str:
    """把 Semgrep 的 errors 数组压成一句原因。

    只取第一条的简短类型，不拼接完整长消息：那些消息可能包含路径与内部细节，
    而且用户真正需要知道的是"这次分析没完成"。
    """
    first = errors[0]
    if isinstance(first, dict):
        kind = _text(first.get("type")) or "未知错误"
    else:
        kind = "未知错误"
    return (
        f"Semgrep 报告了 {len(errors)} 条执行错误（{kind}），"
        "结果可能不完整，已丢弃本次 Semgrep 结果。"
    )
