"""把模型返回的文本转换成统一的 ``Finding``。

模型输出与 Semgrep 输出的可信程度不同：Semgrep 至少是程序生成的 JSON，
而模型可能返回坏 JSON、漏字段、编造行号，甚至把源码里的提示注入当成指令。
因此这里的校验更严格：

1. **逐条校验。** 一条不合格只丢弃这一条，不让整次分析归零；
   但如果模型声称有发现、却没有任何一条通过校验，整次分析报失败——
   不能把"输出全是垃圾"报告成"没发现问题"。
2. **行号必须落在源码范围内。** 越界直接丢弃，不钳制、不猜测。
3. **证据取自源码。** 模型给的 ``evidence`` 不予采信，按行号从原文截取，
   避免把一段实际不存在的代码展示给用户。
4. **措辞保留候选性质。** 在说明末尾追加限定语，LLM 判断不等于确认漏洞。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from app.analyzers.common import snippet_of
from app.analyzers.line_index import LineIndex
from app.schemas.enums import FindingSource
from app.schemas.finding import Finding, make_finding_id
from app.schemas.llm import MAX_LLM_FINDINGS, LlmFinding

#: 说明末尾的限定语，提醒读者这是模型判断而非确认结论。
_QUALIFIER = "（本条为 LLM 基于所给上下文的判断，仍需人工确认。）"

#: ``description`` 的上限，与 ``Finding.description`` 一致。
_MAX_DESCRIPTION_CHARS = 4_000

#: 从模型给的 CWE 文本中提取编号；接受 ``"CWE-89: SQL Injection"`` 这类写法。
_CWE_PATTERN = re.compile(r"CWE-\d{1,5}")


class LlmOutputError(ValueError):
    """模型输出无法作为分析结果使用。"""


@dataclass(frozen=True)
class LlmParseResult:
    """解析结果与丢弃统计。"""

    findings: list[Finding]

    #: 模型给出但未通过校验的条数。
    dropped: int

    #: 模型给出的总条数（不超过 ``MAX_LLM_FINDINGS``）。
    total_items: int


def parse_llm_output(raw: str, index: LineIndex) -> LlmParseResult:
    """解析模型输出并转换成 ``Finding``。

    参数：
        raw: 模型的原始文本输出。
        index: 原始源码的行索引，用于校验行号与取证据。

    返回：
        ``LlmParseResult``，按 ``(漏洞类别, 起始行)`` 去重。

    异常：
        ``LlmOutputError``：不是合法 JSON、缺少 ``findings`` 列表，
        或模型声称有发现但没有一条通过校验。
    """
    payload = load_json_object(raw)
    items = payload.get("findings")
    if not isinstance(items, list):
        raise LlmOutputError("模型输出缺少 findings 列表。")

    total_items = min(len(items), MAX_LLM_FINDINGS)
    # 超过上限的部分同样算"未采用"，计入 dropped，避免静默吞掉。
    dropped = max(0, len(items) - MAX_LLM_FINDINGS)

    findings: list[Finding] = []
    claimed: set[tuple[str, int]] = set()

    for item in items[:MAX_LLM_FINDINGS]:
        finding = _convert(item, index)
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
        raise LlmOutputError(
            f"模型返回了 {total_items} 条发现，但没有一条通过结构校验或行号核对。"
        )

    return LlmParseResult(findings=findings, dropped=dropped, total_items=total_items)


def _convert(item: object, index: LineIndex) -> Finding | None:
    """转换单条发现；结构或行号不合法时返回 ``None``。"""
    if not isinstance(item, dict):
        return None

    try:
        parsed = LlmFinding.model_validate(item)
    except ValidationError:
        return None

    line_start, line_end = _checked_lines(parsed, index)
    if line_start is None and parsed.line_end is not None:
        # 给了结束行却没给起始行，无法定位。
        return None
    if line_start is None and parsed.line_start is not None:
        # 起始行越界：丢弃，不钳制。
        return None

    evidence = snippet_of(index.line_text(line_start)) if line_start is not None else ""
    description = _with_qualifier(parsed.description)

    return Finding(
        id=make_finding_id(
            source=FindingSource.LLM,
            rule_key=f"llm.{parsed.vulnerability_type}",
            line_start=line_start,
            line_end=line_end,
            evidence=evidence,
        ),
        title=parsed.title,
        vulnerability_type=parsed.vulnerability_type,
        severity=parsed.severity,
        description=description,
        evidence=evidence,
        line_start=line_start,
        line_end=line_end,
        recommendation=parsed.recommendation,
        confidence=parsed.confidence,
        source=FindingSource.LLM,
        rule_id=f"llm.{parsed.vulnerability_type}",
        cwe_id=_extract_cwe(parsed.cwe_id),
    )


def _checked_lines(parsed: LlmFinding, index: LineIndex) -> tuple[int | None, int | None]:
    """核对行号并返回 ``(line_start, line_end)``。

    规则：
    - 没给起始行 → ``(None, None)``；
    - 起始行越界 → ``(None, None)``，调用方根据原始字段区分"没给"与"越界"；
    - 结束行越界或小于起始行 → 同样按无法定位处理（返回 None）。
    """
    if parsed.line_start is None:
        return None, None

    if not 1 <= parsed.line_start <= index.line_count:
        return None, None

    line_end = parsed.line_end if parsed.line_end is not None else parsed.line_start
    if not parsed.line_start <= line_end <= index.line_count:
        return None, None

    return parsed.line_start, line_end


def _with_qualifier(description: str) -> str:
    """在说明末尾追加候选性质限定语，并保证不超过字段上限。"""
    room = _MAX_DESCRIPTION_CHARS - len(_QUALIFIER)
    if room <= 0:  # 理论上不会发生；留一个显式分支而不是依赖长度假设
        return _QUALIFIER[:_MAX_DESCRIPTION_CHARS]
    return description[:room] + _QUALIFIER


def _extract_cwe(value: str | None) -> str | None:
    """从模型给的文本里提取 CWE 编号；提取不到就留空，不猜。"""
    if not value:
        return None
    matched = _CWE_PATTERN.search(value)
    return matched.group(0) if matched else None


def load_json_object(raw: str) -> dict[str, Any]:
    """从模型文本中取出 JSON 对象。

    容忍两种常见偏差：外层包了 Markdown 代码块；JSON 前后有少量说明文字。
    仍然解析不了就报错，不做更激进的"修复"——猜出来的 JSON 比没有更危险。

    修复建议解析（阶段 16）也复用本函数，避免两处对"模型输出的常见包裹"
    给出不一致的判断。
    """
    text = raw.strip()
    if not text:
        raise LlmOutputError("模型返回了空内容。")

    candidates = [text]

    fenced = _strip_code_fence(text)
    if fenced != text:
        candidates.append(fenced)

    start = fenced.find("{")
    end = fenced.rfind("}")
    if start != -1 and end > start:
        candidates.append(fenced[start : end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
        # 顶层是数组等情况：继续尝试其他候选，最终统一报错。

    raise LlmOutputError("模型输出不是合法的 JSON 对象。")


def _strip_code_fence(text: str) -> str:
    """剥掉最外层的 Markdown 代码块围栏（如果有）。"""
    if not text.startswith("```"):
        return text

    lines = text.splitlines()
    if len(lines) < 2:
        return text

    body = lines[1:]
    if body and body[-1].strip() == "```":
        body = body[:-1]
    return "\n".join(body).strip()
