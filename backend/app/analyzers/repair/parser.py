"""校验模型返回的修复建议。

模型输出是不可信数据。这里做的检查依次是：

1. 必须是合法 JSON 对象（复用分析器的解析逻辑，容忍外层 Markdown 围栏）；
2. 字段必须齐全、类型正确、长度不超限（``extra="forbid"``）；
3. ``fixed_code`` 去掉可能的围栏与首尾空行后不能为空；
4. 不能与原始代码相同——"没有修改"不是修复；
5. 不能整段带行号前缀——那不是可以直接使用的补丁。

任何一条不满足都报 ``RepairOutputError``，由路由层转换成安全的错误响应。
**不尝试猜测或"修复"模型输出**：猜出来的补丁比没有更危险。
"""

from __future__ import annotations

import re

from pydantic import ValidationError

from app.analyzers.llm.parser import LlmOutputError, load_json_object
from app.schemas.repair import RepairModelOutput

#: 形如 ``12: code`` / ``12 | code`` 的行号前缀。
_LINE_NUMBER_PREFIX = re.compile(r"^\s*\d+\s*[:|]\s?")


class RepairOutputError(ValueError):
    """模型输出不能作为修复建议使用。"""


def parse_repair_output(raw: str, *, original_code: str) -> RepairModelOutput:
    """把模型文本转换成经过校验的修复结果。

    参数：
        raw: 模型的原始文本输出。
        original_code: 待替换的真实原始代码，用于拒绝"未修改"的输出。

    异常：
        RepairOutputError: JSON 不合法、字段不合格、代码为空、未发生修改，
        或带有行号前缀。
    """
    try:
        payload = load_json_object(raw)
    except LlmOutputError as exc:
        raise RepairOutputError("模型输出不是合法的 JSON 对象，无法作为修复建议。") from exc

    try:
        parsed = RepairModelOutput.model_validate(payload)
    except ValidationError as exc:
        raise RepairOutputError(
            "模型返回的修复结果字段缺失、类型不符或超过长度限制，无法采用。"
        ) from exc

    fixed_code = _clean_fixed_code(parsed.fixed_code)
    if not fixed_code.strip():
        raise RepairOutputError(
            "模型未能给出可用的修复代码，可能是无法根据所给上下文确定安全修复方案。"
        )

    if _normalize(fixed_code) == _normalize(original_code):
        raise RepairOutputError("模型返回的代码与原始代码相同，没有给出实际修改。")

    if _looks_line_numbered(fixed_code):
        raise RepairOutputError(
            "模型返回的修复代码带有行号前缀，无法直接作为补丁使用。"
        )

    return parsed.model_copy(update={"fixed_code": fixed_code})


def _clean_fixed_code(code: str) -> str:
    """去掉代码块围栏与首尾空行，保留内部缩进。"""
    lines = code.splitlines()

    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1

    if start < len(lines) and lines[start].strip().startswith("```"):
        body = lines[start + 1 :]
        while body and not body[-1].strip():
            body.pop()
        if body and body[-1].strip() == "```":
            body.pop()
    else:
        body = lines[start:]

    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()

    return "\n".join(body)


def _normalize(code: str) -> str:
    """比较"是否修改"时忽略行尾空白与首尾空行。"""
    stripped = [line.rstrip() for line in code.splitlines()]
    while stripped and not stripped[0]:
        stripped.pop(0)
    while stripped and not stripped[-1]:
        stripped.pop()
    return "\n".join(stripped)


def _looks_line_numbered(code: str) -> bool:
    """所有非空行都带 ``数字: `` 前缀时，认为是模型自行添加了行号。"""
    non_empty = [line for line in code.splitlines() if line.strip()]
    return bool(non_empty) and all(
        _LINE_NUMBER_PREFIX.match(line) for line in non_empty
    )
