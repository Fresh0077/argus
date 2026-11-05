"""修复建议的上下文裁剪。

只把**发现所在行及其前后少量行**发给模型，而不是整个文件：

- 上下文越短，代码离开本机的数据量越小；
- 无关代码越少，模型越不容易把修复扩展到别处；
- 行号由 ``LineIndex`` 提供，模型不需要自己数。

约束：目标行必须完整包含在上下文中；如果目标行本身就超过长度上限，
直接报错而不是截断——半行代码会让模型基于残缺语法给出补丁。
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.line_index import LineIndex
from app.schemas.finding import Finding

#: 目标行前后各保留多少行上下文。
CONTEXT_LINES_BEFORE = 10
CONTEXT_LINES_AFTER = 10


class RepairContextError(ValueError):
    """无法根据发现与源码构造可信的修复上下文。"""


@dataclass(frozen=True)
class RepairContext:
    """裁剪后的上下文与真实行号范围。"""

    #: 待替换的原始代码（仅目标行，不含上下文）。
    original_code: str

    #: 带真实行号的上下文文本。
    context_code: str

    excerpt_line_start: int
    excerpt_line_end: int
    context_line_start: int
    context_line_end: int


def build_repair_context(
    index: LineIndex,
    finding: Finding,
    *,
    max_chars: int,
) -> RepairContext:
    """根据发现位置从源码中截取最小上下文。

    参数：
        index: 原始源码的行索引。
        finding: 待修复的候选发现；必须有可靠的行号。
        max_chars: 上下文代码（含行号前缀）的字符上限，必须为正。

    异常：
        RepairContextError: 没有行号、行号越界、目标行为空，
        或目标行本身超过上限。
    """
    if max_chars <= 0:
        raise ValueError("max_chars 必须为正数")

    if finding.line_start is None:
        raise RepairContextError(
            "该发现没有可靠的行号，无法确定要修复的代码位置。"
            "请重新扫描或手动定位后再生成修复建议。"
        )

    start = finding.line_start
    end = finding.line_end if finding.line_end is not None else start
    total = index.line_count

    if not 1 <= start <= end <= total:
        raise RepairContextError(
            f"发现的行号（{start}–{end}）超出当前源代码范围（共 {total} 行），"
            "无法生成修复建议。请确认提交的代码与扫描时一致。"
        )

    lines = index.lines()
    original_code = "\n".join(lines[start - 1 : end])
    if not original_code.strip():
        raise RepairContextError("发现指向的代码行不包含可修复的内容。")

    first = max(1, start - CONTEXT_LINES_BEFORE)
    last = min(total, end + CONTEXT_LINES_AFTER)

    # 逐步从远离目标的一侧收缩，直到满足字符上限。
    # 目标行 [start, end] 永远不被裁掉。
    while True:
        width = len(str(last))
        total_chars = sum(
            len(f"{line_no:>{width}}: ") + len(lines[line_no - 1])
            for line_no in range(first, last + 1)
        ) + max(0, last - first)

        if total_chars <= max_chars:
            break

        before_extra = start - first
        after_extra = last - end
        if after_extra >= before_extra and last > end:
            last -= 1
        elif first < start:
            first += 1
        else:
            raise RepairContextError(
                "发现所在的代码行本身过长，超出可发送给模型的上下文上限，"
                "无法生成修复建议。请缩小目标行范围后重试。"
            )

    width = len(str(last))
    context_code = "\n".join(
        f"{line_no:>{width}}: {lines[line_no - 1]}"
        for line_no in range(first, last + 1)
    )

    return RepairContext(
        original_code=original_code,
        context_code=context_code,
        excerpt_line_start=start,
        excerpt_line_end=end,
        context_line_start=first,
        context_line_end=last,
    )
