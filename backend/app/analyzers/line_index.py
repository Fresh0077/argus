"""源码行号映射。

行号必须与用户在编辑器里看到的一致，因此本模块**不对换行符做任何归一化**。
把 CRLF 转成 LF 看似无害，实际会让行号发生偏移，用户拿着报告里的行号
回到编辑器却找不到对应位置——那比不报行号更糟。

不使用 ``str.splitlines()``：它除了 ``\\r\\n``/``\\r``/``\\n`` 之外，还会在
``\\v``、``\\f``、``\\x1c``、``\\u2028`` 等字符处断开。源码里出现这些字符
（例如字符串字面量中）时，行号会整体错位。这里只认三种真正的换行风格。
"""

from __future__ import annotations

import bisect
import re

#: 三种换行风格。顺序有意义：``\r\n`` 必须整体匹配，否则会被拆成两个换行。
_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def split_source_lines(text: str) -> list[str]:
    """按行切分源码，返回**不含换行符**的行列表。

    与直接 ``text.split("\\n")`` 的差别在于末尾换行的处理：
    ``"a\\n"`` 是**一行**而不是两行——文件末尾的换行是行终止符，
    不额外产生一个空行。但 ``"a\\n\\n"`` 是两行（第二行确实是空行）。
    """
    if not text:
        return []

    lines = _LINE_BREAK.split(text)

    # 文本以换行结尾时，split 会多产出一个末尾空串；它不是一行。
    # 判断 len > 1 是为了让单独的 "\n" 仍然算作一个空行，而不是零行。
    if len(lines) > 1 and lines[-1] == "" and text[-1] in "\r\n":
        lines.pop()

    return lines


class LineIndex:
    """源码的行号索引。

    构造时建立"每行起始偏移"表，之后按字符偏移查行号是 O(log n)，
    不需要反复扫描文本。

    索引是不可变的，可以安全地在多个分析器之间共享。
    """

    __slots__ = ("_text", "_lines", "_starts")

    def __init__(self, text: str) -> None:
        self._text = text
        self._lines = split_source_lines(text)

        # 按行重建每行的起始偏移。切分时换行符已被丢弃，
        # 因此每行结束后要显式跳过对应的换行符，才能让下一行从正确位置开始。
        starts: list[int] = []
        offset = 0
        for line in self._lines:
            starts.append(offset)
            offset += len(line)
            if offset < len(text) and text[offset] == "\r":
                offset += 1
                if offset < len(text) and text[offset] == "\n":
                    offset += 1
            elif offset < len(text) and text[offset] == "\n":
                offset += 1
        self._starts = starts

    @property
    def text(self) -> str:
        """原始源码。调用方不应把它写入日志。"""
        return self._text

    @property
    def line_count(self) -> int:
        return len(self._lines)

    def line_text(self, line_no: int) -> str:
        """返回指定行的内容（不含换行符），``line_no`` 从 1 开始。

        越界时抛出 ``IndexError`` 而不是返回空串：行号全部由本索引产生，
        越界说明调用方算错了，静默返回空串会把这类错误藏起来。
        """
        if not 1 <= line_no <= len(self._lines):
            raise IndexError(f"行号 {line_no} 超出范围（共 {len(self._lines)} 行）")
        return self._lines[line_no - 1]

    def line_of_offset(self, offset: int) -> int:
        """返回字符偏移所落在的行号（1 起）。

        偏移越界时钳制到首行/末行而不是抛异常：调用方通常在正则匹配之后
        用它，不该因为差一个字符就让整次分析失败。
        """
        if not self._starts:
            return 1
        index = bisect.bisect_right(self._starts, offset) - 1
        return max(1, min(index + 1, len(self._starts)))

    def lines(self) -> list[str]:
        """返回所有行的副本，供只读遍历。"""
        return list(self._lines)
