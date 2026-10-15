"""危险位置"值"的提取与判断。

规则要回答的不只是"这一行有没有危险调用"，还有"喂给它的东西是不是常量"。
后者用正则很难写对：``execute("... %s", (uid,))`` 里也有变量，但那是**绑定参数**，
是安全写法；``execute("..." + uid)`` 里同一个变量出现在**语句本身**里，才是问题。
区别不在变量，而在它出现的位置。

因此这里只做一件事：把"值"这段文本从行里**切出来**，再看它是不是常量。
切分要考虑引号、嵌套括号和顶层逗号——用正则做这件事会在
``execute("a, b", (x,))`` 这类输入上出错。
"""

from __future__ import annotations

import re

#: 成对括号的对应关系。
_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}
_CLOSERS = ")]}"
_QUOTES = "\"'`"

#: 字符串字面量的前缀（``f"..."``、``b'...'``、``rf"..."``），最多两个字母。
_LITERAL_PREFIX = re.compile(r"""^([A-Za-z]{0,2})(?=["'`])""")

#: 各语言里的常量字面量。
_CONSTANTS = frozenset(
    {"true", "false", "null", "undefined", "nil", "True", "False", "None", "TRUE", "FALSE", "NULL"}
)

_NUMBER = re.compile(r"^[-+]?(?:\d+\.?\d*|\.\d+)$")

#: ``name=value`` 形式的关键字实参，取等号右边的值。
_KEYWORD_ARGUMENT = re.compile(r"^[$@]?[A-Za-z_][\w$.]*\s*=(?!=|>)\s*(.+)$", re.DOTALL)

#: 模板 / 插值字符串的标记。出现在字面量内部时，它就不是常量了。
_INTERPOLATION_MARKERS = ("${", "#{")


def _skip_string(text: str, start: int) -> int | None:
    """``text[start]`` 是引号时，返回闭合引号之后的下标。

    未闭合（行尾截断）时返回 ``None``——调用方据此知道"这一行不完整"，
    而不是假装读到了一个完整的字面量。
    """
    quote = text[start]
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        index += 1
    return None


def _matching_close(text: str, open_index: int) -> int | None:
    """``text[open_index]`` 是左括号时，返回与之配对的右括号下标。"""
    closer = _OPEN_TO_CLOSE.get(text[open_index])
    if closer is None:
        return None
    depth = 0
    index = open_index
    while index < len(text):
        char = text[index]
        if char in _QUOTES:
            end = _skip_string(text, index)
            if end is None:
                return None
            index = end
            continue
        if char in _OPEN_TO_CLOSE:
            depth += 1
        elif char in _CLOSERS:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _split_top_level(text: str, separator: str) -> list[str]:
    """按 ``separator`` 切分，忽略引号内与括号内的分隔符。"""
    parts: list[str] = []
    start = 0
    depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char in _QUOTES:
            end = _skip_string(text, index)
            if end is None:
                break
            index = end
            continue
        if char in _OPEN_TO_CLOSE:
            depth += 1
        elif char in _CLOSERS:
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    parts.append(text[start:])
    return parts


def _argument_segments(line: str, open_index: int) -> list[str]:
    """取出 ``line[open_index]`` 这个左括号里的实参，按顶层逗号切分。

    括号不配对时（例如语句跨行书写、本行只看到一半）返回已经读到的部分，
    不报错也不猜测剩下的内容。
    """
    if not 0 <= open_index < len(line) or line[open_index] not in _OPEN_TO_CLOSE:
        return []

    segments: list[str] = []
    start = open_index + 1
    depth = 0
    index = start
    while index < len(line):
        char = line[index]
        if char in _QUOTES:
            end = _skip_string(line, index)
            if end is None:
                break
            index = end
            continue
        if char in _OPEN_TO_CLOSE:
            depth += 1
        elif char in _CLOSERS:
            if depth == 0:
                segments.append(line[start:index])
                return segments
            depth -= 1
        elif char == "," and depth == 0:
            segments.append(line[start:index])
            start = index + 1
        index += 1

    segments.append(line[start:])
    return segments


def strip_line_comment(text: str) -> str:
    """去掉行尾注释。引号内的 ``#``、``//`` 不算注释。

    公开这个函数是因为"来源表达式出现在注释里"必须被排除：
    ``eval(x)  # 值来自 request.args`` 的注释不构成来源证据，
    据此升级等级就是凭一句注释下结论。
    """
    index = 0
    while index < len(text):
        char = text[index]
        if char in _QUOTES:
            end = _skip_string(text, index)
            if end is None:
                return text
            index = end
            continue
        if char == "#":
            return text[:index]
        if char == "/" and text.startswith("//", index):
            return text[:index]
        index += 1
    return text


def _strip_wrapping_parens(text: str) -> str:
    """剥掉把整段值包起来的括号：``(a + b)`` 与 ``a + b`` 是同一件事。

    只有括号确实首尾配对时才剥——``(a) + (b)`` 的首字符是 ``(``、
    末字符是 ``)``，但它们并不配对，剥掉就错了。
    """
    while len(text) >= 2 and text[0] == "(" and text[-1] == ")":
        if _matching_close(text, 0) != len(text) - 1:
            break
        text = text[1:-1].strip()
    return text


def _is_literal(text: str) -> bool:
    """整段文本是否只是一个字符串字面量。"""
    prefix_match = _LITERAL_PREFIX.match(text)
    if prefix_match is None:
        return False

    prefix = prefix_match.group(1)
    if any(letter not in "rfbuRFBU" for letter in prefix):
        return False

    body_start = prefix_match.end()
    body_end = _skip_string(text, body_start)
    if body_end is None:
        return False

    body = text[body_start:body_end]
    # 带插值的字符串不是常量：``f"{uid}"``、``"${x}"``、``"#{x}"`` 的内容是算出来的。
    # 反过来，Python 的 ``"$HOME"`` 里 ``$`` 没有特殊含义，仍按常量处理——
    # 是否插值取决于语言，而这里没有语言信息，只能认这几种通用写法。
    if any(marker in body for marker in _INTERPOLATION_MARKERS):
        return False
    if "f" in prefix.lower() and "{" in body:
        return False

    return text[body_end:].strip() == ""


def is_constant_value(text: str) -> bool:
    """这段值是不是"写死的"。

    写死的值不构成注入面：固定 SQL、固定命令、固定 HTML 片段都不会被外部改变。
    它也不等于"安全"——一个写死的弱口令仍然是问题，只是不属于本层负责的类别。

    认定为常量的情况：
    - 单个字符串字面量（不含插值）；
    - ``true`` / ``null`` / ``None`` 这类字面量常量与数字；
    - 元素全是常量的列表，例如 ``["git", "status"]``；
    - 上面任意一种外面套了括号。

    空文本也按常量处理：``execute()`` 没有实参，谈不上注入。
    """
    value = _strip_wrapping_parens(text.strip().rstrip(";").strip())
    if not value:
        return True
    if value in _CONSTANTS or _NUMBER.match(value):
        return True
    if value.startswith("["):
        closing = _matching_close(value, 0)
        if closing != len(value) - 1:
            return False
        inner = value[1:-1].strip()
        return not inner or all(
            is_constant_value(part) for part in _split_top_level(inner, ",")
        )
    return _is_literal(value)


def first_argument(line: str, open_index: int) -> str:
    """第一个实参的文本（已剥掉 ``name=`` 形式的关键字前缀）。"""
    segments = _argument_segments(line, open_index)
    if not segments:
        return ""
    return _keyword_value(segments[0])


def argument_values(line: str, open_index: int) -> list[str]:
    """所有实参的文本（已剥掉 ``name=`` 形式的关键字前缀）。

    关键字实参必须剥掉名字：``subprocess.run(cmd, shell=True)`` 里
    ``shell`` 是个变量名，不剥的话 ``True`` 会被当成"动态值"。
    """
    return [_keyword_value(segment) for segment in _argument_segments(line, open_index)]


def assigned_value(line: str, start: int) -> str:
    """赋值号右侧到行尾的文本（已去掉行尾注释与分号）。"""
    return strip_line_comment(line[start:]).strip().rstrip(";").strip()


def _keyword_value(segment: str) -> str:
    """``shell=True`` → ``True``；不是关键字实参时原样返回。"""
    text = segment.strip()
    matched = _KEYWORD_ARGUMENT.match(text)
    if matched is None:
        return text
    return matched.group(1).strip()
