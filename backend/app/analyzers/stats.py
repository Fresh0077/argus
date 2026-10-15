"""代码统计与结构特征。

这一层只做**计数**，不做任何判断——它回答"代码有多大、有几个函数"，
不回答"这段代码有没有问题"。

函数数与类数按语言分别匹配声明模式。**这是近似值**：
不解析语法树、不处理宏、不识别箭头函数以外的匿名形式，也不编译或导入代码。
手册要求的是"大致数量"，因此这里如实按模式计数，并在文档中说明其局限。
"""

from __future__ import annotations

import re

from app.analyzers.line_index import LineIndex
from app.schemas.features import MAX_IMPORT_ENTRIES, MAX_IMPORT_NAME_CHARS, CodeStats, CodeStructure

# ---------------------------------------------------------------------------
# 按语言的声明模式
# ---------------------------------------------------------------------------

#: 函数/方法声明模式。未登记的语言不做计数（返回 0），
#: 而不是硬套一套通用正则——那会把变量赋值之类的内容也算成函数。
_FUNCTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "python": re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(?:\w+)", re.MULTILINE),
    "javascript": re.compile(
        r"^[ \t]*(?:export[ \t]+)?(?:async[ \t]+)?function[ \t]+\w+"
        r"|^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+\w+[ \t]*=[ \t]*(?:async[ \t]*)?(?:function\b|\()",
        re.MULTILINE,
    ),
    "php": re.compile(r"^[ \t]*(?:\w+[ \t]+)*function[ \t]+\w+", re.MULTILINE),
    "java": re.compile(r"^[ \t]*(?:\w+[ \t]+)*[\w<>\[\],.]+[ \t]+\w+[ \t]*\([^;{]*\)[ \t]*(?:throws[\w\s,.]+)?\{", re.MULTILINE),
    "go": re.compile(r"^[ \t]*func[ \t]+(?:\([^)]*\)[ \t]*)?\w+", re.MULTILINE),
    "ruby": re.compile(r"^[ \t]*def[ \t]+\w+", re.MULTILINE),
}
_FUNCTION_PATTERNS["typescript"] = _FUNCTION_PATTERNS["javascript"]

#: 类/结构体声明模式。
_CLASS_PATTERNS: dict[str, re.Pattern[str]] = {
    "python": re.compile(r"^[ \t]*class[ \t]+\w+", re.MULTILINE),
    "javascript": re.compile(r"^[ \t]*(?:export[ \t]+)?(?:default[ \t]+)?class[ \t]+\w+", re.MULTILINE),
    "php": re.compile(r"^[ \t]*(?:abstract[ \t]+|final[ \t]+)*class[ \t]+\w+", re.MULTILINE),
    "java": re.compile(r"^[ \t]*(?:\w+[ \t]+)*(?:class|interface|enum|record)[ \t]+\w+", re.MULTILINE),
    "go": re.compile(r"^[ \t]*type[ \t]+\w+[ \t]+(?:struct|interface)\b", re.MULTILINE),
    "ruby": re.compile(r"^[ \t]*class[ \t]+\w+", re.MULTILINE),
}
_CLASS_PATTERNS["typescript"] = _CLASS_PATTERNS["javascript"]

#: 导入语句模式。用捕获组取出模块名；有多组时按组的先后顺序取第一个非空组。
_IMPORT_PATTERNS: dict[str, re.Pattern[str]] = {
    "python": re.compile(
        r"^[ \t]*from[ \t]+([\w.]+)[ \t]+import\b|^[ \t]*import[ \t]+([\w.]+)",
        re.MULTILINE,
    ),
    "javascript": re.compile(
        r"""^[ \t]*import\b[^\n]*?from[ \t]*['"]([^'"]+)['"]"""
        r"""|^[ \t]*import[ \t]*['"]([^'"]+)['"]"""
        r"""|require\([ \t]*['"]([^'"]+)['"]""",
        re.MULTILINE,
    ),
    "php": re.compile(r"""^[ \t]*(?:require|include)(?:_once)?[ \t]*\(?[ \t]*['"]([^'"]+)['"]""", re.MULTILINE),
    "java": re.compile(r"^[ \t]*import[ \t]+(?:static[ \t]+)?([\w.]+)[ \t]*;", re.MULTILINE),
    "go": re.compile(r"""^[ \t]*(?:import[ \t]+)?(?:[\w.]+[ \t]+)?"([\w./\-]+)"[ \t]*$""", re.MULTILINE),
    "ruby": re.compile(r"""^[ \t]*require(?:_relative)?[ \t]+['"]([^'"]+)['"]""", re.MULTILINE),
}
_IMPORT_PATTERNS["typescript"] = _IMPORT_PATTERNS["javascript"]


# ---------------------------------------------------------------------------
# 统计
# ---------------------------------------------------------------------------


def compute_stats(index: LineIndex) -> CodeStats:
    """计算行数、字符数等客观统计量。"""
    lines = index.lines()

    return CodeStats(
        total_lines=len(lines),
        non_blank_lines=sum(1 for line in lines if line.strip()),
        total_chars=len(index.text),
        max_line_length=max((len(line) for line in lines), default=0),
    )


def _count_matches(pattern: re.Pattern[str] | None, text: str) -> int:
    """按模式计数；语言未登记（pattern 为 None）时返回 0。"""
    if pattern is None:
        return 0
    return len(pattern.findall(text))


def _extract_imports(pattern: re.Pattern[str] | None, text: str) -> list[str]:
    """提取导入的模块名，去重并保持出现顺序。

    只保留模块名本身，**不保留整行导入语句**——整行可能带有注释、
    别名或文件路径，既没有分析价值，也更容易夹带无关内容。
    """
    if pattern is None:
        return []

    seen: dict[str, None] = {}
    for match in pattern.finditer(text):
        # 模式的捕获组按语言而异，取第一个非空的组。
        name = next((group for group in match.groups() if group), None)
        if not name:
            continue
        cleaned = name.strip()[:MAX_IMPORT_NAME_CHARS]
        if cleaned:
            seen.setdefault(cleaned, None)
    return list(seen)


def compute_structure(index: LineIndex, language: str | None) -> tuple[CodeStructure, list[str]]:
    """计算函数数、类数与导入信息。

    返回 ``(结构, 说明列表)``。说明列表用于如实记录"哪些信息没取到"，
    例如语言未识别导致完全没有计数，或导入条目超出上限被截断。
    """
    notes: list[str] = []

    if language is None:
        notes.append("语言未识别，未统计函数、类与导入信息（不同语言的声明写法不同，不做跨语言猜测）。")
        return CodeStructure(), notes

    text = index.text
    function_pattern = _FUNCTION_PATTERNS.get(language)
    class_pattern = _CLASS_PATTERNS.get(language)
    import_pattern = _IMPORT_PATTERNS.get(language)

    if function_pattern is None and class_pattern is None and import_pattern is None:
        # 语言被识别出来了（例如扩展名是 .vue），但我们没有为它准备模式。
        # 如实说明，而不是返回一堆 0 让调用方以为"这个文件没有函数和导入"。
        notes.append(f"尚未为语言 {language} 提供结构提取模式，函数、类与导入计数均未统计。")
        return CodeStructure(), notes

    imports = _extract_imports(import_pattern, text)
    import_total = _count_matches(import_pattern, text)

    if len(imports) > MAX_IMPORT_ENTRIES:
        imports = imports[:MAX_IMPORT_ENTRIES]
        notes.append(f"导入条目较多，仅保留前 {MAX_IMPORT_ENTRIES} 条。")

    structure = CodeStructure(
        function_count=_count_matches(function_pattern, text),
        class_count=_count_matches(class_pattern, text),
        import_count=import_total,
        imports=imports,
    )

    notes.append(
        "函数数与类数按语言声明模式匹配得到，属近似值：不解析语法树，"
        "无法识别匿名函数等形式。"
    )
    return structure, notes
