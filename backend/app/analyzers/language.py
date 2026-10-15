"""代码语言识别。

优先级：**调用方显式指定 > 文件扩展名 > 内容启发式 > 未识别**。

前两级是确定性的：显式指定就是调用方说了算；扩展名是查表。
只有在前两级都拿不到结论时才做内容推断，且**必须匹配到明确信号**，
否则返回"未识别"——猜错语言比承认不知道更糟，因为后续的线索提取
会按错误语言的规则去匹配，产出一批看似合理、实则无关的候选线索。

语言未识别时 ``language`` 为 ``None``，不使用 ``"unknown"`` 这类哨兵字符串：
理由与行号的处理一致——哨兵值在类型上与真实取值无法区分，
前端一旦漏判就会把它当成一种真实语言渲染出来。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.uploads import extension_of, language_for_extension
from app.analyzers.line_index import LineIndex
from app.schemas.enums import LanguageSource


@dataclass(frozen=True)
class LanguageDetection:
    """语言识别的结论及其依据。"""

    #: 识别出的语言标识；未识别时为 None。
    language: str | None

    #: 结论的来源，见 ``LanguageSource``。
    source: LanguageSource

    #: 可供展示的判断依据，例如 ``"扩展名 .py"``。始终非空。
    evidence: str


# ---------------------------------------------------------------------------
# shebang 解析
# ---------------------------------------------------------------------------

#: 解释器名 → 语言标识。
#: 只登记本项目支持分析的语言；其他解释器（perl、bash 等）匹配到也不表态，
#: 因为我们没有为它们准备线索模式，识别出来也没有用。
_SHEBANG_LANGUAGES: dict[str, str] = {
    "python": "python",
    "ruby": "ruby",
    "node": "javascript",
    "nodejs": "javascript",
    "php": "php",
}

#: 去掉解释器名末尾的版本号：``python3`` → ``python``，``ruby2.7`` → ``ruby``。
_VERSION_SUFFIX = re.compile(r"[\d.]+$")


def _detect_from_shebang(first_line: str) -> str | None:
    """从 shebang 行解析语言。

    处理 ``#!/usr/bin/env python3`` 这类写法：``env`` 只是启动器，
    真正的解释器是它后面那个参数。
    """
    if not first_line.startswith("#!"):
        return None

    parts = first_line[2:].strip().split()
    if not parts:
        return None

    interpreter = parts[0].rsplit("/", 1)[-1]
    if interpreter == "env":
        if len(parts) < 2:
            return None
        interpreter = parts[1].rsplit("/", 1)[-1]

    stripped = _VERSION_SUFFIX.sub("", interpreter)
    return _SHEBANG_LANGUAGES.get(stripped or interpreter)


# ---------------------------------------------------------------------------
# 内容特征
# ---------------------------------------------------------------------------

#: 内容标记：(语言, 模式, 依据说明)。
#:
#: 每一条都要求**明确的语法标记**，宁可漏判也不猜。刻意不收录的模糊信号：
#: 单独的 ``class Foo``（Java/JS/Python 都可能）、单独的 ``import``（几乎所有语言都有）、
#: ``#{`` 之类在多种语言里都合法的写法。
_CONTENT_MARKERS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("php", re.compile(r"<\?php"), "包含 PHP 起始标记 <?php"),
    ("vue", re.compile(r"<template[\s>][\s\S]*?<script[\s>]"), "包含 Vue 单文件组件的 template + script 结构"),
    ("html", re.compile(r"(?i)<!doctype\s+html|<html[\s>]"), "包含 HTML 文档标记"),
    # Go 的 package 声明没有分号；Java 的 package 声明有。
    ("go", re.compile(r"^\s*package\s+[A-Za-z_]\w*\s*$", re.MULTILINE), "包含无分号的 package 声明（Go 风格）"),
    ("java", re.compile(r"^\s*import\s+java\.[\w.]+\s*;", re.MULTILINE), "包含 import java.* 语句"),
    (
        "java",
        re.compile(r"^\s*package\s+[\w.]+\s*;", re.MULTILINE),
        "包含以分号结尾的 package 声明（Java 风格）",
    ),
    ("ruby", re.compile(r"^\s*require(?:_relative)?\s+['\"][^'\"]+['\"]", re.MULTILINE), "包含 require 语句且为 Ruby 风格"),
    (
        "python",
        re.compile(r"^\s*from\s+[\w.]+\s+import\s+\w+", re.MULTILINE),
        "包含 from ... import ... 语句",
    ),
    ("python", re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\([^)]*\)\s*:", re.MULTILINE), "包含以冒号结尾的 def 函数定义"),
    (
        "javascript",
        re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+\w+\s*\(", re.MULTILINE),
        "包含 function 函数声明",
    ),
    ("javascript", re.compile(r"\bconsole\.log\s*\("), "包含 console.log 调用"),
    ("javascript", re.compile(r"\b(?:const|let)\s+\w+\s*=\s*(?:\([^)]*\)|\w+)\s*=>"), "包含箭头函数赋值"),
)


def _detect_from_content(lines: list[str]) -> tuple[str | None, str]:
    """按内容特征推断语言。

    返回 ``(语言或 None, 依据说明)``。多条标记同时命中时，
    按 ``_CONTENT_MARKERS`` 的登记顺序取第一条——顺序即优先级，
    因此更独特的标记（``<?php``）排在更宽泛的标记前面。
    """
    text = "\n".join(lines)

    for language, pattern, evidence in _CONTENT_MARKERS:
        if pattern.search(text):
            return language, evidence

    return None, "未匹配到任何可靠的语法标记"


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------


def detect_language(
    source_code: str,
    *,
    filename: str | None = None,
    declared: str | None = None,
) -> LanguageDetection:
    """识别代码语言。

    参数：
        source_code: 原始源码。不做换行符归一化。
        filename: 可选的文件名，仅用于取扩展名。**不会被当作路径使用。**
        declared: 调用方显式指定的语言，优先级最高。

    返回：
        ``LanguageDetection``。无法识别时 ``language`` 为 ``None``，
        ``source`` 为 ``LanguageSource.NONE``。
    """
    if declared:
        return LanguageDetection(
            language=declared,
            source=LanguageSource.EXPLICIT,
            evidence=f"调用方显式指定语言为 {declared}",
        )

    if filename:
        extension = extension_of(filename)
        by_extension = language_for_extension(extension)
        if by_extension:
            return LanguageDetection(
                language=by_extension,
                source=LanguageSource.EXTENSION,
                evidence=f"由文件名扩展名 .{extension} 确定",
            )

    # 到这里才做内容推断。用 LineIndex 切行而不是 splitlines()，
    # 保证 shebang 判定与行号计算基于同一套切分规则。
    lines = LineIndex(source_code).lines()

    if lines:
        by_shebang = _detect_from_shebang(lines[0])
        if by_shebang:
            return LanguageDetection(
                language=by_shebang,
                source=LanguageSource.HEURISTIC,
                evidence=f"由首行 shebang 推断：{lines[0].strip()[:80]}",
            )

    by_content, evidence = _detect_from_content(lines)
    if by_content:
        return LanguageDetection(
            language=by_content,
            source=LanguageSource.HEURISTIC,
            evidence=evidence,
        )

    declared_hint = "，且文件名未提供可用扩展名" if filename else "，且未提供文件名"
    return LanguageDetection(
        language=None,
        source=LanguageSource.NONE,
        evidence=f"无法识别语言：{evidence}{declared_hint}",
    )
