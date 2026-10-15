"""语言识别测试。

重点在于**优先级**与**认不出来时肯认输**：
猜错语言会让后续的线索提取按错误的规则去匹配，产出一批看似合理、
实则无关的结果，比直接说"不知道"危害大得多。
"""

from __future__ import annotations

import re

import pytest

from app.analyzers.language import detect_language
from app.schemas.enums import LanguageSource
from app.schemas.scan import LanguageId

#: 契约层对语言标识的限制。识别结果必须落在这个范围内，
#: 否则会构造出连 Pydantic 都通不过的 ScanResponse。
LANGUAGE_ID_PATTERN = re.compile(LanguageId.__metadata__[0].pattern)

#: 把所有可能的识别结果集中起来，供"每个结果都是合法 LanguageId"这项测试使用。
ALL_DETECTABLE_LANGUAGES = (
    "python",
    "javascript",
    "typescript",
    "php",
    "java",
    "go",
    "ruby",
    "html",
    "vue",
)


# ---------------------------------------------------------------------------
# 优先级：显式指定 > 扩展名 > 内容
# ---------------------------------------------------------------------------


def test_declared_language_beats_everything() -> None:
    """调用方说了算：即使文件名和内容都指向别的语言。"""
    result = detect_language('<?php echo "hi";', filename="app.py", declared="go")

    assert result.language == "go"
    assert result.source is LanguageSource.EXPLICIT
    assert "go" in result.evidence


def test_declared_language_is_not_rechecked_against_content() -> None:
    """显式指定的语言即使不在受支持列表里也照用，不在这里做二次判断。

    受支持与否是上传接口的扩展名白名单该管的事；
    在这一层再拦一次会让 JSON 接口的行为变得难以解释。
    """
    result = detect_language("x = 1", declared="rust")

    assert result.language == "rust"
    assert result.source is LanguageSource.EXPLICIT


def test_filename_extension_beats_content() -> None:
    """扩展名是确定性查表，内容只是启发式，因此扩展名优先。"""
    result = detect_language('<?php echo "hi";', filename="views.py")

    assert result.language == "python"
    assert result.source is LanguageSource.EXTENSION
    assert ".py" in result.evidence


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("views.py", "python"),
        ("app.js", "javascript"),
        ("app.jsx", "javascript"),
        ("app.ts", "typescript"),
        ("app.tsx", "typescript"),
        ("index.php", "php"),
        ("Main.java", "java"),
        ("main.go", "go"),
        ("app.rb", "ruby"),
        ("index.html", "html"),
        ("App.vue", "vue"),
        ("VIEWS.PY", "python"),
    ],
)
def test_every_supported_extension_is_recognized(filename: str, expected: str) -> None:
    assert detect_language("x = 1", filename=filename).language == expected


def test_unknown_extension_falls_through_to_content() -> None:
    """扩展名认不出来不是错误，继续往下试内容特征。"""
    result = detect_language("def f():\n    return 1\n", filename="notes.txt")

    assert result.language == "python"
    assert result.source is LanguageSource.HEURISTIC


# ---------------------------------------------------------------------------
# shebang
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("first_line", "expected"),
    [
        ("#!/usr/bin/env python3", "python"),
        ("#!/usr/bin/python", "python"),
        ("#!/usr/bin/python3.11", "python"),
        ("#!/usr/local/bin/ruby2.7", "ruby"),
        ("#!/usr/bin/env node", "javascript"),
        ("#!/usr/bin/nodejs", "javascript"),
        ("#!/usr/bin/php", "php"),
    ],
)
def test_shebang_identifies_language(first_line: str, expected: str) -> None:
    result = detect_language(f"{first_line}\nx = 1\n")

    assert result.language == expected
    assert result.source is LanguageSource.HEURISTIC
    assert "shebang" in result.evidence


def test_shebang_works_with_crlf_line_endings() -> None:
    """CRLF 文件的首行带 \\r，剥不干净就会让解释器名多出一个字符而匹配失败。"""
    result = detect_language("#!/usr/bin/env python3\r\nx = 1\r\n")

    assert result.language == "python"


def test_shebang_works_without_trailing_newline() -> None:
    result = detect_language("#!/usr/bin/env python3")

    assert result.language == "python"


def test_unregistered_interpreter_falls_through_instead_of_guessing() -> None:
    """perl 是解释器，但本项目没有为它准备线索模式，识别出来也没有用，
    因此不表态，继续往下试。"""
    result = detect_language("#!/usr/bin/perl\nprint 1;\n")

    assert result.language is None
    assert result.source is LanguageSource.NONE


def test_hash_symbol_that_is_not_a_shebang_is_ignored() -> None:
    """注释行以 # 开头但不是 #!，不能被当成 shebang。"""
    result = detect_language("# python script for parsing\nx = 1\n")

    assert result.language != "python" or "shebang" not in result.evidence


def test_env_without_interpreter_is_ignored() -> None:
    result = detect_language("#!/usr/bin/env\nx = 1\n")

    assert result.language is None


# ---------------------------------------------------------------------------
# 内容特征
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('<?php echo "hi"; ?>', "php"),
        ("<template><div/></template>\n<script>export default {}</script>", "vue"),
        ("<!DOCTYPE html>\n<html><body></body></html>", "html"),
        ("package main\n\nfunc main() {}\n", "go"),
        ("import java.util.List;\npublic class Main {}\n", "java"),
        ("package com.example;\npublic class Main {}\n", "java"),
        ('require "json"\nputs 1\n', "ruby"),
        ("from os import path\n", "python"),
        ("def handler(request):\n    pass\n", "python"),
        ("export function handler(req, res) {}\n", "javascript"),
        ("console.log('hi')\n", "javascript"),
        ("const add = (a, b) => a + b\n", "javascript"),
    ],
)
def test_content_markers_identify_language(source: str, expected: str) -> None:
    result = detect_language(source)

    assert result.language == expected
    assert result.source is LanguageSource.HEURISTIC
    assert result.evidence


def test_content_detection_survives_crlf() -> None:
    """行尾锚点在 CRLF 下必须仍然成立。"""
    result = detect_language("package main\r\n\r\nfunc main() {}\r\n")

    assert result.language == "go"


def test_ambiguous_content_returns_unknown_rather_than_guessing() -> None:
    """单独的 ``class Foo`` 在 Java/JS/Python 里都合法，不能据此断言语言。"""
    result = detect_language("class Foo:\n    pass\n")

    assert result.language is None
    assert result.source is LanguageSource.NONE


# ---------------------------------------------------------------------------
# 未识别
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "",
        "x = 1",
        "SELECT * FROM users",
        "some plain prose without any code marker",
        "1 + 1",
    ],
)
def test_unrecognizable_input_reports_none(source: str) -> None:
    result = detect_language(source)

    assert result.language is None
    assert result.source is LanguageSource.NONE


def test_evidence_is_always_present_even_when_unrecognized() -> None:
    """未识别时也必须说明"试过了但没匹配到"，不能只返回一个空洞的 None。"""
    result = detect_language("x = 1")

    assert result.evidence
    assert "无法识别语言" in result.evidence
    assert "未提供文件名" in result.evidence


def test_evidence_mentions_unusable_extension_when_filename_given() -> None:
    result = detect_language("x = 1", filename="notes.txt")

    assert "无法识别语言" in result.evidence
    assert "未提供可用扩展名" in result.evidence


def test_evidence_stays_within_the_contract_limit() -> None:
    """依据会被放进 ``language_evidence``（上限 200 字符）。
    shebang 行来自用户输入，可能非常长，必须截断。"""
    hostile = "#!/usr/bin/env python3" + " " + "A" * 5_000

    result = detect_language(f"{hostile}\nx = 1\n")

    assert len(result.evidence) <= 200


def test_shebang_evidence_does_not_leak_the_whole_line() -> None:
    """证据只保留最小必要片段，不把整行用户输入原样回显。"""
    marker = "SECRET_MARKER_SHOULD_NOT_APPEAR"
    result = detect_language(f"#!/usr/bin/env python3 {'A' * 300}{marker}\nx = 1\n")

    assert marker not in result.evidence


# ---------------------------------------------------------------------------
# 与契约的一致性
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("language", ALL_DETECTABLE_LANGUAGES)
def test_detected_language_is_a_valid_contract_value(language: str) -> None:
    """识别结果最终要填进 ``ScanResponse.detected_language``，
    必须是契约允许的 ``LanguageId``，否则整个响应会构造失败。"""
    result = detect_language("x = 1", declared=language)

    assert LANGUAGE_ID_PATTERN.match(result.language or "")
