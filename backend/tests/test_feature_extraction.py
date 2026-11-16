"""特征提取测试。

覆盖三层：

- ``compute_stats``：客观计数，必须与输入完全对得上；
- ``compute_structure``：**近似值**，重点测"什么时候如实承认没算"；
- ``extract_features``：端到端，重点测不抛异常、发现可复现、
  以及"语言未知就不猜线索"。
"""

from __future__ import annotations

import pytest

from app.analyzers.extractor import extract_features
from app.analyzers.line_index import LineIndex
from app.analyzers.stats import compute_stats, compute_structure
from app.schemas.enums import LanguageSource


# ---------------------------------------------------------------------------
# 统计
# ---------------------------------------------------------------------------


def test_stats_count_lines_and_characters() -> None:
    source = "a = 1\n\nb = 2\n"
    stats = compute_stats(LineIndex(source))

    assert stats.total_lines == 3
    assert stats.non_blank_lines == 2
    assert stats.total_chars == len(source)
    assert stats.max_line_length == 5


def test_stats_on_empty_input_are_zero_not_invented() -> None:
    """空输入不能编造默认值——0 就是 0。"""
    stats = compute_stats(LineIndex(""))

    assert stats.total_lines == 0
    assert stats.non_blank_lines == 0
    assert stats.total_chars == 0
    assert stats.max_line_length == 0


def test_stats_treat_whitespace_only_line_as_blank() -> None:
    stats = compute_stats(LineIndex("a\n   \n\t\nb\n"))

    assert stats.total_lines == 4
    assert stats.non_blank_lines == 2


def test_stats_count_crlf_characters() -> None:
    """``total_chars`` 必须与输入逐字符一致，不能因为切行而丢掉换行符。"""
    source = "a\r\nb\r\n"
    stats = compute_stats(LineIndex(source))

    assert stats.total_lines == 2
    assert stats.total_chars == len(source) == 6
    assert stats.max_line_length == 1


def test_stats_without_final_newline() -> None:
    stats = compute_stats(LineIndex("a\nb"))

    assert stats.total_lines == 2
    assert stats.total_chars == 3


# ---------------------------------------------------------------------------
# 结构
# ---------------------------------------------------------------------------


def test_python_structure_counts_functions_classes_and_imports() -> None:
    source = (
        "import os\n"
        "from typing import Any\n"
        "\n"
        "class Handler:\n"
        "    def get(self):\n"
        "        pass\n"
        "\n"
        "async def main():\n"
        "    pass\n"
    )

    structure, _ = compute_structure(LineIndex(source), "python")

    assert structure.function_count == 2
    assert structure.class_count == 1
    assert structure.import_count == 2
    assert structure.imports == ["os", "typing"]


def test_imports_keep_module_names_only_and_dedupe() -> None:
    """只保留模块名，且重复导入只算一次——导入语句整行会带注释与别名，
    既没有分析价值，也更容易夹带无关内容。"""
    source = "import os, sys\nfrom os import path\nimport os.path\n"

    structure, _ = compute_structure(LineIndex(source), "python")

    assert "os" in structure.imports
    assert all("import" not in name for name in structure.imports)
    assert len(structure.imports) == len(set(structure.imports))


@pytest.mark.parametrize(
    ("language", "source"),
    [
        ("javascript", "import fs from 'fs'\nimport { join } from 'path'\nconst x = require('os')\n"),
        ("php", "<?php\nrequire_once 'a.php';\ninclude 'b.php';\n"),
        ("java", "import java.util.List;\nimport static java.lang.Math.max;\n"),
        ("go", 'package main\nimport "fmt"\nimport (\n\t"os"\n)\n'),
        ("ruby", "require 'json'\nrequire_relative 'helper'\n"),
    ],
)
def test_every_registered_language_extracts_imports(language: str, source: str) -> None:
    structure, _ = compute_structure(LineIndex(source), language)

    assert structure.import_count >= 1
    assert structure.imports, f"{language} 没有提取到任何导入"


def test_javascript_counts_arrow_function_assignment() -> None:
    source = "const add = (a, b) => a + b\nfunction mul(a, b) { return a * b }\n"

    structure, _ = compute_structure(LineIndex(source), "javascript")

    assert structure.function_count == 2


def test_unknown_language_yields_zeros_and_says_so() -> None:
    """语言未知时不做跨语言猜测，并且要**明说**没算，
    否则调用方看到一排 0 会以为这个文件没有函数。"""
    structure, notes = compute_structure(LineIndex("def f():\n    pass\n"), None)

    assert structure.function_count == 0
    assert structure.imports == []
    assert any("语言未识别" in note for note in notes)


def test_language_without_registered_patterns_says_so() -> None:
    """``vue`` 语言本身识别得出来，但没为它准备结构模式，
    必须与"这个文件确实没有函数"区分开。"""
    structure, notes = compute_structure(LineIndex("<template></template>\n"), "vue")

    assert structure.function_count == 0
    assert any("vue" in note for note in notes)


def test_structure_notes_disclose_that_counts_are_approximate() -> None:
    """函数数按模式匹配得到，属近似值——这一点必须出现在返回的说明里，
    不能只写在文档中。"""
    _, notes = compute_structure(LineIndex("def f():\n    pass\n"), "python")

    assert any("近似值" in note for note in notes)


def test_import_list_is_capped_with_a_note() -> None:
    """超大文件的导入列表要截断，并在 notes 里说明，
    避免把响应撑大却不留痕迹。"""
    source = "".join(f"import module_{i}\n" for i in range(250))
    structure, notes = compute_structure(LineIndex(source), "python")

    assert len(structure.imports) == 200
    assert structure.import_count == 250
    assert any("前 200 条" in note for note in notes)


# ---------------------------------------------------------------------------
# 端到端
# ---------------------------------------------------------------------------


def test_extract_features_reports_language_and_evidence() -> None:
    features = extract_features("x = 1\n", filename="views.py")

    assert features.language == "python"
    assert features.language_source is LanguageSource.EXTENSION
    assert features.language_evidence
    assert features.stats.total_chars == len("x = 1\n")


def test_unknown_language_is_explicit() -> None:
    features = extract_features("x = 1\n")

    assert features.language is None
    assert features.language_source is LanguageSource.NONE
    assert any("未识别出语言" in note for note in features.notes)


def test_declared_language_wins_without_filename() -> None:
    features = extract_features("eval(payload)\n", declared_language="python")

    assert features.language_source is LanguageSource.EXPLICIT
    assert features.structure.function_count == 0


def test_clean_code_still_produces_features() -> None:
    features = extract_features(
        "def add(a, b):\n    return a + b\n", filename="calc.py"
    )

    assert features.structure.function_count == 1
    assert features.stats.non_blank_lines == 2


@pytest.mark.parametrize("source", ["", " ", "\n\n", "\r\n"])
def test_extract_features_never_raises_on_degenerate_input(source: str) -> None:
    """特征提取是上下文准备，失败不该让整次扫描变成 500。"""
    features = extract_features(source, filename="views.py")

    assert features.stats.total_chars == len(source)


def test_notes_are_always_present_for_non_empty_input() -> None:
    """调用方需要知道这些数字是怎么来的、有什么局限。"""
    features = extract_features("eval(x)\n", filename="views.py")

    assert features.notes


def test_notes_stay_within_the_contract_limit() -> None:
    """``notes`` 每项上限 300 字符，构造超长文件时不能被撑破。"""
    source = "".join(f"import module_{i}\n" for i in range(250)) + "eval(x)\n"
    features = extract_features(source, filename="views.py")

    assert features.notes
    for note in features.notes:
        assert 1 <= len(note) <= 300
