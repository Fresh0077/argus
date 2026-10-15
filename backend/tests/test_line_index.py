"""行号映射测试。

行号是报告里最容易被用户验证的一项：拿着报告回到编辑器对不上，
整份结果的可信度就没了。因此这里把换行风格的边界情况逐个钉死。
"""

from __future__ import annotations

import pytest

from app.analyzers.line_index import LineIndex, split_source_lines


# ---------------------------------------------------------------------------
# 切分
# ---------------------------------------------------------------------------


def test_single_line_without_newline_is_one_line() -> None:
    assert split_source_lines("a = 1") == ["a = 1"]


def test_trailing_newline_does_not_create_an_extra_line() -> None:
    """文件末尾的换行是行终止符，不是"又多了一个空行"。"""
    assert split_source_lines("a = 1\n") == ["a = 1"]


def test_blank_line_at_the_end_is_a_real_line() -> None:
    """``"a\\n\\n"`` 的第二个换行确实产生了一个空行。"""
    assert split_source_lines("a\n\n") == ["a", ""]


def test_lone_newline_is_one_empty_line() -> None:
    assert split_source_lines("\n") == [""]


def test_crlf_is_one_break_not_two() -> None:
    assert split_source_lines("a\r\nb") == ["a", "b"]


def test_lone_cr_is_a_line_break() -> None:
    """老式 Mac 风格换行在源码里仍可能出现。"""
    assert split_source_lines("a\rb") == ["a", "b"]


@pytest.mark.parametrize("control", [chr(0x0B), chr(0x0C), chr(0x1C), chr(0x2028), chr(0x2029)])
def test_other_control_characters_do_not_split_lines(control: str) -> None:
    """``str.splitlines()`` 会在这些字符处断开，导致行号整体错位。

    字符串字面量里出现它们是完全合法的，所以必须只认三种真正的换行。
    """
    text = f"a{control}b"

    assert split_source_lines(text) == [text]


def test_empty_input_has_no_lines() -> None:
    assert split_source_lines("") == []


# ---------------------------------------------------------------------------
# 行号查询
# ---------------------------------------------------------------------------


def test_line_text_is_one_based() -> None:
    index = LineIndex("first\nsecond\n")

    assert index.line_text(1) == "first"
    assert index.line_text(2) == "second"


def test_line_text_rejects_out_of_range() -> None:
    """越界抛异常而不是返回空串：行号都由本索引产生，越界说明调用方算错了。"""
    index = LineIndex("only\n")

    for bad in (0, -1, 2):
        with pytest.raises(IndexError):
            index.line_text(bad)


def test_line_count_matches_lines() -> None:
    index = LineIndex("a\r\nb\nc")

    assert index.line_count == 3
    assert index.lines() == ["a", "b", "c"]


@pytest.mark.parametrize(
    ("text", "offset", "expected_line"),
    [
        ("abc", 0, 1),
        ("abc", 2, 1),
        ("a\nbc", 2, 2),
        ("a\r\nbc", 3, 2),
        ("a\rbc", 2, 2),
        ("a\nb\nc", 4, 3),
    ],
)
def test_line_of_offset(text: str, offset: int, expected_line: int) -> None:
    """偏移查行号：LF、CRLF、CR 三种风格下都要正确，且换行符本身归属前一行。"""
    assert LineIndex(text).line_of_offset(offset) == expected_line


def test_line_of_offset_clamps_instead_of_raising() -> None:
    """偏移查行号通常在正则匹配之后调用，不该因为差一个字符就让整次分析失败。"""
    index = LineIndex("a\nb")

    assert index.line_of_offset(-5) == 1
    assert index.line_of_offset(999) == 2


def test_line_of_offset_on_empty_text_returns_first_line() -> None:
    assert LineIndex("").line_of_offset(0) == 1


def test_offset_table_survives_mixed_newline_styles() -> None:
    """混合换行风格下偏移表仍要指向正确位置——这是重建偏移最容易出错的地方。"""
    text = "aaa\r\nbb\nc"
    index = LineIndex(text)

    assert index.lines() == ["aaa", "bb", "c"]
    assert index.line_of_offset(text.index("bb")) == 2
    assert index.line_of_offset(text.index("c", 7)) == 3


def test_lines_returns_a_copy() -> None:
    """调用方改返回值不应该影响索引内部状态。"""
    index = LineIndex("a\nb")

    snapshot = index.lines()
    snapshot.append("injected")

    assert index.lines() == ["a", "b"]
