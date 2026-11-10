"""上传校验与解码的单元测试。

这些函数是纯计算（不碰文件系统、不依赖 FastAPI），因此可以脱离应用单独测试。
重点覆盖三类输入：正常、边界、非法——尤其是**不能把二进制内容当成源码放进来**。
"""

import codecs

import pytest

from app.core.config import settings
from app.core.errors import ApiError
from app.core.uploads import (
    EXTENSION_LANGUAGE_MAP,
    decode_source_bytes,
    ensure_supported_extension,
    ensure_within_char_limit,
    extension_of,
    language_for_extension,
    supported_extensions_text,
)
from app.schemas.enums import ErrorCode

# ---------------------------------------------------------------------------
# 扩展名解析
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("views.py", "py"),
        ("app.jsx", "jsx"),
        ("archive.tar.py", "py"),
        ("MyFile.TSX", "tsx"),
        ("Makefile", ""),
        ("a.", ""),
    ],
)
def test_extension_of(filename: str, expected: str) -> None:
    assert extension_of(filename) == expected


def test_extension_of_handles_surrounding_whitespace() -> None:
    assert extension_of("  views.py  ") == "py"


def test_language_for_extension_is_case_insensitive() -> None:
    assert language_for_extension("PY") == "python"


def test_language_for_extension_returns_none_for_unregistered() -> None:
    """未登记的扩展名返回 None，而不是编造一个语言名。"""
    assert language_for_extension("rs") is None


def test_default_allowed_extensions_match_language_map() -> None:
    """默认白名单与语言映射表必须一一对应。

    两者分处两个文件，容易在扩充白名单时漏改一处：
    漏改后文件仍能上传，但 ``detected_language`` 会静默变成 null。
    这条测试把这种漂移在提交前就暴露出来。
    """
    assert settings.allowed_extensions == set(EXTENSION_LANGUAGE_MAP)


# ---------------------------------------------------------------------------
# 扩展名白名单
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filename", [".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go", ".rb", ".html", ".vue"])
def test_allowed_extensions_are_accepted(filename: str) -> None:
    assert ensure_supported_extension(f"sample{filename}") == filename.lstrip(".")


def test_uppercase_extension_is_normalized() -> None:
    assert ensure_supported_extension("VIEWS.PY") == "py"


def test_missing_extension_is_rejected_with_415() -> None:
    with pytest.raises(ApiError) as excinfo:
        ensure_supported_extension("Makefile")

    assert excinfo.value.status_code == 415
    assert excinfo.value.code == ErrorCode.UNSUPPORTED_FILE_TYPE


def test_unsupported_extension_is_rejected_with_415() -> None:
    with pytest.raises(ApiError) as excinfo:
        ensure_supported_extension("payload.exe")

    assert excinfo.value.status_code == 415
    assert excinfo.value.code == ErrorCode.UNSUPPORTED_FILE_TYPE
    # 错误提示应列出可用类型，否则用户不知道该改成什么。
    assert ".py" in excinfo.value.details[0].message


def test_supported_extensions_text_lists_all() -> None:
    text = supported_extensions_text()

    assert ".py" in text and ".vue" in text


# ---------------------------------------------------------------------------
# 大小限制
# ---------------------------------------------------------------------------


def test_char_limit_is_checked_independently_of_byte_limit() -> None:
    """字节没超不代表字符没超——两个上限必须分别生效。"""
    with pytest.raises(ApiError) as excinfo:
        ensure_within_char_limit("x" * (settings.max_source_code_chars + 1))

    assert excinfo.value.status_code == 413
    assert excinfo.value.code == ErrorCode.INPUT_TOO_LARGE


# ---------------------------------------------------------------------------
# 解码：正常路径
# ---------------------------------------------------------------------------


def test_plain_utf8_source_is_decoded() -> None:
    text, encoding = decode_source_bytes("# 中文注释\nx = 1\n".encode("utf-8"))

    assert text == "# 中文注释\nx = 1\n"
    assert encoding == "utf-8"


def test_utf8_bom_is_detected_and_stripped() -> None:
    """带 BOM 的文件必须按 BOM 解码，否则首行会多出一个不可见字符。"""
    text, encoding = decode_source_bytes(codecs.BOM_UTF8 + b"x = 1\n")

    assert text == "x = 1\n"
    assert encoding == "utf-8-sig"
    assert "﻿" not in text


@pytest.mark.parametrize("bom", [codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE])
def test_utf16_source_is_decoded(bom: bytes) -> None:
    text, encoding = decode_source_bytes("x = 1\n".encode("utf-16"))

    assert text == "x = 1\n"
    assert encoding == "utf-16"


def test_gbk_source_falls_back_and_reports_encoding() -> None:
    """中文 Windows 上另存为的文件常是 GBK，应能解码并如实报告编码。"""
    text, encoding = decode_source_bytes("# 中文注释\nx = 1\n".encode("gbk"))

    assert "中文注释" in text
    assert encoding == "gbk"


def test_crlf_is_preserved() -> None:
    """换行符不做归一化：行号计算依赖原始内容（阶段 6 处理）。"""
    text, _ = decode_source_bytes(b"a = 1\r\nb = 2\r\n")

    assert text == "a = 1\r\nb = 2\r\n"


def test_last_line_without_newline_is_preserved() -> None:
    text, _ = decode_source_bytes(b"a = 1")

    assert text == "a = 1"


# ---------------------------------------------------------------------------
# 解码：非法路径
# ---------------------------------------------------------------------------


def test_empty_content_is_rejected_as_empty_input() -> None:
    with pytest.raises(ApiError) as excinfo:
        decode_source_bytes(b"")

    assert excinfo.value.status_code == 422
    assert excinfo.value.code == ErrorCode.EMPTY_INPUT


def test_null_bytes_are_rejected_as_non_text() -> None:
    with pytest.raises(ApiError) as excinfo:
        decode_source_bytes(b"x = 1\x00y = 2")

    assert excinfo.value.code == ErrorCode.UNSUPPORTED_ENCODING


def test_binary_content_is_rejected() -> None:
    """0xFF 既不是合法的 UTF-8，也不是合法的 GBK 前导字节。"""
    with pytest.raises(ApiError) as excinfo:
        decode_source_bytes(b"\xff\xff\xff\xff")

    assert excinfo.value.status_code == 422
    assert excinfo.value.code == ErrorCode.UNSUPPORTED_ENCODING


def test_control_character_soup_is_rejected() -> None:
    """大量控制字符说明这不是源码，即使技术上能被某个编码解码。"""
    with pytest.raises(ApiError) as excinfo:
        decode_source_bytes(bytes([1, 2, 3, 4, 5, 6, 7, 8]))

    assert excinfo.value.code == ErrorCode.UNSUPPORTED_ENCODING


def test_encoding_error_does_not_leak_decoder_details() -> None:
    """错误说明只用我们自己的文案，不透传 UnicodeDecodeError 原文。"""
    with pytest.raises(ApiError) as excinfo:
        decode_source_bytes(b"\xff\xff\xff\xff")

    message = excinfo.value.details[0].message
    assert "codec" not in message.lower()
    assert "position" not in message.lower()


def test_tab_and_newline_are_not_treated_as_control_noise() -> None:
    """制表符与换行是正常排版字符，不能被当成二进制特征。"""
    text, _ = decode_source_bytes(b"\t\n\r\n\tx = 1\n")

    assert "x = 1" in text
