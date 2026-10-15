"""上传文件的类型、大小与编码校验。

本模块只做**纯计算**：不读写文件系统、不执行或导入任何被提交的代码，
因此可以脱离 FastAPI 单独测试。

安全边界（对应 CLAUDE.md 安全红线第 4、5、6 条）：

- 允许的扩展名来自统一配置 ``ALLOWED_FILE_EXTENSIONS``，不在路由中散落硬编码。
- **只依据扩展名判断文件类型，绝不采信客户端提交的 MIME 类型**——
  ``Content-Type`` 由调用方随意填写，不构成任何安全依据。
- 文件名只作为展示信息，绝不参与路径拼接；本模块不产生任何文件系统路径。
- 解码显式指定编码，失败即报错，**不用替换字符悄悄"修复"内容**——
  静默替换会把"这个文件解不开"变成"这个文件解开了但内容是乱码"，
  后者会一路流到分析器和界面，产生任何人也无法解释的结论。
"""

from __future__ import annotations

import codecs

from app.core.config import settings
from app.core.errors import ApiError
from app.schemas.enums import ErrorCode
from app.schemas.errors import ErrorDetail

#: 扩展名 → 语言标识。
#:
#: 这里覆盖的是**默认配置**中的扩展名（见 ``ALLOWED_FILE_EXTENSIONS``）。
#: 若通过环境变量扩充了白名单而没有在此登记，``language_for_extension``
#: 会返回 ``None``，扫描仍然可以进行，只是 `detected_language` 为 null，
#: 由阶段 6 的启发式识别补上——不会因为漏登记而拒绝合法文件。
EXTENSION_LANGUAGE_MAP: dict[str, str] = {
    "py": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "php": "php",
    "java": "java",
    "go": "go",
    "rb": "ruby",
    "html": "html",
    "vue": "vue",
}

#: 解码时按优先级尝试的编码。
#:
#: UTF-8 在前：它是 JSON、主流编辑器与现代源码仓库的默认编码。
#: GBK 在后：中文 Windows 下用记事本等工具"另存为"的源码常见此编码，
#: 若只认 UTF-8，这类文件会被全部拒绝，对课程场景过于苛刻。
_FALLBACK_ENCODINGS: tuple[str, ...] = ("utf-8", "gbk")

#: 判断"像不像文本"时，允许出现的控制字符（制表、换行、回车、换页、垂直制表）。
_ALLOWED_CONTROL_CHARS = frozenset("\t\n\r\f\v")

#: 非 ASCII 编码兜底解码后，控制字符占比超过该阈值即判定为二进制内容。
#:
#: GBK 的码位范围比 UTF-8 宽松，随机二进制有时能"碰巧"解码成功。
#: 以 2% 为界：正常源码里几乎不会出现控制字符，而二进制数据会大量出现。
_CONTROL_CHAR_RATIO_LIMIT = 0.02


def supported_extensions_text() -> str:
    """把允许的扩展名渲染成适合放进错误提示的文本，例如 ``.py、.js、.ts``。"""
    return "、".join(f".{ext}" for ext in sorted(settings.allowed_extensions))


def extension_of(filename: str) -> str:
    """取文件名的小写扩展名（不含点）。

    只取最后一个点之后的部分，因此 ``archive.tar.py`` → ``py``。
    没有点（例如 ``Makefile``）或点在最前（例如 ``.gitignore`` 的判定留空）时返回空串，
    由调用方决定如何处理——本函数不做猜测。
    """
    _, dot, extension = filename.strip().lower().rpartition(".")
    return extension if dot else ""


def language_for_extension(extension: str) -> str | None:
    """把扩展名映射为语言标识；未登记时返回 ``None``（不是编造一个值）。"""
    return EXTENSION_LANGUAGE_MAP.get(extension.lower().lstrip("."))


def ensure_supported_extension(filename: str) -> str:
    """校验扩展名在允许列表内，返回归一化后的扩展名。

    失败时抛出 415：文件类型不受支持属于"媒体类型"问题，
    与"内容校验不通过"（422）区分开，前端可以据此给出不同引导。
    """
    extension = extension_of(filename)
    allowed = settings.allowed_extensions

    if not extension:
        raise ApiError(
            status_code=415,
            code=ErrorCode.UNSUPPORTED_FILE_TYPE,
            message="无法判断文件类型：文件名缺少扩展名。",
            details=[
                ErrorDetail(
                    field="file",
                    message=f"请确保文件名带有扩展名。当前支持的类型：{supported_extensions_text()}。",
                )
            ],
        )

    if extension not in allowed:
        raise ApiError(
            status_code=415,
            code=ErrorCode.UNSUPPORTED_FILE_TYPE,
            message="不支持的文件类型。",
            details=[
                ErrorDetail(
                    field="file",
                    message=(
                        f"扩展名 .{extension} 不在允许列表内。"
                        f"当前支持的类型：{supported_extensions_text()}。"
                    ),
                )
            ],
        )

    return extension


def ensure_within_size_limit(size: int) -> None:
    """校验字节数未超过上传上限，超过则抛出 413。"""
    limit = settings.max_upload_size_bytes
    if size > limit:
        raise ApiError(
            status_code=413,
            code=ErrorCode.INPUT_TOO_LARGE,
            message="上传文件超过大小限制。",
            details=[
                ErrorDetail(
                    field="file",
                    message=f"文件大小 {size} 字节，超过上限 {limit} 字节（约 {limit // 1024} KB）。",
                )
            ],
        )


def ensure_within_char_limit(text: str) -> None:
    """校验**解码后**的字符数未超过代码文本上限。

    字节上限与字符上限是两个独立约束，必须分别检查：
    1 MB 的纯 ASCII 文件有 100 多万字符，字节数没超但字符数早就超了。
    若只查字节数就构造 ``ScanRequest``，用户会收到一条与上传无关的、
    关于 ``source_code`` 的报错，很难理解问题出在哪里。
    """
    limit = settings.max_source_code_chars
    if len(text) > limit:
        raise ApiError(
            status_code=413,
            code=ErrorCode.INPUT_TOO_LARGE,
            message="解码后的代码长度超过限制。",
            details=[
                ErrorDetail(
                    field="file",
                    message=(
                        f"解码后共 {len(text)} 个字符，超过上限 {limit} 个字符。"
                        "请拆分文件后再提交。"
                    ),
                )
            ],
        )


def _control_char_ratio(text: str) -> float:
    """返回文本中控制字符所占比例。

    换行、制表等正常排版字符不计入。
    """
    if not text:
        return 0.0
    suspicious = sum(
        1 for char in text if char not in _ALLOWED_CONTROL_CHARS and (char < " " or char == "\x7f")
    )
    return suspicious / len(text)


def decode_source_bytes(data: bytes) -> tuple[str, str]:
    """把上传的字节解码为文本。

    返回 ``(文本, 实际使用的编码)``。第二个返回值会出现在响应里——
    用 GBK 兜底解码时必须让用户知道，否则就是一次静默的字符集转换。

    处理顺序：

    1. 空内容 → 422（在读取字节、判断编码之前先拒绝）。
    2. 有 UTF-8 / UTF-16 BOM 时按 BOM 指定的编码解码，不做兜底猜测。
    3. 含 NUL 字节 → 直接判定为非文本，不再尝试解码。
    4. 依次严格尝试 UTF-8、GBK；对 GBK 的结果追加控制字符比例检查，
       避免二进制内容"碰巧"解码成功后被当成源码分析。

    全程使用 ``errors="strict"``：宁可明确报错，也不产出乱码。
    """
    if not data:
        raise ApiError(
            status_code=422,
            code=ErrorCode.EMPTY_INPUT,
            message="上传的文件内容为空。",
            details=[ErrorDetail(field="file", message="文件没有任何内容，无法进行分析。")],
        )

    if data.startswith(codecs.BOM_UTF8):
        return _decode_strict(data, "utf-8-sig"), "utf-8-sig"

    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = _decode_strict(data, "utf-16")
        # UTF-32 的 BOM 以 UTF-16 LE 的 BOM 开头，会被误判到这里。
        # 解码结果里残留 NUL 就说明猜错了编码，宁可拒绝也不返回带 NUL 的文本。
        if "\x00" in text:
            raise _encoding_error("文件编码无法识别。")
        return text, "utf-16"

    # NUL 是二进制内容的强特征，源码文件不应包含它。
    if b"\x00" in data:
        raise _encoding_error("文件包含 NUL 字节，看起来不是文本源码。")

    for encoding in _FALLBACK_ENCODINGS:
        try:
            text = data.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            continue
        if _control_char_ratio(text) > _CONTROL_CHAR_RATIO_LIMIT:
            continue
        return text, encoding

    raise _encoding_error(
        "无法按 UTF-8 或 GBK 解码该文件。请将文件另存为 UTF-8 编码后重试。"
    )


def _decode_strict(data: bytes, encoding: str) -> str:
    """按指定编码严格解码；失败时转为统一的 422，不泄漏底层异常文本。"""
    try:
        return data.decode(encoding, errors="strict")
    except UnicodeDecodeError:
        raise _encoding_error(f"文件声明为 {encoding} 编码，但内容无法按该编码解码。") from None


def _encoding_error(reason: str) -> ApiError:
    """构造编码相关的 422 错误。

    只回传我们自己写的说明：``UnicodeDecodeError`` 的原文包含字节偏移量
    与部分解码内容，既对用户没有帮助，也等于把源码片段写进了错误响应。
    """
    return ApiError(
        status_code=422,
        code=ErrorCode.UNSUPPORTED_ENCODING,
        message="文件编码不受支持或内容不是文本。",
        details=[ErrorDetail(field="file", message=reason)],
    )
