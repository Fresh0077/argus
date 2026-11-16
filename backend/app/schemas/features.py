"""特征提取结果模型。

这些数据是**分析上下文**，不是漏洞结论：

- ``stats`` / ``structure`` 是对代码的客观计数，不含任何判断；
- 特征摘要会作为上下文传给 LLM，帮助模型了解代码规模与依赖。

本模块只描述“看到了什么”，不回答“这是不是漏洞”。
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.schemas.enums import LanguageSource

#: 导入模块名的长度上限。导入语句可能很长（尤其是带长路径的相对导入），
#: 这里只保留足够识别依赖的片段。
MAX_IMPORT_NAME_CHARS = 120

#: 最多保留的导入条目数。超出部分丢弃并在 ``notes`` 中说明，
#: 避免超大文件把响应撑大。
MAX_IMPORT_ENTRIES = 200


class CodeStats(BaseModel):
    """代码的客观统计量。

    只做计数，不做任何判断。空输入的计数值全部为 0，而不是编造默认值。
    """

    model_config = ConfigDict(extra="forbid")

    #: 总行数。末行的换行符不额外算作一行（``"a\\n"`` 是 1 行）。
    total_lines: int = Field(ge=0)

    #: 非空行数（去除仅含空白字符的行）。
    non_blank_lines: int = Field(ge=0)

    #: 字符总数，与输入完全一致（含换行符）。
    total_chars: int = Field(ge=0)

    #: 最长一行的字符数（不含换行符）。
    max_line_length: int = Field(ge=0)


class CodeStructure(BaseModel):
    """从代码中提取的结构信息。

    **函数数与类数是"大致数量"**：它们通过按语言匹配声明模式得到，
    无法识别匿名函数、箭头函数赋值之外的形式，也不做语法解析（不编译、不导入）。
    因此这两个数字用于了解代码规模，不可作为精确指标。
    """

    model_config = ConfigDict(extra="forbid")

    #: 函数/方法的大致数量。无法按模式识别时为 0。
    function_count: int = Field(default=0, ge=0)

    #: 类/结构体的大致数量。
    class_count: int = Field(default=0, ge=0)

    #: 识别到的导入条目数。可能大于 ``imports`` 的长度（超出上限的部分被丢弃）。
    import_count: int = Field(default=0, ge=0)

    #: 导入的模块名列表，已去重并截断。**只保留模块名，不含整行导入语句**，
    #: 因为整行可能带有注释或路径信息。
    imports: list[Annotated[str, StringConstraints(max_length=MAX_IMPORT_NAME_CHARS)]] = Field(
        default_factory=list
    )


class FeatureExtractionResult(BaseModel):
    """特征提取的整体产出。

    语言识别的结论同时出现在 ``ScanResponse.detected_language`` 与这里，
    但这里额外给出 ``language_source`` 与 ``language_evidence``——
    用户需要知道"python"这个结论是调用方指定的、扩展名推的，还是从内容猜的。
    """

    model_config = ConfigDict(extra="forbid")

    #: 识别出的语言；未识别时为 None（不使用 "unknown" 这类哨兵字符串，
    #: 理由与行号一致：哨兵值在类型上与真实取值无法区分）。
    language: str | None = None

    #: 语言结论的来源。未识别时为 ``LanguageSource.NONE``。
    language_source: LanguageSource

    #: 得出该结论的依据，例如 ``"扩展名 .py"``、``"匹配 shebang：python3"``。
    #: 未识别时说明尝试过但未匹配到可靠信号。
    language_evidence: Annotated[str, StringConstraints(min_length=1, max_length=200)]

    stats: CodeStats

    structure: CodeStructure

    #: 需要让调用方知道的处理说明，例如「语言未识别，函数/类计数可能不准确」。
    #: 这类信息不适合放进 ``analyzer_status[].reason``（那条只描述非成功状态），
    #: 但又必须可见，因此单独列出。
    notes: list[Annotated[str, StringConstraints(min_length=1, max_length=300)]] = Field(
        default_factory=list
    )
