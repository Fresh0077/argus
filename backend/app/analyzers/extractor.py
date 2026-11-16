"""特征提取入口。

把语言识别、代码统计与结构提取串成一条流水线。

设计原则：

1. **不抛异常给调用方。** 特征提取是分析前的上下文准备，
   失败不应该让整次扫描变成 500。
2. **不猜测。** 语言识别不出来就是 ``None``；函数/类数量是按语言模式
   计数得到的近似值，会在 ``notes`` 里说明。
3. **只描述“看到了什么”。** 特征不判定安全性；漏洞判断由 LLM 完成。
"""

from __future__ import annotations

from app.analyzers.language import detect_language
from app.analyzers.line_index import LineIndex
from app.analyzers.stats import compute_stats, compute_structure
from app.schemas.features import FeatureExtractionResult


def extract_features(
    source_code: str,
    *,
    filename: str | None = None,
    declared_language: str | None = None,
) -> FeatureExtractionResult:
    """对源码执行语言识别、统计与结构提取。

    参数：
        source_code: 源码文本。不做换行符归一化，行号按原样计算。
        filename: 可选文件名，仅用于取扩展名判断语言。
        declared_language: 调用方显式指定的语言，优先级最高。

    返回：
        ``FeatureExtractionResult``。本函数不抛异常：无法识别的输入
        会体现在各个计数值为 0、``language`` 为 None 与 ``notes`` 中。
    """
    index = LineIndex(source_code)
    detection = detect_language(
        source_code, filename=filename, declared=declared_language
    )

    notes: list[str] = []
    if detection.language is None:
        notes.append(
            "未识别出语言；仍可进行 LLM 分析，但函数/类/导入计数可能不准确。"
        )

    stats = compute_stats(index)
    structure, structure_notes = compute_structure(index, detection.language)
    notes.extend(structure_notes)

    return FeatureExtractionResult(
        language=detection.language,
        language_source=detection.source,
        language_evidence=detection.evidence,
        stats=stats,
        structure=structure,
        notes=notes,
    )
