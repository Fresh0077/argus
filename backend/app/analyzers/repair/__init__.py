"""修复建议分析器。

对外只暴露 ``generate_repair`` 与它可能抛出的异常，提示词、上下文裁剪
与输出解析分别放在 ``prompt`` / ``context`` / ``parser``，便于单独测试。
"""

from app.analyzers.repair.context import (
    RepairContext,
    RepairContextError,
    build_repair_context,
)
from app.analyzers.repair.detector import (
    RepairModelError,
    RepairUnavailableError,
    generate_repair,
)
from app.analyzers.repair.parser import RepairOutputError, parse_repair_output
from app.analyzers.repair.prompt import RepairPrompt, build_repair_prompt

__all__ = [
    "RepairContext",
    "RepairContextError",
    "RepairModelError",
    "RepairOutputError",
    "RepairPrompt",
    "RepairUnavailableError",
    "build_repair_context",
    "build_repair_prompt",
    "generate_repair",
    "parse_repair_output",
]
