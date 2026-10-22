"""Semgrep 适配层（可选静态分析器）。

这一层把外部工具 Semgrep 包成一个与本地规则检测同形的分析器：

    detect_semgrep_findings(source_code, language) -> SemgrepOutcome

**Semgrep 是可选依赖。** 未安装、超时或输出异常时，它只影响自己那一条
``analyzer_status``，其余分析器照常给出结果。

内置规则集在 ``rules/argus.yml``，全部使用 taint 模式——Semgrep 做的是
函数内数据流追踪，与本地正则规则（只看单行）互补。规则来源、覆盖范围与
已知的误报漏报写在 ``docs/analysis-design.md``。

模块分工：

- ``catalog``：语言映射、等级映射、规则集路径；
- ``runner``：定位 CLI、临时文件、子进程调用与超时；
- ``parser``：JSON → ``Finding``，负责取证据与校验行号；
- ``detector``：对外入口。
"""

from __future__ import annotations

from app.analyzers.semgrep.catalog import (
    CONFIDENCE_BY_SEVERITY,
    RULES_PATH,
    SEMGREP_LANGUAGES,
    SEVERITY_MAP,
    semgrep_language,
)
from app.analyzers.semgrep.detector import SemgrepOutcome, detect_semgrep_findings
from app.analyzers.semgrep.parser import SemgrepOutputError, parse_semgrep_output

__all__ = [
    "CONFIDENCE_BY_SEVERITY",
    "RULES_PATH",
    "SEMGREP_LANGUAGES",
    "SEVERITY_MAP",
    "SemgrepOutcome",
    "SemgrepOutputError",
    "detect_semgrep_findings",
    "parse_semgrep_output",
    "semgrep_language",
]
