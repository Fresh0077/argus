"""Semgrep 分析器的对外入口。

接口与本地规则检测层保持一致：给它源码与语言，它返回一批 ``Finding``
与一个状态。区别在于它**可能不可用**（未安装、超时、输出异常），
因此状态不是一个可选的 ``skip_reason``，而是完整的 ``AnalyzerState``。

调用方必须区分这四种状态，它们对用户意味着完全不同的事：

    success       跑过了，``findings`` 为空才是"没发现问题"
    skipped       没跑（语言不支持），不能据此认为安全
    unavailable   工具不存在，装好之后就能跑
    failed        跑了但出错，结果不可信
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.analyzers.line_index import LineIndex
from app.analyzers.semgrep.catalog import semgrep_language
from app.analyzers.semgrep.parser import SemgrepOutputError, parse_semgrep_output
from app.analyzers.semgrep.runner import run_semgrep
from app.schemas.enums import AnalyzerState
from app.schemas.finding import Finding


@dataclass(frozen=True)
class SemgrepOutcome:
    """一次 Semgrep 分析的结果。"""

    state: AnalyzerState
    findings: list[Finding] = field(default_factory=list)
    reason: str | None = None


def detect_semgrep_findings(
    source_code: str,
    language: str | None,
    *,
    command: str = "semgrep",
    timeout_seconds: float = 30.0,
) -> SemgrepOutcome:
    """对源码执行一次 Semgrep 分析。

    参数：
        source_code: 待分析源码。**只被当作文本**，不执行、不编译、不导入。
        language: 已识别的语言；``None`` 表示未识别。
        command: Semgrep 可执行文件名或路径。
        timeout_seconds: 子进程超时时间。

    返回：
        ``SemgrepOutcome``。本函数不抛异常：外部工具的所有失败都转换成
        带原因的 ``unavailable`` / ``failed``，不影响其他分析器的结果。
    """
    if not language:
        return SemgrepOutcome(
            state=AnalyzerState.SKIPPED,
            reason="未识别出语言，已跳过 Semgrep。先确定语言才能选择对应的规则。",
        )

    target = semgrep_language(language)
    if target is None:
        return SemgrepOutcome(
            state=AnalyzerState.SKIPPED,
            reason=(
                f"Semgrep 不分析 {language}：内置规则集没有为该语言登记规则。"
                "这不代表该文件没有问题，只是本次没有用它做检查。"
            ),
        )

    run = run_semgrep(
        source_code,
        target,
        command=command,
        timeout_seconds=timeout_seconds,
    )
    if run.state is not AnalyzerState.SUCCESS or run.payload is None:
        return SemgrepOutcome(state=run.state, reason=run.reason)

    try:
        findings = parse_semgrep_output(run.payload, LineIndex(source_code))
    except SemgrepOutputError as exc:
        return SemgrepOutcome(state=AnalyzerState.FAILED, reason=str(exc))

    return SemgrepOutcome(state=AnalyzerState.SUCCESS, findings=findings)
