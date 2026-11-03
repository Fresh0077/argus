"""在当前环境中运行各路分析器，并产出可计算指标的样例结果。

可选分析器（Semgrep / LLM）不可用时**不会让评估失败**：

- Semgrep 未安装 → 报告 ``unavailable``，不计算它的指标；
- Semgrep 不支持某语言（HTML / Vue）→ 该样例不进入 Semgrep 的分母；
- LLM 默认不运行；只有显式 ``--enable-llm`` 且配置齐全时才调用，
  否则报告 ``disabled`` / ``unavailable`` 并继续评估其余分析器。

“没有执行”不会被当成“没有发现问题”计入 recall。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.analyzers.llm.detector import detect_llm_findings
from app.analyzers.rules.detector import detect_rule_findings
from app.analyzers.semgrep.detector import detect_semgrep_findings
from app.core.config import settings
from app.llm.client import missing_settings
from app.schemas.enums import AnalyzerState
from app.schemas.finding import Finding
from app.services.scan_service import (
    merge_findings,
    merge_llm_findings,
    merge_semgrep_findings,
)

from .manifest import EVALUATED_TYPES, LoadedSample
from .matching import ExpectedItem, SampleOutcome, evaluate_sample

#: 逐样例进度回调；用于 CLI 打印进度，避免长时间无输出看起来像卡住。
ProgressReporter = Callable[[str], None]


@dataclass
class AnalyzerRun:
    """一路分析器（或组合）在全部样例上的结果。"""

    name: str
    label: str
    state: str
    reason: str | None = None
    outcomes: dict[str, SampleOutcome] = field(default_factory=dict)
    findings_by_sample: dict[str, list[Finding]] = field(default_factory=dict)
    #: 未进入该分析器指标分母的样例 → 原因。
    not_evaluated: dict[str, str] = field(default_factory=dict)
    #: 发现的、但不属于五类评估范围的条目数量（例如未知类别）。
    out_of_scope: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def evaluated_count(self) -> int:
        return len(self.outcomes)


def _split_scope(findings: list[Finding]) -> tuple[list[Finding], int]:
    in_scope = [item for item in findings if item.vulnerability_type in EVALUATED_TYPES]
    return in_scope, len(findings) - len(in_scope)


def _outcome_for(
    sample: LoadedSample, findings: list[Finding], tolerance: int
) -> SampleOutcome:
    return evaluate_sample(
        sample.id,
        [
            ExpectedItem(vulnerability_type=item.vulnerability_type, line=item.line)
            for item in sample.expected
        ],
        findings,
        line_tolerance=tolerance,
    )


def run_rules(samples: tuple[LoadedSample, ...], tolerance: int) -> AnalyzerRun:
    """本地规则分析；语言已知时总会执行。"""
    run = AnalyzerRun(name="rules", label="本地规则", state="success")
    for sample in samples:
        outcome = detect_rule_findings(sample.source_code, sample.language)
        if outcome.skip_reason:
            run.not_evaluated[sample.id] = outcome.skip_reason
            continue
        scoped, outside = _split_scope(outcome.findings)
        run.out_of_scope += outside
        run.findings_by_sample[sample.id] = scoped
        run.outcomes[sample.id] = _outcome_for(sample, scoped, tolerance)

    if not run.outcomes:
        run.state = "skipped"
        run.reason = "所有样例都未执行本地规则检测。"
    elif run.not_evaluated:
        run.state = "partial"
        run.reason = f"{len(run.not_evaluated)} 个样例未执行规则检测。"
    return run


def run_semgrep(
    samples: tuple[LoadedSample, ...],
    tolerance: int,
    *,
    enabled: bool,
    progress: ProgressReporter | None = None,
) -> AnalyzerRun:
    """Semgrep 分析；不可用或语言不支持时只影响它自己的分母。"""
    if not enabled:
        return AnalyzerRun(
            name="semgrep",
            label="Semgrep",
            state="disabled",
            reason="本次评估未启用 Semgrep（--no-semgrep）。",
        )

    run = AnalyzerRun(name="semgrep", label="Semgrep", state="success")
    unavailable_reason: str | None = None

    for index, sample in enumerate(samples, start=1):
        if progress is not None:
            progress(f"Semgrep {index}/{len(samples)}：{sample.id}")
        outcome = detect_semgrep_findings(
            sample.source_code,
            sample.language,
            command=settings.semgrep_command,
            timeout_seconds=settings.semgrep_timeout_seconds,
        )
        if outcome.state is AnalyzerState.UNAVAILABLE:
            unavailable_reason = outcome.reason or "Semgrep 不可用。"
            break
        if outcome.state is not AnalyzerState.SUCCESS:
            run.not_evaluated[sample.id] = f"{outcome.state.value}：{outcome.reason or '未说明'}"
            continue

        scoped, outside = _split_scope(outcome.findings)
        run.out_of_scope += outside
        run.findings_by_sample[sample.id] = scoped
        run.outcomes[sample.id] = _outcome_for(sample, scoped, tolerance)

    if unavailable_reason is not None:
        run.reason = unavailable_reason
        run.state = "partial" if run.outcomes else "unavailable"
        # 不可用之后没有继续尝试的样例，统一记为未评估，避免误以为扫过。
        for sample in samples:
            run.not_evaluated.setdefault(sample.id, unavailable_reason)
    elif not run.outcomes:
        run.state = "skipped"
        run.reason = "Semgrep 没有成功分析任何样例。"
    elif any(not reason.startswith("skipped：") for reason in run.not_evaluated.values()):
        run.state = "partial"
        run.reason = f"{len(run.not_evaluated)} 个样例未被 Semgrep 分析。"
    return run


def run_llm(
    samples: tuple[LoadedSample, ...],
    tolerance: int,
    *,
    enabled: bool,
    progress: ProgressReporter | None = None,
) -> AnalyzerRun:
    """LLM 分析；默认不运行，配置不完整时跳过而不是让评估失败。"""
    if not enabled:
        return AnalyzerRun(
            name="llm",
            label="LLM",
            state="disabled",
            reason=(
                "默认不评估 LLM。传入 --enable-llm 且配置 LLM_BASE_URL / LLM_API_KEY / "
                "LLM_MODEL 后才会调用；启用后样例代码会被发送到所配置的第三方服务商。"
            ),
        )

    if not settings.llm_enabled:
        return AnalyzerRun(
            name="llm",
            label="LLM",
            state="disabled",
            reason="服务端未启用 LLM（LLM_ENABLED=false），本次跳过 LLM 评估。",
        )

    missing = missing_settings(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        model=settings.llm_model,
    )
    if missing:
        return AnalyzerRun(
            name="llm",
            label="LLM",
            state="unavailable",
            reason=f"未配置 {', '.join(missing)}，本次跳过 LLM 评估。",
        )

    run = AnalyzerRun(name="llm", label="LLM", state="success")
    for index, sample in enumerate(samples, start=1):
        if progress is not None:
            progress(f"LLM {index}/{len(samples)}：{sample.id}")
        outcome = detect_llm_findings(
            sample.source_code,
            sample.language,
            # 单独评估 LLM：不把其他分析器的结论放进提示词，避免“跟随”规则结果。
            prior_findings=(),
            timeout_seconds=settings.llm_timeout_seconds,
        )
        if outcome.state is not AnalyzerState.SUCCESS:
            run.not_evaluated[sample.id] = f"{outcome.state.value}：{outcome.reason or '未说明'}"
            continue
        scoped, outside = _split_scope(outcome.findings)
        run.out_of_scope += outside
        run.findings_by_sample[sample.id] = scoped
        run.outcomes[sample.id] = _outcome_for(sample, scoped, tolerance)

    if not run.outcomes:
        run.state = "failed"
        run.reason = "LLM 没有成功分析任何样例。"
    elif run.not_evaluated:
        run.state = "partial"
        run.reason = f"{len(run.not_evaluated)} 个样例未被 LLM 分析。"
    return run


def run_combined(
    samples: tuple[LoadedSample, ...],
    *,
    rules: AnalyzerRun,
    semgrep: AnalyzerRun,
    llm: AnalyzerRun,
    tolerance: int,
) -> AnalyzerRun:
    """按生产环境的合并顺序组合规则 / Semgrep / LLM 的结果。

    组合分析的分母是“本地规则成功执行”的样例：规则不需要外部依赖，
    其他分析器不可用时组合结果自然退化为可用部分，与线上行为一致。
    启发式线索（``untrusted_input_source``）不属于五类漏洞，未计入指标。
    """
    run = AnalyzerRun(
        name="combined",
        label="组合分析",
        state="success",
        notes=[
            "组合顺序与生产环境一致：本地规则 → Semgrep → LLM。",
            "启发式线索不属于五类风险，未计入 precision / recall。",
        ],
    )

    for sample in samples:
        if sample.id not in rules.outcomes:
            run.not_evaluated[sample.id] = "本地规则未执行，无法组成组合结果。"
            continue

        merged = merge_findings([], rules.findings_by_sample.get(sample.id, []))
        if sample.id in semgrep.outcomes:
            merged = merge_semgrep_findings(
                merged, semgrep.findings_by_sample.get(sample.id, [])
            )
        if sample.id in llm.outcomes:
            merged = merge_llm_findings(merged, llm.findings_by_sample.get(sample.id, []))

        scoped, outside = _split_scope(merged)
        run.out_of_scope += outside
        run.findings_by_sample[sample.id] = scoped
        run.outcomes[sample.id] = _outcome_for(sample, scoped, tolerance)

    if not run.outcomes:
        run.state = "skipped"
        run.reason = "没有任何样例成功组成组合结果。"
    elif run.not_evaluated:
        run.state = "partial"
        run.reason = f"{len(run.not_evaluated)} 个样例缺少本地规则结果。"
    return run
