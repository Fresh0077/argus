"""在样例集上运行 LLM 分析，并产出可计算指标的结果。

LLM 默认不运行；只有显式 ``--enable-llm`` 且配置齐全时才调用。
“没有执行”不会被当成“没有发现问题”计入 recall。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.analyzers.llm.detector import detect_llm_findings
from app.core.config import settings
from app.llm.client import missing_settings
from app.schemas.enums import AnalyzerState
from app.schemas.finding import Finding

from .manifest import EVALUATED_TYPES, LoadedSample
from .matching import ExpectedItem, SampleOutcome, evaluate_sample

#: 逐样例进度回调；用于 CLI 打印进度，避免长时间无输出看起来像卡住。
ProgressReporter = Callable[[str], None]


@dataclass
class AnalyzerRun:
    """LLM 在全部样例上的结果。"""

    name: str
    label: str
    state: str
    reason: str | None = None
    outcomes: dict[str, SampleOutcome] = field(default_factory=dict)
    findings_by_sample: dict[str, list[Finding]] = field(default_factory=dict)
    #: 未进入指标分母的样例 → 原因。
    not_evaluated: dict[str, str] = field(default_factory=dict)
    #: 发现的、但不属于五类评估范围的条目数量。
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
            timeout_seconds=settings.llm_timeout_seconds,
        )
        if outcome.state is not AnalyzerState.SUCCESS:
            run.not_evaluated[sample.id] = (
                f"{outcome.state.value}：{outcome.reason or '未说明'}"
            )
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
