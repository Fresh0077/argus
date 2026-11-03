"""把分析结果与人工标签做一对一匹配，并计算 precision / recall / F1。

匹配规则（与 docs/evaluation.md 保持一致）：

- 只比较 ``EVALUATED_TYPES`` 中的五类风险；
- 一条发现与一条标签匹配，当且仅当**类别相同**且
  ``abs(发现行号 - 标签行号) <= line_tolerance``；
- 同一类别、同一行号的重复发现先去重，避免同一问题被多次计分；
- 每条标签最多匹配一条发现，每条发现最多匹配一条标签（贪心，按标签顺序）；
- 没有行号的发现无法与标签对齐，计为误报；
- 安全/普通样例没有任何标签，任何五类发现都计为误报。

``precision`` / ``recall`` / ``F1`` 在分母为 0 时返回 ``None``，由报告层显示为
"—"，而不是编造 1.0 或 0.0。
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from app.schemas.finding import Finding

from .manifest import EVALUATED_TYPES


@dataclass(frozen=True)
class ExpectedItem:
    vulnerability_type: str
    line: int

    def describe(self) -> str:
        return f"{self.vulnerability_type}@{self.line}"


@dataclass(frozen=True)
class PredictedItem:
    vulnerability_type: str
    line: int | None
    title: str = ""

    def describe(self) -> str:
        location = "未能定位" if self.line is None else f"@{self.line}"
        suffix = f"（{self.title}）" if self.title else ""
        return f"{self.vulnerability_type}{location}{suffix}"


@dataclass(frozen=True)
class SampleOutcome:
    """单个样例的匹配结果。"""

    sample_id: str
    expected: tuple[ExpectedItem, ...]
    predicted: tuple[PredictedItem, ...]
    matched_expected: frozenset[int] = field(default_factory=frozenset)
    matched_predicted: frozenset[int] = field(default_factory=frozenset)

    @property
    def true_positives(self) -> int:
        return len(self.matched_expected)

    @property
    def false_positives(self) -> int:
        return len(self.predicted) - self.true_positives

    @property
    def false_negatives(self) -> int:
        return len(self.expected) - self.true_positives

    @property
    def missed(self) -> tuple[ExpectedItem, ...]:
        return tuple(
            item for index, item in enumerate(self.expected) if index not in self.matched_expected
        )

    @property
    def unexpected(self) -> tuple[PredictedItem, ...]:
        return tuple(
            item for index, item in enumerate(self.predicted) if index not in self.matched_predicted
        )


@dataclass(frozen=True)
class Counts:
    """一组可累加的 TP / FP / FN。"""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    def __add__(self, other: "Counts") -> "Counts":
        return Counts(
            true_positives=self.true_positives + other.true_positives,
            false_positives=self.false_positives + other.false_positives,
            false_negatives=self.false_negatives + other.false_negatives,
        )

    @property
    def predicted(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def actual(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def precision(self) -> float | None:
        return self.true_positives / self.predicted if self.predicted else None

    @property
    def recall(self) -> float | None:
        return self.true_positives / self.actual if self.actual else None

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)


def evaluate_sample(
    sample_id: str,
    expected: Sequence[ExpectedItem],
    findings: Iterable[Finding],
    *,
    line_tolerance: int,
) -> SampleOutcome:
    """对一个样例做贪心一对一匹配。只接收五类风险中的发现。"""
    if line_tolerance < 0:
        raise ValueError("line_tolerance 不能为负数")

    predicted: list[PredictedItem] = []
    seen: set[tuple[str, int | None]] = set()
    for finding in findings:
        if finding.vulnerability_type not in EVALUATED_TYPES:
            # 调用方应已过滤；这里再挡一次，避免线索或未知类别污染指标。
            continue
        key = (finding.vulnerability_type, finding.line_start)
        if key in seen:
            continue
        seen.add(key)
        predicted.append(
            PredictedItem(
                vulnerability_type=finding.vulnerability_type,
                line=finding.line_start,
                title=finding.title,
            )
        )

    matched_expected: set[int] = set()
    matched_predicted: set[int] = set()
    for expected_index, item in enumerate(expected):
        for predicted_index, candidate in enumerate(predicted):
            if predicted_index in matched_predicted:
                continue
            if candidate.vulnerability_type != item.vulnerability_type:
                continue
            if candidate.line is None:
                continue
            if abs(candidate.line - item.line) <= line_tolerance:
                matched_expected.add(expected_index)
                matched_predicted.add(predicted_index)
                break

    return SampleOutcome(
        sample_id=sample_id,
        expected=tuple(expected),
        predicted=tuple(predicted),
        matched_expected=frozenset(matched_expected),
        matched_predicted=frozenset(matched_predicted),
    )


def aggregate(outcomes: Iterable[SampleOutcome]) -> Counts:
    """把所有样例的 TP / FP / FN 相加。"""
    total = Counts()
    for outcome in outcomes:
        total = total + Counts(
            true_positives=outcome.true_positives,
            false_positives=outcome.false_positives,
            false_negatives=outcome.false_negatives,
        )
    return total


def aggregate_by_type(outcomes: Iterable[SampleOutcome]) -> dict[str, Counts]:
    """按漏洞类别分组统计；五个类别都返回，即使计数为 0。"""
    totals = {name: Counts() for name in EVALUATED_TYPES}
    for outcome in outcomes:
        for index, item in enumerate(outcome.expected):
            if index not in outcome.matched_expected:
                totals[item.vulnerability_type] = totals[item.vulnerability_type] + Counts(
                    false_negatives=1
                )
        for index, item in enumerate(outcome.predicted):
            if index in outcome.matched_predicted:
                totals[item.vulnerability_type] = totals[item.vulnerability_type] + Counts(
                    true_positives=1
                )
            else:
                totals[item.vulnerability_type] = totals[item.vulnerability_type] + Counts(
                    false_positives=1
                )
    return totals
