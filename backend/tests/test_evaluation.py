"""样例集与评估指标计算的测试。

这些测试**不运行 Semgrep 或 LLM**：前者依赖外部可执行文件，后者会把代码
发送到第三方。这里只校验清单、标签与匹配逻辑本身。
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.enums import FindingSource, Severity
from app.schemas.finding import Finding
from scripts.argus_eval.manifest import (
    EVALUATED_TYPES,
    Manifest,
    ManifestError,
    SampleSpec,
    load_manifest,
    load_samples,
)
from scripts.argus_eval.matching import (
    Counts,
    ExpectedItem,
    aggregate,
    aggregate_by_type,
    evaluate_sample,
)
from scripts.argus_eval.runner import run_llm, run_rules, run_semgrep

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLES_DIR = PROJECT_ROOT / "test_samples"


def make_finding(
    vulnerability_type: str,
    line: int | None,
    *,
    title: str = "测试发现",
    finding_id: str | None = None,
) -> Finding:
    """构造一条最小合法 Finding，用于匹配测试。"""
    return Finding(
        id=finding_id or f"{vulnerability_type}-{line}",
        title=title,
        vulnerability_type=vulnerability_type,
        severity=Severity.HIGH,
        description="测试用描述",
        evidence="测试用证据",
        line_start=line,
        recommendation="测试用建议",
        confidence=0.8,
        source=FindingSource.STATIC_RULE,
    )


# ---------------------------------------------------------------------------
# 清单与样例文件
# ---------------------------------------------------------------------------


def test_manifest_and_samples_are_complete() -> None:
    manifest = load_manifest(SAMPLES_DIR / "manifest.json")
    samples = load_samples(SAMPLES_DIR, manifest)

    assert manifest.schema_version == 1
    assert manifest.line_tolerance == 2
    assert set(manifest.evaluated_types) == set(EVALUATED_TYPES)
    assert len(samples) >= 24

    kinds = Counter(sample.spec.kind for sample in samples)
    assert kinds["vulnerable"] >= 12
    assert kinds["secure"] >= 8
    assert kinds["benign"] >= 2

    vulnerable_types = {
        expected.vulnerability_type
        for sample in samples
        if sample.spec.kind == "vulnerable"
        for expected in sample.expected
    }
    # 手册要求至少覆盖 SQL 注入、XSS、命令注入与不安全动态执行。
    assert {
        "sql_injection",
        "xss",
        "command_injection",
        "unsafe_dynamic_execution",
    } <= vulnerable_types

    secure_categories = {
        sample.spec.category for sample in samples if sample.spec.kind == "secure"
    }
    # 安全写法必须与风险样例成对出现，不能只准备正例。
    assert {"sql_injection", "command_injection", "xss"} <= secure_categories
    assert any(sample.spec.kind == "benign" for sample in samples)


def test_samples_do_not_contain_credential_material() -> None:
    manifest = load_manifest(SAMPLES_DIR / "manifest.json")
    samples = load_samples(SAMPLES_DIR, manifest)

    forbidden = (
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "sk-",
    )
    for sample in samples:
        for marker in forbidden:
            assert marker not in sample.source_code, f"{sample.id} 含有疑似凭据：{marker}"


def test_manifest_paths_and_lines_are_valid() -> None:
    manifest = load_manifest(SAMPLES_DIR / "manifest.json")
    samples = load_samples(SAMPLES_DIR, manifest)

    seen_ids: set[str] = set()
    for sample in samples:
        assert sample.id not in seen_ids
        seen_ids.add(sample.id)
        assert sample.absolute_path.is_file()
        assert sample.line_count >= 1
        for expected in sample.expected:
            assert 1 <= expected.line <= sample.line_count


def test_sample_spec_rejects_inconsistent_labels() -> None:
    base = {
        "id": "demo-sample",
        "path": "vulnerable/python/demo.py",
        "language": "python",
        "kind": "vulnerable",
        "category": "sql_injection",
        "description": "说明",
        "risk_reason": "原因",
        "expected_behavior": "预期",
    }

    with pytest.raises(ValidationError):
        SampleSpec.model_validate({**base, "expected": []})

    with pytest.raises(ValidationError):
        SampleSpec.model_validate(
            {
                **base,
                "kind": "secure",
                "expected": [{"vulnerability_type": "sql_injection", "line": 3}],
            }
        )

    with pytest.raises(ValidationError):
        SampleSpec.model_validate({**base, "path": "../outside.py"})

    with pytest.raises(ValidationError):
        SampleSpec.model_validate(
            {
                **base,
                "expected": [{"vulnerability_type": "unknown_type", "line": 3}],
            }
        )


def test_manifest_rejects_duplicate_ids() -> None:
    payload = {
        "schema_version": 1,
        "description": "测试",
        "line_tolerance": 2,
        "evaluated_types": list(EVALUATED_TYPES),
        "samples": [
            {
                "id": "same-id",
                "path": "vulnerable/python/a.py",
                "language": "python",
                "kind": "vulnerable",
                "category": "sql_injection",
                "expected": [{"vulnerability_type": "sql_injection", "line": 1}],
                "description": "说明",
                "risk_reason": "原因",
                "expected_behavior": "预期",
            },
            {
                "id": "same-id",
                "path": "vulnerable/python/b.py",
                "language": "python",
                "kind": "vulnerable",
                "category": "sql_injection",
                "expected": [{"vulnerability_type": "sql_injection", "line": 1}],
                "description": "说明",
                "risk_reason": "原因",
                "expected_behavior": "预期",
            },
        ],
    }
    with pytest.raises(ValidationError):
        Manifest.model_validate(payload)


def test_missing_manifest_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ManifestError):
        load_manifest(tmp_path / "missing.json")


# ---------------------------------------------------------------------------
# 匹配与指标
# ---------------------------------------------------------------------------


def test_matching_uses_type_line_and_tolerance() -> None:
    expected = [ExpectedItem("sql_injection", 10), ExpectedItem("xss", 20)]
    findings = [
        make_finding("sql_injection", 12),
        make_finding("sql_injection", 12),  # 同一位置重复，应去重
        make_finding("xss", 23),  # 差 3 行，超出容差
        make_finding("command_injection", 30),  # 类别不符，计误报
    ]

    outcome = evaluate_sample("demo", expected, findings, line_tolerance=2)

    assert outcome.true_positives == 1
    assert outcome.false_positives == 2
    assert outcome.false_negatives == 1
    assert [item.describe() for item in outcome.missed] == ["xss@20"]
    assert len(outcome.unexpected) == 2


def test_matching_counts_missing_line_as_false_positive() -> None:
    expected = [ExpectedItem("sql_injection", 10)]
    findings = [make_finding("sql_injection", None)]

    outcome = evaluate_sample("demo", expected, findings, line_tolerance=2)

    assert outcome.true_positives == 0
    assert outcome.false_positives == 1
    assert outcome.false_negatives == 1


def test_each_finding_matches_at_most_one_expected_item() -> None:
    expected = [ExpectedItem("command_injection", 10), ExpectedItem("command_injection", 11)]
    findings = [make_finding("command_injection", 10)]

    outcome = evaluate_sample("demo", expected, findings, line_tolerance=2)

    assert outcome.true_positives == 1
    assert outcome.false_positives == 0
    assert outcome.false_negatives == 1


def test_metrics_are_none_when_denominator_is_zero() -> None:
    empty = Counts()
    assert empty.precision is None
    assert empty.recall is None
    assert empty.f1 is None

    only_false_positive = Counts(false_positives=1)
    assert only_false_positive.precision == 0.0
    assert only_false_positive.recall is None
    assert only_false_positive.f1 is None

    perfect = Counts(true_positives=5)
    assert perfect.precision == 1.0
    assert perfect.recall == 1.0
    assert perfect.f1 == 1.0


def test_aggregate_and_by_type() -> None:
    first = evaluate_sample(
        "one",
        [ExpectedItem("sql_injection", 10)],
        [make_finding("sql_injection", 10)],
        line_tolerance=2,
    )
    second = evaluate_sample(
        "two",
        [ExpectedItem("xss", 20)],
        [make_finding("sql_injection", 30)],
        line_tolerance=2,
    )

    total = aggregate([first, second])
    assert (total.true_positives, total.false_positives, total.false_negatives) == (1, 1, 1)

    by_type = aggregate_by_type([first, second])
    assert by_type["sql_injection"].true_positives == 1
    assert by_type["sql_injection"].false_positives == 1
    assert by_type["xss"].false_negatives == 1


# ---------------------------------------------------------------------------
# 分析器运行层（不触碰 Semgrep / LLM 外部依赖）
# ---------------------------------------------------------------------------


def test_rule_runner_evaluates_every_sample() -> None:
    manifest = load_manifest(SAMPLES_DIR / "manifest.json")
    samples = load_samples(SAMPLES_DIR, manifest)

    run = run_rules(samples, manifest.line_tolerance)

    assert run.state == "success"
    assert run.evaluated_count == len(samples)
    assert set(run.outcomes) == {sample.id for sample in samples}
    # 指标必须能从真实运行结果算出，而不是空转。
    total = aggregate(run.outcomes.values())
    assert total.actual == sum(len(sample.expected) for sample in samples)
    assert total.predicted >= total.true_positives


def test_optional_analyzers_can_be_disabled_without_calling_them() -> None:
    manifest = load_manifest(SAMPLES_DIR / "manifest.json")
    samples = load_samples(SAMPLES_DIR, manifest)

    semgrep = run_semgrep(samples, manifest.line_tolerance, enabled=False)
    assert semgrep.state == "disabled"
    assert semgrep.outcomes == {}

    llm = run_llm(samples, manifest.line_tolerance, enabled=False)
    assert llm.state == "disabled"
    assert llm.outcomes == {}
