"""契约模型测试。

覆盖三类输入：
- 合法输入应被接受，并做预期的归一化；
- 边界输入（空、超长、刚好等于上限）行为明确；
- 非法输入应被拒绝，且**不得被悄悄修正成看似合法的值**。
"""

import pytest
from pydantic import ValidationError

from app.core.config import settings
from app.schemas.enums import AnalyzerName, AnalyzerState, FindingSource, ScanStatus, Severity
from app.schemas.finding import MAX_EVIDENCE_CHARS, Finding, make_finding_id
from app.schemas.scan import (
    DEFAULT_DISCLAIMER,
    AnalysisOptions,
    AnalyzerStatus,
    ScanRequest,
    ScanResponse,
    ScanSummary,
    SeverityCounts,
    validate_display_filename,
)

# ---------------------------------------------------------------------------
# 测试辅助
# ---------------------------------------------------------------------------


def build_finding(**overrides: object) -> Finding:
    """构造一条合法的 Finding，便于按需覆盖单个字段。"""
    payload: dict[str, object] = {
        "id": "abc123def456",
        "title": "疑似 SQL 注入",
        "vulnerability_type": "sql_injection",
        "severity": Severity.HIGH,
        "description": "查询语句通过字符串拼接构造，可能受用户输入影响。",
        "evidence": 'query = "SELECT * FROM users WHERE id = " + user_id',
        "line_start": 12,
        "line_end": 12,
        "recommendation": "改用参数化查询或 ORM 的绑定参数。",
        "confidence": 0.6,
        "source": FindingSource.STATIC_RULE,
        "cwe_id": "CWE-89",
    }
    payload.update(overrides)
    return Finding(**payload)


# ---------------------------------------------------------------------------
# Severity：大小写归一化
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("High", Severity.HIGH),
        ("  medium  ", Severity.MEDIUM),
        ("Info", Severity.INFO),
        ("low", Severity.LOW),
    ],
)
def test_severity_is_case_insensitive(raw: str, expected: Severity) -> None:
    assert Severity(raw) is expected


def test_severity_accepts_uppercase_through_model() -> None:
    """模型层同样应接受大写等级，避免上游分析器必须自己转小写。"""
    assert build_finding(severity="HIGH").severity is Severity.HIGH


def test_invalid_severity_is_rejected_not_guessed() -> None:
    """无法识别的等级必须报错，不能猜测一个等级。

    直接调用枚举构造器时抛出的是 ``ValueError``（``ValidationError`` 是它的子类），
    所以这里断言 ``ValueError``；模型层的表现另见下一个用例。
    """
    with pytest.raises(ValueError):
        Severity("severe")


def test_invalid_severity_through_model_is_rejected() -> None:
    with pytest.raises(ValidationError):
        build_finding(severity="unknown")


def test_severity_rank_covers_all_levels_and_is_ordered() -> None:
    """排序权重必须覆盖全部等级，且 critical 最小（最严重）。"""
    from app.schemas.enums import SEVERITY_RANK

    assert set(SEVERITY_RANK) == set(Severity)
    assert SEVERITY_RANK[Severity.CRITICAL] < SEVERITY_RANK[Severity.INFO]


# ---------------------------------------------------------------------------
# Finding：行号
# ---------------------------------------------------------------------------


def test_line_numbers_may_be_none() -> None:
    """无法可靠定位时行号为 None，这是合法情况而非错误。"""
    finding = build_finding(line_start=None, line_end=None)

    assert finding.line_start is None
    assert finding.line_end is None
    assert finding.has_reliable_location is False


def test_only_line_start_is_allowed() -> None:
    """单行发现只给出起始行。"""
    finding = build_finding(line_start=7, line_end=None)

    assert finding.line_start == 7
    assert finding.has_reliable_location is True


@pytest.mark.parametrize("bad_line", [0, -1, -100])
def test_non_positive_line_numbers_are_rejected(bad_line: int) -> None:
    """0 与负数不是合法行号，必须拒绝而不是当成「未知」。"""
    with pytest.raises(ValidationError):
        build_finding(line_start=bad_line)


def test_line_end_without_line_start_is_rejected() -> None:
    with pytest.raises(ValidationError, match="line_start"):
        build_finding(line_start=None, line_end=10)


def test_line_end_before_line_start_is_rejected() -> None:
    with pytest.raises(ValidationError, match="不能小于"):
        build_finding(line_start=20, line_end=10)


def test_equal_line_start_and_end_is_allowed() -> None:
    assert build_finding(line_start=5, line_end=5).line_end == 5


# ---------------------------------------------------------------------------
# Finding：confidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0.0, 0.35, 1.0])
def test_confidence_within_range_is_accepted(value: float) -> None:
    assert build_finding(confidence=value).confidence == value


@pytest.mark.parametrize("value", [-0.01, -1, 1.01, 2])
def test_confidence_out_of_range_is_rejected(value: float) -> None:
    """置信度越界必须拒绝，避免出现 1.5 这种无法解释的数值。"""
    with pytest.raises(ValidationError):
        build_finding(confidence=value)


def test_confidence_boundaries_are_inclusive() -> None:
    """0 与 1 是闭区间端点，应当被接受。"""
    assert build_finding(confidence=0).confidence == 0.0
    assert build_finding(confidence=1).confidence == 1.0


# ---------------------------------------------------------------------------
# Finding：其他字段约束
# ---------------------------------------------------------------------------


def test_empty_title_is_rejected() -> None:
    with pytest.raises(ValidationError):
        build_finding(title="")


def test_overlong_evidence_is_rejected() -> None:
    """证据片段有长度上限，防止把整个源文件塞进单条发现。"""
    with pytest.raises(ValidationError):
        build_finding(evidence="x" * (MAX_EVIDENCE_CHARS + 1))


def test_empty_evidence_is_allowed() -> None:
    """没有可展示的片段时宁可留空，也不编造证据。"""
    assert build_finding(evidence="").evidence == ""


@pytest.mark.parametrize("cwe", ["CWE-89", "CWE-79", "CWE-1"])
def test_valid_cwe_id_is_accepted(cwe: str) -> None:
    assert build_finding(cwe_id=cwe).cwe_id == cwe


@pytest.mark.parametrize("cwe", ["89", "cwe-89", "CWE-", "CWE-89; DROP", "CWE-1234567"])
def test_invalid_cwe_id_is_rejected(cwe: str) -> None:
    """CWE 编号严格校验，避免把自由文本当成标准编号。"""
    with pytest.raises(ValidationError):
        build_finding(cwe_id=cwe)


def test_cwe_id_is_optional() -> None:
    assert build_finding(cwe_id=None).cwe_id is None


def test_unknown_extra_fields_are_ignored() -> None:
    """LLM 常带额外字段，忽略而非报错，避免整条发现有价值信息被丢弃。"""
    finding = Finding(
        **{
            "id": "x1",
            "title": "t",
            "vulnerability_type": "sql_injection",
            "severity": "high",
            "description": "d",
            "recommendation": "r",
            "confidence": 0.5,
            "source": "llm",
            "model_reasoning": "这是模型自作主张多返回的字段",
        }
    )

    assert not hasattr(finding, "model_reasoning")


def test_serialization_uses_lowercase_enum_values() -> None:
    """序列化后枚举应是小写字符串，前后端取值一致。"""
    dumped = build_finding().model_dump(mode="json")

    assert dumped["severity"] == "high"
    assert dumped["source"] == "static_rule"


# ---------------------------------------------------------------------------
# make_finding_id：稳定性与区分度
# ---------------------------------------------------------------------------


def test_finding_id_is_stable_for_same_input() -> None:
    """同样的问题重复扫描应得到同一个 id，便于去重与前端列表复用。"""
    kwargs = {
        "source": FindingSource.STATIC_RULE,
        "rule_key": "ARGUS-SQLI-001",
        "line_start": 12,
        "line_end": 12,
        "evidence": "query = a + b",
    }

    assert make_finding_id(**kwargs) == make_finding_id(**kwargs)


def test_finding_id_ignores_rule_key_case_and_evidence_whitespace() -> None:
    base = {
        "source": FindingSource.STATIC_RULE,
        "line_start": 3,
        "line_end": 3,
        "evidence": "eval(user_input)",
    }

    assert make_finding_id(rule_key="ARGUS-EVAL-001", **base) == make_finding_id(
        rule_key="argus-eval-001", extra="  ", **base
    )


def test_finding_id_differs_across_lines_and_sources() -> None:
    """不同位置或不同来源必须是不同发现，不能被错误合并。"""
    base = {
        "rule_key": "ARGUS-SQLI-001",
        "line_start": 12,
        "line_end": 12,
        "evidence": "query = a + b",
    }

    assert make_finding_id(source=FindingSource.STATIC_RULE, **base) != make_finding_id(
        source=FindingSource.LLM, **base
    )
    assert make_finding_id(source=FindingSource.STATIC_RULE, **base) != make_finding_id(
        source=FindingSource.STATIC_RULE, **{**base, "line_start": 13, "line_end": 13}
    )


def test_finding_id_handles_missing_line_numbers() -> None:
    """行号未知时仍能生成稳定 id，不能因此报错。"""
    kwargs = {
        "source": FindingSource.HEURISTIC,
        "rule_key": "SINK-EVAL",
        "line_start": None,
        "line_end": None,
        "evidence": "eval(",
    }

    assert make_finding_id(**kwargs) == make_finding_id(**kwargs)


# ---------------------------------------------------------------------------
# ScanRequest
# ---------------------------------------------------------------------------


def test_valid_scan_request_is_accepted() -> None:
    request = ScanRequest(source_code="print('hello')")

    assert request.source_code == "print('hello')"
    assert request.language is None
    assert request.filename is None
    assert request.analysis_options.enable_llm is False
    assert request.analysis_options.enable_semgrep is False


@pytest.mark.parametrize("code", ["", "   ", "\n\n\t  \r\n"])
def test_empty_or_blank_source_code_is_rejected(code: str) -> None:
    with pytest.raises(ValidationError, match="不能为空"):
        ScanRequest(source_code=code)


def test_source_code_at_limit_is_accepted() -> None:
    """长度刚好等于上限应通过。"""
    code = "a" * settings.max_source_code_chars

    assert len(ScanRequest(source_code=code).source_code) == settings.max_source_code_chars


def test_source_code_over_limit_is_rejected() -> None:
    code = "a" * (settings.max_source_code_chars + 1)

    with pytest.raises(ValidationError, match="超过上限"):
        ScanRequest(source_code=code)


def test_source_code_preserves_whitespace() -> None:
    """不做 strip：缩进与首尾空行对代码分析有意义。"""
    code = "\n\ndef f():\n    return 1\n\n"

    assert ScanRequest(source_code=code).source_code == code


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("Python", "python"), ("  JavaScript ", "javascript"), ("C++", "c++")],
)
def test_language_is_normalized_to_lowercase(raw: str, expected: str) -> None:
    assert ScanRequest(source_code="x = 1", language=raw).language == expected


def test_blank_language_is_treated_as_missing() -> None:
    assert ScanRequest(source_code="x = 1", language="   ").language is None


@pytest.mark.parametrize("bad_language", ["py thon", "python;rm -rf", "../x", "语" * 40])
def test_invalid_language_is_rejected(bad_language: str) -> None:
    with pytest.raises(ValidationError):
        ScanRequest(source_code="x = 1", language=bad_language)


def test_unknown_extra_field_in_request_is_rejected() -> None:
    """请求体字段拼错时应显式报错，而不是静默忽略导致配置看起来没生效。"""
    with pytest.raises(ValidationError):
        ScanRequest(source_code="x = 1", source_codee="typo")


def test_unknown_option_in_analysis_options_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalysisOptions(enable_llmm=True)


# ---------------------------------------------------------------------------
# 文件名校验（仅作为展示信息）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["views.py", "app.jsx", "index.html", "MyFile.TSX"])
def test_safe_filenames_are_accepted(name: str) -> None:
    assert validate_display_filename(name) == name


def test_filename_is_optional() -> None:
    assert validate_display_filename(None) is None


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        "   ",
        "../etc/passwd",
        "..\\windows\\system32\\cmd.exe",
        "dir/views.py",
        "dir\\views.py",
        "views.py\x00.txt",
        "CON",
        "con.py",
        "NUL.txt",
        "LPT1.py",
        "x" * 256,
    ],
)
def test_dangerous_filenames_are_rejected(bad_name: str) -> None:
    """路径穿越、Windows 保留名、空字符与超长名都必须拒绝。"""
    with pytest.raises(ValueError):
        validate_display_filename(bad_name)


def test_filename_with_dotdot_inside_is_conservatively_rejected() -> None:
    """``..`` 出现在名字中间也会被拒绝——偏保守，避免绕过技巧。"""
    with pytest.raises(ValueError):
        validate_display_filename("archive..tar.py")


def test_filename_in_request_is_validated() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(source_code="x = 1", filename="../../secret.py")


def test_valid_filename_passes_through_request() -> None:
    request = ScanRequest(source_code="x = 1", filename="views.py")

    assert request.filename == "views.py"


# ---------------------------------------------------------------------------
# AnalyzerStatus：必须区分「失败」与「未发现」
# ---------------------------------------------------------------------------


def test_success_status_needs_no_reason() -> None:
    status = AnalyzerStatus(name=AnalyzerName.RULES, state=AnalyzerState.SUCCESS, findings_count=2)

    assert status.reason is None
    assert status.findings_count == 2


@pytest.mark.parametrize(
    "state", [AnalyzerState.SKIPPED, AnalyzerState.UNAVAILABLE, AnalyzerState.FAILED]
)
def test_non_success_status_requires_reason(state: AnalyzerState) -> None:
    """非成功状态必须说明原因，否则会被误读成「没有风险」。"""
    with pytest.raises(ValidationError, match="必须提供 reason"):
        AnalyzerStatus(name=AnalyzerName.SEMGREP, state=state)


@pytest.mark.parametrize(
    "state", [AnalyzerState.SKIPPED, AnalyzerState.UNAVAILABLE, AnalyzerState.FAILED]
)
def test_non_success_status_with_reason_is_accepted(state: AnalyzerState) -> None:
    status = AnalyzerStatus(
        name=AnalyzerName.SEMGREP, state=state, reason="未安装 semgrep 可执行文件"
    )

    assert status.state is state
    assert status.findings_count == 0


def test_negative_duration_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalyzerStatus(
            name=AnalyzerName.RULES, state=AnalyzerState.SUCCESS, duration_ms=-1
        )


def test_zero_findings_with_success_means_no_issue_found() -> None:
    """success + 0 条发现 = 本次分析未发现问题（不等于代码安全）。"""
    status = AnalyzerStatus(name=AnalyzerName.RULES, state=AnalyzerState.SUCCESS)

    assert status.findings_count == 0
    assert status.state is AnalyzerState.SUCCESS


# ---------------------------------------------------------------------------
# ScanSummary：统计必须来自真实结果
# ---------------------------------------------------------------------------


def test_summary_counts_are_computed_from_findings() -> None:
    findings = [
        build_finding(id="a", severity="high"),
        build_finding(id="b", severity="HIGH"),
        build_finding(id="c", severity="low", source=FindingSource.LLM),
    ]

    summary = ScanSummary.from_findings(findings)

    assert summary.total_findings == 3
    assert summary.severity_counts.high == 2
    assert summary.severity_counts.low == 1
    assert summary.severity_counts.critical == 0
    assert summary.severity_counts.total == 3
    assert summary.source_counts[FindingSource.STATIC_RULE] == 2
    assert summary.source_counts[FindingSource.LLM] == 1


def test_summary_of_no_findings_is_all_zero() -> None:
    summary = ScanSummary.from_findings([])

    assert summary.total_findings == 0
    assert summary.severity_counts.total == 0
    assert summary.source_counts == {}


def test_severity_counts_defaults_to_zero_for_all_levels() -> None:
    counts = SeverityCounts()

    assert counts.model_dump() == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def test_negative_summary_count_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ScanSummary(total_findings=-1, severity_counts=SeverityCounts())


# ---------------------------------------------------------------------------
# ScanResponse
# ---------------------------------------------------------------------------


def test_scan_response_contains_disclaimer_by_default() -> None:
    """定位声明必须随响应返回，避免前端「忘记」展示它。"""
    response = ScanResponse(
        scan_id="scan-00000001",
        status=ScanStatus.COMPLETED,
        summary=ScanSummary.from_findings([]),
        duration_ms=12,
    )

    assert response.disclaimer == DEFAULT_DISCLAIMER
    assert "不是安全证明工具" in response.disclaimer


def test_scan_response_with_partial_status_keeps_results() -> None:
    """部分分析器失败时，已成功的结果仍须返回。"""
    finding = build_finding()
    response = ScanResponse(
        scan_id="scan-00000002",
        status=ScanStatus.PARTIAL,
        detected_language="python",
        findings=[finding],
        summary=ScanSummary.from_findings([finding]),
        duration_ms=42,
        analyzer_status=[
            AnalyzerStatus(name=AnalyzerName.RULES, state=AnalyzerState.SUCCESS, findings_count=1),
            AnalyzerStatus(
                name=AnalyzerName.LLM,
                state=AnalyzerState.UNAVAILABLE,
                reason="未配置 LLM_API_KEY",
            ),
        ],
    )

    assert response.status is ScanStatus.PARTIAL
    assert len(response.findings) == 1
    assert response.summary.total_findings == 1
    assert len(response.analyzer_status) == 2


def test_scan_response_rejects_negative_duration() -> None:
    with pytest.raises(ValidationError):
        ScanResponse(
            scan_id="scan-00000003",
            status=ScanStatus.COMPLETED,
            summary=ScanSummary.from_findings([]),
            duration_ms=-5,
        )


def test_scan_response_rejects_short_scan_id() -> None:
    with pytest.raises(ValidationError):
        ScanResponse(
            scan_id="short",
            status=ScanStatus.COMPLETED,
            summary=ScanSummary.from_findings([]),
            duration_ms=1,
        )
