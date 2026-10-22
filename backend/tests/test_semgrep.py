"""Semgrep 适配层的测试。

测试重点与实现的三条边界一一对应：

1. **失败必须与"没发现问题"区分开**：未安装、超时、非零退出、输出异常
   各自得到一个明确状态，且不影响其他分析器。
2. **不信任 Semgrep 的输出结构**：行号越界就丢弃，证据从原始源码里取，
   因为 OSS 版的 ``extra.lines`` 恒为 ``"requires login"``。
3. **调用方式本身是安全边界**：参数列表、无 shell、临时目录、剔除外传变量。

除一条带 ``skipif`` 的集成测试外，全部使用 mock，不依赖本机是否装了 Semgrep。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.analyzers.line_index import LineIndex
from app.analyzers.semgrep import (
    SEMGREP_LANGUAGES,
    SemgrepOutcome,
    SemgrepOutputError,
    detect_semgrep_findings,
    parse_semgrep_output,
    semgrep_language,
)
from app.analyzers.semgrep import runner as semgrep_runner
from app.services import scan_service
from app.schemas.enums import AnalyzerState, FindingSource, Severity
from app.schemas.finding import Finding, make_finding_id

_PY_SOURCE = (
    'uid = request.args.get("id")\n'
    'q = "SELECT * FROM users WHERE id = " + uid\n'
    "cursor.execute(q)\n"
)


def _result(
    *,
    check_id: str = "argus.semgrep.python-sqli",
    line: int = 3,
    end_line: int | None = None,
    severity: str = "ERROR",
    metadata: dict[str, object] | None = None,
    extra_lines: str = "requires login",
    message: str = "疑似 SQL 注入",
) -> dict[str, object]:
    """构造一条与 Semgrep 真实输出同形的 result 项。"""
    return {
        "check_id": check_id,
        "path": "input.py",
        "start": {"line": line, "col": 1, "offset": 0},
        "end": {"line": end_line if end_line is not None else line, "col": 10},
        "extra": {
            "message": message,
            "metadata": metadata or {},
            "severity": severity,
            "lines": extra_lines,
        },
    }


def _payload(*results: dict[str, object], errors: list[object] | None = None) -> dict[str, object]:
    return {"results": list(results), "errors": errors or [], "paths": {"scanned": ["input.py"]}}


# ---------------------------------------------------------------------------
# 语言映射
# ---------------------------------------------------------------------------


def test_supported_languages_cover_the_rule_set() -> None:
    """规则集登记的语言必须都能被映射到，否则规则永远不会生效。"""
    assert set(SEMGREP_LANGUAGES) == {
        "python",
        "javascript",
        "typescript",
        "php",
        "java",
        "go",
        "ruby",
    }


@pytest.mark.parametrize("language", ["html", "vue", "cobol", "unknown"])
def test_languages_semgrep_cannot_parse_are_not_mapped(language: str) -> None:
    """Semgrep 遇到不认识的扩展名会静默跳过，因此必须在这里拦住。"""
    assert semgrep_language(language) is None


def test_unknown_language_skips_before_invoking_semgrep(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("语言不支持时不应该调用 Semgrep")

    monkeypatch.setattr(semgrep_runner.subprocess, "run", explode)

    outcome = detect_semgrep_findings("<div></div>", "html")

    assert outcome.state is AnalyzerState.SKIPPED
    assert outcome.findings == []
    assert "不分析 html" in (outcome.reason or "")


def test_missing_language_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        semgrep_runner.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError())
    )

    outcome = detect_semgrep_findings("x = 1\n", None)

    assert outcome.state is AnalyzerState.SKIPPED
    assert "未识别出语言" in (outcome.reason or "")


# ---------------------------------------------------------------------------
# 结果解析
# ---------------------------------------------------------------------------


def test_result_is_converted_to_a_finding() -> None:
    payload = _payload(
        _result(
            metadata={
                "argus-type": "sql_injection",
                "argus-title": "疑似 SQL 注入（数据流）",
                "argus-recommendation": "改用参数化查询。",
                "cwe": "CWE-89: SQL Injection",
            }
        )
    )

    [finding] = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))

    assert finding.source is FindingSource.SEMGREP
    assert finding.rule_id == "argus.semgrep.python-sqli"
    assert finding.vulnerability_type == "sql_injection"
    assert finding.title == "疑似 SQL 注入（数据流）"
    assert finding.recommendation == "改用参数化查询。"
    assert finding.severity is Severity.HIGH
    assert finding.cwe_id == "CWE-89"
    assert finding.line_start == 3
    assert finding.line_end == 3


def test_evidence_comes_from_the_source_not_from_semgrep() -> None:
    """OSS 版把 ``extra.lines`` 填成 ``"requires login"``，直接用它就是编造证据。"""
    payload = _payload(_result(extra_lines="requires login"))

    [finding] = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))

    assert finding.evidence == "cursor.execute(q)"
    assert "requires login" not in finding.evidence


def test_evidence_is_truncated_to_the_shared_snippet_limit() -> None:
    source = "x = " + "a" * 1000 + "\n"
    payload = _payload(_result(line=1))

    [finding] = parse_semgrep_output(payload, LineIndex(source))

    assert len(finding.evidence) <= 300


@pytest.mark.parametrize(
    ("semgrep_severity", "expected"),
    [("ERROR", Severity.HIGH), ("WARNING", Severity.MEDIUM), ("INFO", Severity.LOW)],
)
def test_severity_mapping(semgrep_severity: str, expected: Severity) -> None:
    payload = _payload(_result(severity=semgrep_severity))

    [finding] = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))

    assert finding.severity is expected


def test_unknown_severity_falls_back_to_medium() -> None:
    """未知等级不猜 high，也不丢弃——用中等等级并要求人工确认。"""
    payload = _payload(_result(severity="CRITICAL"))

    [finding] = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))

    assert finding.severity is Severity.MEDIUM


def test_severity_never_exceeds_high() -> None:
    """规则层不给 critical，Semgrep 层同样不给：可利用性需要人确认。"""
    payload = _payload(_result(severity="ERROR"))

    [finding] = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))

    assert finding.severity is not Severity.CRITICAL


def test_multi_line_range_is_preserved() -> None:
    payload = _payload(_result(line=2, end_line=3))

    [finding] = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))

    assert (finding.line_start, finding.line_end) == (2, 3)


@pytest.mark.parametrize("line", [4, 99])
def test_out_of_range_line_is_dropped_not_clamped(line: int) -> None:
    """越界行号不能钳制到末行——那会造出一个指向别处的、看起来合理的行号。"""
    payload = _payload(_result(line=line))

    assert parse_semgrep_output(payload, LineIndex(_PY_SOURCE)) == []


def test_end_line_before_start_is_normalised_to_a_single_line() -> None:
    item = _result(line=3)
    item["end"] = {"line": 1, "col": 1}

    [finding] = parse_semgrep_output(_payload(item), LineIndex(_PY_SOURCE))

    assert (finding.line_start, finding.line_end) == (3, 3)


@pytest.mark.parametrize(
    "item",
    [
        {},
        {"check_id": "", "start": {"line": 1}},
        {"check_id": "x", "start": {"line": 0}},
        {"check_id": "x", "start": {"line": "1"}},
        {"check_id": "x", "start": None},
        {"check_id": "x", "start": {"line": True}},
        "not-a-dict",
    ],
)
def test_malformed_results_are_dropped(item: object) -> None:
    assert parse_semgrep_output(_payload(item), LineIndex(_PY_SOURCE)) == []  # type: ignore[arg-type]


def test_results_are_deduplicated_by_category_and_line() -> None:
    payload = _payload(
        _result(metadata={"argus-type": "sql_injection"}),
        _result(metadata={"argus-type": "sql_injection"}),
        _result(metadata={"argus-type": "command_injection"}),
    )

    findings = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))

    assert [(item.vulnerability_type, item.line_start) for item in findings] == [
        ("sql_injection", 3),
        ("command_injection", 3),
    ]


def test_missing_metadata_uses_a_generic_category() -> None:
    """没有类别元数据时不猜具体类别：猜错会让人往错的方向排查。"""
    [finding] = parse_semgrep_output(_payload(_result()), LineIndex(_PY_SOURCE))

    assert finding.vulnerability_type == "semgrep_finding"
    assert finding.cwe_id is None
    assert finding.recommendation


@pytest.mark.parametrize(
    ("cwe", "expected"),
    [
        ("CWE-89: SQL Injection", "CWE-89"),
        (["CWE-79: XSS", "CWE-89"], "CWE-79"),
        (["not a cwe"], None),
        (None, None),
    ],
)
def test_cwe_is_extracted_from_metadata(cwe: object, expected: str | None) -> None:
    payload = _payload(_result(metadata={"cwe": cwe}))

    [finding] = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))

    assert finding.cwe_id == expected


def test_description_says_it_is_still_a_candidate() -> None:
    [finding] = parse_semgrep_output(_payload(_result()), LineIndex(_PY_SOURCE))

    assert "候选发现" in finding.description


def test_semgrep_reported_errors_become_a_failure() -> None:
    """部分完成的静态分析报成 success，会让"没扫全"伪装成"没问题"。"""
    payload = _payload(errors=[{"type": "InvalidRuleSchemaError", "level": "error"}])

    with pytest.raises(SemgrepOutputError, match="执行错误"):
        parse_semgrep_output(payload, LineIndex(_PY_SOURCE))


def test_missing_results_list_is_an_error() -> None:
    with pytest.raises(SemgrepOutputError, match="results"):
        parse_semgrep_output({"errors": []}, LineIndex(_PY_SOURCE))


def test_finding_id_is_stable_across_runs() -> None:
    payload = _payload(_result())

    first = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))[0]
    second = parse_semgrep_output(payload, LineIndex(_PY_SOURCE))[0]

    assert first.id == second.id


# ---------------------------------------------------------------------------
# 子进程调用
# ---------------------------------------------------------------------------


class _FakeCompleted:
    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = ""
        self.stderr = stderr


def _fake_run(
    *,
    payload: dict[str, object] | None = None,
    returncode: int = 0,
    stderr: str = "",
    write_output: bool = True,
    captured: dict[str, object] | None = None,
) -> object:
    """构造一个假的 ``subprocess.run``：按 argv 里的路径写出 JSON。"""

    def fake(argv: list[str], **kwargs: object) -> _FakeCompleted:
        if captured is not None:
            captured["argv"] = list(argv)
            captured["kwargs"] = dict(kwargs)
            captured["cwd"] = kwargs.get("cwd")
        if write_output and payload is not None:
            for argument in argv:
                if isinstance(argument, str) and argument.startswith("--json-output="):
                    Path(argument.split("=", 1)[1]).write_text(
                        json.dumps(payload), encoding="utf-8"
                    )
        return _FakeCompleted(returncode=returncode, stderr=stderr)

    return fake


@pytest.fixture
def python_language():
    language = semgrep_language("python")
    assert language is not None
    return language


def test_successful_run_returns_the_payload(
    monkeypatch: pytest.MonkeyPatch, python_language
) -> None:
    monkeypatch.setattr(semgrep_runner.subprocess, "run", _fake_run(payload=_payload()))

    run = semgrep_runner.run_semgrep(_PY_SOURCE, python_language, command="semgrep")

    assert run.state is AnalyzerState.SUCCESS
    assert run.payload is not None


def test_arguments_are_passed_as_a_list_without_a_shell(
    monkeypatch: pytest.MonkeyPatch, python_language, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )
    monkeypatch.setattr(
        semgrep_runner.subprocess, "run", _fake_run(payload=_payload(), captured=captured)
    )

    semgrep_runner.run_semgrep(_PY_SOURCE, python_language)

    argv = captured["argv"]
    kwargs = captured["kwargs"]
    assert isinstance(argv, list)
    assert argv[0] == "/usr/bin/semgrep"
    assert kwargs["shell"] is False
    # 源码只经临时文件传递，绝不作为命令行参数出现。
    assert not any("request.args" in argument for argument in argv)
    assert "--metrics=off" in argv
    assert "--disable-version-check" in argv
    assert "--no-rewrite-rule-ids" in argv
    assert "--no-git-ignore" in argv


def test_temporary_directory_is_removed_after_the_run(
    monkeypatch: pytest.MonkeyPatch, python_language
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )
    monkeypatch.setattr(
        semgrep_runner.subprocess, "run", _fake_run(payload=_payload(), captured=captured)
    )

    semgrep_runner.run_semgrep(_PY_SOURCE, python_language)

    cwd = captured["cwd"]
    assert isinstance(cwd, str)
    assert not Path(cwd).exists()


def test_environment_forces_utf8_and_drops_the_app_token(
    monkeypatch: pytest.MonkeyPatch, python_language
) -> None:
    """中文 Windows 默认 GBK；设置不当会让 Semgrep 读规则文件时直接崩溃。

    同时必须剔除 ``SEMGREP_APP_TOKEN``：存在它时 Semgrep 会把结果上传到 SaaS。
    """
    captured: dict[str, object] = {}
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "secret-token")
    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )
    monkeypatch.setattr(
        semgrep_runner.subprocess, "run", _fake_run(payload=_payload(), captured=captured)
    )

    semgrep_runner.run_semgrep(_PY_SOURCE, python_language)

    env = captured["kwargs"]["env"]
    assert isinstance(env, dict)
    assert env["PYTHONUTF8"] == "1"
    assert env["SEMGREP_SEND_METRICS"] == "off"
    assert "SEMGREP_APP_TOKEN" not in env


def test_timeout_becomes_failed(monkeypatch: pytest.MonkeyPatch, python_language) -> None:
    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=1)

    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )
    monkeypatch.setattr(semgrep_runner.subprocess, "run", timeout)

    run = semgrep_runner.run_semgrep(_PY_SOURCE, python_language, timeout_seconds=1)

    assert run.state is AnalyzerState.FAILED
    assert "超时" in (run.reason or "") or "超过" in (run.reason or "")


def test_non_zero_exit_becomes_failed(
    monkeypatch: pytest.MonkeyPatch, python_language
) -> None:
    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )
    monkeypatch.setattr(
        semgrep_runner.subprocess,
        "run",
        _fake_run(returncode=7, stderr="invalid configuration file", write_output=False),
    )

    run = semgrep_runner.run_semgrep(_PY_SOURCE, python_language)

    assert run.state is AnalyzerState.FAILED
    assert "7" in (run.reason or "")
    assert "invalid configuration" in (run.reason or "")


def test_missing_output_file_becomes_failed(
    monkeypatch: pytest.MonkeyPatch, python_language
) -> None:
    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )
    monkeypatch.setattr(
        semgrep_runner.subprocess, "run", _fake_run(payload=None, write_output=False)
    )

    run = semgrep_runner.run_semgrep(_PY_SOURCE, python_language)

    assert run.state is AnalyzerState.FAILED
    assert "JSON" in (run.reason or "")


def test_invalid_json_becomes_failed(
    monkeypatch: pytest.MonkeyPatch, python_language
) -> None:
    def broken(argv: list[str], **kwargs: object) -> _FakeCompleted:
        for argument in argv:
            if isinstance(argument, str) and argument.startswith("--json-output="):
                Path(argument.split("=", 1)[1]).write_text("{not json", encoding="utf-8")
        return _FakeCompleted()

    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )
    monkeypatch.setattr(semgrep_runner.subprocess, "run", broken)

    run = semgrep_runner.run_semgrep(_PY_SOURCE, python_language)

    assert run.state is AnalyzerState.FAILED
    assert "解析" in (run.reason or "")


def test_oversized_output_is_rejected(
    monkeypatch: pytest.MonkeyPatch, python_language
) -> None:
    monkeypatch.setattr(semgrep_runner, "MAX_OUTPUT_BYTES", 10)
    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )
    monkeypatch.setattr(semgrep_runner.subprocess, "run", _fake_run(payload=_payload()))

    run = semgrep_runner.run_semgrep(_PY_SOURCE, python_language)

    assert run.state is AnalyzerState.FAILED
    assert "过大" in (run.reason or "")


def test_missing_executable_is_unavailable(monkeypatch: pytest.MonkeyPatch, python_language) -> None:
    """未安装时只影响自己那一条状态，不抛异常、不影响其他分析器。"""
    monkeypatch.setattr(semgrep_runner, "locate_executable", lambda command: None)

    run = semgrep_runner.run_semgrep(_PY_SOURCE, python_language)

    assert run.state is AnalyzerState.UNAVAILABLE
    assert run.reason


def test_detector_maps_runner_failure_to_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        semgrep_runner.subprocess,
        "run",
        _fake_run(returncode=2, stderr="boom", write_output=False),
    )
    monkeypatch.setattr(
        semgrep_runner, "locate_executable", lambda command: "/usr/bin/semgrep"
    )

    outcome = detect_semgrep_findings(_PY_SOURCE, "python")

    assert outcome.state is AnalyzerState.FAILED
    assert outcome.findings == []


# ---------------------------------------------------------------------------
# 与扫描编排的衔接
# ---------------------------------------------------------------------------


def _finding(line: int, kind: str, *, rule_id: str = "ARGUS-SQL-001") -> Finding:
    evidence = "cursor.execute(q)"
    return Finding(
        id=make_finding_id(
            source=FindingSource.STATIC_RULE,
            rule_key=rule_id,
            line_start=line,
            line_end=line,
            evidence=evidence,
        ),
        title="本地规则发现",
        vulnerability_type=kind,
        severity=Severity.HIGH,
        description="本地规则给出的说明。",
        evidence=evidence,
        line_start=line,
        line_end=line,
        recommendation="改用参数化查询。",
        confidence=0.8,
        source=FindingSource.STATIC_RULE,
        rule_id=rule_id,
    )


def _semgrep_finding(line: int, kind: str, *, rule_id: str = "argus.semgrep.python-sqli") -> Finding:
    finding = _finding(line, kind)
    return finding.model_copy(
        update={
            "source": FindingSource.SEMGREP,
            "rule_id": rule_id,
            "severity": Severity.HIGH,
            "confidence": 0.75,
            "title": "Semgrep 发现",
        }
    )


def test_merge_keeps_one_finding_and_records_the_second_source() -> None:
    """两个分析器报同一位置：不出两条，也不丢掉第二个来源。"""
    local = _finding(3, "sql_injection")

    merged = scan_service.merge_semgrep_findings([local], [_semgrep_finding(3, "sql_injection")])

    assert len(merged) == 1
    assert merged[0].source is FindingSource.STATIC_RULE
    assert "argus.semgrep.python-sqli" in merged[0].description
    assert merged[0].id == local.id, "说明变化不应改变稳定 ID"


def test_merge_keeps_semgrep_only_findings() -> None:
    local = _finding(3, "sql_injection")

    merged = scan_service.merge_semgrep_findings([local], [_semgrep_finding(9, "xss")])

    assert len(merged) == 2
    assert [item.line_start for item in merged] == [3, 9]


def test_merge_does_not_duplicate_the_note_on_repeated_scans() -> None:
    local = _finding(3, "sql_injection")
    once = scan_service.merge_semgrep_findings([local], [_semgrep_finding(3, "sql_injection")])

    twice = scan_service.merge_semgrep_findings(once, [_semgrep_finding(3, "sql_injection")])

    assert twice == once


def test_failed_semgrep_does_not_remove_other_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """可选分析器失败时，其余分析器的结果必须原样保留。"""
    from app.services.scan_service import run_scan
    from app.schemas.scan import AnalysisOptions, ScanRequest

    monkeypatch.setattr(
        scan_service,
        "detect_semgrep_findings",
        lambda *a, **k: SemgrepOutcome(state=AnalyzerState.FAILED, reason="超时"),
    )

    response = run_scan(
        ScanRequest(
            source_code=_PY_SOURCE,
            language="python",
            analysis_options=AnalysisOptions(enable_semgrep=True),
        )
    )

    status = {item.name.value: item for item in response.analyzer_status}
    assert status["semgrep"].state is AnalyzerState.FAILED
    assert status["rules"].state is AnalyzerState.SUCCESS
    assert response.findings, "Semgrep 失败不应抹掉本地规则的结果"
    assert response.status.value == "partial"


def test_unavailable_semgrep_is_reported_separately(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.scan_service import run_scan
    from app.schemas.scan import AnalysisOptions, ScanRequest

    monkeypatch.setattr(
        scan_service,
        "detect_semgrep_findings",
        lambda *a, **k: SemgrepOutcome(state=AnalyzerState.UNAVAILABLE, reason="未安装"),
    )

    response = run_scan(
        ScanRequest(
            source_code="x = 1\n",
            language="python",
            analysis_options=AnalysisOptions(enable_semgrep=True),
        )
    )

    status = {item.name.value: item for item in response.analyzer_status}
    assert status["semgrep"].state is AnalyzerState.UNAVAILABLE
    assert status["semgrep"].reason == "未安装"


def test_disabled_semgrep_is_skipped_without_running(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("未启用时不应调用 Semgrep")

    monkeypatch.setattr(scan_service, "detect_semgrep_findings", explode)

    from app.schemas.scan import ScanRequest
    from app.services.scan_service import run_scan

    response = run_scan(ScanRequest(source_code="x = 1\n", language="python"))

    status = {item.name.value: item for item in response.analyzer_status}
    assert status["semgrep"].state is AnalyzerState.SKIPPED
    assert status["semgrep"].duration_ms is None


# ---------------------------------------------------------------------------
# 真实 CLI 集成测试（未安装时自动跳过）
# ---------------------------------------------------------------------------

# 用与生产代码相同的定位逻辑判断可用性：只查 PATH 会漏掉
# "没激活虚拟环境、但 semgrep 装在 venv 里"的情况。
_SEMGREP_AVAILABLE = semgrep_runner.locate_executable("semgrep") is not None


@pytest.mark.skipif(not _SEMGREP_AVAILABLE, reason="本机未安装 Semgrep，跳过集成测试")
def test_real_semgrep_finds_tainted_sql_and_ignores_parameterised_queries() -> None:
    """真实 CLI 的回归测试：确认规则集确实命中，且安全写法不被误报。"""
    source = (
        'uid = request.args.get("id")\n'
        'q = "SELECT * FROM users WHERE id = " + uid\n'
        "cursor.execute(q)\n"
        'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
    )

    outcome = detect_semgrep_findings(source, "python")

    assert outcome.state is AnalyzerState.SUCCESS
    assert [(item.line_start, item.vulnerability_type) for item in outcome.findings] == [
        (3, "sql_injection")
    ]
    assert outcome.findings[0].source is FindingSource.SEMGREP
    assert outcome.findings[0].evidence == "cursor.execute(q)"


@pytest.mark.skipif(not _SEMGREP_AVAILABLE, reason="本机未安装 Semgrep，跳过集成测试")
def test_real_semgrep_reports_nothing_for_clean_code() -> None:
    outcome = detect_semgrep_findings(
        'uid = request.args.get("id")\ncursor.execute("SELECT 1")\n',
        "python",
    )

    assert outcome.state is AnalyzerState.SUCCESS
    assert outcome.findings == []
