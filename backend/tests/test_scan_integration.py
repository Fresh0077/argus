"""多分析器整合的集成测试。

这里集中验证"扫描编排"本身的行为，而不是某个分析器的内部细节：

- 只有规则可用时，其余分析器如实报 ``skipped``；
- 可选分析器抛出**未预期异常**时，整次扫描仍然返回 200，异常被收敛成 ``failed``；
- 总时限用尽后不再启动可选分析器；
- 剩余预算不足时，外部调用的超时被压缩；
- 干净代码确实可以返回空结果。

各分析器自己的解析、重试与降级路径分别在 ``test_semgrep.py`` /
``test_llm.py`` 中测试。本文件全部使用 mock，不发起真实网络请求。
"""

from __future__ import annotations

import time

import pytest
from pydantic import SecretStr, ValidationError

from app.analyzers.llm import LlmOutcome
from app.analyzers.semgrep import SemgrepOutcome
from app.core.config import Settings, settings
from app.schemas.enums import AnalyzerName, AnalyzerState, FindingSource, ScanStatus
from app.schemas.scan import ScanRequest
from app.services import scan_service
from app.services.scan_service import run_scan

SOURCE = """from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system("echo " + cmd)
"""


def _status(response, name: AnalyzerName):
    return next(item for item in response.analyzer_status if item.name == name)


def _enable_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "llm_enabled": True,
        "llm_base_url": "https://llm.test/v1",
        "llm_api_key": SecretStr("test-key"),
        "llm_model": "test-model",
    }
    for key, value in values.items():
        monkeypatch.setattr(settings, key, value)


def test_only_rules_run_when_optional_analyzers_are_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_enabled", False)
    response = run_scan(ScanRequest(source_code=SOURCE, language="python"))

    assert _status(response, AnalyzerName.RULES).state is AnalyzerState.SUCCESS
    assert _status(response, AnalyzerName.SEMGREP).state is AnalyzerState.SKIPPED
    assert _status(response, AnalyzerName.LLM).state is AnalyzerState.SKIPPED
    assert response.status is ScanStatus.PARTIAL
    assert any(item.source is FindingSource.STATIC_RULE for item in response.findings)


def test_unexpected_semgrep_exception_is_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*args: object, **kwargs: object) -> SemgrepOutcome:
        raise RuntimeError("内部路径 /secret/does-not-leak")

    monkeypatch.setattr(scan_service, "detect_semgrep_findings", explode)
    response = run_scan(
        ScanRequest(
            source_code=SOURCE,
            language="python",
            analysis_options={"enable_semgrep": True},
        )
    )

    semgrep = _status(response, AnalyzerName.SEMGREP)
    assert semgrep.state is AnalyzerState.FAILED
    assert "内部错误" in semgrep.reason
    assert "RuntimeError" in semgrep.reason
    assert "/secret/does-not-leak" not in semgrep.reason

    # 规则结果必须仍然存在，不能被一个可选分析器的崩溃抹掉。
    assert _status(response, AnalyzerName.RULES).state is AnalyzerState.SUCCESS
    assert any(item.source is FindingSource.STATIC_RULE for item in response.findings)
    assert response.status is ScanStatus.PARTIAL


def test_unexpected_llm_exception_is_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_llm(monkeypatch)

    class Crashing:
        def complete(self, system: str, user: str) -> str:
            raise RuntimeError("boom")

    response = run_scan(
        ScanRequest(
            source_code=SOURCE,
            language="python",
            analysis_options={"enable_llm": True},
        ),
        llm_client=Crashing(),
    )

    llm = _status(response, AnalyzerName.LLM)
    assert llm.state is AnalyzerState.FAILED
    assert "内部错误" in llm.reason
    assert _status(response, AnalyzerName.RULES).state is AnalyzerState.SUCCESS
    assert any(item.source is FindingSource.STATIC_RULE for item in response.findings)


def test_scan_budget_exhausted_skips_optional_analyzers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """总时限用尽后什么都不再启动，并说明是预算问题而不是"没发现"。"""
    monkeypatch.setattr(settings, "scan_timeout_seconds", 0.001)
    original_extract = scan_service.extract_features

    def slow_extract(*args: object, **kwargs: object):
        time.sleep(0.02)
        return original_extract(*args, **kwargs)

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("预算用尽后不应继续调用可选分析器")

    monkeypatch.setattr(scan_service, "extract_features", slow_extract)
    monkeypatch.setattr(scan_service, "detect_semgrep_findings", explode)
    monkeypatch.setattr(scan_service, "detect_llm_findings", explode)

    response = run_scan(
        ScanRequest(
            source_code=SOURCE,
            language="python",
            analysis_options={"enable_semgrep": True, "enable_llm": True},
        )
    )

    for name in (AnalyzerName.SEMGREP, AnalyzerName.LLM):
        item = _status(response, name)
        assert item.state is AnalyzerState.FAILED
        assert "总时限" in item.reason
        assert "SCAN_TIMEOUT_SECONDS" in item.reason
    assert _status(response, AnalyzerName.RULES).state is AnalyzerState.SUCCESS


def test_semgrep_timeout_is_limited_by_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "scan_timeout_seconds", 5.0)
    monkeypatch.setattr(settings, "semgrep_timeout_seconds", 30.0)
    captured: dict[str, float] = {}

    def fake_semgrep(
        source_code: str, language: str | None, *, command: str, timeout_seconds: float
    ) -> SemgrepOutcome:
        captured["timeout"] = timeout_seconds
        return SemgrepOutcome(state=AnalyzerState.SKIPPED, reason="测试替身")

    monkeypatch.setattr(scan_service, "detect_semgrep_findings", fake_semgrep)
    run_scan(
        ScanRequest(
            source_code=SOURCE,
            language="python",
            analysis_options={"enable_semgrep": True},
        )
    )

    assert 0 < captured["timeout"] <= 5.0


def test_llm_timeout_is_limited_by_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "scan_timeout_seconds", 1.0)
    monkeypatch.setattr(settings, "llm_timeout_seconds", 30.0)
    monkeypatch.setattr(settings, "llm_max_retries", 2)
    captured: dict[str, float | None] = {}

    def fake_llm(*args: object, **kwargs: object) -> LlmOutcome:
        captured["timeout"] = kwargs.get("timeout_seconds")  # type: ignore[assignment]
        return LlmOutcome(state=AnalyzerState.SUCCESS)

    monkeypatch.setattr(scan_service, "detect_llm_findings", fake_llm)
    run_scan(
        ScanRequest(
            source_code=SOURCE,
            language="python",
            analysis_options={"enable_llm": True},
        )
    )

    timeout = captured["timeout"]
    assert timeout is not None
    # 剩余约 1 秒：单次上限被收紧到 1 秒，而不是配置的 30 秒。
    assert 0 < timeout <= 1.0
    assert timeout < 30.0


def test_llm_timeout_keeps_configured_value_when_budget_is_ample(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "scan_timeout_seconds", 60.0)
    monkeypatch.setattr(settings, "llm_timeout_seconds", 30.0)
    monkeypatch.setattr(settings, "llm_max_retries", 2)
    captured: dict[str, float | None] = {}

    def fake_llm(*args: object, **kwargs: object) -> LlmOutcome:
        captured["timeout"] = kwargs.get("timeout_seconds")  # type: ignore[assignment]
        return LlmOutcome(state=AnalyzerState.SUCCESS)

    monkeypatch.setattr(scan_service, "detect_llm_findings", fake_llm)
    run_scan(
        ScanRequest(
            source_code=SOURCE,
            language="python",
            analysis_options={"enable_llm": True},
        )
    )
    assert captured["timeout"] == 30.0


def test_clean_code_can_return_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """空结果必须来自真实分析，而不是某个分析器失败后的空白。"""
    monkeypatch.setattr(settings, "llm_enabled", False)
    response = run_scan(ScanRequest(source_code="x = 1\n", language="python"))

    assert response.findings == []
    assert response.summary.total_findings == 0
    assert _status(response, AnalyzerName.RULES).state is AnalyzerState.SUCCESS


def test_scan_timeout_config_rejects_invalid_values() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, scan_timeout_seconds=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, scan_timeout_seconds=601)
