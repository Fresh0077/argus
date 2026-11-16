"""扫描编排的集成测试。

扫描链路现在是：特征提取（上下文）→ 可选 LLM。本文件只验证编排行为：

- 未启用 LLM 时，特征提取照常完成，LLM 如实报 ``skipped``；
- LLM 抛出未预期异常时，扫描仍返回 200，异常被收敛成 ``failed``；
- 总时限用尽后不再启动 LLM；
- 剩余预算不足时，LLM 请求超时被压缩；
- 干净代码确实可以返回空结果。

全部使用 mock，不发起真实网络请求。
"""

from __future__ import annotations

import time

import pytest
from pydantic import SecretStr, ValidationError

from app.analyzers.llm import LlmOutcome
from app.core.config import Settings, settings
from app.schemas.enums import AnalyzerName, AnalyzerState, ScanStatus
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


def test_features_run_and_llm_is_skipped_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_enabled", False)
    response = run_scan(ScanRequest(source_code=SOURCE, language="python"))

    assert _status(response, AnalyzerName.LANGUAGE_DETECTION).state is AnalyzerState.SUCCESS
    assert _status(response, AnalyzerName.FEATURE_EXTRACTION).state is AnalyzerState.SUCCESS
    assert _status(response, AnalyzerName.LLM).state is AnalyzerState.SKIPPED
    assert response.status is ScanStatus.PARTIAL
    assert response.findings == []
    assert response.features is not None
    assert response.features.structure.import_count >= 2


def test_unexpected_llm_exception_is_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_llm(monkeypatch)

    def explode(*args: object, **kwargs: object) -> LlmOutcome:
        raise RuntimeError("内部路径 /secret/does-not-leak")

    monkeypatch.setattr(scan_service, "detect_llm_findings", explode)
    response = run_scan(
        ScanRequest(
            source_code=SOURCE,
            language="python",
            analysis_options={"enable_llm": True},
        )
    )

    llm = _status(response, AnalyzerName.LLM)
    assert llm.state is AnalyzerState.FAILED
    assert "未预期错误" in llm.reason
    assert "RuntimeError" in llm.reason
    assert "/secret/does-not-leak" not in llm.reason
    assert _status(response, AnalyzerName.FEATURE_EXTRACTION).state is AnalyzerState.SUCCESS
    assert response.status is ScanStatus.PARTIAL


def test_scan_budget_exhausted_skips_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """总时限用尽后不再启动 LLM，并说明是预算问题。"""
    monkeypatch.setattr(settings, "scan_timeout_seconds", 0.001)
    original_extract = scan_service.extract_features

    def slow_extract(*args: object, **kwargs: object):
        time.sleep(0.02)
        return original_extract(*args, **kwargs)

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("预算用尽后不应继续调用 LLM")

    monkeypatch.setattr(scan_service, "extract_features", slow_extract)
    monkeypatch.setattr(scan_service, "detect_llm_findings", explode)

    response = run_scan(
        ScanRequest(
            source_code=SOURCE,
            language="python",
            analysis_options={"enable_llm": True},
        )
    )

    item = _status(response, AnalyzerName.LLM)
    assert item.state is AnalyzerState.FAILED
    assert "总时限" in item.reason
    assert "SCAN_TIMEOUT_SECONDS" in item.reason
    assert _status(response, AnalyzerName.FEATURE_EXTRACTION).state is AnalyzerState.SUCCESS


def test_llm_timeout_is_limited_by_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "scan_timeout_seconds", 1.0)
    monkeypatch.setattr(settings, "llm_timeout_seconds", 30.0)
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
    assert 0 < timeout <= 1.0
    assert timeout < 30.0


def test_llm_timeout_keeps_configured_value_when_budget_is_ample(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "scan_timeout_seconds", 60.0)
    monkeypatch.setattr(settings, "llm_timeout_seconds", 30.0)
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
    assert _status(response, AnalyzerName.FEATURE_EXTRACTION).state is AnalyzerState.SUCCESS


def test_scan_timeout_config_rejects_invalid_values() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, scan_timeout_seconds=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, scan_timeout_seconds=601)
