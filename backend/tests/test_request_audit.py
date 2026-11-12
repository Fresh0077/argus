"""HTTP 请求包审计的接口、确认流程与 LLM 输出校验测试。

请求包审计只保留 LLM 这一路分析；预览阶段不产生发现。
所有模型调用都使用假实现，不会发起真实网络请求，也不依赖真实 API key。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.analyzers.http_request.detector import (
    RequestLlmOutcome,
    detect_request_llm_findings,
)
from app.analyzers.http_request.llm_parser import (
    RequestLlmOutputError,
    parse_request_llm_output,
)
from app.core.config import Settings
from app.main import app
from app.schemas.enums import AnalyzerState, FindingSource, Severity
from app.schemas.finding import Finding
from app.services import request_audit_service

client = TestClient(app)

AUDIT_URL = "/api/v1/audit/request"

RAW_WITH_SECRET = (
    "POST /login?next=/home&token=supersecret123 HTTP/1.1\n"
    "Host: example.com\n"
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
    "Cookie: session=abc123; theme=dark\n"
    "Content-Type: application/json\n"
    "\n"
    '{"username":"alice","password":"hunter2"}'
)

RAW_CLEAN = (
    "GET /search?q=hello HTTP/1.1\n"
    "Host: example.com\n"
    "\n"
)


class FakeCompleter:
    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.raw


def make_config(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "llm_enabled": True,
        "llm_base_url": "https://llm.test/v1",
        "llm_api_key": SecretStr("test-key"),
        "llm_model": "test-model",
    }
    values.update(overrides)
    return Settings(**values)


def make_llm_finding(
    *,
    line_start: int | None = 1,
    line_end: int | None = None,
    vulnerability_type: str = "sensitive_data_in_url",
    evidence: str = "POST /login?next=/home&token=<REDACTED> HTTP/1.1",
) -> Finding:
    return Finding(
        id="llm-finding-1",
        title="LLM 请求发现",
        vulnerability_type=vulnerability_type,
        severity=Severity.HIGH,
        description="模型判断。",
        evidence=evidence,
        line_start=line_start,
        line_end=line_end if line_end is not None else line_start,
        recommendation="处置建议。",
        confidence=0.7,
        source=FindingSource.LLM,
        rule_id=f"llm.request.{vulnerability_type}",
        cwe_id="CWE-598",
    )


def preview(raw: str = RAW_CLEAN) -> dict[str, Any]:
    response = client.post(
        AUDIT_URL, json={"raw_request": raw, "preview_only": True}
    )
    assert response.status_code == 200
    return response.json()


# ---------------------------------------------------------------------------
# 预览与确认
# ---------------------------------------------------------------------------


def test_preview_returns_redacted_text_without_findings() -> None:
    response = client.post(
        AUDIT_URL, json={"raw_request": RAW_WITH_SECRET, "preview_only": True}
    )
    assert response.status_code == 200
    body = response.json()

    assert body["preview_only"] is True
    assert body["status"] == "partial"
    assert body["llm_invoked"] is False
    assert body["findings"] == []
    assert body["summary"]["total_findings"] == 0
    assert "supersecret123" not in body["redacted_request"]
    assert "hunter2" not in body["redacted_request"]
    assert "abc123" not in body["redacted_request"]
    assert "<REDACTED>" in body["redacted_request"]

    statuses = {item["name"]: item for item in body["analyzer_status"]}
    assert statuses["http_request_parse"]["state"] == "success"
    assert statuses["http_request_llm"]["state"] == "skipped"


def test_preview_does_not_call_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> RequestLlmOutcome:
        raise AssertionError("预览模式不应调用 LLM")

    monkeypatch.setattr(
        request_audit_service, "detect_request_llm_findings", fail
    )

    response = client.post(
        AUDIT_URL, json={"raw_request": RAW_CLEAN, "preview_only": True}
    )
    assert response.status_code == 200


def test_llm_requires_explicit_confirmation() -> None:
    response = client.post(
        AUDIT_URL,
        json={
            "raw_request": RAW_CLEAN,
            "confirm_send": False,
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "request_confirmation_required"


def test_llm_rejects_outdated_preview_fingerprint() -> None:
    preview_body = preview()

    response = client.post(
        AUDIT_URL,
        json={
            "raw_request": RAW_CLEAN,
            "confirm_send": True,
            "preview_fingerprint": "0" * 64,
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "request_preview_outdated"
    assert preview_body["preview_fingerprint"] != "0" * 64


def test_llm_success_after_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_detect(redacted_request: str, **kwargs: object) -> RequestLlmOutcome:
        captured["redacted_request"] = redacted_request
        captured.update(kwargs)
        return RequestLlmOutcome(
            state=AnalyzerState.SUCCESS,
            findings=[
                make_llm_finding(
                    vulnerability_type="suspicious_payload_pattern",
                    evidence="POST /login?next=/home&token=<REDACTED> HTTP/1.1",
                )
            ],
        )

    monkeypatch.setattr(
        request_audit_service, "detect_request_llm_findings", fake_detect
    )
    preview_body = preview(RAW_WITH_SECRET)

    response = client.post(
        AUDIT_URL,
        json={
            "raw_request": RAW_WITH_SECRET,
            "confirm_send": True,
            "preview_fingerprint": preview_body["preview_fingerprint"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["llm_invoked"] is True
    assert any(item["source"] == "llm" for item in body["findings"])
    assert "supersecret123" not in captured["redacted_request"]
    assert captured["method"] == "POST"


def test_llm_failure_returns_partial_without_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        request_audit_service,
        "detect_request_llm_findings",
        lambda *args, **kwargs: RequestLlmOutcome(
            state=AnalyzerState.FAILED,
            reason="模型调用失败：测试原因。",
        ),
    )
    preview_body = preview(RAW_WITH_SECRET)

    response = client.post(
        AUDIT_URL,
        json={
            "raw_request": RAW_WITH_SECRET,
            "confirm_send": True,
            "preview_fingerprint": preview_body["preview_fingerprint"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "partial"
    assert body["findings"] == []
    statuses = {item["name"]: item for item in body["analyzer_status"]}
    assert statuses["http_request_llm"]["state"] == "failed"
    assert statuses["http_request_llm"]["reason"]


def test_clean_origin_form_request_preview_has_no_findings() -> None:
    response = client.post(
        AUDIT_URL, json={"raw_request": RAW_CLEAN, "preview_only": True}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["findings"] == []
    assert body["status"] == "partial"
    statuses = {item["name"]: item for item in body["analyzer_status"]}
    assert set(statuses) == {"http_request_parse", "http_request_llm"}
    assert statuses["http_request_parse"]["state"] == "success"
    assert statuses["http_request_llm"]["state"] == "skipped"


def test_audit_uses_edited_redacted_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_detect(redacted_request: str, **kwargs: object) -> RequestLlmOutcome:
        captured["text"] = redacted_request
        return RequestLlmOutcome(state=AnalyzerState.SUCCESS, findings=[])

    monkeypatch.setattr(
        request_audit_service, "detect_request_llm_findings", fake_detect
    )
    preview_body = preview(RAW_CLEAN)
    edited = preview_body["redacted_request"].replace(
        "Host: example.com", "Host: edited.example"
    )
    fingerprint = hashlib.sha256(edited.encode("utf-8")).hexdigest()

    response = client.post(
        AUDIT_URL,
        json={
            "raw_request": RAW_CLEAN,
            "redacted_request": edited,
            "confirm_send": True,
            "preview_fingerprint": fingerprint,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["edited"] is True
    assert body["redacted_request"] == edited
    assert captured["text"] == edited


def test_edited_text_with_old_fingerprint_is_rejected() -> None:
    preview_body = preview(RAW_CLEAN)
    edited = preview_body["redacted_request"].replace(
        "Host: example.com", "Host: edited.example"
    )

    response = client.post(
        AUDIT_URL,
        json={
            "raw_request": RAW_CLEAN,
            "redacted_request": edited,
            "confirm_send": True,
            "preview_fingerprint": preview_body["preview_fingerprint"],
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "request_preview_outdated"


def test_invalid_edited_text_is_rejected() -> None:
    edited = "NOT A VALID REQUEST\n\n"
    fingerprint = hashlib.sha256(edited.encode("utf-8")).hexdigest()

    response = client.post(
        AUDIT_URL,
        json={
            "raw_request": RAW_CLEAN,
            "redacted_request": edited,
            "confirm_send": True,
            "preview_fingerprint": fingerprint,
        },
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "request_parse_failed"


def test_preview_only_rejects_redacted_request() -> None:
    response = client.post(
        AUDIT_URL,
        json={
            "raw_request": RAW_CLEAN,
            "redacted_request": RAW_CLEAN,
            "preview_only": True,
        },
    )
    assert response.status_code == 422


def test_parse_error_does_not_echo_raw_request() -> None:
    raw = "NOT-A-REQUEST secret-value\n\n"
    response = client.post(AUDIT_URL, json={"raw_request": raw})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "request_parse_failed"
    assert "secret-value" not in response.text


def test_cross_origin_request_is_forbidden() -> None:
    response = client.post(
        AUDIT_URL,
        json={"raw_request": RAW_CLEAN},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


# ---------------------------------------------------------------------------
# LLM 输出校验
# ---------------------------------------------------------------------------


def model_output(**overrides: object) -> str:
    payload: dict[str, object] = {
        "findings": [
            {
                "title": "URL 中存在令牌",
                "vulnerability_type": "sensitive_data_in_url",
                "severity": "high",
                "description": "查询参数中出现令牌形态。",
                "evidence": "GET /search?q=hello HTTP/1.1",
                "line_start": 1,
                "line_end": 1,
                "recommendation": "改用请求体或认证头。",
                "confidence": 0.7,
                "cwe_id": "CWE-598",
            }
        ]
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=False)


def test_parse_accepts_valid_llm_output() -> None:
    result = parse_request_llm_output(
        model_output(),
        redacted_request=RAW_CLEAN,
        included_lines=3,
    )
    assert len(result.findings) == 1
    assert result.findings[0].source == FindingSource.LLM
    assert result.findings[0].rule_id == "llm.request.sensitive_data_in_url"


def test_parse_rejects_fabricated_evidence() -> None:
    raw = model_output()
    payload = json.loads(raw)
    payload["findings"][0]["evidence"] = "GET /fabricated HTTP/1.1"

    with pytest.raises(RequestLlmOutputError, match="没有一条通过"):
        parse_request_llm_output(
            json.dumps(payload, ensure_ascii=False),
            redacted_request=RAW_CLEAN,
            included_lines=3,
        )


def test_parse_rejects_out_of_range_line() -> None:
    raw = model_output()
    payload = json.loads(raw)
    payload["findings"][0]["line_start"] = 99
    payload["findings"][0]["line_end"] = 99

    with pytest.raises(RequestLlmOutputError, match="没有一条通过"):
        parse_request_llm_output(
            json.dumps(payload, ensure_ascii=False),
            redacted_request=RAW_CLEAN,
            included_lines=3,
        )


def test_parse_caps_critical_severity() -> None:
    raw = model_output()
    payload = json.loads(raw)
    payload["findings"][0]["severity"] = "critical"

    result = parse_request_llm_output(
        json.dumps(payload, ensure_ascii=False),
        redacted_request=RAW_CLEAN,
        included_lines=3,
    )
    assert result.findings[0].severity == Severity.HIGH


def test_parse_caps_category_severity() -> None:
    raw = model_output()
    payload = json.loads(raw)
    payload["findings"][0]["vulnerability_type"] = "suspicious_payload_pattern"
    payload["findings"][0]["severity"] = "high"

    result = parse_request_llm_output(
        json.dumps(payload, ensure_ascii=False),
        redacted_request=RAW_CLEAN,
        included_lines=3,
    )
    assert result.findings[0].severity == Severity.MEDIUM


def test_parse_derives_line_from_unique_evidence() -> None:
    raw = model_output()
    payload = json.loads(raw)
    payload["findings"][0].pop("line_start")
    payload["findings"][0].pop("line_end")

    result = parse_request_llm_output(
        json.dumps(payload, ensure_ascii=False),
        redacted_request=RAW_CLEAN,
        included_lines=3,
    )
    assert result.findings[0].line_start == 1


# ---------------------------------------------------------------------------
# LLM 检测器
# ---------------------------------------------------------------------------


def test_detector_skips_when_disabled() -> None:
    outcome = detect_request_llm_findings(
        RAW_CLEAN,
        method="GET",
        http_version="HTTP/1.1",
        scheme=None,
        content_type=None,
        body_kind="none",
        config=make_config(llm_enabled=False),
    )
    assert outcome.state == AnalyzerState.SKIPPED


def test_detector_reports_unavailable_without_key() -> None:
    outcome = detect_request_llm_findings(
        RAW_CLEAN,
        method="GET",
        http_version="HTTP/1.1",
        scheme=None,
        content_type=None,
        body_kind="none",
        config=make_config(llm_api_key=SecretStr("")),
    )
    assert outcome.state == AnalyzerState.UNAVAILABLE


def test_detector_wraps_untrusted_request_and_returns_findings() -> None:
    completer = FakeCompleter(model_output())
    outcome = detect_request_llm_findings(
        RAW_CLEAN,
        method="GET",
        http_version="HTTP/1.1",
        scheme=None,
        content_type=None,
        body_kind="none",
        config=make_config(),
        client=completer,
    )

    assert outcome.state == AnalyzerState.SUCCESS
    assert outcome.findings
    system, user = completer.calls[0]
    assert "不可信数据" in system
    assert "<request-" in user
    assert "GET /search?q=hello HTTP/1.1" in user
